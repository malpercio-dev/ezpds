//! [`IosScheduler`], the iOS [`Scheduler`]: each [`BackgroundJob`] is a `BGProcessingTask`
//! under an app-supplied identifier, via objc2 (`objc2-background-tasks` + `block2`).
//!
//! Each identifier must appear in the app's `Info.ios.plist` `BGTaskSchedulerPermittedIdentifiers`
//! (with the `processing` `UIBackgroundModes` entry): iOS refuses to register or submit one it
//! does not permit. [`IosScheduler::register`] must run before app launch completes.
//!
//! A request is periodic: it is kept in memory, re-submitted as the task begins (Apple's
//! guidance), and dropped on `cancel`. "Unmetered only", which `BGProcessingTaskRequest` cannot
//! express, is checked when the task fires via `SCNetworkReachability`'s `IS_WWAN` flag (an
//! unreadable network type fails open to "not metered"). The task is marked complete exactly
//! once, via a latch shared by the worker and the expiration handler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use obsign_core::scheduler::{skip_for_network, BackgroundJob, JobRequest, Scheduler};

/// Starts `job` on the app's async runtime, calls the second argument when it finishes, and
/// returns a function that aborts it. Supplied by the shell, which owns the runtime and the
/// app's `Core`.
pub type StartJob =
    Arc<dyn Fn(BackgroundJob, Box<dyn FnOnce() + Send>) -> Box<dyn FnOnce() + Send> + Send + Sync>;

pub struct IosScheduler(Arc<Inner>);

struct Inner {
    identifiers: Vec<(BackgroundJob, &'static str)>,
    start: StartJob,
    requests: Mutex<HashMap<BackgroundJob, JobRequest>>,
}

impl IosScheduler {
    /// `identifiers` maps each job the app runs in the background to its permitted
    /// `BGTaskScheduler` identifier.
    pub fn new(identifiers: Vec<(BackgroundJob, &'static str)>, start: StartJob) -> Self {
        Self(Arc::new(Inner {
            identifiers,
            start,
            requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Register every job's launch handler. Must run before app launch completes. Failures are
    /// logged rather than fatal: every job also runs in the foreground.
    pub fn register(&self) {
        use block2::RcBlock;
        use objc2_background_tasks::{BGTask, BGTaskScheduler};
        use objc2_foundation::NSString;
        use std::ptr::NonNull;

        let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
        for &(job, identifier) in &self.0.identifiers {
            let inner = self.0.clone();
            // Escaping launch handler; iOS stores a copy for the process lifetime and calls it
            // on the main thread when it decides to run the task, handing us the live `BGTask`.
            let launch_handler = RcBlock::new(move |task_ptr: NonNull<BGTask>| {
                // We were handed the task with no ownership; retain it (+1) so it survives the
                // async job. Non-null by the framework's contract.
                let Some(task) = (unsafe { objc2::rc::Retained::retain(task_ptr.as_ptr()) }) else {
                    return;
                };
                inner.handle_launch(job, task);
            });
            let registered = unsafe {
                scheduler.registerForTaskWithIdentifier_usingQueue_launchHandler(
                    &NSString::from_str(identifier),
                    None, // run the launch handler on the default background queue
                    &launch_handler,
                )
            };
            if !registered {
                tracing::warn!(
                    ?job,
                    "BGTaskScheduler refused to register the task identifier"
                );
            }
        }
    }
}

impl Scheduler for IosScheduler {
    fn schedule(&self, request: JobRequest) {
        self.0.lock_requests().insert(request.job, request);
        self.0.submit(&request);
    }

    fn cancel(&self, job: BackgroundJob) {
        use objc2_background_tasks::BGTaskScheduler;
        use objc2_foundation::NSString;

        self.0.lock_requests().remove(&job);
        if let Some(identifier) = self.0.identifier(job) {
            let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
            unsafe { scheduler.cancelTaskRequestWithIdentifier(&NSString::from_str(identifier)) };
        }
    }
}

impl Inner {
    fn identifier(&self, job: BackgroundJob) -> Option<&'static str> {
        self.identifiers
            .iter()
            .find(|(j, _)| *j == job)
            .map(|&(_, id)| id)
    }

    fn lock_requests(&self) -> std::sync::MutexGuard<'_, HashMap<BackgroundJob, JobRequest>> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Build and submit the `BGProcessingTaskRequest` for `request`. Failures (the simulator
    /// has no `BGTaskScheduler`; an unpermitted identifier; too many pending requests) are
    /// logged, never fatal.
    fn submit(&self, request: &JobRequest) {
        use objc2::AnyThread;
        use objc2_background_tasks::{BGProcessingTaskRequest, BGTaskScheduler};
        use objc2_foundation::{NSDate, NSString};

        let Some(identifier) = self.identifier(request.job) else {
            tracing::warn!(job = ?request.job, "no BGTaskScheduler identifier for this job");
            return;
        };
        let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
        let task_request = unsafe {
            BGProcessingTaskRequest::initWithIdentifier(
                BGProcessingTaskRequest::alloc(),
                &NSString::from_str(identifier),
            )
        };
        unsafe {
            task_request.setRequiresNetworkConnectivity(request.requires_network);
            task_request.setRequiresExternalPower(request.requires_external_power);
            let earliest =
                NSDate::dateWithTimeIntervalSinceNow(request.earliest_after.as_secs_f64());
            task_request.setEarliestBeginDate(Some(&earliest));
        }
        // A `BGProcessingTaskRequest` is a `BGTaskRequest`; `submitTaskRequest_error` takes the
        // superclass (deref coercion).
        if let Err(e) = unsafe { scheduler.submitTaskRequest_error(&task_request) } {
            tracing::warn!(job = ?request.job, error = ?e, "failed to submit the background task request");
        }
    }

    /// The launch-handler body (runs on the main thread): re-arm the next run, apply the
    /// network condition, then start the job and wire up completion and expiration.
    fn handle_launch(
        &self,
        job: BackgroundJob,
        task: objc2::rc::Retained<objc2_background_tasks::BGTask>,
    ) {
        use block2::RcBlock;

        // Re-arm the follow-up immediately (Apple's guidance is to submit the next request as
        // the task begins). A request cancelled since the last fire is simply not re-armed.
        let request = self.lock_requests().get(&job).copied();
        if let Some(request) = &request {
            self.submit(request);
        }

        let task = Arc::new(SendTask(task));
        let done = Arc::new(AtomicBool::new(false));

        if request.is_some_and(|r| skip_for_network(&r, on_cellular())) {
            tracing::info!(
                ?job,
                "background job skipped this run: unmetered only, and on cellular"
            );
            complete_once(&task, &done, true);
            return;
        }

        let on_done = {
            let task = task.clone();
            let done = done.clone();
            Box::new(move || complete_once(&task, &done, true))
        };
        let abort = Mutex::new(Some((self.start)(job, on_done)));

        // iOS calls this (on the main thread) when our time is nearly up: abort the job and
        // end cleanly. The jobs are idempotent and resume on the next fire.
        let expiration = {
            let task = task.clone();
            RcBlock::new(move || {
                if let Some(abort) = abort
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    abort();
                }
                complete_once(&task, &done, false);
            })
        };
        unsafe { task.0.setExpirationHandler(Some(&expiration)) };
    }
}

/// A `Retained<BGTask>` we promise to use soundly across threads.
///
/// iOS calls the launch handler on the main thread, but the job runs on the app's async
/// runtime; the worker (or the expiration handler) must call `setTaskCompletedWithSuccess`
/// when it finishes. objc2 conservatively leaves framework objects `!Send`, so we assert it.
///
/// SAFETY: the only `BGTask` methods we call on it are the completion methods, which Apple
/// documents as callable from any thread (their sample code completes the task from an
/// `NSOperation` completion block on a background queue), and every such call is gated behind
/// a one-shot atomic latch so it happens exactly once.
struct SendTask(objc2::rc::Retained<objc2_background_tasks::BGTask>);

// SAFETY: see the `SendTask` doc comment — completion methods are thread-safe by Apple's
// contract and serialized to a single call by the `done` latch in `complete_once`.
unsafe impl Send for SendTask {}
// SAFETY: as above; the shared handle is only ever used to make the thread-safe completion
// call, so concurrent `&SendTask` access from the worker and the expiration handler is sound.
unsafe impl Sync for SendTask {}

/// Mark the task complete at most once — whichever of the worker (success) or the expiration
/// handler (failure) reaches it first wins; the loser is a no-op. iOS treats a second
/// `setTaskCompletedWithSuccess` on the same task as a fatal misuse, so the latch is required.
fn complete_once(task: &SendTask, done: &AtomicBool, success: bool) {
    if !done.swap(true, Ordering::SeqCst) {
        unsafe { task.0.setTaskCompletedWithSuccess(success) };
    }
}

/// Whether the device's default route is currently a cellular (WWAN) link, via
/// `SCNetworkReachability` flags for the unspecified address (general internet reachability).
/// On any read failure we report `false` (not cellular) so a diagnostic hiccup never silently
/// disables a job — an occasional cellular run is the lesser evil than a mirror that quietly
/// stops updating.
fn on_cellular() -> bool {
    use std::net::{Ipv4Addr, SocketAddr};
    use system_configuration::network_reachability::{ReachabilityFlags, SCNetworkReachability};

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let reachability = SCNetworkReachability::from(addr);
    match reachability.reachability() {
        Ok(flags) => {
            flags.contains(ReachabilityFlags::REACHABLE)
                && flags.contains(ReachabilityFlags::IS_WWAN)
        }
        Err(e) => {
            tracing::warn!(error = ?e, "could not read network type; assuming not cellular");
            false
        }
    }
}
