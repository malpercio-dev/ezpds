//! [`IosScheduler`], the iOS [`Scheduler`]: each [`BackgroundJob`] is a `BGProcessingTask` or a
//! `BGAppRefreshTask` ([`TaskKind`]) under an app-supplied identifier, via objc2
//! (`objc2-background-tasks` + `block2`).
//!
//! Each identifier must appear in the app's `Info.ios.plist` `BGTaskSchedulerPermittedIdentifiers`
//! (with the `processing` or `fetch` `UIBackgroundModes` entry for its kind): iOS refuses to
//! register or submit one it does not permit. [`IosScheduler::register`] must run before app
//! launch completes.
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

/// Which `BGTaskRequest` a job is submitted as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskKind {
    /// `BGProcessingTaskRequest`: minutes of runtime, usually while the device is idle (often
    /// overnight), and honours `requires_network` / `requires_external_power`.
    Processing,
    /// `BGAppRefreshTaskRequest`: about 30 seconds, run through the day as iOS learns how the
    /// app is used. It takes no conditions, so `requires_network` and `requires_external_power`
    /// are ignored; the job must tolerate running offline.
    AppRefresh,
}

pub struct IosScheduler(Arc<Inner>);

struct Inner {
    identifiers: Vec<(BackgroundJob, &'static str, TaskKind)>,
    start: StartJob,
    requests: Mutex<HashMap<BackgroundJob, JobRequest>>,
}

impl IosScheduler {
    /// `identifiers` maps each job the app runs in the background to its permitted
    /// `BGTaskScheduler` identifier and the kind of task it is submitted as.
    pub fn new(identifiers: Vec<(BackgroundJob, &'static str, TaskKind)>, start: StartJob) -> Self {
        Self(Arc::new(Inner {
            identifiers,
            start,
            requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Register every job's launch handler. Failures are logged rather than fatal: every job also
    /// runs in the foreground.
    ///
    /// # Safety
    ///
    /// Call once per process, before app launch completes, with the identifiers passed to
    /// [`IosScheduler::new`] distinct. `BGTaskScheduler` raises an Objective-C exception on a
    /// late or repeated registration, and an exception unwinding through Rust frames is
    /// undefined behaviour.
    pub unsafe fn register(&self) {
        use block2::RcBlock;
        use objc2_background_tasks::{BGTask, BGTaskScheduler};
        use objc2_foundation::NSString;
        use std::ptr::NonNull;

        // SAFETY: `sharedScheduler` takes no arguments and has no preconditions.
        let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
        for &(job, identifier, _) in &self.0.identifiers {
            let inner = self.0.clone();
            // Escaping launch handler; iOS stores a copy for the process lifetime and calls it
            // on a background queue (the `None` below) when it decides to run the task, handing
            // us the live `BGTask`.
            let launch_handler = RcBlock::new(move |task_ptr: NonNull<BGTask>| {
                // We were handed the task with no ownership; retain it (+1) so it survives the
                // async job.
                // SAFETY: `task_ptr` is a live `BGTask` for the duration of this call, so retaining
                // it is sound.
                let Some(task) = (unsafe { objc2::rc::Retained::retain(task_ptr.as_ptr()) }) else {
                    return;
                };
                inner.handle_launch(job, task);
            });
            // SAFETY: the caller's contract (see `# Safety`) rules out the late or repeated
            // registration that would raise; the arguments are a valid string and block.
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
        if let Some((identifier, _)) = self.0.identifier(job) {
            // SAFETY: `sharedScheduler` takes no arguments and has no preconditions.
            let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
            // SAFETY: a valid identifier string; cancelling an unknown one is a no-op.
            unsafe { scheduler.cancelTaskRequestWithIdentifier(&NSString::from_str(identifier)) };
        }
    }
}

impl Inner {
    fn identifier(&self, job: BackgroundJob) -> Option<(&'static str, TaskKind)> {
        self.identifiers
            .iter()
            .find(|(j, _, _)| *j == job)
            .map(|&(_, id, kind)| (id, kind))
    }

    fn lock_requests(&self) -> std::sync::MutexGuard<'_, HashMap<BackgroundJob, JobRequest>> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Build and submit the `BGTaskRequest` of the job's [`TaskKind`] for `request`. Failures
    /// (the simulator has no `BGTaskScheduler`; an unpermitted identifier; too many pending
    /// requests) are logged, never fatal.
    fn submit(&self, request: &JobRequest) {
        use objc2::rc::Retained;
        use objc2::AnyThread;
        use objc2_background_tasks::{
            BGAppRefreshTaskRequest, BGProcessingTaskRequest, BGTaskRequest, BGTaskScheduler,
        };
        use objc2_foundation::{NSDate, NSString};

        let Some((identifier, kind)) = self.identifier(request.job) else {
            tracing::warn!(job = ?request.job, "no BGTaskScheduler identifier for this job");
            return;
        };
        let identifier = NSString::from_str(identifier);
        let task_request: Retained<BGTaskRequest> = match kind {
            TaskKind::Processing => {
                // SAFETY: `init` consumes a fresh `alloc` and a valid identifier string.
                let processing = unsafe {
                    BGProcessingTaskRequest::initWithIdentifier(
                        BGProcessingTaskRequest::alloc(),
                        &identifier,
                    )
                };
                // SAFETY: plain property setters on a request we own and have not submitted.
                unsafe {
                    processing.setRequiresNetworkConnectivity(request.requires_network);
                    processing.setRequiresExternalPower(request.requires_external_power);
                }
                Retained::into_super(processing)
            }
            // SAFETY: `init` consumes a fresh `alloc` and a valid identifier string.
            TaskKind::AppRefresh => Retained::into_super(unsafe {
                BGAppRefreshTaskRequest::initWithIdentifier(
                    BGAppRefreshTaskRequest::alloc(),
                    &identifier,
                )
            }),
        };
        // SAFETY: a finite interval builds a valid date; the setter is a plain property write on a
        // request we own and have not submitted.
        unsafe {
            let earliest =
                NSDate::dateWithTimeIntervalSinceNow(request.earliest_after.as_secs_f64());
            task_request.setEarliestBeginDate(Some(&earliest));
        }
        // SAFETY: `sharedScheduler` takes no arguments and has no preconditions.
        let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
        // SAFETY: a valid, unsubmitted request; failures (an unpermitted identifier, no
        // scheduler on the simulator) come back as `Err`, not an exception.
        if let Err(e) = unsafe { scheduler.submitTaskRequest_error(&task_request) } {
            tracing::warn!(job = ?request.job, error = ?e, "failed to submit the background task request");
        }
    }

    /// The launch-handler body (runs on BGTaskScheduler's background queue): re-arm the next
    /// run, apply the network condition, then start the job and wire up completion and
    /// expiration.
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

        // iOS calls this (on a queue of its choosing) when our time is nearly up: abort the job and
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
        // SAFETY: the task is live (we hold a retain) and the block is `Fn()` as the handler's
        // `void (^)(void)` type requires; iOS copies it.
        unsafe { task.0.setExpirationHandler(Some(&expiration)) };
    }
}

/// A `Retained<BGTask>` we promise to use soundly across threads.
///
/// iOS calls the launch handler on a background queue, but the job runs on the app's async
/// runtime; the worker (or the expiration handler) must call `setTaskCompletedWithSuccess`
/// when it finishes. objc2 conservatively leaves framework objects `!Send`, so we assert it.
///
/// SAFETY: apart from setting the expiration handler on the thread that received the task, the
/// only `BGTask` methods we call on it are the completion methods, which Apple
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
        // SAFETY: see `SendTask` — callable from any thread, and the latch makes this the only
        // call.
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
