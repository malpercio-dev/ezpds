// pattern: Mixed (Functional Core sweep orchestration + iOS-only imperative scheduling bridge)
//
// Background media-backup scheduling. The user-held blob backup (`blob_backup.rs`) ships
// the explicit "Back up media" action plus an opportunistic pass on app open; this module
// adds the deliberate later step — an iOS `BGProcessingTask` so an opted-in identity's
// iCloud mirror stays topped up without the user opening the app (media posted days ago
// shouldn't sit unprotected until the next launch).
//
// On fire it runs the same incremental, CID-verified, per-blob-degrading `run_blob_backup`
// pass for every opted-in DID. That is safe to overlap with a foreground pass: the per-DID
// mirror lock in `blob_backup` serializes the manifest writes, and the pass is idempotent
// by construction (content-addressed, immutable files), so a sweep iOS interrupts mid-run
// self-heals on the next pass.
//
// Scheduling is a device concern: everything that touches `BGTaskScheduler` is iOS-only,
// reached through objc2's BackgroundTasks binding — the same no-new-Swift bridge pattern as
// blob_backup's ubiquity-container call. Off-device the whole surface is inert, so the
// browser harness fake is untouched. The sweep *orchestration* (`run_sweep_with`) is
// platform-agnostic and unit-tested.

use crate::blob_backup;

/// The `BGTaskScheduler` identifier for the media-backup processing task. MUST match the
/// entry in `Info.ios.plist`'s `BGTaskSchedulerPermittedIdentifiers` array — iOS refuses to
/// register or submit an identifier the plist doesn't permit — and is bundle-id-prefixed by
/// Apple convention (bundle id `dev.malpercio.identitywallet`, `tauri.conf.json`). Kept in
/// sync with the plist the same way the ubiquity container id is.
#[cfg(target_os = "ios")]
const BACKUP_TASK_IDENTIFIER: &str = "dev.malpercio.identitywallet.blob-backup";

/// The earliest the system may run a scheduled task, as a delay from submission. A floor,
/// not a deadline — iOS picks the actual moment from usage, power, and network availability.
/// ~12h keeps the mirror fresh (new media is protected within a day) without asking to wake
/// more often than a media backup needs to.
#[cfg(target_os = "ios")]
const EARLIEST_BEGIN_AFTER_SECS: f64 = 12.0 * 60.0 * 60.0;

/// Summary of one background sweep — counts only, for `tracing` and the unit tests.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BackupSweepReport {
    /// Opted-in identities the sweep attempted a pass for.
    pub attempted: u32,
    /// Attempts that completed without error.
    pub succeeded: u32,
    /// Attempts that returned an error (logged, never aborts the sweep).
    pub failed: u32,
    /// Identities skipped because the user has not opted in.
    pub skipped: u32,
}

/// Sweep core: back up every opted-in identity, degrading per-DID — one identity's failure
/// is tallied and logged, never stops the others. Generic over the opt-in predicate and the
/// per-DID backup step so it is unit-testable without a live PDS, Keychain, or iCloud.
/// Sequential by design: the passes share the network and the process-global per-DID mirror
/// locks, and a background sweep has no reason to race them concurrently.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
pub(crate) async fn run_sweep_with<F, Fut>(
    dids: &[String],
    is_enabled: impl Fn(&str) -> bool,
    backup_one: F,
) -> BackupSweepReport
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), blob_backup::BlobBackupError>>,
{
    let mut report = BackupSweepReport::default();
    for did in dids {
        if !is_enabled(did) {
            report.skipped += 1;
            continue;
        }
        report.attempted += 1;
        match backup_one(did.clone()).await {
            Ok(()) => report.succeeded += 1,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "background media backup: pass failed");
                report.failed += 1;
            }
        }
    }
    report
}

/// Run one background backup sweep over every managed identity, backing up those opted in.
/// The launch handler's payload. Resolves the managed DIDs from the `IdentityStore` and
/// delegates to `run_sweep_with` with the real opt-in flag + per-DID backup.
#[cfg(target_os = "ios")]
pub(crate) async fn run_backup_sweep(app: &tauri::AppHandle) -> BackupSweepReport {
    let dids = crate::identity_store::IdentityStore
        .list_identities()
        .unwrap_or_default();
    let report = run_sweep_with(
        &dids,
        |did| blob_backup::is_backup_enabled(did),
        |did| {
            let app = app.clone();
            async move { blob_backup::run_backup_for_did(&app, &did).await.map(|_| ()) }
        },
    )
    .await;
    tracing::info!(
        attempted = report.attempted,
        succeeded = report.succeeded,
        failed = report.failed,
        skipped = report.skipped,
        "background media backup sweep complete"
    );
    report
}

// ── iOS BGProcessingTask bridge ──────────────────────────────────────────────

/// A `Retained<BGTask>` we promise to use soundly across threads.
///
/// iOS calls the launch handler on the main thread, but the backup sweep runs on the tokio
/// runtime; the worker (or the expiration handler) must call `setTaskCompletedWithSuccess`
/// when it finishes. objc2 conservatively leaves framework objects `!Send`, so we assert it.
///
/// SAFETY: the only `BGTask` methods we call on it are the completion methods, which Apple
/// documents as callable from any thread (their sample code completes the task from an
/// `NSOperation` completion block on a background queue), and every such call is gated behind
/// a one-shot atomic latch so it happens exactly once.
#[cfg(target_os = "ios")]
struct SendTask(objc2::rc::Retained<objc2_background_tasks::BGTask>);

#[cfg(target_os = "ios")]
// SAFETY: see the `SendTask` doc comment — completion methods are thread-safe by Apple's
// contract and serialized to a single call by the `done` latch in `complete_once`.
unsafe impl Send for SendTask {}
#[cfg(target_os = "ios")]
// SAFETY: as above; the shared handle is only ever used to make the thread-safe completion
// call, so concurrent `&SendTask` access from the worker and the expiration handler is sound.
unsafe impl Sync for SendTask {}

/// Mark the task complete at most once — whichever of the worker (success) or the expiration
/// handler (failure) reaches it first wins; the loser is a no-op. iOS treats a second
/// `setTaskCompletedWithSuccess` on the same task as a fatal misuse, so the latch is required.
#[cfg(target_os = "ios")]
fn complete_once(task: &SendTask, done: &std::sync::atomic::AtomicBool, success: bool) {
    use std::sync::atomic::Ordering;
    if !done.swap(true, Ordering::SeqCst) {
        unsafe { task.0.setTaskCompletedWithSuccess(success) };
    }
}

/// Register the background media-backup task and submit the first request. Called once from
/// the Tauri `setup` hook on iOS — registration must happen before app launch completes, and
/// `setup` runs within `application:didFinishLaunchingWithOptions:`. Every failure is logged
/// rather than fatal: the opportunistic app-open pass still protects opted-in identities.
#[cfg(target_os = "ios")]
pub(crate) fn register_and_schedule(app: &tauri::AppHandle) {
    use block2::RcBlock;
    use objc2_background_tasks::{BGTask, BGTaskScheduler};
    use objc2_foundation::NSString;
    use std::ptr::NonNull;

    let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
    let identifier = NSString::from_str(BACKUP_TASK_IDENTIFIER);

    let app_for_handler = app.clone();
    // Escaping launch handler; iOS stores a copy for the process lifetime and calls it on the
    // main thread when it decides to run the task, handing us the live `BGTask`.
    let launch_handler = RcBlock::new(move |task_ptr: NonNull<BGTask>| {
        // We were handed the task with no ownership; retain it (+1) so it survives the async
        // sweep. Non-null by the framework's contract.
        let Some(task) = (unsafe { objc2::rc::Retained::retain(task_ptr.as_ptr()) }) else {
            return;
        };
        handle_launch(&app_for_handler, task);
    });

    let registered = unsafe {
        scheduler.registerForTaskWithIdentifier_usingQueue_launchHandler(
            &identifier,
            None, // run the launch handler on the default background queue
            &launch_handler,
        )
    };
    if !registered {
        tracing::warn!(
            "background media backup: BGTaskScheduler refused to register the task identifier"
        );
        return;
    }

    schedule_next(&scheduler, &identifier);
}

/// The launch-handler body (runs on the main thread): re-arm the next run, then kick off the
/// sweep on the tokio runtime and wire up completion + expiration.
#[cfg(target_os = "ios")]
fn handle_launch(
    app: &tauri::AppHandle,
    task: objc2::rc::Retained<objc2_background_tasks::BGTask>,
) {
    use block2::RcBlock;
    use objc2_background_tasks::BGTaskScheduler;
    use objc2_foundation::NSString;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    // Re-schedule the follow-up immediately (Apple's guidance is to submit the next request as
    // the task begins), so the mirror keeps getting topped up run after run.
    let scheduler = unsafe { BGTaskScheduler::sharedScheduler() };
    let identifier = NSString::from_str(BACKUP_TASK_IDENTIFIER);
    schedule_next(&scheduler, &identifier);

    // Share the task + a one-shot completion latch between the worker and the expiration
    // handler so the task is marked complete exactly once.
    let task = Arc::new(SendTask(task));
    let done = Arc::new(AtomicBool::new(false));

    // Run the actual sweep off the main thread.
    let worker = {
        let app = app.clone();
        let task = task.clone();
        let done = done.clone();
        tauri::async_runtime::spawn(async move {
            let _ = run_backup_sweep(&app).await;
            complete_once(&task, &done, true);
        })
    };

    // iOS calls this (on the main thread) when our time is nearly up: abort the sweep and end
    // cleanly. Aborting mid-pass is safe — the mirror write is atomic and the manifest is
    // checkpointed, so the interrupted DID simply resumes on the next sweep.
    let expiration = {
        let task = task.clone();
        RcBlock::new(move || {
            worker.abort();
            complete_once(&task, &done, false);
        })
    };
    unsafe { task.0.setExpirationHandler(Some(&expiration)) };
}

/// Build and submit the next `BGProcessingTaskRequest`. Failures (the simulator has no
/// `BGTaskScheduler`; an unpermitted identifier; too many pending requests) are logged, never
/// fatal.
#[cfg(target_os = "ios")]
fn schedule_next(
    scheduler: &objc2_background_tasks::BGTaskScheduler,
    identifier: &objc2_foundation::NSString,
) {
    use objc2::AnyThread;
    use objc2_background_tasks::BGProcessingTaskRequest;
    use objc2_foundation::NSDate;

    let request = unsafe {
        BGProcessingTaskRequest::initWithIdentifier(BGProcessingTaskRequest::alloc(), identifier)
    };
    unsafe {
        // The sweep fetches blobs, so it needs the network. External power is left off so the
        // sweep isn't starved on devices that rarely charge on a predictable schedule; iOS
        // already prefers to run processing tasks while charging. Power-gating a video-heavy
        // account by its mirror size is a documented future refinement.
        request.setRequiresNetworkConnectivity(true);
        request.setRequiresExternalPower(false);
        let earliest = NSDate::dateWithTimeIntervalSinceNow(EARLIEST_BEGIN_AFTER_SECS);
        request.setEarliestBeginDate(Some(&earliest));
    }

    // A `BGProcessingTaskRequest` is a `BGTaskRequest`; `submitTaskRequest_error` takes the
    // superclass (deref coercion).
    if let Err(e) = unsafe { scheduler.submitTaskRequest_error(&request) } {
        tracing::warn!(error = ?e, "background media backup: failed to submit task request");
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use blob_backup::BlobBackupError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn dids(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn sweep_backs_up_only_opted_in_identities() {
        let all = dids(&["did:plc:a", "did:plc:b", "did:plc:c"]);
        // b is opted out.
        let enabled = |did: &str| did != "did:plc:b";
        let backed_up = Mutex::new(Vec::new());

        let report = run_sweep_with(&all, enabled, |did| {
            let backed_up = &backed_up;
            async move {
                backed_up.lock().unwrap().push(did);
                Ok(())
            }
        })
        .await;

        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 2,
                succeeded: 2,
                failed: 0,
                skipped: 1,
            }
        );
        assert_eq!(
            *backed_up.lock().unwrap(),
            vec!["did:plc:a".to_string(), "did:plc:c".to_string()]
        );
    }

    #[tokio::test]
    async fn sweep_degrades_per_did_and_continues() {
        let all = dids(&["did:plc:a", "did:plc:b", "did:plc:c"]);
        let attempts = AtomicUsize::new(0);

        // The middle identity fails; the sweep must still attempt the third.
        let report = run_sweep_with(
            &all,
            |_| true,
            |did| {
                let attempts = &attempts;
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    if did == "did:plc:b" {
                        Err(BlobBackupError::NetworkError {
                            message: "boom".to_string(),
                        })
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 3,
                succeeded: 2,
                failed: 1,
                skipped: 0,
            }
        );
    }

    #[tokio::test]
    async fn sweep_with_no_opted_in_identities_does_nothing() {
        let all = dids(&["did:plc:a", "did:plc:b"]);
        let called = AtomicUsize::new(0);

        let report = run_sweep_with(&all, |_| false, |did| {
            let called = &called;
            async move {
                called.fetch_add(1, Ordering::SeqCst);
                let _ = did;
                Ok(())
            }
        })
        .await;

        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 0,
                succeeded: 0,
                failed: 0,
                skipped: 2,
            }
        );
    }

    #[tokio::test]
    async fn sweep_over_empty_identity_list_is_a_noop() {
        let report = run_sweep_with(&[], |_| true, |_did| async { Ok(()) }).await;
        assert_eq!(report, BackupSweepReport::default());
    }
}
