//! Background work: the [`Scheduler`] trait a shell implements, and [`run`], the job bodies.
//!
//! The core says what to run and under which conditions; the platform decides how (iOS
//! `BGTaskScheduler`, Android `WorkManager`). A request is periodic: the platform keeps it,
//! re-arms it each time the job fires, and drops it on [`cancel`]. When a job fires the
//! platform calls [`run`] on the app's async runtime.
//!
//! Installation follows [`keystore`](crate::keystore). With no scheduler installed (desktop,
//! the Simulator, tests) requests are dropped: background work is a device concern, and every
//! job also runs in the foreground (the app-open backup pass, the PLC monitor's timer).

use std::sync::OnceLock;
use std::time::Duration;

/// The background work the core asks the platform to run.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BackgroundJob {
    /// Top up the user-held media and repo mirrors for every opted-in identity.
    BackupMirror,
    /// Sweep every did:plc identity for directory operations the device key did not sign.
    PlcCheck,
}

/// One periodic request: what to run, and the conditions the platform must wait for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobRequest {
    pub job: BackgroundJob,
    /// The earliest the job may run, measured from when the request is (re-)armed. A floor,
    /// not a deadline: the platform picks the moment.
    pub earliest_after: Duration,
    pub requires_network: bool,
    pub requires_external_power: bool,
    /// Skip a run that would happen on a metered (cellular) link. Checked when the job fires
    /// where the platform cannot express it as a request condition (iOS).
    pub unmetered_only: bool,
}

pub trait Scheduler: Send + Sync {
    /// Submit `request`, replacing any pending request for the same job. Failures are the
    /// platform's to log: a job that never runs in the background still runs in the foreground.
    fn schedule(&self, request: JobRequest);

    /// Withdraw any pending request for `job`.
    fn cancel(&self, job: BackgroundJob);
}

static INSTALLED: OnceLock<Box<dyn Scheduler>> = OnceLock::new();

/// Install the process-wide scheduler. The second and later calls are refused and hand the
/// scheduler back.
pub fn install(scheduler: Box<dyn Scheduler>) -> Result<(), Box<dyn Scheduler>> {
    INSTALLED.set(scheduler)
}

/// Submit `request` to the installed scheduler, if any.
pub fn schedule(request: JobRequest) {
    match INSTALLED.get() {
        Some(scheduler) => scheduler.schedule(request),
        None => tracing::debug!(job = ?request.job, "no scheduler installed; request dropped"),
    }
}

/// Withdraw `job` from the installed scheduler, if any.
pub fn cancel(job: BackgroundJob) {
    if let Some(scheduler) = INSTALLED.get() {
        scheduler.cancel(job);
    }
}

/// Whether a run of `request` should be skipped because it would happen on a metered link.
/// For platforms that check "unmetered only" when the job fires rather than as a request
/// condition (iOS).
pub fn skip_for_network(request: &JobRequest, on_metered: bool) -> bool {
    request.unmetered_only && on_metered
}

/// Run `job` once. What the platform calls when a request fires.
pub async fn run(job: BackgroundJob, core: &crate::oauth::Core) {
    match job {
        BackgroundJob::BackupMirror => crate::backup_policy::run_backup_sweep(core).await,
        BackgroundJob::PlcCheck => crate::plc_monitor::run_monitoring_cycle_and_alert(core).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmetered_only_skips_only_on_a_metered_link() {
        let request = |unmetered_only| JobRequest {
            job: BackgroundJob::BackupMirror,
            earliest_after: Duration::ZERO,
            requires_network: true,
            requires_external_power: false,
            unmetered_only,
        };
        assert!(skip_for_network(&request(true), true));
        assert!(!skip_for_network(&request(true), false));
        // The preference off never skips, even on a metered link.
        assert!(!skip_for_network(&request(false), true));
        assert!(!skip_for_network(&request(false), false));
    }
}
