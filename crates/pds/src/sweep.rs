// pattern: Imperative Shell

//! The periodic-sweep scheduler.
//!
//! A sweep is a [`Sweep`] impl: its cadence plus one `run` pass. [`spawn`] owns everything
//! else — the interval loop, the skipped boot tick, missed-tick policy, the failure posture,
//! and writing `AppState.sweeps` for `GET /v1/admin/health`.
//!
//! Failure posture: a pass that returns `Err` is logged and records nothing, so a stale (or
//! absent) status entry stays the operator's alarm. A pass that returns `Ok` records, even
//! when it found nothing to do. A sweep's own OTel instruments are recorded inside its `run`,
//! on the success path only, for the same reason.

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::sweep_status::SweepRun;

/// What one completed pass did; the scheduler stamps the completion time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pass {
    /// Rows/files acted on (see [`SweepRun::swept`]).
    pub swept: u64,
    /// Failed operations in a pass that still completed (see [`SweepRun::errors`]).
    pub errors: u64,
}

impl Pass {
    pub fn swept(swept: u64) -> Self {
        Self { swept, errors: 0 }
    }
}

pub trait Sweep: Send + Sync + 'static {
    /// Log label and `AppState.sweeps` key; one of `sweep_status::names`.
    const NAME: &'static str;

    /// Whether a completed pass is published to `GET /v1/admin/health`. Only the
    /// sovereign-session nonce sweep opts out: its health slot was never part of the payload.
    const REPORTS_STATUS: bool = true;

    fn interval(&self) -> Duration;

    /// Set [`tokio::time::MissedTickBehavior::Skip`] so a late pass is never followed by a
    /// burst of catch-up passes; `false` keeps tokio's default (`Burst`).
    fn skip_missed_ticks(&self) -> bool {
        false
    }

    /// One pass. `Err` means the pass did not complete and must record nothing.
    fn run(&self, state: &AppState) -> impl Future<Output = anyhow::Result<Pass>> + Send;
}

/// Run one pass and publish it per the failure posture above. The loop's body, and what tests
/// call to exercise a sweep end to end.
pub async fn run_once<S: Sweep>(sweep: &S, state: &AppState) -> Option<Pass> {
    match sweep.run(state).await {
        Ok(pass) => {
            if S::REPORTS_STATUS {
                state
                    .sweeps
                    .record(S::NAME, SweepRun::now_with_errors(pass.swept, pass.errors));
            }
            Some(pass)
        }
        Err(error) => {
            tracing::error!(sweep = S::NAME, error = %error, "sweep pass failed; skipping");
            None
        }
    }
}

/// Spawn the sweep: consume the first tick without running a pass (so nothing sweeps
/// mid-boot), then run once per interval for the life of the process. The handle is meant to
/// be dropped on shutdown rather than joined.
pub fn spawn<S: Sweep>(sweep: S, state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(sweep.interval());
        if sweep.skip_missed_ticks() {
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_once(&sweep, &state).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::time::sleep;

    struct Probe {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl Sweep for Probe {
        const NAME: &'static str = "probe";

        fn interval(&self) -> Duration {
            Duration::from_millis(20)
        }

        async fn run(&self, _state: &AppState) -> anyhow::Result<Pass> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("boom");
            }
            Ok(Pass::swept(3))
        }
    }

    #[tokio::test]
    async fn skips_the_first_tick_then_runs_on_later_intervals() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let handle = spawn(
            Probe {
                calls: calls.clone(),
                fail: false,
            },
            state,
        );

        // Well under one interval in: the first tick was consumed, not run.
        sleep(Duration::from_millis(5)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Generous margin past a second interval: at least one pass must have run by now.
        sleep(Duration::from_millis(80)).await;
        assert!(calls.load(Ordering::SeqCst) >= 1);

        handle.abort();
    }

    #[tokio::test]
    async fn a_completed_pass_records_and_a_failed_pass_records_nothing() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));

        let failing = Probe {
            calls: calls.clone(),
            fail: true,
        };
        assert_eq!(run_once(&failing, &state).await, None);
        assert!(state.sweeps.snapshot().get("probe").is_none());

        let ok = Probe { calls, fail: false };
        assert_eq!(run_once(&ok, &state).await, Some(Pass::swept(3)));
        let run = state.sweeps.snapshot().get("probe").unwrap();
        assert_eq!((run.swept, run.errors), (3, 0));
    }
}
