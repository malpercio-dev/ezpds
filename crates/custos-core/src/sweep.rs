// pattern: Imperative Shell

//! The periodic-sweep scheduler.
//!
//! A sweep is a [`Sweep`] impl: its cadence plus one `run` pass. [`Scheduler`] owns everything
//! else — the interval loop, the skipped boot tick (or an opt-in first pass at boot), jitter,
//! missed-tick policy, shutdown, the failure posture, and writing `CoreState.sweeps` for
//! `GET /v1/admin/health`.
//!
//! Both are generic over the state a sweep reads (`St`): any state the scheduler can project a
//! [`CoreState`] out of, so a feature's sweep can take that feature's state.
//!
//! Failure posture: a pass that returns `Err` is logged and records nothing, so a stale (or
//! absent) status entry stays the operator's alarm. A pass that returns `Ok` records, even
//! when it found nothing to do. A sweep's own OTel instruments are recorded inside its `run`,
//! on the success path only, for the same reason.

use std::future::Future;
use std::time::Duration;

use axum::extract::FromRef;

use rand_core::{OsRng, RngCore};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::sweep_status::SweepRun;
use crate::CoreState;

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

pub trait Sweep<St>: Send + Sync + 'static {
    /// Log label and `CoreState.sweeps` key; one of `sweep_status::names`.
    const NAME: &'static str;

    /// Whether a completed pass is published to `GET /v1/admin/health`. Only the
    /// sovereign-session nonce sweep opts out: its health slot was never part of the payload.
    const REPORTS_STATUS: bool = true;

    fn interval(&self) -> Duration;

    /// Upper bound of the random delay added before each interval-driven pass, so sweeps that
    /// share a cadence (or replicas started together) do not all hit the database on the same
    /// tick. Defaults to a tenth of the interval; the boot pass is never delayed.
    fn max_jitter(&self) -> Duration {
        self.interval() / 10
    }

    /// Run the first pass right after boot instead of one `interval` later. Only for a pass that
    /// merely rebuilds a cache the operator wants populated by the end of a deploy.
    fn first_pass_at_boot(&self) -> bool {
        false
    }

    /// Set [`tokio::time::MissedTickBehavior::Skip`] so a late pass is never followed by a
    /// burst of catch-up passes; `false` keeps tokio's default (`Burst`).
    fn skip_missed_ticks(&self) -> bool {
        false
    }

    /// One pass. `Err` means the pass did not complete and must record nothing.
    fn run(&self, state: &St) -> impl Future<Output = anyhow::Result<Pass>> + Send;
}

/// Run one pass and publish it per the failure posture above. The loop's body, and what tests
/// call to exercise a sweep end to end.
pub async fn run_once<St, S: Sweep<St>>(sweep: &S, state: &St) -> Option<Pass>
where
    CoreState: FromRef<St>,
{
    match sweep.run(state).await {
        Ok(pass) => {
            if S::REPORTS_STATUS {
                CoreState::from_ref(state)
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

/// A uniformly random delay in `[0, max]`.
fn jitter_delay(max: Duration) -> Duration {
    let max_ms = max.as_millis() as u64;
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(OsRng.next_u64() % (max_ms + 1))
}

/// Owns the running sweeps. Spawn each with [`Scheduler::spawn`]; at process shutdown call
/// [`Scheduler::shutdown`], which stops every loop between passes and waits for any pass in
/// flight (a half-finished GC pass is not something to abort).
pub struct Scheduler<St> {
    state: St,
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl<St> Scheduler<St>
where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    pub fn new(state: St) -> Self {
        Self {
            state,
            stop: watch::channel(false).0,
            handles: Vec::new(),
        }
    }

    /// Start the sweep's loop: consume the first tick without running a pass (so nothing sweeps
    /// mid-boot) unless it asks for [`Sweep::first_pass_at_boot`], then run once per interval,
    /// each pass after a random [`Sweep::max_jitter`] delay.
    pub fn spawn<S: Sweep<St>>(&mut self, sweep: S) {
        let state = self.state.clone();
        let mut stop = self.stop.subscribe();
        self.handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sweep.interval());
            if sweep.skip_missed_ticks() {
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }
            let mut at_boot = sweep.first_pass_at_boot();
            if !at_boot {
                ticker.tick().await;
            }
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = stop.changed() => return,
                }
                if !std::mem::take(&mut at_boot) {
                    tokio::select! {
                        _ = tokio::time::sleep(jitter_delay(sweep.max_jitter())) => {}
                        _ = stop.changed() => return,
                    }
                }
                run_once(&sweep, &state).await;
            }
        }));
    }

    /// Stop every loop and wait up to `grace` for passes already running to finish.
    pub async fn shutdown(self, grace: Duration) {
        let _ = self.stop.send(true);
        let deadline = tokio::time::Instant::now() + grace;
        for handle in self.handles {
            if tokio::time::timeout_at(deadline, handle).await.is_err() {
                tracing::warn!("a sweep pass was still running at shutdown; abandoning it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::time::sleep;

    struct Probe {
        calls: Arc<AtomicUsize>,
        fail: bool,
        at_boot: bool,
    }

    impl Sweep<CoreState> for Probe {
        const NAME: &'static str = "probe";

        fn interval(&self) -> Duration {
            Duration::from_millis(20)
        }

        fn first_pass_at_boot(&self) -> bool {
            self.at_boot
        }

        async fn run(&self, _state: &CoreState) -> anyhow::Result<Pass> {
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
        let mut scheduler = Scheduler::new(state);
        scheduler.spawn(Probe {
            calls: calls.clone(),
            fail: false,
            at_boot: false,
        });

        // Well under one interval in: the first tick was consumed, not run.
        sleep(Duration::from_millis(5)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Generous margin past a second interval: at least one pass must have run by now.
        sleep(Duration::from_millis(80)).await;
        assert!(calls.load(Ordering::SeqCst) >= 1);

        scheduler.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn a_completed_pass_records_and_a_failed_pass_records_nothing() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));

        let failing = Probe {
            calls: calls.clone(),
            fail: true,
            at_boot: false,
        };
        assert_eq!(run_once(&failing, &state).await, None);
        assert!(state.sweeps.snapshot().get("probe").is_none());

        let ok = Probe {
            calls,
            fail: false,
            at_boot: false,
        };
        assert_eq!(run_once(&ok, &state).await, Some(Pass::swept(3)));
        let run = state.sweeps.snapshot().get("probe").unwrap();
        assert_eq!((run.swept, run.errors), (3, 0));
    }

    #[tokio::test]
    async fn a_first_pass_at_boot_runs_before_the_first_interval_elapses() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut scheduler = Scheduler::new(state);
        scheduler.spawn(Probe {
            calls: calls.clone(),
            fail: false,
            at_boot: true,
        });
        sleep(Duration::from_millis(10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        scheduler.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn shutdown_stops_the_loop() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut scheduler = Scheduler::new(state);
        scheduler.spawn(Probe {
            calls: calls.clone(),
            fail: false,
            at_boot: true,
        });
        sleep(Duration::from_millis(10)).await;
        scheduler.shutdown(Duration::from_secs(1)).await;
        let after_shutdown = calls.load(Ordering::SeqCst);
        sleep(Duration::from_millis(80)).await;
        assert_eq!(calls.load(Ordering::SeqCst), after_shutdown);
    }

    #[test]
    fn jitter_stays_within_its_bound() {
        assert_eq!(jitter_delay(Duration::ZERO), Duration::ZERO);
        let max = Duration::from_millis(50);
        for _ in 0..200 {
            assert!(jitter_delay(max) <= max);
        }
    }
}
