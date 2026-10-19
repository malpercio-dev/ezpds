// pattern: Imperative Shell

//! Generic periodic-sweep runner.
//!
//! `account_reaper`, `agent_claim_sweep`, `admin_nonce_sweep`, `space_jti_sweep`,
//! `space_oplog_sweep`, and `sovereign_session_nonce_sweep` each spawn a background task that
//! ticks on its own interval for the life of the process. Only the pass body — and what it
//! records on completion — differs between them; [`spawn_sweep`] owns the shared
//! `interval → skip first tick → loop → tick → run` shell so each sweep module keeps only its
//! own `run_*` function.

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;

/// Spawn a periodic sweep: consume the first tick without running a pass (so nothing sweeps
/// mid-boot), then call `run` once per subsequent interval for the life of the process. The
/// returned handle is meant to be dropped on shutdown rather than joined, like the sweeps it
/// replaces.
///
/// `skip_missed_ticks` sets [`tokio::time::MissedTickBehavior::Skip`] so a late pass is never
/// followed by a burst of catch-up passes; pass `false` to keep tokio's default (`Burst`).
pub fn spawn_sweep<F, Fut>(
    interval: Duration,
    skip_missed_ticks: bool,
    state: AppState,
    run: F,
) -> JoinHandle<()>
where
    F: Fn(AppState) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        if skip_missed_ticks {
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run(state.clone()).await;
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

    #[tokio::test]
    async fn skips_the_first_tick_then_runs_on_later_intervals() {
        let state = test_state().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let handle = spawn_sweep(Duration::from_millis(20), false, state, move |_state| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Well under one interval in: the first tick was consumed, not run.
        sleep(Duration::from_millis(5)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Generous margin past a second interval: at least one pass must have run by now.
        sleep(Duration::from_millis(80)).await;
        assert!(calls.load(Ordering::SeqCst) >= 1);

        handle.abort();
    }
}
