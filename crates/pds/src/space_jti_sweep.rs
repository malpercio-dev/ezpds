// pattern: Imperative Shell

//! Periodic retention sweep for spent spaces-token jtis (`space_jti_replay`).
//!
//! The `(scope, jti)` primary key is the replay defense; each row's
//! `expires_at` was stamped by its writer with the token's own acceptance
//! horizon, so this best-effort task only reclaims rows no token could still
//! ride. The sync-path DPoP scope is the high-volume class, hence the
//! shorter-than-hourly cadence.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::db::space_jti::sweep_expired_jtis;

/// Sweep every ten minutes: the DPoP-proof scope turns rows over at request
/// rate with ~minutes-long horizons, so an hourly cadence would let the
/// table's working set grow well past its live window.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Tally of what one sweep pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub swept: u64,
}

/// Spawn the periodic sweep. The first pass runs one full interval after startup.
pub fn spawn_space_jti_sweep(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        // A late pass must not be followed by a burst of catch-up passes.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_space_jti_sweep(&state).await;
        }
    })
}

/// Run one best-effort sweep pass.
pub async fn run_space_jti_sweep(state: &AppState) -> SweepStats {
    let swept = match sweep_expired_jtis(&state.db).await {
        Ok(swept) => swept,
        Err(error) => {
            tracing::debug!(%error, "space jti sweep failed; skipping pass");
            return SweepStats::default();
        }
    };

    if swept > 0 {
        tracing::debug!(swept, "space jti sweep pass complete");
    } else {
        tracing::trace!("space jti sweep pass complete (nothing to sweep)");
    }

    state
        .sweeps
        .record_space_jti_sweep(crate::sweep_status::SweepRun::now(swept));

    SweepStats { swept }
}
