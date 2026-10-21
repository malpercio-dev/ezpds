// pattern: Imperative Shell

//! Periodic retention sweep for spent spaces-token jtis (`space_jti_replay`).
//!
//! The `(scope, jti)` primary key is the replay defense; each row's
//! `expires_at` was stamped by its writer with the token's own acceptance
//! horizon, so this best-effort task only reclaims rows no token could still
//! ride. Delegation tokens turn over at credential-renewal rate (one per
//! ten-minute credential per syncer), hence the shorter-than-hourly cadence.

use std::time::Duration;

use crate::db::space_jti::sweep_expired_jtis;
use crate::sweep::{Pass, Sweep};
use crate::sweep_status::names;
use axum::extract::FromRef;
use custos_core::CoreState;

/// Sweep every ten minutes: delegation and attestation rows carry horizons of
/// at most five minutes, so an hourly cadence would let the table's working
/// set grow well past its live window.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

pub struct SpaceJtiSweep;

// Generic over the scheduler's state so `pds` runs it on its own `Scheduler<AppState>`; the pass
// reads only the pool.
impl<St> Sweep<St> for SpaceJtiSweep
where
    St: Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    const NAME: &'static str = names::SPACE_JTI_SWEEP;

    fn interval(&self) -> Duration {
        SWEEP_INTERVAL
    }

    fn skip_missed_ticks(&self) -> bool {
        true
    }

    async fn run(&self, state: &St) -> anyhow::Result<Pass> {
        let db = CoreState::from_ref(state).db;
        let swept = sweep_expired_jtis(&db).await?;
        if swept > 0 {
            tracing::debug!(swept, "space jti sweep pass complete");
        } else {
            tracing::trace!("space jti sweep pass complete (nothing to sweep)");
        }
        Ok(Pass::swept(swept))
    }
}
