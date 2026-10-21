// pattern: Imperative Shell

//! Periodic retention sweep for sovereign-session anti-replay nonces.
//!
//! Every accepted sovereign-session proof inserts a DID-scoped nonce. The primary key is the
//! replay defense; this best-effort task only reclaims rows after they can no longer accompany a
//! timestamp-valid request.

use std::time::Duration;

use crate::app::AppState;
use crate::db::sovereign_session_nonces::sweep_stale_nonces;
use crate::sweep::{Pass, Sweep};
use crate::sweep_status::names;

/// Sweep hourly, matching the retention cadence of the other nonce store.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Retain rows for one hour, well beyond the full sovereign-session replay-acceptance span.
pub const MAX_AGE_SECS: i64 = 60 * 60;

const _: () = assert!(common::retention_covers_replay(
    MAX_AGE_SECS,
    common::SOVEREIGN_TIMESTAMP_WINDOW_SECS
));

pub struct SovereignSessionNonceSweep;

impl Sweep for SovereignSessionNonceSweep {
    const NAME: &'static str = names::SOVEREIGN_SESSION_NONCE_SWEEP;
    const REPORTS_STATUS: bool = false;

    fn interval(&self) -> Duration {
        SWEEP_INTERVAL
    }

    async fn run(&self, state: &AppState) -> anyhow::Result<Pass> {
        let swept = sweep_stale_nonces(&state.db, MAX_AGE_SECS).await?;
        if swept > 0 {
            tracing::debug!(swept, "sovereign-session nonce sweep pass complete");
        } else {
            tracing::trace!("sovereign-session nonce sweep pass complete (nothing to sweep)");
        }
        Ok(Pass::swept(swept))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    #[tokio::test]
    async fn sweeps_stale_nonces_and_preserves_fresh_rows() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:nonce-sweep', 'nonce-sweep@example.com', NULL, \
                     datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sovereign_session_nonces (did, nonce, seen_at) \
             VALUES ('did:plc:nonce-sweep', 'stale', datetime('now', '-2 hours'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::sovereign_session_nonces::insert_nonce_if_absent(
            &state.db,
            "did:plc:nonce-sweep",
            "fresh",
        )
        .await
        .unwrap();

        let pass = crate::sweep::run_once(&SovereignSessionNonceSweep, &state)
            .await
            .unwrap();
        assert_eq!(pass.swept, 1);
        assert!(state
            .sweeps
            .snapshot()
            .get(names::SOVEREIGN_SESSION_NONCE_SWEEP)
            .is_none());

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT nonce FROM sovereign_session_nonces ORDER BY nonce")
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining, vec!["fresh"]);
    }
}
