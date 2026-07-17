// pattern: Imperative Shell

//! Periodic retention sweep for sovereign-session anti-replay nonces.
//!
//! Every accepted sovereign-session proof inserts a DID-scoped nonce. The primary key is the
//! replay defense; this best-effort task only reclaims rows after they can no longer accompany a
//! timestamp-valid request.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::db::sovereign_session_nonces::{sweep_stale_nonces, REPLAY_ACCEPTANCE_SPAN_SECS};

/// Sweep hourly, matching the retention cadence of the other nonce store.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Retain rows for one hour, well beyond the full sovereign-session replay-acceptance span.
pub const MAX_AGE_SECS: i64 = 60 * 60;

const _: () = assert!(MAX_AGE_SECS > REPLAY_ACCEPTANCE_SPAN_SECS);

/// Tally of what one sweep pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub swept: u64,
}

/// Spawn the periodic sweep. The first pass runs one full interval after startup.
pub fn spawn_sovereign_session_nonce_sweep(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_sovereign_session_nonce_sweep(&state).await;
        }
    })
}

/// Run one best-effort sweep pass.
pub async fn run_sovereign_session_nonce_sweep(state: &AppState) -> SweepStats {
    let swept = match sweep_stale_nonces(&state.db, MAX_AGE_SECS).await {
        Ok(swept) => swept,
        Err(error) => {
            tracing::debug!(%error, "sovereign-session nonce sweep failed; skipping pass");
            return SweepStats::default();
        }
    };

    if swept > 0 {
        tracing::debug!(swept, "sovereign-session nonce sweep pass complete");
    } else {
        tracing::trace!("sovereign-session nonce sweep pass complete (nothing to sweep)");
    }

    SweepStats { swept }
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

        let stats = run_sovereign_session_nonce_sweep(&state).await;
        assert_eq!(stats.swept, 1);

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT nonce FROM sovereign_session_nonces ORDER BY nonce")
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining, vec!["fresh"]);
    }
}
