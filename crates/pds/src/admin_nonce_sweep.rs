// pattern: Imperative Shell
//
//! Periodic `admin_nonces` retention sweep.
//!
//! Every device-signed admin request (`auth::guards::require_admin`) inserts a row into
//! `admin_nonces` for anti-replay. The `(device_id, nonce)` primary key is what actually
//! blocks a replay — this sweep is pure storage reclamation, not a security control — so a
//! failed or delayed pass never weakens replay protection. Retention only needs to exceed
//! the signed-request timestamp window (`auth::guards::ADMIN_TIMESTAMP_WINDOW_SECS`, ±60s):
//! a nonce older than that window can never verify again.
//!
//! Template: `account_reaper.rs` / `firehose_gc.rs` — the first interval tick is skipped, an
//! error skips the pass (retried next tick), and the task runs for the life of the process.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::db::admin_devices::sweep_stale_nonces;

/// Tally of what one sweep pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    /// Nonce rows deleted this pass.
    pub swept: u64,
}

/// Spawn the periodic stale-nonce sweep. The first tick is consumed without sweeping so the
/// server does not run it mid-boot; the first pass runs one `interval` after startup.
pub fn spawn_admin_nonce_sweep(
    state: AppState,
    interval: Duration,
    max_age_secs: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_admin_nonce_sweep(&state, max_age_secs).await;
        }
    })
}

/// Run a single sweep pass: delete every `admin_nonces` row older than `max_age_secs`.
pub async fn run_admin_nonce_sweep(state: &AppState, max_age_secs: i64) -> SweepStats {
    let swept = match sweep_stale_nonces(&state.db, max_age_secs).await {
        Ok(swept) => swept,
        Err(e) => {
            tracing::debug!(error = %e, "admin nonce sweep: failed to sweep; skipping pass");
            return SweepStats::default();
        }
    };

    if swept > 0 {
        tracing::debug!(swept, "admin nonce sweep pass complete");
    } else {
        tracing::trace!("admin nonce sweep pass complete (nothing to sweep)");
    }

    state.metrics.admin_nonce_sweep_swept.add(swept, &[]);
    state
        .metrics
        .admin_nonce_sweep_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_admin_nonce_sweep(crate::sweep_status::SweepRun::now(swept));

    SweepStats { swept }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    async fn insert_stale_nonce(db: &sqlx::SqlitePool, device_id: &str, nonce: &str) {
        sqlx::query(
            "INSERT INTO admin_nonces (nonce, device_id, seen_at) \
             VALUES (?, ?, datetime('now', '-2 hours'))",
        )
        .bind(nonce)
        .bind(device_id)
        .execute(db)
        .await
        .unwrap();
    }

    async fn seed_device(db: &sqlx::SqlitePool, id: &str) {
        crate::db::admin_devices::insert_device(
            db,
            &crate::db::admin_devices::NewAdminDevice {
                id,
                label: "Operator iPhone",
                public_key: "did:key:zTestNonceSweep",
                platform: "ios",
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sweeps_stale_nonces_and_records_instruments() {
        let state = test_state().await;
        seed_device(&state.db, "dev-nonce-sweep").await;
        insert_stale_nonce(&state.db, "dev-nonce-sweep", "stale-1").await;
        crate::db::admin_devices::insert_nonce_if_absent(&state.db, "fresh-1", "dev-nonce-sweep")
            .await
            .unwrap();

        let stats = run_admin_nonce_sweep(&state, 3600).await;
        assert_eq!(stats.swept, 1);

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_nonces")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(count, 1, "the fresh nonce survives");

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("admin_nonce_sweep_swept_total"),
            "missing admin_nonce_sweep_swept_total in:\n{rendered}"
        );
        assert!(
            rendered.contains("admin_nonce_sweep_last_run_timestamp"),
            "missing admin_nonce_sweep_last_run_timestamp in:\n{rendered}"
        );
        assert_eq!(state.sweeps.snapshot().admin_nonce_sweep.unwrap().swept, 1);
    }

    #[tokio::test]
    async fn nothing_stale_is_a_noop_that_still_timestamps() {
        let state = test_state().await;
        let stats = run_admin_nonce_sweep(&state, 3600).await;
        assert_eq!(stats, SweepStats::default());

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("admin_nonce_sweep_last_run_timestamp"),
            "missing admin_nonce_sweep_last_run_timestamp in:\n{rendered}"
        );
        let run = state.sweeps.snapshot().admin_nonce_sweep.unwrap();
        assert_eq!(run.swept, 0);
    }
}
