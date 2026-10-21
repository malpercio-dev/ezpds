// pattern: Imperative Shell
//
//! Periodic `admin_nonces` retention sweep.
//!
//! Every device-signed admin request (`auth::guards::require_admin`) inserts a row into
//! `admin_nonces` for anti-replay. The `(device_id, nonce)` primary key is what actually
//! blocks a replay — this sweep is pure storage reclamation, not a security control — so a
//! failed or delayed pass never weakens replay protection, *provided* retention exceeds the
//! request's full replay-acceptance window: a captured request stays replayable for up to
//! `2 * ADMIN_TIMESTAMP_WINDOW_SECS` (worst case, first use at the earliest edge of the
//! ±window) after its nonce is first inserted, so config validation
//! (`common::ADMIN_TIMESTAMP_WINDOW_SECS`) rejects a `nonce_max_age_secs` at or below that
//! span.
//!
use std::time::Duration;

use crate::app::AppState;
use crate::db::admin_devices::sweep_stale_nonces;
use crate::sweep::{Pass, Sweep};
use crate::sweep_status::names;

/// Delete every `admin_nonces` row older than `max_age_secs` once per `interval`.
pub struct AdminNonceSweep {
    pub interval: Duration,
    pub max_age_secs: i64,
}

impl Sweep for AdminNonceSweep {
    const NAME: &'static str = names::ADMIN_NONCE_SWEEP;

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self, state: &AppState) -> anyhow::Result<Pass> {
        anyhow::ensure!(
            common::retention_covers_replay(self.max_age_secs, common::ADMIN_TIMESTAMP_WINDOW_SECS),
            "admin nonce retention {}s does not exceed the replay-acceptance span",
            self.max_age_secs
        );
        let swept = sweep_stale_nonces(&state.db, self.max_age_secs).await?;

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
        Ok(Pass::swept(swept))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::sweep::run_once;

    fn sweep() -> AdminNonceSweep {
        AdminNonceSweep {
            interval: Duration::from_secs(1),
            max_age_secs: 3600,
        }
    }

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

        let pass = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(pass.swept, 1);

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
        assert_eq!(
            state
                .sweeps
                .snapshot()
                .get(names::ADMIN_NONCE_SWEEP)
                .unwrap()
                .swept,
            1
        );
    }

    #[tokio::test]
    async fn nothing_stale_is_a_noop_that_still_timestamps() {
        let state = test_state().await;
        let pass = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(pass, Pass::default());

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("admin_nonce_sweep_last_run_timestamp"),
            "missing admin_nonce_sweep_last_run_timestamp in:\n{rendered}"
        );
        let run = state
            .sweeps
            .snapshot()
            .get(names::ADMIN_NONCE_SWEEP)
            .unwrap();
        assert_eq!(run.swept, 0);
    }
}
