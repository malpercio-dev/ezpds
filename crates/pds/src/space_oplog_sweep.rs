// pattern: Imperative Shell

//! Periodic retention sweep for the permissioned-repo oplog (`space_repo_ops`).
//!
//! The oplog is a transport optimization by spec — a host may compact it or drop it entirely,
//! and `listRepoOps` promises only the retained window. This sweep is the compaction half:
//! age-based pruning that keeps the table bounded (the `firehose_gc` policy on the
//! `space_jti_sweep` chassis). A syncer whose `since` predates the window gets a short page
//! whose head commit no longer matches its own fold, which is its signal to heal via
//! `getRepo` — losing oplog history is never a correctness problem, only an extra full sync.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::db::space_repos::sweep_old_repo_ops;

/// Hourly cadence: ops accrue at write rate, far below the jti table's request rate.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Retain seven days of ops — the firehose log's default backfill window, and the same
/// trade: a syncer further behind than this re-syncs in full rather than replaying.
pub const OPLOG_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// Tally of what one sweep pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub swept: u64,
}

/// Spawn the periodic sweep. The first pass runs one full interval after startup.
pub fn spawn_space_oplog_sweep(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        // A late pass must not be followed by a burst of catch-up passes.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_space_oplog_sweep(&state).await;
        }
    })
}

/// Run one best-effort sweep pass.
pub async fn run_space_oplog_sweep(state: &AppState) -> SweepStats {
    let swept = match sweep_old_repo_ops(&state.db, OPLOG_RETENTION_SECS).await {
        Ok(swept) => swept,
        Err(error) => {
            tracing::debug!(%error, "space oplog sweep failed; skipping pass");
            return SweepStats::default();
        }
    };

    if swept > 0 {
        tracing::debug!(swept, "space oplog sweep pass complete");
    } else {
        tracing::trace!("space oplog sweep pass complete (nothing to sweep)");
    }

    SweepStats { swept }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    /// Ops older than the retention window are reclaimed; ops inside it survive. Rows are
    /// back-dated directly — `created_at` is the sweep's only input.
    #[tokio::test]
    async fn sweep_prunes_only_ops_past_retention() {
        let state = test_state().await;
        let space = crate::space_uri::parse_space_ref(
            "at://did:plc:oplogsweepaaaaaaaaaaaaaa/space/org.example.bucket/main",
        )
        .unwrap();
        let did = "did:plc:oplogsweepaaaaaaaaaaaaaa";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'sweep@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        crate::space_record_write::apply_space_writes(
            &state,
            &space,
            did,
            &[
                crate::space_record_write::SpaceWriteOp {
                    action: crate::space_record_write::SpaceWriteAction::Put,
                    collection: "org.example.note".to_string(),
                    rkey: "old".to_string(),
                    value: Some(serde_json::json!({ "text": "old" })),
                },
                crate::space_record_write::SpaceWriteOp {
                    action: crate::space_record_write::SpaceWriteAction::Put,
                    collection: "org.example.note".to_string(),
                    rkey: "new".to_string(),
                    value: Some(serde_json::json!({ "text": "new" })),
                },
            ],
            crate::space_record_write::SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();

        // Age one op past the window; leave the other at "now".
        sqlx::query(
            "UPDATE space_repo_ops SET created_at = datetime('now', '-8 days') WHERE rkey = 'old'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let stats = run_space_oplog_sweep(&state).await;
        assert_eq!(stats.swept, 1);

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT rkey FROM space_repo_ops ORDER BY rowid")
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining, vec!["new".to_string()]);

        // A second pass is a no-op — the sweep is storage reclamation, not a ratchet.
        assert_eq!(run_space_oplog_sweep(&state).await.swept, 0);
    }
}
