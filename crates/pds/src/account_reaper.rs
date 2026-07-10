// pattern: Imperative Shell
//
//! Scheduled account-deletion reaper.
//!
//! `com.atproto.server.deactivateAccount` accepts an optional `deleteAfter` instant — a request to
//! permanently delete the account once that time passes. This periodic background task is what
//! finally acts on it: each pass lists every account whose `deleteAfter` has elapsed and permanently
//! deletes it via [`account_delete::purge_account`] (the same path as the interactive
//! `deleteAccount` endpoint — full local-data removal plus an `#account` deleted firehose frame).
//!
//! Resilient by design, like the blob and firehose GCs: an error deleting one account is logged and
//! counted but never aborts the pass, and the task runs for the life of the process (dropped on
//! shutdown rather than joined). `deleteAfter` is only ever set alongside `deactivated_at` and is
//! cleared on reactivation, so an account that reactivates before its window elapses is naturally
//! spared — its row no longer matches the "due" query.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::account_delete::{purge_account, PurgeOutcome};
use crate::app::AppState;
use crate::db::accounts::accounts_due_for_deletion;

/// Tally of what one reaper pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReaperStats {
    /// Accounts permanently deleted this pass.
    pub deleted: u64,
    /// Accounts that were due but skipped due to an error (logged, not fatal).
    pub errors: u64,
}

/// Spawn the periodic scheduled-deletion reaper.
///
/// The first interval tick is consumed without running the reaper, so the server does not delete
/// accounts during startup; the first pass runs one `interval` after boot. The task loops for the
/// life of the process and is dropped on shutdown.
pub fn spawn_account_reaper(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval`'s first tick fires immediately — skip it so the reaper doesn't run mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_account_reaper(&state).await;
        }
    })
}

/// Run a single reaper pass: permanently delete every account whose `deleteAfter` has elapsed.
///
/// A no-op when nothing is due. An error listing the due accounts skips the whole pass (the next
/// pass retries); an error deleting a single account is logged and counted but lets the pass
/// continue with the rest.
pub async fn run_account_reaper(state: &AppState) -> ReaperStats {
    let mut stats = ReaperStats::default();

    let due = match accounts_due_for_deletion(&state.db).await {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(error = %e, "account reaper: failed to list due accounts; skipping pass");
            return stats;
        }
    };

    for did in due {
        match purge_account(state, &did).await {
            Ok(PurgeOutcome::Deleted) => {
                stats.deleted += 1;
                tracing::info!(did = %did, "account reaper: permanently deleted scheduled account");
            }
            // Already gone (raced with an interactive deleteAccount): not an error.
            Ok(PurgeOutcome::NotFound) => {}
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(did = %did, error = %e, "account reaper: failed to delete account; will retry next pass");
            }
        }
    }

    if stats.deleted > 0 || stats.errors > 0 {
        tracing::info!(
            deleted = stats.deleted,
            errors = stats.errors,
            "account reaper pass complete"
        );
    }

    // The failed-to-start early return above skips this on purpose: a stale
    // `account_reaper_last_run_timestamp` signals that passes are not completing.
    state.metrics.account_reaper_swept.add(stats.deleted, &[]);
    state
        .metrics
        .account_reaper_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_account_reaper(crate::sweep_status::SweepRun::now(stats.deleted));

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    /// Insert a deactivated account with an explicit `delete_after`.
    async fn insert_deactivated(db: &sqlx::SqlitePool, did: &str, delete_after: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at, deactivated_at, delete_after) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'), datetime('now'), ?)",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .bind(delete_after)
        .execute(db)
        .await
        .unwrap();
    }

    async fn account_exists(db: &sqlx::SqlitePool, did: &str) -> bool {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap();
        count > 0
    }

    #[tokio::test]
    async fn reaps_accounts_past_their_delete_after() {
        let state = test_state().await;
        insert_deactivated(&state.db, "did:plc:reapdue", "2020-01-01T00:00:00Z").await;

        let stats = run_account_reaper(&state).await;
        assert_eq!(stats.deleted, 1);

        // The pass's instruments fire: the deletion is counted and the pass is timestamped.
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("account_reaper_swept_total"),
            "missing account_reaper_swept_total in:\n{rendered}"
        );
        assert!(
            rendered.contains("account_reaper_last_run_timestamp"),
            "missing account_reaper_last_run_timestamp in:\n{rendered}"
        );
        // The readable snapshot records the same completed pass with its literal count.
        assert_eq!(state.sweeps.snapshot().account_reaper.unwrap().swept, 1);
        assert_eq!(stats.errors, 0);
        assert!(!account_exists(&state.db, "did:plc:reapdue").await);
    }

    #[tokio::test]
    async fn reaps_account_due_earlier_today() {
        // Boundary case: a `delete_after` earlier *today*, stored in RFC 3339 (with the `T`
        // separator and a `Z`), must be reaped. A raw text comparison against `datetime('now')`
        // (`YYYY-MM-DD HH:MM:SS`) would wrongly keep it, since `'T'` sorts after `' '`; the query
        // normalises both sides through `datetime()` to avoid exactly that.
        let state = test_state().await;
        let one_minute_ago = (chrono::Utc::now() - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        insert_deactivated(&state.db, "did:plc:reaptoday", &one_minute_ago).await;

        let stats = run_account_reaper(&state).await;
        assert_eq!(stats.deleted, 1, "an instant earlier today is due");
        assert!(!account_exists(&state.db, "did:plc:reaptoday").await);
    }

    #[tokio::test]
    async fn spares_accounts_with_a_future_delete_after() {
        let state = test_state().await;
        insert_deactivated(&state.db, "did:plc:reapfuture", "2999-01-01T00:00:00Z").await;

        let stats = run_account_reaper(&state).await;
        assert_eq!(stats.deleted, 0);
        assert!(account_exists(&state.db, "did:plc:reapfuture").await);
    }

    #[tokio::test]
    async fn ignores_accounts_without_a_delete_after() {
        let state = test_state().await;
        // A deactivated account that never asked to be deleted (delete_after NULL).
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at, deactivated_at) \
             VALUES ('did:plc:reapnodelete', 'x@example.com', NULL, datetime('now'), datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let stats = run_account_reaper(&state).await;
        assert_eq!(stats.deleted, 0);
        assert!(account_exists(&state.db, "did:plc:reapnodelete").await);
    }

    #[tokio::test]
    async fn no_due_accounts_is_a_noop() {
        let state = test_state().await;
        let stats = run_account_reaper(&state).await;
        assert_eq!(stats, ReaperStats::default());
    }
}
