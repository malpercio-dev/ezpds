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
//! counted but never aborts the pass, and the scheduler runs it for the life of the process
//! (stopped at shutdown). `deleteAfter` is only ever set alongside `deactivated_at` and is
//! cleared on reactivation, so an account that reactivates before its window elapses is naturally
//! spared — its row no longer matches the "due" query.

use std::time::Duration;

use crate::account_delete::{purge_account, PurgeOutcome};
use crate::app::AppState;
use crate::db::accounts::accounts_due_for_deletion;
use crate::sweep::{Pass, Sweep};
use crate::sweep_status::names;

/// Permanently delete every account whose `deleteAfter` has elapsed once per `interval`.
///
/// A no-op when nothing is due. An error listing the due accounts fails the pass (the next
/// pass retries); an error deleting a single account is logged but lets the pass continue with
/// the rest, and is not reported in the health readout's `errors`.
pub struct AccountReaper {
    pub interval: Duration,
}

impl Sweep<AppState> for AccountReaper {
    const NAME: &'static str = names::ACCOUNT_REAPER;

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self, state: &AppState) -> anyhow::Result<Pass> {
        let due = accounts_due_for_deletion(&state.db).await?;

        let (mut deleted, mut errors) = (0u64, 0u64);
        for did in due {
            match purge_account(state, &did).await {
                Ok(PurgeOutcome::Deleted) => {
                    deleted += 1;
                    tracing::info!(did = %did, "account reaper: permanently deleted scheduled account");
                }
                // Already gone (raced with an interactive deleteAccount): not an error.
                Ok(PurgeOutcome::NotFound) => {}
                Err(e) => {
                    errors += 1;
                    tracing::warn!(did = %did, error = %e, "account reaper: failed to delete account; will retry next pass");
                }
            }
        }

        if deleted > 0 || errors > 0 {
            tracing::info!(deleted, errors, "account reaper pass complete");
        }

        state.metrics.account_reaper_swept.add(deleted, &[]);
        state
            .metrics
            .account_reaper_last_run_timestamp
            .record(crate::metrics::unix_now(), &[]);
        Ok(Pass::swept(deleted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::sweep::run_once;

    fn sweep() -> AccountReaper {
        AccountReaper {
            interval: Duration::from_secs(1),
        }
    }

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

        let stats = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(stats.swept, 1);

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
        assert_eq!(
            state
                .sweeps
                .snapshot()
                .get(names::ACCOUNT_REAPER)
                .unwrap()
                .swept,
            1
        );
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

        let stats = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(stats.swept, 1, "an instant earlier today is due");
        assert!(!account_exists(&state.db, "did:plc:reaptoday").await);
    }

    #[tokio::test]
    async fn spares_accounts_with_a_future_delete_after() {
        let state = test_state().await;
        insert_deactivated(&state.db, "did:plc:reapfuture", "2999-01-01T00:00:00Z").await;

        let stats = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(stats.swept, 0);
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

        let stats = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(stats.swept, 0);
        assert!(account_exists(&state.db, "did:plc:reapnodelete").await);
    }

    #[tokio::test]
    async fn no_due_accounts_is_a_noop() {
        let state = test_state().await;
        let stats = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(stats, Pass::default());
    }

    /// A parent's deleted sovereign child is purged once its grace window lapses: account, repo,
    /// handle, and provisioning row gone, the parent's tombstone kept, and an `#account` deleted
    /// frame emitted. Scheduling the deletion is `custos-agents`' half (`agent_child.rs`).
    #[tokio::test]
    async fn reaper_purges_a_deleted_child_and_keeps_the_tombstone() {
        use crate::firehose::FirehoseEvent;
        use custos_agents::test_support::{
            access_jwt, child_request, mint_child_for, seed_account_with_repo, state_with_grace,
            test_app,
        };
        use tower::ServiceExt;

        // grace = 0 → the child is due the moment it is scheduled, so one reaper pass purges it.
        let (core, _plc) = state_with_grace(0).await;
        let parent = "did:plc:parentchilddelete1111";
        seed_account_with_repo(&core.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&core, "deletable-writer.example.com", &token).await;
        let response = test_app(core.clone())
            .oneshot(child_request(
                "/agent/child/delete",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let state = AppState::for_test(core).await;
        // Subscribe *after* the delete so only the purge frame is observed.
        let mut rx = state.firehose.subscribe();

        // The reaper permanently purges the child (account/repo/handle gone) and emits #account
        // deleted — the FK-ordered purge also drops the provisioning row without a constraint error.
        let reaper = AccountReaper {
            interval: std::time::Duration::from_secs(1),
        };
        let stats = run_once(&reaper, &state).await.unwrap();
        assert_eq!(stats.swept, 1);
        assert!(!crate::db::accounts::account_exists(&state.db, &child)
            .await
            .unwrap());
        let provisioning: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_child_provisionings WHERE child_did = ?",
        )
        .bind(&child)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(
            provisioning, 0,
            "the child's provisioning row must be purged"
        );

        // The deletion stays auditable after the fact: the tombstone outlives the purged child.
        let tombstones: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_child_deletions WHERE parent_did = ?")
                .bind(parent)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(
            tombstones, 1,
            "the deletion tombstone must survive the child's purge"
        );

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event for the deletion");
        };
        assert_eq!(event.did, child);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deleted"));
    }
}
