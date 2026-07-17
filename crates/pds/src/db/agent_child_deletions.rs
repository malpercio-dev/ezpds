// pattern: Imperative Shell
//
// Durable tombstone queries for a parent's deletion of a sovereign child agent (schema: V049).
// Deleting a child reuses the deactivate + `delete_after` + reaper pipeline, so the reaper
// eventually runs `account_delete::purge_account`, which drops the child's account, repo, handle,
// blobs, its `agent_identities` capability row AND (via the FK chain) its whole `agent_audit_events`
// trail — the child's own history cannot anchor "the deletion is auditable after the fact". This
// table is that anchor: keyed by `child_did` with no FK on that column, so a child purge leaves it
// intact, and anchored to `parent_did` so the parent's audit view outlives the child. It is
// reclaimed only when the parent itself is deleted (`purge_account` deletes it `WHERE parent_did =
// ?`, never `WHERE child_did = ?`).

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

/// One recorded child deletion, newest-first in list queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChildDeletionRow {
    pub(crate) child_did: String,
    pub(crate) handle: String,
    pub(crate) registration_id: String,
    /// When the parent scheduled the deletion.
    pub(crate) scheduled_at: String,
    /// The instant after which the reaper permanently purges the child.
    pub(crate) delete_after: String,
}

/// Record (or refresh) a child-deletion tombstone. Generic over the executor so callers write it
/// inside the same transaction as the deactivation + revocation it records. `scheduled_at` is
/// stamped server-side; `delete_after` is the caller-computed grace deadline (RFC 3339). A repeat
/// delete of the same child is an idempotent upsert on the `child_did` primary key.
pub(crate) async fn upsert_child_deletion<'e, E>(
    executor: E,
    child_did: &str,
    parent_did: &str,
    handle: &str,
    registration_id: &str,
    delete_after: &str,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO agent_child_deletions \
         (child_did, parent_did, handle, registration_id, scheduled_at, delete_after) \
         VALUES (?, ?, ?, ?, datetime('now'), ?) \
         ON CONFLICT(child_did) DO UPDATE SET \
             parent_did = excluded.parent_did, \
             handle = excluded.handle, \
             registration_id = excluded.registration_id, \
             scheduled_at = excluded.scheduled_at, \
             delete_after = excluded.delete_after",
    )
    .bind(child_did)
    .bind(parent_did)
    .bind(handle)
    .bind(registration_id)
    .bind(delete_after)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            child_did = %child_did,
            parent_did = %parent_did,
            error = %e,
            "DB error recording child deletion"
        );
        ApiError::new(ErrorCode::InternalError, "failed to record child deletion")
    })?;
    Ok(())
}

/// List a parent's recorded child deletions, newest-first. Survives the children's purge, so it is
/// the parent's durable "which children did I retire, and when" audit view.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn list_child_deletions_of_parent(
    db: &sqlx::SqlitePool,
    parent_did: &str,
) -> Result<Vec<ChildDeletionRow>, ApiError> {
    type Row = (String, String, String, String, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT child_did, handle, registration_id, scheduled_at, delete_after \
         FROM agent_child_deletions \
         WHERE parent_did = ? \
         ORDER BY scheduled_at DESC, child_did DESC",
    )
    .bind(parent_did)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(parent_did = %parent_did, error = %e, "DB error listing child deletions");
        ApiError::new(ErrorCode::InternalError, "failed to list child deletions")
    })?;

    Ok(rows
        .into_iter()
        .map(
            |(child_did, handle, registration_id, scheduled_at, delete_after)| ChildDeletionRow {
                child_did,
                handle,
                registration_id,
                scheduled_at,
                delete_after,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    async fn seed_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .expect("seed account");
    }

    #[tokio::test]
    async fn upsert_is_idempotent_and_lists_by_parent() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:parent").await;

        upsert_child_deletion(
            &state.db,
            "did:plc:child",
            "did:plc:parent",
            "child.example.com",
            "reg_child",
            "2099-01-01T00:00:00Z",
        )
        .await
        .expect("first upsert");

        // A repeat delete refreshes the same row rather than erroring on the PK.
        upsert_child_deletion(
            &state.db,
            "did:plc:child",
            "did:plc:parent",
            "child.example.com",
            "reg_child",
            "2099-02-02T00:00:00Z",
        )
        .await
        .expect("second upsert");

        let rows = list_child_deletions_of_parent(&state.db, "did:plc:parent")
            .await
            .expect("list");
        assert_eq!(rows.len(), 1, "upsert collapses to one tombstone per child");
        assert_eq!(rows[0].child_did, "did:plc:child");
        assert_eq!(rows[0].delete_after, "2099-02-02T00:00:00Z");
    }

    #[tokio::test]
    async fn tombstone_survives_after_the_child_account_is_gone() {
        // The whole point: the row is keyed by child_did but has no FK to accounts on that column,
        // so it does not require the child account to exist and it is not swept when the child is
        // purged. Only the parent is referenced.
        let state = test_state().await;
        seed_account(&state.db, "did:plc:parent2").await;

        upsert_child_deletion(
            &state.db,
            "did:plc:goneChild",
            "did:plc:parent2",
            "gone.example.com",
            "reg_gone",
            "2099-01-01T00:00:00Z",
        )
        .await
        .expect("upsert with no child account present");

        let rows = list_child_deletions_of_parent(&state.db, "did:plc:parent2")
            .await
            .expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].registration_id, "reg_gone");
    }
}
