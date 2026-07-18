// pattern: Imperative Shell

//! Queries over `recovery_escrow` (V050): the PDS-held Shamir Share 2 for
//! accounts on the client-generated share model, one row per DID.
//!
//! Rows store only the KEK-wrapped share envelope ciphertext (wrapping and
//! unwrapping live in the caller — this module moves opaque ciphertext, like
//! `db/kek.rs`). The deposit/replace/delete steps are generic over the
//! executor so the owner endpoints can compose them with their audit-event
//! insert in one transaction.

use sqlx::Sqlite;

/// Whether an account currently holds an escrow row. The deposit endpoint
/// uses this (inside its transaction) to pick insert-vs-replace and the
/// matching audit event; readers of the ciphertext itself arrive with the
/// escrow release flow.
pub(crate) async fn escrow_share_exists<'e, E>(executor: E, did: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recovery_escrow WHERE did = ?)")
        .bind(did)
        .fetch_one(executor)
        .await
}

/// Insert the account's first escrow row (the initial deposit).
pub(crate) async fn insert_escrow_share<'e, E>(
    executor: E,
    did: &str,
    share_encrypted: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO recovery_escrow (did, share_encrypted, created_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(did)
    .bind(share_encrypted)
    .execute(executor)
    .await?;
    Ok(())
}

/// Replace an existing escrow row's ciphertext, stamping `rotated_at` and
/// clearing any in-flight release state — a replacement share voids a pending
/// release of the old one. Returns whether a row was actually replaced, so the
/// caller can pick insert-vs-replace without a race window (single-connection
/// pool, and the caller runs both inside one transaction anyway).
pub(crate) async fn replace_escrow_share<'e, E>(
    executor: E,
    did: &str,
    share_encrypted: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE recovery_escrow SET \
             share_encrypted = ?, \
             rotated_at = datetime('now'), \
             release_requested_at = NULL, \
             release_pending_until = NULL \
         WHERE did = ?",
    )
    .bind(share_encrypted)
    .bind(did)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Delete an account's escrow row (owner opt-out). Returns whether a row
/// existed — the caller audits only a real deletion, keeping the repeat call
/// an idempotent no-op with no duplicate event.
pub(crate) async fn delete_escrow_share<'e, E>(executor: E, did: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query("DELETE FROM recovery_escrow WHERE did = ?")
        .bind(did)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// The in-flight release view of an account's escrow row, read by the release/poll flow.
pub(crate) struct ReleaseState {
    /// The KEK-wrapped Share 2 envelope ciphertext (the caller unwraps it only when delivering).
    pub(crate) share_encrypted: String,
    /// Whether a release is currently in flight (`release_requested_at` set).
    pub(crate) release_in_flight: bool,
    /// When the pending release becomes collectable (`release_pending_until`), if in flight.
    pub(crate) release_pending_until: Option<String>,
    /// Whether the pending window has elapsed — the share is collectable now
    /// (`release_pending_until <= now`, evaluated in SQL so "now" is derived once).
    pub(crate) available: bool,
}

/// Read an account's escrow row for the release flow. `None` when the account holds no escrow
/// (never deposited, or owner opted out) — the caller maps that to the same uniform failure as a
/// wrong OTP so escrow presence is never an oracle.
pub(crate) async fn get_release_state(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<ReleaseState>, sqlx::Error> {
    let row: Option<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT share_encrypted, release_requested_at, release_pending_until, \
                CASE WHEN release_pending_until IS NOT NULL \
                      AND release_pending_until <= datetime('now') THEN 1 ELSE 0 END \
         FROM recovery_escrow WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(db)
    .await?;

    Ok(row.map(
        |(share_encrypted, requested_at, pending_until, available)| ReleaseState {
            share_encrypted,
            release_in_flight: requested_at.is_some(),
            release_pending_until: pending_until,
            available: available == 1,
        },
    ))
}

/// Open (or re-open) a pending release: stamp `release_requested_at = now` and
/// `release_pending_until = now + delay`. Returns whether an escrow row existed to open against
/// (so the caller keeps the same uniform failure for an escrow-less account). A fresh open resets
/// the window — re-requesting after a cancel starts a new delay.
pub(crate) async fn open_release<'e, E>(
    executor: E,
    did: &str,
    delay_secs: u64,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    // `datetime('now', '+N seconds')`: the modifier is a bound parameter, not string-built SQL.
    let modifier = format!("+{delay_secs} seconds");
    let result = sqlx::query(
        "UPDATE recovery_escrow SET \
             release_requested_at = datetime('now'), \
             release_pending_until = datetime('now', ?) \
         WHERE did = ?",
    )
    .bind(modifier)
    .bind(did)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Clear an account's in-flight release state (`release_requested_at` / `release_pending_until`
/// back to NULL). Returns whether a pending release was actually cleared, so the caller audits
/// only a real transition (the cancel of a non-existent release, or a repeat, leaves no event).
/// Used both by the cancel endpoint and by the release endpoint after the share is handed back.
pub(crate) async fn clear_release<'e, E>(executor: E, did: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE recovery_escrow SET \
             release_requested_at = NULL, \
             release_pending_until = NULL \
         WHERE did = ? AND release_requested_at IS NOT NULL",
    )
    .bind(did)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// One in-flight escrow release, for the operator visibility list.
pub(crate) struct PendingRelease {
    pub(crate) did: String,
    pub(crate) release_requested_at: String,
    pub(crate) release_pending_until: Option<String>,
    /// Whether the delay window has already elapsed (the share is collectable now).
    pub(crate) available: bool,
}

/// List every account with an in-flight escrow release, newest request first. The share
/// ciphertext is never selected — only the release timing an operator needs to see or act on.
pub(crate) async fn list_pending_releases(
    db: &sqlx::SqlitePool,
) -> Result<Vec<PendingRelease>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT did, release_requested_at, release_pending_until, \
                CASE WHEN release_pending_until IS NOT NULL \
                      AND release_pending_until <= datetime('now') THEN 1 ELSE 0 END \
         FROM recovery_escrow \
         WHERE release_requested_at IS NOT NULL \
         ORDER BY release_requested_at DESC, did ASC",
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(did, release_requested_at, release_pending_until, available)| PendingRelease {
                did,
                release_requested_at,
                release_pending_until,
                available: available == 1,
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

    async fn stored_row(db: &sqlx::SqlitePool, did: &str) -> Option<(String, Option<String>)> {
        sqlx::query_as("SELECT share_encrypted, rotated_at FROM recovery_escrow WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn deposit_replace_delete_lifecycle() {
        let state = test_state().await;
        let did = "did:plc:escrowlifecycle";
        seed_account(&state.db, did).await;

        assert!(!escrow_share_exists(&state.db, did).await.unwrap());

        insert_escrow_share(&state.db, did, "ciphertext-1")
            .await
            .unwrap();
        assert!(escrow_share_exists(&state.db, did).await.unwrap());
        let (share, rotated_at) = stored_row(&state.db, did).await.unwrap();
        assert_eq!(share, "ciphertext-1");
        assert!(rotated_at.is_none(), "fresh deposit is not a rotation");

        assert!(replace_escrow_share(&state.db, did, "ciphertext-2")
            .await
            .unwrap());
        let (share, rotated_at) = stored_row(&state.db, did).await.unwrap();
        assert_eq!(share, "ciphertext-2");
        assert!(rotated_at.is_some(), "replacement stamps rotated_at");

        assert!(delete_escrow_share(&state.db, did).await.unwrap());
        assert!(!escrow_share_exists(&state.db, did).await.unwrap());
        assert!(
            !delete_escrow_share(&state.db, did).await.unwrap(),
            "repeat delete reports nothing existed"
        );
    }

    #[tokio::test]
    async fn replace_clears_release_state() {
        let state = test_state().await;
        let did = "did:plc:escrowrelease";
        seed_account(&state.db, did).await;
        insert_escrow_share(&state.db, did, "ciphertext-1")
            .await
            .unwrap();
        sqlx::query(
            "UPDATE recovery_escrow SET release_requested_at = datetime('now'), \
             release_pending_until = datetime('now', '+1 day') WHERE did = ?",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        replace_escrow_share(&state.db, did, "ciphertext-2")
            .await
            .unwrap();

        let (requested, pending): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT release_requested_at, release_pending_until FROM recovery_escrow WHERE did = ?",
        )
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(requested, None, "a new share voids a pending release");
        assert_eq!(pending, None);
    }

    #[tokio::test]
    async fn unknown_account_is_a_foreign_key_error() {
        let state = test_state().await;
        assert!(
            insert_escrow_share(&state.db, "did:plc:escrowghost", "ciphertext")
                .await
                .is_err(),
            "FK to accounts must reject an orphan escrow row"
        );
    }

    #[tokio::test]
    async fn replace_without_a_row_reports_false() {
        let state = test_state().await;
        let did = "did:plc:escrownorow";
        seed_account(&state.db, did).await;
        assert!(!replace_escrow_share(&state.db, did, "ciphertext")
            .await
            .unwrap());
    }
}
