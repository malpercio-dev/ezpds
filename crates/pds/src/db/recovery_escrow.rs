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

/// Void the legacy server-generated Share 2 (`accounts.recovery_share`, V010)
/// for a DID that has just re-keyed onto the client-generated escrow model.
///
/// The pre-existing (old-model) split was generated server-side over a secret
/// bound to nothing, and the server saw all three shares at ceremony time — so
/// once the account has a client-generated Share 2 in `recovery_escrow`, the
/// legacy column is dead material that must not linger in backups. Returns
/// whether a non-NULL value was actually cleared, so the caller records the
/// void only when there was material to void. Idempotent: a repeat call, or a
/// call for an account that never had a legacy share (created after the
/// ceremony inversion), is a no-op returning `false`.
pub(crate) async fn null_legacy_recovery_share<'e, E>(
    executor: E,
    did: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE accounts SET recovery_share = NULL WHERE did = ? AND recovery_share IS NOT NULL",
    )
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

    #[tokio::test]
    async fn null_legacy_recovery_share_clears_only_when_present() {
        let state = test_state().await;
        let did = "did:plc:legacyrekey";
        seed_account(&state.db, did).await;

        // Account with no legacy material: the void is a no-op.
        assert!(
            !null_legacy_recovery_share(&state.db, did).await.unwrap(),
            "an account without a legacy share has nothing to void"
        );

        // Simulate an old-model account carrying a server-generated Share 2.
        sqlx::query("UPDATE accounts SET recovery_share = ? WHERE did = ?")
            .bind("LEGACYSHARE2")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        assert!(
            null_legacy_recovery_share(&state.db, did).await.unwrap(),
            "the first void clears the dead legacy material"
        );
        let remaining: Option<String> =
            sqlx::query_scalar("SELECT recovery_share FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining, None, "legacy column is NULL after the void");

        assert!(
            !null_legacy_recovery_share(&state.db, did).await.unwrap(),
            "the void is idempotent — a second call clears nothing"
        );
    }
}
