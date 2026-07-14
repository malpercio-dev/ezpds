// pattern: Imperative Shell

//! Email verification token queries (V036).
//!
//! These back the standard `com.atproto.server.confirmEmail` and `updateEmail` flows: before
//! the PDS marks an email confirmed or lets a confirmed email be changed, the requester must
//! prove control of the current address by presenting a token minted by the matching
//! `request*` endpoint and delivered by email. Tokens are single-use and short-lived, and only
//! the SHA-256 hash of the plaintext is ever stored — the same envelope as `password_reset`
//! (V014), `plc_operation_tokens` (V033), and `account_deletion_tokens` (V034).
//!
//! The one addition here is [`EmailTokenPurpose`]: a single `email_tokens` table serves both
//! flows, and every insert/consume is bound to the purpose so a confirmation token can never be
//! spent as an email-change authorization or vice versa.

use common::{ApiError, ErrorCode};

/// Which flow an [`email_tokens`](self) row authorizes. Persisted as the `purpose` column so the
/// same table can back both the confirm and update flows without one token type standing in for
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTokenPurpose {
    /// Minted by `requestEmailConfirmation`, consumed by `confirmEmail`.
    Confirm,
    /// Minted by `requestEmailUpdate`, consumed by `updateEmail`.
    Update,
}

impl EmailTokenPurpose {
    fn as_str(self) -> &'static str {
        match self {
            EmailTokenPurpose::Confirm => "confirm",
            EmailTokenPurpose::Update => "update",
        }
    }
}

/// Insert a new email token with a 1-hour expiry for the given `purpose`.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext token (never stored in plaintext).
/// Multiple outstanding tokens per DID/purpose are allowed — the newest email simply provides
/// another valid token; [`consume_email_token`] invalidates whichever one is redeemed.
pub async fn insert_email_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
    purpose: EmailTokenPurpose,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO email_tokens \
         (token_hash, did, purpose, expires_at, created_at) \
         VALUES (?, ?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .bind(purpose.as_str())
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, purpose = purpose.as_str(), "failed to insert email token");
        ApiError::new(ErrorCode::InternalError, "failed to create email token")
    })?;
    Ok(())
}

/// Atomically validate and consume an email token for `(did, purpose)`.
///
/// Returns `true` when the token existed, belonged to `did`, matched `purpose`, was unexpired,
/// and had not already been used — marking it used in the same statement so it can never be
/// redeemed twice. Returns `false` otherwise (unknown / wrong DID / wrong purpose / expired /
/// already used), which the caller maps to an auth rejection. Binding the update to the DID and
/// purpose prevents one account from spending another's token and prevents cross-flow reuse.
pub async fn consume_email_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
    purpose: EmailTokenPurpose,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE email_tokens \
         SET used_at = datetime('now') \
         WHERE token_hash = ? AND did = ? AND purpose = ? \
           AND used_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .bind(did)
    .bind(purpose.as_str())
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, purpose = purpose.as_str(), "failed to consume email token");
        ApiError::new(ErrorCode::InternalError, "failed to consume email token")
    })?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::generate_token;
    use crate::db::{open_pool, run_migrations};

    async fn test_pool() -> sqlx::SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    async fn insert_account(pool: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn valid_token_consumes_once() {
        let pool = test_pool().await;
        let did = "did:plc:emailtokowner1111111111";
        insert_account(&pool, did).await;
        let token = generate_token();
        insert_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
            .await
            .unwrap();

        assert!(
            consume_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
                .await
                .unwrap(),
            "first consume should succeed"
        );
        assert!(
            !consume_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
                .await
                .unwrap(),
            "second consume must fail (single-use)"
        );
    }

    #[tokio::test]
    async fn token_bound_to_did() {
        let pool = test_pool().await;
        let owner = "did:plc:emailtokowner2222222222";
        let other = "did:plc:emailtokother33333333333";
        insert_account(&pool, owner).await;
        insert_account(&pool, other).await;
        let token = generate_token();
        insert_email_token(&pool, owner, &token.hash, EmailTokenPurpose::Update)
            .await
            .unwrap();

        assert!(
            !consume_email_token(&pool, other, &token.hash, EmailTokenPurpose::Update)
                .await
                .unwrap(),
            "a different DID must not be able to consume the token"
        );
        assert!(
            consume_email_token(&pool, owner, &token.hash, EmailTokenPurpose::Update)
                .await
                .unwrap(),
            "the owner can still consume it"
        );
    }

    #[tokio::test]
    async fn token_bound_to_purpose() {
        let pool = test_pool().await;
        let did = "did:plc:emailtokpurpose4444444";
        insert_account(&pool, did).await;
        let token = generate_token();
        // Minted for confirmation...
        insert_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
            .await
            .unwrap();

        // ...must not be redeemable as an email-change authorization.
        assert!(
            !consume_email_token(&pool, did, &token.hash, EmailTokenPurpose::Update)
                .await
                .unwrap(),
            "a confirm token must not be consumable as an update token"
        );
        // ...but is still valid for its own purpose.
        assert!(
            consume_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
                .await
                .unwrap(),
            "the confirm token remains valid for confirmation"
        );
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:emailtokexpired55555555";
        insert_account(&pool, did).await;
        let token = generate_token();
        sqlx::query(
            "INSERT INTO email_tokens (token_hash, did, purpose, expires_at, created_at) \
             VALUES (?, ?, 'confirm', datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !consume_email_token(&pool, did, &token.hash, EmailTokenPurpose::Confirm)
                .await
                .unwrap(),
            "expired token must be rejected"
        );
    }

    #[tokio::test]
    async fn unknown_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:emailtoknotoken6666666";
        insert_account(&pool, did).await;
        assert!(
            !consume_email_token(&pool, did, "deadbeef", EmailTokenPurpose::Confirm)
                .await
                .unwrap(),
            "unknown token must be rejected"
        );
    }
}
