// pattern: Imperative Shell

//! Account-deletion email token queries.
//!
//! These back the standard `com.atproto.server.deleteAccount` flow: before the PDS
//! will permanently delete an account, the requester must prove control of its email
//! by presenting a token minted by `com.atproto.server.requestAccountDelete`. Tokens
//! are single-use and short-lived, and only the SHA-256 hash of the plaintext is ever
//! stored — the same envelope as `plc_operation_tokens` (V033) and `password_reset`
//! (V014).

use common::{ApiError, ErrorCode};

/// Insert a new account-deletion token with a 1-hour expiry.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext token (never stored in
/// plaintext). Multiple outstanding tokens per DID are allowed — the newest email
/// simply provides another valid token; [`consume_account_deletion_token`]
/// invalidates whichever one is redeemed.
pub async fn insert_account_deletion_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO account_deletion_tokens \
         (token_hash, did, expires_at, created_at) \
         VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert account deletion token");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to create account deletion token",
        )
    })?;
    Ok(())
}

/// Atomically validate and consume an account-deletion token for `did`.
///
/// Returns `true` when the token existed, belonged to `did`, was unexpired, and had
/// not already been used — marking it used in the same statement so it can never be
/// redeemed twice. Returns `false` otherwise (unknown / wrong DID / expired / already
/// used), which the caller maps to an auth rejection. Binding the update to the DID
/// prevents one account from spending another's token.
pub async fn consume_account_deletion_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE account_deletion_tokens \
         SET used_at = datetime('now') \
         WHERE token_hash = ? AND did = ? \
           AND used_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to consume account deletion token");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to consume account deletion token",
        )
    })?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};
    use crate::token::generate_token;

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
        let did = "did:plc:deltokenowner11111111111";
        insert_account(&pool, did).await;
        let token = generate_token();
        insert_account_deletion_token(&pool, did, &token.hash)
            .await
            .unwrap();

        assert!(
            consume_account_deletion_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "first consume should succeed"
        );
        assert!(
            !consume_account_deletion_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "second consume must fail (single-use)"
        );
    }

    #[tokio::test]
    async fn token_bound_to_did() {
        let pool = test_pool().await;
        let owner = "did:plc:deltokenowner22222222222";
        let other = "did:plc:delotheracct33333333333";
        insert_account(&pool, owner).await;
        insert_account(&pool, other).await;
        let token = generate_token();
        insert_account_deletion_token(&pool, owner, &token.hash)
            .await
            .unwrap();

        assert!(
            !consume_account_deletion_token(&pool, other, &token.hash)
                .await
                .unwrap(),
            "a different DID must not be able to consume the token"
        );
        assert!(
            consume_account_deletion_token(&pool, owner, &token.hash)
                .await
                .unwrap(),
            "the owner can still consume it"
        );
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:delexpiredtok4444444444";
        insert_account(&pool, did).await;
        let token = generate_token();
        sqlx::query(
            "INSERT INTO account_deletion_tokens (token_hash, did, expires_at, created_at) \
             VALUES (?, ?, datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !consume_account_deletion_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "expired token must be rejected"
        );
    }

    #[tokio::test]
    async fn unknown_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:delnotoken5555555555555";
        insert_account(&pool, did).await;
        assert!(
            !consume_account_deletion_token(&pool, did, "deadbeef")
                .await
                .unwrap(),
            "unknown token must be rejected"
        );
    }
}
