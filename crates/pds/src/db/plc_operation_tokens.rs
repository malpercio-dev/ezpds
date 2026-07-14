// pattern: Imperative Shell

//! PLC-operation signature token queries.
//!
//! These back the interop account-migration path (ADR-0002): before the PDS will
//! sign a DID-repointing PLC operation on the account's behalf
//! (`com.atproto.identity.signPlcOperation`), the account must prove control of
//! its email by presenting a token minted by
//! `com.atproto.identity.requestPlcOperationSignature`. Tokens are single-use and
//! short-lived, and only the SHA-256 hash of the plaintext is ever stored — the
//! same envelope as `password_reset` (V014).

use common::{ApiError, ErrorCode};

/// Insert a new PLC-operation signature token with a 1-hour expiry.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext token (never stored in
/// plaintext). Multiple outstanding tokens per DID are allowed — the newest email
/// simply provides another valid token; `consume_plc_operation_token` invalidates
/// whichever one is redeemed.
pub async fn insert_plc_operation_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO plc_operation_tokens \
         (token_hash, did, expires_at, created_at) \
         VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert PLC operation token");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to create PLC operation token",
        )
    })?;
    Ok(())
}

/// Check — without consuming — whether a token is currently valid for `did`
/// (exists, belongs to `did`, unexpired, unused).
///
/// This is the cheap pre-flight the `signPlcOperation` handler runs *before* the
/// expensive plc.directory round-trip, so an obviously-bad token is rejected
/// without wasted work. It does **not** guarantee single-use — the atomic
/// [`consume_plc_operation_token`] at the end of the flow is what redeems the
/// token exactly once, closing the window between this check and that consume.
pub async fn plc_operation_token_is_valid(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<bool, ApiError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM plc_operation_tokens \
         WHERE token_hash = ? AND did = ? \
           AND used_at IS NULL AND expires_at > datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .fetch_one(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to check PLC operation token validity");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to check PLC operation token",
        )
    })?;
    Ok(valid)
}

/// Atomically validate and consume a PLC-operation signature token for `did`.
///
/// Returns `true` when the token existed, belonged to `did`, was unexpired, and
/// had not already been used — marking it used in the same statement so it can
/// never be redeemed twice. Returns `false` otherwise (unknown / wrong DID /
/// expired / already used), which the caller maps to an auth rejection. Binding
/// the update to the DID prevents one account from spending another's token.
pub async fn consume_plc_operation_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE plc_operation_tokens \
         SET used_at = datetime('now') \
         WHERE token_hash = ? AND did = ? \
           AND used_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to consume PLC operation token");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to consume PLC operation token",
        )
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
        let did = "did:plc:tokenowner1111111111111";
        insert_account(&pool, did).await;
        let token = generate_token();
        insert_plc_operation_token(&pool, did, &token.hash)
            .await
            .unwrap();

        assert!(
            consume_plc_operation_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "first consume should succeed"
        );
        assert!(
            !consume_plc_operation_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "second consume must fail (single-use)"
        );
    }

    #[tokio::test]
    async fn token_bound_to_did() {
        let pool = test_pool().await;
        let owner = "did:plc:tokenowner2222222222222";
        let other = "did:plc:otheracct3333333333333";
        insert_account(&pool, owner).await;
        insert_account(&pool, other).await;
        let token = generate_token();
        insert_plc_operation_token(&pool, owner, &token.hash)
            .await
            .unwrap();

        assert!(
            !consume_plc_operation_token(&pool, other, &token.hash)
                .await
                .unwrap(),
            "a different DID must not be able to consume the token"
        );
        assert!(
            consume_plc_operation_token(&pool, owner, &token.hash)
                .await
                .unwrap(),
            "the owner can still consume it"
        );
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:expiredtok4444444444444";
        insert_account(&pool, did).await;
        let token = generate_token();
        // Insert already-expired.
        sqlx::query(
            "INSERT INTO plc_operation_tokens (token_hash, did, expires_at, created_at) \
             VALUES (?, ?, datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !consume_plc_operation_token(&pool, did, &token.hash)
                .await
                .unwrap(),
            "expired token must be rejected"
        );
    }

    #[tokio::test]
    async fn unknown_token_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:notoken55555555555555555";
        insert_account(&pool, did).await;
        assert!(
            !consume_plc_operation_token(&pool, did, "deadbeef")
                .await
                .unwrap(),
            "unknown token must be rejected"
        );
    }
}
