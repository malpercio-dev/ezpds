// pattern: Imperative Shell

//! Recovery-release email OTP queries (V053).
//!
//! These back the escrow-assisted recovery release: `POST /v1/recovery/initiate` mints a
//! single-use, 1-hour email OTP, and the opening `POST /v1/recovery/release` call consumes it
//! to open the release. Only the SHA-256 hash of the plaintext is ever stored — the same
//! envelope as `account_deletion_tokens` (V034), `plc_operation_tokens` (V033), and
//! `password_reset_tokens` (V014). Consumption is atomic and bound to `(token_hash, did)` so an
//! OTP can neither be replayed nor spent against another account.

use common::{ApiError, ErrorCode};

/// Insert a new recovery-release OTP with a 1-hour expiry.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext OTP (never stored in plaintext).
/// Multiple outstanding OTPs per DID are allowed — a fresh `initiate` simply provides another
/// valid OTP; [`consume_recovery_otp`] invalidates whichever one is redeemed.
pub async fn insert_recovery_otp(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO recovery_otps (token_hash, did, expires_at, created_at) \
         VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert recovery OTP");
        ApiError::new(ErrorCode::InternalError, "failed to create recovery OTP")
    })?;
    Ok(())
}

/// Atomically validate and consume a recovery-release OTP for `did`.
///
/// Returns `true` when the OTP existed, belonged to `did`, was unexpired, and had not already
/// been used — marking it used in the same statement so it can never be redeemed twice. Returns
/// `false` otherwise (unknown / wrong DID / expired / already used), which the caller maps to a
/// uniform auth rejection (no oracle). Binding the update to the DID prevents one account from
/// spending another's OTP.
pub async fn consume_recovery_otp(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE recovery_otps \
         SET used_at = datetime('now') \
         WHERE token_hash = ? AND did = ? \
           AND used_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to consume recovery OTP");
        ApiError::new(ErrorCode::InternalError, "failed to consume recovery OTP")
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
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn valid_otp_consumes_once() {
        let pool = test_pool().await;
        let did = "did:plc:recotpowner1111111111111";
        insert_account(&pool, did).await;
        let token = generate_token();
        insert_recovery_otp(&pool, did, &token.hash).await.unwrap();

        assert!(
            consume_recovery_otp(&pool, did, &token.hash).await.unwrap(),
            "first consume should succeed"
        );
        assert!(
            !consume_recovery_otp(&pool, did, &token.hash).await.unwrap(),
            "second consume must fail (single-use = replay rejection)"
        );
    }

    #[tokio::test]
    async fn otp_bound_to_did() {
        let pool = test_pool().await;
        let owner = "did:plc:recotpowner2222222222222";
        let other = "did:plc:recotpother3333333333333";
        insert_account(&pool, owner).await;
        insert_account(&pool, other).await;
        let token = generate_token();
        insert_recovery_otp(&pool, owner, &token.hash)
            .await
            .unwrap();

        assert!(
            !consume_recovery_otp(&pool, other, &token.hash)
                .await
                .unwrap(),
            "a different DID must not be able to consume the OTP"
        );
        assert!(
            consume_recovery_otp(&pool, owner, &token.hash)
                .await
                .unwrap(),
            "the owner can still consume it"
        );
    }

    #[tokio::test]
    async fn expired_otp_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:recotpexpired4444444444";
        insert_account(&pool, did).await;
        let token = generate_token();
        sqlx::query(
            "INSERT INTO recovery_otps (token_hash, did, expires_at, created_at) \
             VALUES (?, ?, datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !consume_recovery_otp(&pool, did, &token.hash).await.unwrap(),
            "expired OTP must be rejected"
        );
    }

    #[tokio::test]
    async fn unknown_otp_rejected() {
        let pool = test_pool().await;
        let did = "did:plc:recotpnone5555555555555";
        insert_account(&pool, did).await;
        assert!(
            !consume_recovery_otp(&pool, did, "deadbeef").await.unwrap(),
            "unknown OTP must be rejected"
        );
    }
}
