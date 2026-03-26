// pattern: Imperative Shell

use common::{ApiError, ErrorCode};
use sqlx::{Sqlite, Transaction};

pub(crate) struct ResetTokenRow {
    pub(crate) did: String,
    pub(crate) used_at: Option<String>,
}

/// Insert a new password reset token into the database with a 1-hour expiry.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext token (never stored in plaintext).
/// The expiry is always 1 hour from the current DB clock, matching the ATProto spec.
pub(crate) async fn insert_reset_token(
    db: &sqlx::SqlitePool,
    did: &str,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO password_reset_tokens \
         (token_hash, did, expires_at, created_at) \
         VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert password reset token");
        ApiError::new(ErrorCode::InternalError, "failed to create reset token")
    })?;
    Ok(())
}

/// Look up a reset token by its SHA-256 hash within an open transaction.
///
/// Returns `None` if no row matches. The caller is responsible for checking
/// `expires_at` and `used_at` to determine validity.
pub(crate) async fn get_reset_token(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
) -> Result<Option<ResetTokenRow>, ApiError> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT did, used_at \
         FROM password_reset_tokens \
         WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to look up password reset token");
        ApiError::new(ErrorCode::InternalError, "failed to look up reset token")
    })?;

    Ok(row.map(|(did, used_at)| ResetTokenRow { did, used_at }))
}

/// Mark a reset token as used by setting `used_at` to the current time.
pub(crate) async fn mark_reset_token_used(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE password_reset_tokens \
         SET used_at = datetime('now') \
         WHERE token_hash = ?",
    )
    .bind(token_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to mark reset token as used");
        ApiError::new(ErrorCode::InternalError, "failed to consume reset token")
    })?;
    Ok(())
}

/// Update the password hash for an account within an open transaction.
pub(crate) async fn update_password_hash(
    tx: &mut Transaction<'_, Sqlite>,
    did: &str,
    password_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE accounts \
         SET password_hash = ?, updated_at = datetime('now') \
         WHERE did = ?",
    )
    .bind(password_hash)
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to update password hash");
        ApiError::new(ErrorCode::InternalError, "failed to update password")
    })?;
    Ok(())
}
