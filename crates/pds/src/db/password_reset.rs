// pattern: Imperative Shell

//! Password-reset token queries over `password_reset_tokens` (V014): the SHA-256-hashed,
//! 1-hour, single-use envelope.
//!
//! `insert_reset_token` mints a row (hash only — the plaintext is never stored);
//! `get_reset_token` / `mark_reset_token_used` are the in-transaction lookup/consume pair;
//! `update_password_hash` writes the new credential. The admin repair route inserts the same
//! one-hour hashed token envelope inside its audit transaction — only for accounts that
//! already have a password; a passwordless account is refused.

use common::{ApiError, ApiResultExt, ErrorCode};
use sqlx::{Sqlite, Transaction};

pub(crate) struct ResetTokenRow {
    pub(crate) did: String,
    pub(crate) used_at: Option<String>,
    /// True when `expires_at <= datetime('now')` at the time of the query.
    pub(crate) is_expired: bool,
}

/// Insert a new password reset token into the database with a 1-hour expiry.
///
/// `token_hash` is the SHA-256 hex digest of the plaintext token (never stored in plaintext).
/// The 1-hour TTL is an implementation choice for v0.1; the ATProto spec does not mandate it.
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
    .or_internal_as(
        "failed to insert password reset token",
        "failed to create reset token",
    )?;
    Ok(())
}

/// Look up a reset token by its SHA-256 hash within an open transaction.
///
/// Returns `None` if no row matches. The returned `ResetTokenRow` includes
/// `used_at` and `is_expired` so the caller can determine validity without
/// issuing a second query.
pub(crate) async fn get_reset_token(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
) -> Result<Option<ResetTokenRow>, ApiError> {
    let row: Option<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT did, used_at, expires_at <= datetime('now') as is_expired \
         FROM password_reset_tokens \
         WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .or_internal_as(
        "failed to look up password reset token",
        "failed to look up reset token",
    )?;

    Ok(row.map(|(did, used_at, is_expired)| ResetTokenRow {
        did,
        used_at,
        is_expired,
    }))
}

/// Mark a reset token as used by setting `used_at` to the current time.
///
/// Returns `InternalError` if no row was updated (token was deleted between
/// the lookup and this call, which should not happen but defends against
/// future refactors that remove the atomicity guarantee).
pub(crate) async fn mark_reset_token_used(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
) -> Result<(), ApiError> {
    let result = sqlx::query(
        "UPDATE password_reset_tokens \
         SET used_at = datetime('now') \
         WHERE token_hash = ?",
    )
    .bind(token_hash)
    .execute(&mut **tx)
    .await
    .or_internal_as(
        "failed to mark reset token as used",
        "failed to consume reset token",
    )?;

    if result.rows_affected() == 0 {
        return Err({
            tracing::error!(
                "mark_reset_token_used affected 0 rows — token disappeared inside transaction"
            );
            ApiError::new(ErrorCode::InternalError, "failed to consume reset token")
        });
    }
    Ok(())
}

/// Update the password hash for an account within an open transaction.
///
/// Returns `InternalError` if no row was updated (account was deleted between
/// the token lookup and this call).
pub(crate) async fn update_password_hash(
    tx: &mut Transaction<'_, Sqlite>,
    did: &str,
    password_hash: &str,
) -> Result<(), ApiError> {
    let result = sqlx::query(
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

    if result.rows_affected() == 0 {
        return Err({
            tracing::error!(
            did = %did, "update_password_hash affected 0 rows — account disappeared inside transaction");
            ApiError::new(ErrorCode::InternalError, "failed to update password")
        });
    }
    Ok(())
}
