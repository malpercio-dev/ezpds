// pattern: Imperative Shell

//! Refresh-token reads against the `refresh_tokens` table (V002, rebuilt into the live
//! schema by V006). Standalone single-table lookups only: `get_active_refresh_token`
//! (+ `ActiveRefreshToken`) is the unexpired-token lookup for `refreshSession`, and
//! `session_id_for_jti` maps jti → session_id for `deleteSession` with no expiry filter.
//! The multi-table rotation (insert the new token + mark the old one used) and revocation
//! (delete the session's tokens + the session row) transactions stay in their route
//! handlers.

use common::{ApiError, ApiResultExt};

/// An active (unexpired) refresh token's rotation-relevant columns.
pub struct ActiveRefreshToken {
    pub did: String,
    pub session_id: String,
    /// Set once this token has been rotated; a non-NULL value signals a replay.
    pub next_jti: Option<String>,
    /// Non-NULL when the session is app-password-scoped; carried forward on rotation.
    pub app_password_name: Option<String>,
}

/// Look up an unexpired refresh token by `jti`. `None` when it is absent or already expired.
pub async fn get_active_refresh_token(
    db: &sqlx::SqlitePool,
    jti: &str,
) -> Result<Option<ActiveRefreshToken>, ApiError> {
    let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT did, session_id, next_jti, app_password_name FROM refresh_tokens \
         WHERE jti = ? AND expires_at > datetime('now')",
    )
    .bind(jti)
    .fetch_optional(db)
    .await
    .or_internal_as("DB error looking up refresh token", "internal error")?;

    Ok(row.map(
        |(did, session_id, next_jti, app_password_name)| ActiveRefreshToken {
            did,
            session_id,
            next_jti,
            app_password_name,
        },
    ))
}

/// The `session_id` a refresh token belongs to, keyed by `jti`. No expiry filter — revocation must
/// find already-expired tokens too. `None` when the token is unknown (already revoked).
pub async fn session_id_for_jti(
    db: &sqlx::SqlitePool,
    jti: &str,
) -> Result<Option<String>, ApiError> {
    let session_id: Option<String> =
        sqlx::query_scalar("SELECT session_id FROM refresh_tokens WHERE jti = ?")
            .bind(jti)
            .fetch_optional(db)
            .await
            .or_internal_as(
                "DB error looking up refresh token for deleteSession",
                "internal error",
            )?;

    Ok(session_id)
}
