// pattern: Imperative Shell
//
// Session-row writes against the `sessions` table. Only the standalone provisioning-session
// insert lives here; every other session insert is one leg of a multi-table auth transaction
// (createSession, account genesis, migration) and stays in its route handler alongside the
// paired refresh-token write.

use common::{ApiError, ErrorCode};

/// Insert a bearer-authenticated provisioning session (no device, one-year TTL). The session's
/// opaque token is stored as its SHA-256 hash.
pub async fn insert_provisioning_session(
    db: &sqlx::SqlitePool,
    session_id: &str,
    did: &str,
    token_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
    )
    .bind(session_id)
    .bind(did)
    .bind(token_hash)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert provisioning session");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    Ok(())
}
