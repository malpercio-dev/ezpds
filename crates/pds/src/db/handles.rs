// pattern: Imperative Shell
//
// Handle queries against the `handles` table — each row binds one handle string to the DID that
// owns it. Returns plain data; no business logic (a caller decides whether a hit/miss means 404,
// 409, or an idempotent no-op). Multi-table handle swaps — e.g. `updateHandle`'s atomic
// DELETE-then-INSERT — stay in their route handler's transaction; only standalone single-table
// statements live here.

use common::{ApiError, ErrorCode};

use super::is_unique_violation;

/// Outcome of [`insert_handle`].
pub enum InsertHandleOutcome {
    Inserted,
    /// The handle is already bound to some DID (UNIQUE violation on `handles.handle`).
    HandleTaken,
}

/// Resolve a handle to the DID that owns it locally. `None` when no local row exists (the caller
/// may then fall back to DNS / HTTP well-known resolution).
pub async fn resolve_handle(
    db: &sqlx::SqlitePool,
    handle: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(handle)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    Ok(row.map(|(did,)| did))
}

/// Insert a new handle → DID binding. A UNIQUE violation on the handle is reported as
/// [`InsertHandleOutcome::HandleTaken`] rather than an error, so the caller can map it to a 409.
pub async fn insert_handle(
    db: &sqlx::SqlitePool,
    handle: &str,
    did: &str,
) -> Result<InsertHandleOutcome, ApiError> {
    let result =
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(handle)
            .bind(did)
            .execute(db)
            .await;

    match result {
        Ok(_) => Ok(InsertHandleOutcome::Inserted),
        Err(e) if is_unique_violation(&e) => Ok(InsertHandleOutcome::HandleTaken),
        Err(e) => {
            tracing::error!(error = %e, "failed to insert handle");
            Err(ApiError::new(
                ErrorCode::InternalError,
                "failed to register handle",
            ))
        }
    }
}
