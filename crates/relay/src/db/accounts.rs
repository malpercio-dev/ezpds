// pattern: Imperative Shell
//
// Account lookup queries. Gathers from the accounts + handles tables; returns
// plain data structs. No business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};

/// Flat account row returned by `resolve_identifier`.
pub(crate) struct AccountRow {
    pub(crate) did: String,
    pub(crate) email: String,
    /// Argon2id PHC string. `None` for mobile accounts (password auth not allowed).
    pub(crate) password_hash: Option<String>,
    /// One associated handle (if any). Empty string returned in the response when absent.
    pub(crate) handle: Option<String>,
}

/// Resolve a handle or DID to an active (non-deactivated) account.
///
/// Returns `None` when not found; `Err` only on DB errors.
pub(crate) async fn resolve_identifier(
    db: &sqlx::SqlitePool,
    identifier: &str,
) -> Result<Option<AccountRow>, ApiError> {
    if identifier.starts_with("did:") {
        let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT a.email, a.password_hash, h.handle \
             FROM accounts a \
             LEFT JOIN handles h ON h.did = a.did \
             WHERE a.did = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DB error resolving DID");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(email, password_hash, handle)| AccountRow {
            did: identifier.to_string(),
            email,
            password_hash,
            handle,
        }))
    } else {
        let row: Option<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT a.did, a.email, a.password_hash, h.handle \
             FROM handles h \
             JOIN accounts a ON a.did = h.did \
             WHERE h.handle = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DB error resolving handle");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(did, email, password_hash, handle)| AccountRow {
            did,
            email,
            password_hash,
            handle: Some(handle),
        }))
    }
}
