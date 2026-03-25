// pattern: Imperative Shell
//
// Account lookup queries. Gathers from the accounts + handles + did_documents tables;
// returns plain data structs. No business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};

/// Flat account row returned by `resolve_identifier`.
pub(crate) struct AccountRow {
    pub(crate) did: String,
    pub(crate) email: String,
    /// Argon2id PHC string. `None` for mobile accounts (password auth not allowed).
    pub(crate) password_hash: Option<String>,
    /// One associated handle (if any). `None` means no row exists in the `handles` table.
    pub(crate) handle: Option<String>,
}

/// Flat account row used by `getSession` — includes confirmation status and DID document.
pub(crate) struct SessionAccountRow {
    pub(crate) did: String,
    pub(crate) email: String,
    /// `true` when `email_confirmed_at` is non-NULL in the DB.
    pub(crate) email_confirmed: bool,
    /// One associated handle (if any).
    pub(crate) handle: Option<String>,
    /// Raw JSON string from `did_documents.document`, if present.
    pub(crate) did_doc: Option<String>,
}

/// Fetch account info needed for `getSession` by DID.
///
/// Returns `None` when the DID is not found or the account is deactivated.
pub(crate) async fn get_session_account(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<SessionAccountRow>, ApiError> {
    // (email, email_confirmed_at, handle, did_document)
    type Row = (String, Option<String>, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT a.email, a.email_confirmed_at, h.handle, d.document \
         FROM accounts a \
         LEFT JOIN handles h ON h.did = a.did \
         LEFT JOIN did_documents d ON d.did = a.did \
         WHERE a.did = ? AND a.deactivated_at IS NULL \
         LIMIT 1",
    )
    .bind(did)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error fetching session account");
        ApiError::new(ErrorCode::InternalError, "failed to load account")
    })?;

    Ok(row.map(
        |(email, email_confirmed_at, handle, did_doc)| SessionAccountRow {
            did: did.to_string(),
            email,
            email_confirmed: email_confirmed_at.is_some(),
            handle,
            did_doc,
        },
    ))
}

/// Resolve an email address to an active (non-deactivated) account.
///
/// Used by the provisioning session login endpoint (`POST /v1/accounts/sessions`).
/// Returns `None` when not found or deactivated; `Err` only on DB errors.
pub(crate) async fn resolve_by_email(
    db: &sqlx::SqlitePool,
    email: &str,
) -> Result<Option<AccountRow>, ApiError> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT a.did, a.password_hash, h.handle \
         FROM accounts a \
         LEFT JOIN handles h ON h.did = a.did \
         WHERE a.email = ? AND a.deactivated_at IS NULL \
         LIMIT 1",
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        // Logging the email domain aids ops triage without exposing the full address in logs.
        let domain = email.split('@').nth(1).unwrap_or("<unknown>");
        tracing::error!(error = %e, email_domain = %domain, "DB error resolving email");
        ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
    })?;

    Ok(row.map(|(did, password_hash, handle)| AccountRow {
        did,
        email: email.to_string(),
        password_hash,
        handle,
    }))
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
            tracing::error!(identifier = %identifier, error = %e, "DB error resolving DID");
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
            tracing::error!(identifier = %identifier, error = %e, "DB error resolving handle");
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
