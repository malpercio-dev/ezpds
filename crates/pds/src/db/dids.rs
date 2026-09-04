// pattern: Imperative Shell

//! DID-document cache queries over the `did_documents` table (V002), plus the
//! Custos-managed did:web hosting queries (V044).
//!
//! Cache: `get_did_document` / `did_document_exists` (lookup / cheap existence probe).
//! `rewrite_did_document` is an UPDATE-only heal of an existing cache row with a freshly
//! resolved doc — it never inserts, because the cache has no TTL and a foreign row would
//! then be stale forever; it backs the force-refresh path. `upsert_did_document` is the
//! INSERT-or-UPDATE write path for a document that may not be cached yet (account
//! creation/migration, signing-key rotation, a submitted PLC operation, a handle swap's PLC
//! cache refresh). `fetch_also_known_as` renders a DID's handles as `at://<handle>` for the
//! document's `alsoKnownAs` array, and `update_also_known_as` writes that field back into the
//! stored document.
//!
//! did:web hosting (over `accounts.did_web_hosting_enabled_at`): `serve_hosted_did_document`
//! is the gated `.well-known/did.json` serve — account exists, opted in, active lifecycle,
//! document present, else `None` — with `set_did_web_hosting` / `did_web_hosting_enabled` as
//! the opt-in toggle and probe.

use common::{ApiError, ErrorCode};
use sqlx::{Sqlite, SqlitePool};

/// Look up a locally cached DID document by DID string.
///
/// Returns `None` when no row exists for the given DID; `Err` only on DB errors.
pub async fn get_did_document(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT document FROM did_documents WHERE did = ? LIMIT 1")
            .bind(did)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error fetching DID document");
                ApiError::new(ErrorCode::InternalError, "failed to load DID document")
            })?;

    match row {
        None => Ok(None),
        Some((doc_str,)) => {
            let doc = serde_json::from_str(&doc_str).map_err(|e| {
                let preview = &doc_str[..doc_str.len().min(500)];
                tracing::error!(did = %did, error = %e, raw = %preview, "malformed DID document in DB");
                ApiError::new(ErrorCode::InternalError, "malformed DID document")
            })?;
            Ok(Some(doc))
        }
    }
}

/// Whether a locally cached DID document exists for `did`. A cheaper existence probe than
/// [`get_did_document`] — it never deserializes the document.
pub async fn did_document_exists(db: &SqlitePool, did: &str) -> Result<bool, ApiError> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM did_documents WHERE did = ? LIMIT 1")
        .bind(did)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to check DID document");
            ApiError::new(ErrorCode::InternalError, "failed to check DID document")
        })?;

    Ok(row.is_some())
}

/// Fetch all handles for a DID and assemble them into `at://<handle>` form,
/// suitable for a DID document's `alsoKnownAs` array.
///
/// The order follows the `handles` table's natural row order. Returns an empty
/// vec when the DID has no handles.
pub async fn fetch_also_known_as(db: &SqlitePool, did: &str) -> Result<Vec<String>, ApiError> {
    let handles: Vec<(String,)> = sqlx::query_as("SELECT handle FROM handles WHERE did = ?")
        .bind(did)
        .fetch_all(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to fetch handles for alsoKnownAs update");
            ApiError::new(ErrorCode::InternalError, "failed to update DID document")
        })?;

    Ok(handles
        .into_iter()
        .map(|(h,)| format!("at://{h}"))
        .collect())
}

/// Rewrite an existing cached DID document row with a freshly-resolved document.
///
/// UPDATE-only (never inserts): `did_documents` is a persistent store with no TTL, so writing a
/// row for a DID this server doesn't host would create an entry nothing ever refreshes again — the
/// exact serve-forever-stale failure the force-refresh path exists to heal. Only rows that already
/// exist (this server's own and migrated-in accounts) are rewritten. Returns whether a row was
/// updated (`false` = the DID wasn't cached, so there was nothing to heal).
pub async fn rewrite_did_document(
    db: &SqlitePool,
    did: &str,
    document: &serde_json::Value,
) -> Result<bool, ApiError> {
    let doc_str = serde_json::to_string(document).map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to serialize DID document for cache rewrite");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;

    let result = sqlx::query(
        "UPDATE did_documents SET document = ?, updated_at = datetime('now') WHERE did = ?",
    )
    .bind(&doc_str)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error rewriting cached DID document");
        ApiError::new(ErrorCode::InternalError, "failed to update DID document")
    })?;

    Ok(result.rows_affected() > 0)
}

/// Upsert the locally-cached DID document for `did`: insert a fresh row, or refresh an existing
/// one in place. Unlike [`rewrite_did_document`] (UPDATE-only, heals a row this server already
/// caches), this is the write path for a document a route has just authored or freshly resolved
/// and may be caching for the first time — account creation/migration, a repo signing-key
/// rotation, a submitted PLC operation, and a handle swap's PLC cache refresh all need the
/// INSERT branch for a DID with no prior row. Generic over the executor so a caller already
/// inside a transaction (account creation, handle swap) can run it without a second connection
/// acquisition.
pub async fn upsert_did_document<'e, E>(
    executor: E,
    did: &str,
    document: &serde_json::Value,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let doc_str = serde_json::to_string(document).map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to serialize DID document for cache upsert");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;

    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET document = excluded.document, updated_at = datetime('now')",
    )
    .bind(did)
    .bind(&doc_str)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error upserting cached DID document");
        ApiError::new(ErrorCode::InternalError, "failed to store DID document")
    })?;

    Ok(())
}

/// Fetch the DID document to serve for a Custos-hosted `did:web` account, gated on the opt-in.
///
/// Returns `Some(document)` only when the account for `did` exists, has managed did:web hosting
/// enabled (`did_web_hosting_enabled_at IS NOT NULL`), is in an active lifecycle (not deactivated,
/// suspended, or taken down — the same all-NULL gate as every other serving path), and has a stored
/// document. Any of those failing yields `None`, so the `.well-known/did.json` route 404s a host
/// that isn't opted in exactly as it does an unknown one — no existence oracle for the opt-in state.
///
/// The caller is responsible for having mapped the request host to `did:web:{host}`; this query does
/// not itself constrain the DID method, but a `did:plc` account never sets the opt-in column, so it
/// can never be served here.
pub async fn serve_hosted_did_document(
    db: &SqlitePool,
    did: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT d.document \
         FROM accounts a \
         JOIN did_documents d ON d.did = a.did \
         WHERE a.did = ? \
           AND a.did_web_hosting_enabled_at IS NOT NULL \
           AND a.deactivated_at IS NULL \
           AND a.suspended_at IS NULL \
           AND a.taken_down_at IS NULL \
         LIMIT 1",
    )
    .bind(did)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error fetching hosted DID document");
        ApiError::new(ErrorCode::InternalError, "failed to load DID document")
    })?;

    match row {
        None => Ok(None),
        Some((doc_str,)) => {
            let doc = serde_json::from_str(&doc_str).map_err(|e| {
                let preview = &doc_str[..doc_str.len().min(500)];
                tracing::error!(did = %did, error = %e, raw = %preview, "malformed hosted DID document in DB");
                ApiError::new(ErrorCode::InternalError, "malformed DID document")
            })?;
            Ok(Some(doc))
        }
    }
}

/// Enable or disable Custos-managed did:web hosting for an account.
///
/// Sets `did_web_hosting_enabled_at` to the current time (enable) or `NULL` (disable). Status is
/// derived from the column, so disabling stops the serve path immediately. Returns whether a row was
/// updated (`false` = no such account). The caller enforces the business preconditions (the account
/// is a `did:web` identity with a stored document) before enabling.
pub async fn set_did_web_hosting(
    db: &SqlitePool,
    did: &str,
    enabled: bool,
) -> Result<bool, ApiError> {
    let sql = if enabled {
        "UPDATE accounts SET did_web_hosting_enabled_at = datetime('now'), updated_at = datetime('now') WHERE did = ?"
    } else {
        "UPDATE accounts SET did_web_hosting_enabled_at = NULL, updated_at = datetime('now') WHERE did = ?"
    };

    let result = sqlx::query(sql).bind(did).execute(db).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error toggling did:web hosting");
        ApiError::new(ErrorCode::InternalError, "failed to update did:web hosting")
    })?;

    Ok(result.rows_affected() > 0)
}

/// Whether Custos-managed did:web hosting is currently enabled for an account.
///
/// A cheap probe over the derived opt-in state (`did_web_hosting_enabled_at IS NOT NULL`); `false`
/// when the account doesn't exist or hosting is off.
pub async fn did_web_hosting_enabled(db: &SqlitePool, did: &str) -> Result<bool, ApiError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM accounts WHERE did = ? AND did_web_hosting_enabled_at IS NOT NULL LIMIT 1",
    )
    .bind(did)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error checking did:web hosting state");
        ApiError::new(ErrorCode::InternalError, "failed to check did:web hosting")
    })?;

    Ok(row.is_some())
}

/// Update the `alsoKnownAs` array in a DID document.
///
/// Fetches the current document, replaces the `alsoKnownAs` field, and writes it back.
/// Returns `Ok(false)` if no document exists for the DID, `Ok(true)` on success.
pub async fn update_also_known_as(
    db: &SqlitePool,
    did: &str,
    also_known_as: &[String],
) -> Result<bool, ApiError> {
    let doc = match get_did_document(db, did).await? {
        Some(doc) => doc,
        None => return Ok(false),
    };

    let mut doc = doc;
    doc["alsoKnownAs"] = serde_json::json!(also_known_as);

    let doc_str = serde_json::to_string(&doc).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize DID document");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;

    sqlx::query(
        "UPDATE did_documents SET document = ?, updated_at = datetime('now') WHERE did = ?",
    )
    .bind(&doc_str)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error updating DID document alsoKnownAs");
        ApiError::new(ErrorCode::InternalError, "failed to update DID document")
    })?;

    Ok(true)
}

/// Insert a DID document row directly into `did_documents`, bypassing any resolution.
///
/// `did_documents` has no FK to `accounts`, so this can be used without a corresponding
/// account row. Lives here (not `routes::test_utils`) so `auth::permission_sets`'s tests can
/// depend on it without `auth/` importing from `routes/`; re-exported from
/// `routes::test_utils` for existing route test call sites.
#[cfg(test)]
pub(crate) async fn seed_did_document(db: &SqlitePool, did: &str, document: serde_json::Value) {
    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(document.to_string())
    .execute(db)
    .await
    .expect("insert did_document");
}
