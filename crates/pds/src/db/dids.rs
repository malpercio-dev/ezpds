// pattern: Imperative Shell
//
// DID document lookup queries against the did_documents table.
// Returns plain data structs; no business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};
use sqlx::SqlitePool;

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
