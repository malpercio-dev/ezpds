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
