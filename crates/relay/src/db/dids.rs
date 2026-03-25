// pattern: Imperative Shell
//
// DID document lookup. Returns a parsed JSON document from the did_documents table.
// No business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};

/// Look up a locally cached DID document by DID string.
///
/// Returns `None` when no row exists for the given DID; `Err` only on DB errors.
pub(crate) async fn get_did_document(
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
                tracing::error!(did = %did, error = %e, "malformed DID document in DB");
                ApiError::new(ErrorCode::InternalError, "malformed DID document")
            })?;
            Ok(Some(doc))
        }
    }
}
