// pattern: Imperative Shell
//
// Gathers: query params (did, cid), AppState
// Processes: look up blob metadata by CID → verify DID ownership → read blob from filesystem
// Returns: raw blob bytes with Content-Type header
//
// Implements: GET /xrpc/com.atproto.sync.getBlob

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::blob_store;
use crate::db::blobs;

// ── Query parameters ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetBlobParams {
    pub did: String,
    pub cid: String,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// GET /xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>
///
/// Serves blob content by CID. No authentication required.
/// Validates that the blob belongs to the specified DID's repo.
pub async fn get_blob(
    State(state): State<AppState>,
    Query(params): Query<GetBlobParams>,
) -> Result<Response, ApiError> {
    // 1. Look up blob metadata by CID.
    let blob = blobs::get_blob_by_cid(&state.db, &params.cid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, cid = %params.cid, "failed to query blob metadata");
            ApiError::new(ErrorCode::InternalError, "failed to query blob metadata")
        })?
        .ok_or_else(|| {
            // Generic message: do not confirm whether a CID exists.
            ApiError::new(ErrorCode::NotFound, "blob not found")
        })?;

    // 2. Verify DID ownership — blob must belong to the specified DID's repo.
    // Same 404 as above to prevent CID enumeration: an attacker must not be able
    // to distinguish "CID doesn't exist" from "CID exists but belongs to another DID".
    if blob.account_did != params.did {
        return Err(ApiError::new(ErrorCode::NotFound, "blob not found"));
    }

    // 3. Read blob content from filesystem.
    let content =
        blob_store::read_blob(&state.config.data_dir, &blob.storage_path).map_err(|e| {
            tracing::error!(
                error = %e,
                cid = %params.cid,
                path = %blob.storage_path,
                "failed to read blob from filesystem"
            );
            ApiError::new(ErrorCode::InternalError, "failed to read blob")
        })?;

    // 4. Build response with correct Content-Type.
    // Use the stored MIME type string directly; fall back to application/octet-stream
    // if somehow empty (shouldn't happen with current blob_store logic).
    let content_type = if blob.mime_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        blob.mime_type
    };

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        Body::from(content),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::routes::test_utils::body_json;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    fn app_with_state(state: AppState) -> Router {
        Router::new()
            .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
            .with_state(state)
    }

    /// Helper: seed an account and a blob for testing.
    async fn seed_blob(state: &AppState, did: &str, cid: &str, mime_type: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'blob@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        // Write a real file to the filesystem.
        let prefix = &cid[..2.min(cid.len())];
        let storage_path = format!("blobs/{prefix}/{cid}");
        let abs_path = state.config.data_dir.join(&storage_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        std::fs::write(&abs_path, b"test blob content").unwrap();

        sqlx::query(
            "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, temp_until) \
             VALUES (?, ?, ?, ?, ?, NULL)",
        )
        .bind(cid)
        .bind(did)
        .bind(mime_type)
        .bind(17i64) // len of "test blob content"
        .bind(&storage_path)
        .execute(&state.db)
        .await
        .unwrap();
    }

    /// Happy path: returns blob content with correct MIME type.
    #[tokio::test]
    async fn returns_blob_with_correct_mime_type() {
        let state = test_state().await;
        seed_blob(&state, "did:plc:test1", "bafkreitest123", "image/png").await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:test1&cid=bafkreitest123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "image/png");

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"test blob content");
    }

    /// Non-existent blob returns 404.
    #[tokio::test]
    async fn nonexistent_blob_returns_404() {
        let state = test_state().await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:none&cid=bafkreinoexist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    /// DID mismatch returns 404 (same as not found — prevents CID enumeration).
    #[tokio::test]
    async fn did_mismatch_returns_404() {
        let state = test_state().await;
        seed_blob(&state, "did:plc:owner", "bafkreimismatch", "image/jpeg").await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:other&cid=bafkreimismatch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "NOT_FOUND");
        // Error message must not leak CID or DID.
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(
            !msg.contains("bafkreimismatch"),
            "message must not leak CID"
        );
        assert!(!msg.contains("did:plc:"), "message must not leak DID");
    }

    /// Missing query params returns 400.
    #[tokio::test]
    async fn missing_params_returns_400() {
        let state = test_state().await;

        // Missing cid
        let response = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Missing did
        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?cid=bafktest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
