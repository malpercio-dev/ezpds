// pattern: Imperative Shell
//
// Gathers: query params (did, cid), AppState
// Processes: look up blob metadata via the DID's ownership row → read blob from filesystem
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
    // 1. Look up blob metadata by CID, scoped to the requested DID's ownership rows
    //    (`blob_owners` — the same content may be owned by several accounts). A missing CID
    //    and a CID owned only by another DID return the same generic 404, so an attacker
    //    cannot enumerate which CIDs exist on the server.
    let blob = blobs::get_owned_blob(&state.db, &params.did, &params.cid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, cid = %params.cid, "failed to query blob metadata");
            ApiError::new(ErrorCode::InternalError, "failed to query blob metadata")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "blob not found"))?;

    // 2. Read blob content from filesystem.
    let content = blob_store::read_blob(&state.config.data_dir, &blob.storage_path)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                cid = %params.cid,
                path = %blob.storage_path,
                "failed to read blob from filesystem"
            );
            ApiError::new(ErrorCode::InternalError, "failed to read blob")
        })?;

    // 3. Build response with the stored Content-Type, hardened against a stored-XSS vector.
    //    A blob's type is client-controlled (an uploader can declare image/svg+xml, which
    //    browsers execute script from) and this endpoint is same-origin with the OAuth/landing
    //    surface, so a rendered blob could script that origin. `default-src 'none'; sandbox`
    //    neutralizes any script if the blob is navigated to as a document, and `nosniff` stops
    //    a declared image/* being sniffed into HTML — matching the reference PDS's blob headers.
    //    (Embedding via `<img>` is unaffected: the CSP only binds the blob as a top-level
    //    document, not as a sub-resource.)
    let content_type = if blob.mime_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        blob.mime_type
    };

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
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

        crate::db::blobs::insert_blob(
            &state.db,
            cid,
            did,
            mime_type,
            17, // len of "test blob content"
            &storage_path,
            "2030-01-01 00:00:00",
        )
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

    /// Blob responses carry hardening headers so a client-controlled active type (e.g.
    /// image/svg+xml) can't execute as stored XSS on this same-origin endpoint.
    #[tokio::test]
    async fn serves_content_security_and_nosniff_headers() {
        let state = test_state().await;
        seed_blob(
            &state,
            "did:plc:svgserve",
            "bafkreisvgserve",
            "image/svg+xml",
        )
        .await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:svgserve&cid=bafkreisvgserve")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "image/svg+xml"
        );
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            "default-src 'none'; sandbox"
        );
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
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

    /// A blob uploaded by two accounts is served for both DIDs: ownership is per-account
    /// (`blob_owners`), not a single-owner column on the physical row.
    #[tokio::test]
    async fn shared_blob_is_served_for_every_owner() {
        let state = test_state().await;
        seed_blob(&state, "did:plc:sharefirst", "bafkreishared", "image/png").await;

        // A second account uploads the same bytes: same CID, same file, its own ownership row.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:sharesecond', 'blob2@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::blobs::insert_blob(
            &state.db,
            "bafkreishared",
            "did:plc:sharesecond",
            "image/png",
            17,
            "blobs/ba/bafkreishared",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        for did in ["did:plc:sharefirst", "did:plc:sharesecond"] {
            let response = app_with_state(state.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/xrpc/com.atproto.sync.getBlob?did={did}&cid=bafkreishared"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "owner {did} must be served"
            );
        }
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
