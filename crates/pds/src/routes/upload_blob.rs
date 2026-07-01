// pattern: Imperative Shell
//
// Gathers: raw request body, AppState, AuthenticatedUser
// Processes: size check → store_blob on filesystem → insert_blob metadata into SQLite
// Returns: JSON { blob: { $type, ref, mimeType, size } }
//
// Implements: POST /xrpc/com.atproto.repo.uploadBlob

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Json,
};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::blob_store;
use crate::db::blobs;

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobRef {
    #[serde(rename = "$link")]
    pub link: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobMetadata {
    #[serde(rename = "$type")]
    pub blob_type: String,
    #[serde(rename = "ref")]
    pub blob_ref: BlobRef,
    pub mime_type: String,
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadBlobResponse {
    pub blob: BlobMetadata,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// POST /xrpc/com.atproto.repo.uploadBlob
///
/// Uploads a blob for later reference in records.
/// The blob is stored on the local filesystem and its metadata in SQLite.
/// New blobs are marked temporary (6h TTL) until referenced by a repo record.
pub async fn upload_blob(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    request: Request<Body>,
) -> Result<(StatusCode, Json<UploadBlobResponse>), ApiError> {
    let max_size = state.config.blobs.max_blob_size as usize;

    // 1. Fast-path rejection: check Content-Length header before reading the body.
    if let Some(content_length) = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if content_length > max_size {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("blob exceeds maximum size of {max_size} bytes"),
            ));
        }
    }

    // 2. Read the full request body, enforcing max size.
    let bytes = collect_body_with_limit(request.into_body(), max_size).await?;

    // 3. Check per-account storage quota.
    let quota = state.config.blobs.max_storage_per_account as i64;
    let used = blobs::account_storage_bytes(&state.db, &user.did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to check account storage");
            ApiError::new(ErrorCode::InternalError, "failed to check storage quota")
        })?;
    if used + bytes.len() as i64 > quota {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "account storage quota exceeded: {used} of {quota} bytes used, \
                 upload of {} bytes would exceed limit",
                bytes.len()
            ),
        ));
    }

    // 4. Store blob on filesystem (CID computation + MIME detection + write).
    let stored = blob_store::store_blob(&state.config.data_dir, &bytes).map_err(|e| {
        tracing::error!(error = %e, "failed to store blob on filesystem");
        ApiError::new(ErrorCode::InternalError, "failed to store blob")
    })?;

    // 5. Compute temp_until = now + the configured grace TTL. Until a repo record
    //    references this blob, it is a garbage-collection candidate after this instant.
    //    Format must match SQLite's `datetime('now')` (`YYYY-MM-DD HH:MM:SS`): `temp_until`
    //    is compared lexicographically as TEXT, so a `T`/`Z` ISO form would sort after the
    //    space-separated form and delay collection until the calendar date advances.
    let temp_until =
        chrono::Utc::now() + chrono::Duration::seconds(state.config.blobs.temp_ttl_secs as i64);
    let temp_until_str = temp_until.format("%Y-%m-%d %H:%M:%S").to_string();

    // 6. Insert blob metadata into SQLite.
    blobs::insert_blob(
        &state.db,
        &stored.cid,
        &user.did,
        &stored.mime_type,
        stored.size_bytes as i64,
        &stored.storage_path,
        &temp_until_str,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, cid = %stored.cid, "failed to insert blob metadata");
        ApiError::new(ErrorCode::InternalError, "failed to record blob metadata")
    })?;

    tracing::info!(
        did = %user.did,
        cid = %stored.cid,
        mime = %stored.mime_type,
        size = stored.size_bytes,
        "blob uploaded"
    );

    // 7. Build response.
    Ok((
        StatusCode::OK,
        Json(UploadBlobResponse {
            blob: BlobMetadata {
                blob_type: "blob".to_string(),
                blob_ref: BlobRef { link: stored.cid },
                mime_type: stored.mime_type,
                size: stored.size_bytes,
            },
        }),
    ))
}

/// Read the request body up to `max_bytes`, returning an error if exceeded.
///
/// `axum::body::to_bytes` enforces the limit; any read error is treated as a size
/// violation (the only failure mode when the body is a simple in-memory `Bytes`).
async fn collect_body_with_limit(body: Body, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    axum::body::to_bytes(body, max_bytes)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("blob exceeds maximum size of {max_bytes} bytes"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::auth::jwt::issue_access_jwt;
    use crate::routes::test_utils::body_json;
    use axum::{body::Body, http::Request, routing::post, Router};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app_with_state(state: AppState) -> Router {
        Router::new()
            .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
            .with_state(state)
    }

    /// Helper: issue a valid HS256 JWT for the given DID using the test state's secret.
    fn issue_test_jwt(state: &AppState, did: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        issue_access_jwt(
            &state.jwt_secret,
            did,
            &state.config.public_url,
            now,
            "com.atproto.access",
        )
        .unwrap()
    }

    /// Helper: create a test state with a small max_blob_size (100 bytes).
    async fn state_with_small_blob_limit() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.blobs.max_blob_size = 100;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Helper: create a test state with a small per-account storage quota (250 bytes).
    async fn state_with_small_storage_quota() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.blobs.max_blob_size = 1000;
        config.blobs.max_storage_per_account = 250;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Helper: seed an account for blob uploads.
    async fn seed_account(state: &AppState, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'test@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
    }

    /// Unauthenticated request must return 401.
    #[tokio::test]
    async fn unauthenticated_returns_401() {
        let state = test_state().await;
        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("content-type", "application/octet-stream")
                    .body(Body::from("hello"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Authenticated upload with known magic bytes returns blob metadata.
    #[tokio::test]
    async fn upload_png_returns_blob_metadata() {
        let state = test_state().await;
        seed_account(&state, "did:plc:uploadtest").await;
        let jwt = issue_test_jwt(&state, "did:plc:uploadtest");

        // PNG magic bytes.
        let png_bytes: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(png_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["blob"]["$type"], "blob");
        assert_eq!(body["blob"]["mimeType"], "image/png");
        assert_eq!(body["blob"]["size"], 10);
        assert!(body["blob"]["ref"]["$link"]
            .as_str()
            .unwrap()
            .starts_with("bafk"));
    }

    /// Authenticated upload of unknown format gets application/octet-stream fallback.
    #[tokio::test]
    async fn upload_unknown_format_gets_octet_stream() {
        let state = test_state().await;
        seed_account(&state, "did:plc:uploadtest2").await;
        let jwt = issue_test_jwt(&state, "did:plc:uploadtest2");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(b"plain text content".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["blob"]["mimeType"], "application/octet-stream");
    }

    /// Oversized body via Content-Length header returns 413 before reading the body.
    #[tokio::test]
    async fn content_length_exceeding_limit_returns_413() {
        let state = state_with_small_blob_limit().await;
        seed_account(&state, "did:plc:toobig").await;
        let jwt = issue_test_jwt(&state, "did:plc:toobig");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-length", "999999")
                    .body(Body::from(vec![0u8; 999999]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Oversized body without Content-Length returns 413 after reading.
    #[tokio::test]
    async fn oversized_body_without_content_length_returns_413() {
        let state = state_with_small_blob_limit().await;
        seed_account(&state, "did:plc:toobig2").await;
        let jwt = issue_test_jwt(&state, "did:plc:toobig2");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(vec![0u8; 200]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Uploading the same content twice returns 200 both times (idempotent).
    #[tokio::test]
    async fn duplicate_cid_upload_is_idempotent() {
        let state = test_state().await;
        seed_account(&state, "did:plc:dup1").await;
        let jwt = issue_test_jwt(&state, "did:plc:dup1");

        let content = b"duplicate content";

        let r1 = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(content.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let body1: serde_json::Value = body_json(r1).await;
        let cid = body1["blob"]["ref"]["$link"].as_str().unwrap().to_string();

        // Second upload — same content, same CID, must succeed.
        let jwt2 = issue_test_jwt(&state, "did:plc:dup1");
        let r2 = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt2}"))
                    .body(Body::from(content.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);

        let body2: serde_json::Value = body_json(r2).await;
        assert_eq!(
            body2["blob"]["ref"]["$link"].as_str().unwrap(),
            cid,
            "same content must produce same CID"
        );
    }

    /// Upload exceeding per-account storage quota returns 413.
    #[tokio::test]
    async fn storage_quota_exceeded_returns_413() {
        let state = state_with_small_storage_quota().await;
        seed_account(&state, "did:plc:quota").await;

        // First upload: 200 bytes — fits within 250 byte quota.
        let jwt = issue_test_jwt(&state, "did:plc:quota");
        let r1 = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(vec![0xAA; 200]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        // Second upload: 100 bytes — would bring total to 300, exceeding 250.
        let jwt2 = issue_test_jwt(&state, "did:plc:quota");
        let r2 = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt2}"))
                    .body(Body::from(vec![0xBB; 100]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Empty body (0 bytes) uploads successfully.
    #[tokio::test]
    async fn empty_body_uploads_successfully() {
        let state = test_state().await;
        seed_account(&state, "did:plc:empty").await;
        let jwt = issue_test_jwt(&state, "did:plc:empty");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["blob"]["size"], 0);
        assert_eq!(body["blob"]["mimeType"], "application/octet-stream");
    }
}
