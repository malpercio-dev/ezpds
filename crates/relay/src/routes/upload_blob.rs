// pattern: Imperative Shell
//
// Gathers: raw request body, AppState, AuthenticatedUser
// Processes: size check → store_blob on filesystem → insert_blob metadata into SQLite
// Returns: JSON { blob: { $type, ref, mimeType, size } }
//
// Implements: POST /xrpc/com.atproto.repo.uploadBlob

use axum::{body::Body, extract::State, http::StatusCode, response::Json};
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
    body: Body,
) -> Result<(StatusCode, Json<UploadBlobResponse>), ApiError> {
    // 1. Read the full request body, enforcing max size.
    let max_size = state.config.blobs.max_blob_size as usize;
    let bytes = collect_body_with_limit(body, max_size).await?;

    // 2. Store blob on filesystem (CID computation + MIME detection + write).
    let stored = blob_store::store_blob(&state.config.data_dir, &bytes).map_err(|e| {
        tracing::error!(error = %e, "failed to store blob on filesystem");
        ApiError::new(ErrorCode::InternalError, "failed to store blob")
    })?;

    // 3. Compute temp_until = now + 6 hours.
    let temp_until = chrono::Utc::now() + chrono::Duration::hours(6);
    let temp_until_str = temp_until.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // 4. Insert blob metadata into SQLite.
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

    // 5. Build response.
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
/// Uses `axum::body::to_bytes` with a buffer that grows up to the limit.
/// Returns `PayloadTooLarge` (413) if the body exceeds `max_bytes`.
async fn collect_body_with_limit(body: Body, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = axum::body::to_bytes(body, max_bytes).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("length") || msg.contains("limit") || msg.contains("too large") {
            ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("blob exceeds maximum size of {max_bytes} bytes"),
            )
        } else {
            tracing::error!(error = %e, "failed to read request body");
            ApiError::new(ErrorCode::InternalError, "failed to read request body")
        }
    })?;

    // axum::body::to_bytes doesn't enforce a hard limit — it just pre-allocates up to
    // the hint. Check the actual size after collection.
    if bytes.len() > max_bytes {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!("blob exceeds maximum size of {max_bytes} bytes"),
        ));
    }

    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::auth::jwt::issue_access_jwt;
    use crate::routes::test_utils::body_json;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::ServiceExt;

    fn app_with_state(state: AppState) -> Router {
        Router::new()
            .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
            .with_state(state)
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

        // Seed an account so the FK on account_did is satisfied.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:uploadtest', 'up@test.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        // Issue a valid HS256 access JWT (exp = now + 2h).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = issue_access_jwt(
            &state.jwt_secret,
            "did:plc:uploadtest",
            &state.config.public_url,
            now,
        )
        .unwrap();

        // PNG magic bytes.
        let png_bytes: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];

        let response = app_with_state(state.clone())
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

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:uploadtest2', 'up2@test.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = issue_access_jwt(
            &state.jwt_secret,
            "did:plc:uploadtest2",
            &state.config.public_url,
            now,
        )
        .unwrap();

        let response = app_with_state(state.clone())
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
}
