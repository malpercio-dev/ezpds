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
use crate::db::blobs;
use crate::{auth::oauth_scopes, blob_store};

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

    // Capture the client-declared blob type before the body is consumed. The reference PDS
    // records this `Content-Type` (reconciled against a content sniff) rather than sniffing
    // alone, so formats without magic bytes (SVG, JSON, VTT) keep their real type.
    let declared_content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

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

    if !user.scope.is_access() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    // 2. Read the full request body, enforcing max size.
    let bytes = collect_body_with_limit(request.into_body(), max_size).await?;
    // Resolve the stored MIME type from the declared Content-Type reconciled against a content
    // sniff (blob_store::resolve_mime_type). The same value gates the granular blob-scope check,
    // is persisted, and is served back by getBlob — so a `blob:image/*` token accepts a
    // legitimate SVG avatar instead of being rejected against a sniff-only octet-stream.
    let mime_type = blob_store::resolve_mime_type(declared_content_type.as_deref(), &bytes);
    if user.scope == crate::auth::jwt::AuthScope::Access {
        oauth_scopes::require_blob(&user.scope_claim, &mime_type)?;
    }

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

    // 4. Store blob on filesystem (CID computation + write); persist the resolved MIME type.
    let stored = blob_store::store_blob(&state.config.data_dir, &bytes, &mime_type)
        .await
        .map_err(|e| {
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

    // An agent-attributed upload records its audit row before the success response: the audit
    // trail is the accountability guarantee, so a failure here fails the request (the stored
    // blob is content-addressed — a retry is an idempotent duplicate-CID upload).
    if let Some(registration_id) = user.registration_id.as_deref() {
        let detail = serde_json::json!({
            "cid": stored.cid,
            "mime_type": stored.mime_type,
            "size": stored.size_bytes,
        })
        .to_string();
        crate::db::agent_audit::insert_agent_audit_event(
            &state.db,
            &uuid::Uuid::new_v4().to_string(),
            registration_id,
            Some(&user.did),
            crate::db::agent_audit::AgentAuditEventType::BlobUpload,
            Some(&detail),
        )
        .await?;
    }

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
        issue_test_jwt_with_scope(state, did, "com.atproto.access")
    }

    fn issue_test_jwt_with_scope(state: &AppState, did: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": scope,
                "sub": did,
                "aud": state.config.public_url,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(&state.jwt_secret),
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

    /// An agent-derived upload records a `blob_upload` audit row attributed to its
    /// `registration_id`, carrying only mechanical facts (cid/mime/size).
    #[tokio::test]
    async fn agent_upload_writes_attributed_audit_row() {
        let state = test_state().await;
        seed_account(&state, "did:plc:agentblobaudit").await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_blob_audit', 'did:plc:agentblobaudit', 'service_auth', '[]', \
                     '2099-01-01 00:00:00', 'claimed', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let jwt = crate::routes::test_utils::agent_jwt(
            &state.jwt_secret,
            "did:plc:agentblobaudit",
            "com.atproto.access",
            "reg_blob_audit",
        );

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

        let events =
            crate::db::agent_audit::list_agent_audit_events(&state.db, "reg_blob_audit", None, 10)
                .await
                .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "blob_upload");
        let detail = events[0].detail.as_deref().unwrap();
        assert!(detail.contains("image/png"), "detail: {detail}");
        assert!(detail.contains("\"size\":10"), "detail: {detail}");
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

    #[tokio::test]
    async fn granular_blob_scope_is_enforced_by_mime_type() {
        let state = test_state().await;
        seed_account(&state, "did:plc:blobscope").await;
        let repo_only_jwt = issue_test_jwt_with_scope(
            &state,
            "did:plc:blobscope",
            "atproto repo:app.bsky.feed.post?action=create",
        );

        let denied = app_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {repo_only_jwt}"))
                    .body(Body::from(vec![
                        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let body = body_json(denied).await;
        assert_eq!(body["error"]["code"], "InsufficientScope");

        let image_jwt =
            issue_test_jwt_with_scope(&state, "did:plc:blobscope", "atproto blob:image/*");
        let allowed = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {image_jwt}"))
                    .body(Body::from(vec![
                        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    /// A `blob:image/*` token may upload an SVG avatar: the declared `Content-Type` is honored
    /// (SVG has no magic bytes), so the scope check sees `image/svg+xml`, not `octet-stream`.
    #[tokio::test]
    async fn svg_upload_with_image_scope_uses_declared_content_type() {
        let state = test_state().await;
        seed_account(&state, "did:plc:svgblob").await;
        let image_jwt =
            issue_test_jwt_with_scope(&state, "did:plc:svgblob", "atproto blob:image/*");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {image_jwt}"))
                    .header("content-type", "image/svg+xml")
                    .body(Body::from(
                        b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_vec(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["blob"]["mimeType"], "image/svg+xml");
    }

    /// An unsniffable format (JSON) keeps its declared `Content-Type` in the stored metadata.
    #[tokio::test]
    async fn declared_content_type_recorded_for_unsniffable_content() {
        let state = test_state().await;
        seed_account(&state, "did:plc:jsonblob").await;
        let jwt = issue_test_jwt(&state, "did:plc:jsonblob");

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(b"{\"hello\":\"world\"}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["blob"]["mimeType"], "application/json");
    }

    /// A confident binary sniff overrides a mismatched declared type: PNG bytes announced as
    /// `text/html` are stored as `image/png`, so the blob can never be served as HTML.
    #[tokio::test]
    async fn binary_sniff_overrides_mismatched_content_type() {
        let state = test_state().await;
        seed_account(&state, "did:plc:lyingblob").await;
        let jwt = issue_test_jwt(&state, "did:plc:lyingblob");

        let png_bytes: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.uploadBlob")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "text/html")
                    .body(Body::from(png_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["blob"]["mimeType"], "image/png");
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
