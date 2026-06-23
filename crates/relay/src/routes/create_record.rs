// pattern: Imperative Shell

//! com.atproto.repo.createRecord - Create a new record in a repository.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

/// Base32-sortable alphabet for TID encoding.
const BASE32_SORTABLE: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

#[derive(Deserialize)]
pub struct CreateRecordBody {
    /// The DID of the repo (e.g. "did:plc:abc123").
    repo: String,
    /// The NSID of the record collection (e.g. "app.bsky.feed.post").
    collection: String,
    /// Optional record key. Auto-generated TID if not provided.
    #[serde(default)]
    rkey: Option<String>,
    /// The record data as a JSON object.
    record: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRecordResponse {
    uri: String,
    cid: String,
}

/// Generate a Timestamp Identifier (TID) for ATProto record keys.
///
/// A TID is a 64-bit integer encoded as a 13-character base32-sortable string:
/// - Bit 0 (MSB): Always 0
/// - Bits 1-52: Microseconds since UNIX epoch
/// - Bits 53-63: Random 10-bit clock identifier
fn generate_tid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    let micros = now.as_micros() as u64;

    // Random 10-bit clock identifier for collision resistance.
    let clock_id: u64 = (OsRng.next_u32() & 0x3FF) as u64;

    // Compose the 64-bit integer: 0 | micros (52 bits) | clock_id (10 bits)
    // Shift micros left by 10 bits to make room for clock_id.
    let tid_int: u64 = (micros << 10) | clock_id;

    // Encode as 13-character base32-sortable string.
    let mut chars = [0u8; 13];
    for i in (0..13).rev() {
        let idx = (tid_int >> (i * 5)) & 0x1F;
        chars[12 - i] = BASE32_SORTABLE[idx as usize];
    }

    String::from_utf8(chars.to_vec()).expect("base32 encoding is always valid ASCII")
}

/// POST /xrpc/com.atproto.repo.createRecord
///
/// Create a new record in the repository. If `rkey` is not provided, a TID is
/// auto-generated.
pub async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreateRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &body.repo;
    let collection = &body.collection;
    let rkey = body.rkey.unwrap_or_else(generate_tid);

    // Validate DID format.
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Authenticate: require a valid access token whose subject owns this repo.
    let token = crate::auth::extract_bearer_token(&headers)?;
    let claims = crate::auth::jwt::verify_access_token(token, &state)?;
    if claims.sub != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }

    // Reject a malformed collection/rkey before touching the repo.
    repo_engine::validate_record_path(collection, &rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    // Look up the repo root CID.
    let root_cid_str: Option<String> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to create record")
            })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to create record")
    })?;

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to create record")
    })?;

    // Sign the commit with this account's published #atproto signing key.
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signer =
        crate::routes::get_repo_signing_key::load_repo_signer(&state.db, did, master_key).await?;

    // Build the MST key: collection/rkey
    let mst_key = format!("{collection}/{rkey}");

    // Write the record (JSON is converted to the ATProto data model: $link → CID,
    // $bytes → byte string, floats rejected).
    let record_cid = repo_engine::put_record_json(&mut repo, &signer, &mst_key, &body.record)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to create record");
            match e {
                repo_engine::RecordError::InvalidRecord(_) => {
                    ApiError::new(ErrorCode::InvalidClaim, "invalid record")
                }
                _ => ApiError::new(ErrorCode::InternalError, "failed to create record"),
            }
        })?;

    // Advance the repo root with optimistic concurrency: only if it hasn't moved
    // since we read it. If a concurrent write advanced it first, that write wins and
    // we return 409 so the client retries against the new root (rather than silently
    // clobbering the other commit). The new blocks we wrote are orphaned and GC-able.
    let new_root = repo.root().to_string();
    let updated =
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ? AND repo_root_cid = ?")
            .bind(&new_root)
            .bind(did)
            .bind(&root_cid_str)
            .execute(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to update repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to create record")
            })?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    // Best-effort GC: reclaim blocks superseded by this commit. A GC failure must not
    // fail the write — the commit is durable; orphaned blocks are harmless until swept.
    if let Err(e) = crate::routes::get_repo::gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

    let uri = format!("at://{did}/{collection}/{rkey}");
    Ok((
        StatusCode::OK,
        axum::Json(CreateRecordResponse {
            uri,
            cid: record_cid.to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{seed_account_with_repo, state_with_master_key};

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:createrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.access",
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn create_record_without_auth_returns_401() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "hello"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_record_wrong_did_returns_403() {
        let (state, did) = setup_account_with_repo().await;
        let other_token = access_jwt(&state.jwt_secret, "did:plc:someoneelse");
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {other_token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "hello"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_record_with_explicit_rkey_returns_uri_and_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Hello, ATProto!",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "mykey1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.uri, format!("at://{did}/app.bsky.feed.post/mykey1"));
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn create_record_auto_generates_tid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "auto rkey"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        // URI should contain a 13-char TID as the rkey.
        let parts: Vec<&str> = resp.uri.split('/').collect();
        let auto_rkey = parts.last().unwrap();
        assert_eq!(
            auto_rkey.len(),
            13,
            "auto-generated rkey should be a 13-char TID"
        );
        assert!(
            auto_rkey
                .chars()
                .all(|c| "234567abcdefghijklmnopqrstuvwxyz".contains(c)),
            "auto-generated rkey should use base32-sortable chars"
        );
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn create_record_invalid_collection_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "notanid",
                    "record": {"text": "x"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_record_with_float_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Floats are not part of the ATProto data model.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"score": 1.5}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_record_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nonexistent");
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": "did:plc:nonexistent",
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "test"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_record_retrievable_via_get_record() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Created and retrievable",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        // Create the record.
        let create_request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "retrievable1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        // Now retrieve it via getRecord.
        let get_request = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=retrievable1"
            ))
            .body(Body::empty())
            .unwrap();

        let get_response = app.oneshot(get_request).await.unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            resp["uri"],
            format!("at://{did}/app.bsky.feed.post/retrievable1")
        );
        assert_eq!(resp["value"]["text"], "Created and retrievable");
    }

    #[test]
    fn generate_tid_produces_valid_format() {
        let tid = generate_tid();
        assert_eq!(tid.len(), 13);
        assert!(
            tid.chars()
                .all(|c| "234567abcdefghijklmnopqrstuvwxyz".contains(c)),
            "TID should use base32-sortable alphabet"
        );
        // First char must be in [234567abcdefghij]
        assert!(
            "234567abcdefghij".contains(tid.chars().next().unwrap()),
            "first TID char must be in valid range"
        );
    }

    #[test]
    fn generate_tids_are_monotonically_increasing() {
        let tid1 = generate_tid();
        // Small delay to ensure different timestamp.
        std::thread::sleep(std::time::Duration::from_micros(100));
        let tid2 = generate_tid();
        assert!(tid1 < tid2, "TIDs should be monotonically increasing");
    }
}
