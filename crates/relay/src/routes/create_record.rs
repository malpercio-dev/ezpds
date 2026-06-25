// pattern: Imperative Shell

//! com.atproto.repo.createRecord - Create a new record in a repository.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct CreateRecordBody {
    /// The DID of the repo (e.g. "did:plc:abc123").
    repo: String,
    /// The NSID of the record collection (e.g. "app.bsky.feed.post").
    collection: String,
    /// Optional record key. Auto-generated TID if not provided or empty.
    rkey: Option<String>,
    /// The record data as a JSON object.
    record: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRecordResponse {
    uri: String,
    cid: String,
}

/// POST /xrpc/com.atproto.repo.createRecord
///
/// Create a new record in the repository. If `rkey` is not provided (or is empty),
/// a TID is auto-generated. Returns 409 if the rkey already exists.
pub async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreateRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &body.repo;
    let collection = &body.collection;
    // Treat empty string as "absent" — generate a TID.
    let rkey = body
        .rkey
        .filter(|r| !r.is_empty())
        .unwrap_or_else(repo_engine::generate_tid);

    // Reject a malformed collection/rkey before touching the repo.
    repo_engine::validate_record_path(collection, &rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let mst_key = format!("{collection}/{rkey}");

    // Delegate to the shared write helper with create_only=true.
    let (_result, record_cid) = crate::record_write::write_record(
        &state,
        &headers,
        did,
        &mst_key,
        &body.record,
        true, // create_only: reject if record already exists
    )
    .await?;

    let uri = format!("at://{did}/{collection}/{rkey}");
    Ok((
        axum::http::StatusCode::OK,
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
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, state_with_master_key};

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:createrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
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
    async fn create_record_empty_rkey_generates_tid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Explicit empty string should be treated as "absent".
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "",
                    "record": {"text": "empty rkey"}
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

        // Should have auto-generated a TID, not failed with 400.
        let parts: Vec<&str> = resp.uri.split('/').collect();
        let auto_rkey = parts.last().unwrap();
        assert_eq!(auto_rkey.len(), 13);
    }

    #[tokio::test]
    async fn create_record_duplicate_rkey_returns_409() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "first version",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        // Create the record first.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "duplicate1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Try to create again with the same rkey — should fail with 409.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "duplicate1",
                    "record": {"text": "second version"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
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
        let tid = repo_engine::generate_tid();
        let alphabet = "234567abcdefghijklmnopqrstuvwxyz";
        assert_eq!(tid.len(), 13);
        assert!(
            tid.chars().all(|c| alphabet.contains(c)),
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
        let tid1 = repo_engine::generate_tid();
        // Small delay to ensure different timestamp.
        std::thread::sleep(std::time::Duration::from_micros(100));
        let tid2 = repo_engine::generate_tid();
        assert!(tid1 < tid2, "TIDs should be monotonically increasing");
    }
}
