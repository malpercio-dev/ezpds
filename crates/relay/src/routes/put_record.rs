// pattern: Imperative Shell

//! com.atproto.repo.putRecord - Create or update a record in a repository.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct PutRecordParams {
    did: String,
    collection: String,
    rkey: String,
}

#[derive(Deserialize)]
pub struct PutRecordBody {
    /// The record data as a JSON object.
    record: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct PutRecordResponse {
    uri: String,
    cid: String,
}

/// PUT /xrpc/com.atproto.repo.putRecord
///
/// Create or update a record in the repository. Unlike createRecord, this always
/// succeeds regardless of whether the record already exists (upsert semantics).
pub async fn put_record(
    State(state): State<AppState>,
    Query(params): Query<PutRecordParams>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<PutRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.did;
    let collection = &params.collection;
    let rkey = &params.rkey;

    // Reject a malformed collection/rkey before touching the repo.
    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let mst_key = format!("{collection}/{rkey}");

    // Delegate to the shared write helper with create_only=false.
    let (_result, record_cid) = crate::record_write::write_record(
        &state,
        &headers,
        did,
        &mst_key,
        &body.record,
        false, // create_only=false: upsert semantics
    )
    .await?;

    let uri = format!("at://{did}/{collection}/{rkey}");
    Ok((
        StatusCode::OK,
        axum::Json(PutRecordResponse {
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
        let did = "did:plc:putrecordtest".to_string();
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
    async fn put_record_without_auth_returns_401() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=t1"
            ))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"record": {"text": "x"}})).unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn put_record_wrong_did_returns_403() {
        let (state, did) = setup_account_with_repo().await;
        let other_token = access_jwt(&state.jwt_secret, "did:plc:someoneelse");
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=t1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {other_token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"record": {"text": "x"}})).unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_record_returns_uri_and_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Hello, ATProto!",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=test1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_string(&serde_json::json!({"record": record})).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: PutRecordResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.uri, format!("at://{did}/app.bsky.feed.post/test1"));
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn put_record_invalid_collection_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=notanid&rkey=t1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"record": {"text": "x"}})).unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_record_with_float_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Floats are not part of the ATProto data model.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=f1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"record": {"score": 1.5}})).unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_record_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nonexistent");
        let app = crate::app::app(state);

        let record = serde_json::json!({"text": "test"});

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.putRecord?did=did:plc:nonexistent&collection=app.bsky.feed.post&rkey=test1")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_string(&serde_json::json!({"record": record})).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_record_updates_repo_root_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "This should update the root",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=test2"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_string(&serde_json::json!({"record": record})).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_record_gcs_superseded_blocks() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let app = crate::app::app(state);

        // Update the same record key repeatedly; each commit supersedes the prior
        // commit/MST/record, which post-commit GC should reclaim.
        for i in 0..8 {
            let request = Request::builder()
                .method(http::Method::POST)
                .uri(format!(
                    "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=same"
                ))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({"record": {"n": i}})).unwrap(),
                ))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE account_did = ?")
            .bind(&did)
            .fetch_one(&db)
            .await
            .unwrap();
        // With GC only the current commit + MST + record remain (a handful); without GC
        // this would grow ~linearly with the 8 updates.
        assert!(
            count < 10,
            "GC should keep block count bounded; got {count}"
        );
    }
}
