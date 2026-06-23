// pattern: Imperative Shell

//! com.atproto.repo.getRecord - Read a record from a repository.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

#[derive(Deserialize)]
pub struct GetRecordParams {
    did: String,
    collection: String,
    rkey: String,
}

/// GET /xrpc/com.atproto.repo.getRecord?did=<did>&collection=<collection>&rkey=<rkey>
///
/// Read a record from the repository.
pub async fn get_record(
    State(state): State<AppState>,
    Query(params): Query<GetRecordParams>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.did;
    let collection = &params.collection;
    let rkey = &params.rkey;

    // Validate DID format.
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Look up the repo root CID.
    let root_cid_str: Option<String> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to get record")
            })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to get record")
    })?;

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to get record")
    })?;

    // Build the MST key: collection/rkey
    let mst_key = format!("{collection}/{rkey}");

    // Read the record.
    let record: Option<serde_json::Value> = repo_engine::get_record(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to get record");
            ApiError::new(ErrorCode::InternalError, "failed to get record")
        })?;

    match record {
        Some(value) => {
            let uri = format!("at://{did}/{collection}/{rkey}");
            Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "uri": uri,
                    "value": value
                })),
            )
                .into_response())
        }
        None => Err(ApiError::new(ErrorCode::NotFound, "record not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::db::blocks::SqliteBlockStore;
    use repo_engine::{create_genesis_repo, CommitSigner};

    fn test_signer() -> (crypto::P256Keypair, CommitSigner) {
        let kp = crypto::generate_p256_keypair().expect("keypair");
        let signer = CommitSigner::from_bytes(&kp.private_key_bytes).expect("signer");
        (kp, signer)
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

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = crate::app::test_state().await;

        let did = "did:plc:getrecordtest";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'getrecord@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let (_kp, signer) = test_signer();
        let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let cid = create_genesis_repo(block_store, did, &signer)
            .await
            .unwrap();

        let cid_str = cid.to_string();
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
            .bind(&cid_str)
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        (state, did.to_string())
    }

    #[tokio::test]
    async fn get_record_nonexistent_returns_404() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=nonexistent"
            ))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_record_invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.repo.getRecord?did=not-a-did&collection=app.bsky.feed.post&rkey=test1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_record_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.repo.getRecord?did=did:plc:nonexistent&collection=app.bsky.feed.post&rkey=test1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);

        // First, put a record using the put_record handler.
        let app = crate::app::app(state.clone());

        let record = serde_json::json!({
            "text": "Hello, ATProto!",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let put_request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=roundtrip1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"record": record})).unwrap(),
            ))
            .unwrap();

        let put_response = app.clone().oneshot(put_request).await.unwrap();
        assert_eq!(put_response.status(), StatusCode::OK);

        // Now get the record back.
        let get_request = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=roundtrip1"
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
            format!("at://{did}/app.bsky.feed.post/roundtrip1")
        );
        assert_eq!(resp["value"]["text"], "Hello, ATProto!");
        assert_eq!(resp["value"]["createdAt"], "2026-06-22T00:00:00Z");
    }
}
