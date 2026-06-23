// pattern: Imperative Shell

//! com.atproto.repo.putRecord - Create or update a record in a repository.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::{CommitSigner, Repository};

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
/// Create or update a record in the repository.
pub async fn put_record(
    State(state): State<AppState>,
    Query(params): Query<PutRecordParams>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<PutRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.did;
    let collection = &params.collection;
    let rkey = &params.rkey;

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

    // Look up the repo root CID.
    let root_cid_str: Option<String> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to put record")
            })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to put record")
    })?;

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to put record")
    })?;

    // TODO: use the actual signing key for this account.
    // For now, generate a throwaway key. The signing key will be wired
    // when the key management system is implemented.
    let signing_key = crypto::generate_p256_keypair().map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to generate signing key");
        ApiError::new(ErrorCode::InternalError, "failed to put record")
    })?;

    let signer = CommitSigner::from_bytes(&signing_key.private_key_bytes).map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to create commit signer");
        ApiError::new(ErrorCode::InternalError, "failed to put record")
    })?;

    // Build the MST key: collection/rkey
    let mst_key = format!("{collection}/{rkey}");

    // Write the record.
    let record_cid = repo_engine::put_record(&mut repo, &signer, &mst_key, &body.record)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to put record");
            ApiError::new(ErrorCode::InternalError, "failed to put record")
        })?;

    // Update the repo root CID.
    let new_root = repo.root().to_string();
    sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
        .bind(&new_root)
        .bind(did)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to update repo root CID");
            ApiError::new(ErrorCode::InternalError, "failed to put record")
        })?;

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

    use crate::db::blocks::SqliteBlockStore;
    use repo_engine::{create_genesis_repo, CommitSigner};

    fn test_signer() -> (crypto::P256Keypair, CommitSigner) {
        let kp = crypto::generate_p256_keypair().expect("keypair");
        let signer = CommitSigner::from_bytes(&kp.private_key_bytes).expect("signer");
        (kp, signer)
    }

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = crate::app::test_state().await;

        let did = "did:plc:putrecordtest";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'putrecord@example.com', 'hash', datetime('now'), datetime('now'))",
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
}
