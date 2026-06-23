// pattern: Imperative Shell

//! com.atproto.repo.deleteRecord - Delete a record from a repository.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

#[derive(Deserialize)]
pub struct DeleteRecordParams {
    did: String,
    collection: String,
    rkey: String,
}

/// POST /xrpc/com.atproto.repo.deleteRecord
///
/// Delete a record. Idempotent: deleting a record that does not exist succeeds.
pub async fn delete_record(
    State(state): State<AppState>,
    Query(params): Query<DeleteRecordParams>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.did;
    let collection = &params.collection;
    let rkey = &params.rkey;

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

    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let root_cid_str: Option<String> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to delete record")
            })?;
    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    let mst_key = format!("{collection}/{rkey}");

    // Idempotent: if the record is already absent, succeed without a new commit.
    let existing: Option<serde_json::Value> = repo_engine::get_record(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to read record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;
    if existing.is_none() {
        return Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
    }

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

    repo_engine::delete_record(&mut repo, &signer, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to delete record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;

    // Advance the root with optimistic concurrency (see putRecord for rationale).
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
                ApiError::new(ErrorCode::InternalError, "failed to delete record")
            })?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    // Best-effort GC: reclaim blocks superseded by this commit (non-fatal on error).
    if let Err(e) = crate::routes::get_repo::gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{seed_account_with_repo, state_with_master_key};

    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({"scope": "com.atproto.access", "sub": sub, "iat": now, "exp": now + 7200_u64}),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn delete_req(did: &str, rkey: &str, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(http::Method::POST).uri(format!(
            "/xrpc/com.atproto.repo.deleteRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
        ));
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn delete_record_without_auth_returns_401() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let app = crate::app::app(state);
        let resp = app.oneshot(delete_req(&did, "t1", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_missing_record_is_idempotent() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        // Nothing was ever written — delete must still succeed.
        let resp = app
            .oneshot(delete_req(&did, "neverexisted", Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
