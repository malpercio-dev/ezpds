// pattern: Imperative Shell

//! com.atproto.sync.getRepo - Export a repository as a CAR file.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::export_repo_car;

#[derive(Deserialize)]
pub struct GetRepoParams {
    did: String,
}

/// GET /xrpc/com.atproto.sync.getRepo?did=<did>
///
/// Returns the full ATProto repository as a CARv1 file.
/// The CAR root is the signed commit CID; the file contains the commit block,
/// all MST nodes, and all record blocks.
pub async fn get_repo(
    State(state): State<AppState>,
    Query(params): Query<GetRepoParams>,
) -> Result<Response, ApiError> {
    let did = &params.did;

    // Validate DID format.
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Look up the repo root CID from the accounts table.
    let root_cid_str: Option<String> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo root CID");
                ApiError::new(ErrorCode::InternalError, "failed to get repo")
            })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to get repo")
    })?;

    // Export the repo as a CAR file.
    let mut block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let car_bytes = export_repo_car(&mut block_store, root_cid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to export repo as CAR");
            ApiError::new(ErrorCode::InternalError, "failed to get repo")
        })?;

    // Return as application/vnd.ipld.car.
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response())
}

/// Reclaim an account's blocks that are no longer reachable from `root` (the current
/// repo commit): superseded MST nodes, old commits, orphans from conflicted writes.
///
/// Best-effort and idempotent — callers run this after a commit and log (not fail) on
/// error, since orphaned blocks are harmless until the next sweep. Returns the count
/// reclaimed. Note: this walks the whole repo, so for very large repos a periodic sweep
/// would be cheaper than running it on every write.
pub(crate) async fn gc_repo_blocks(
    pool: &sqlx::SqlitePool,
    did: &str,
    root: repo_engine::Cid,
) -> Result<u64, ApiError> {
    use std::collections::HashSet;

    let mut store = SqliteBlockStore::new(pool.clone(), did.to_string());
    let reachable: HashSet<String> = repo_engine::collect_reachable_cids(&mut store, root)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to compute reachable blocks for GC");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })?
        .into_iter()
        .map(|c| c.to_string())
        .collect();

    crate::db::blocks::delete_unreachable_blocks(pool, did, &reachable)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to delete unreachable blocks");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::db::blocks::SqliteBlockStore;
    use repo_engine::{create_genesis_repo, CommitSigner};

    /// Helper: generate a test keypair and signer.
    fn test_signer() -> (crypto::P256Keypair, CommitSigner) {
        let kp = crypto::generate_p256_keypair().expect("keypair");
        let signer = CommitSigner::from_bytes(&kp.private_key_bytes).expect("signer");
        (kp, signer)
    }

    /// Helper: create a test account with a genesis repo and return the state + DID.
    async fn setup_account_with_repo() -> (AppState, String) {
        let state = crate::app::test_state().await;

        // Insert a test account.
        let did = "did:plc:getrepotest";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'getrepo@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        // Create genesis repo.
        let (_kp, signer) = test_signer();
        let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let cid = create_genesis_repo(block_store, did, &signer)
            .await
            .unwrap();

        // Store root CID.
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
    async fn get_repo_returns_car_with_correct_content_type() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/vnd.ipld.car"
        );
    }

    #[tokio::test]
    async fn get_repo_returns_non_empty_car_bytes() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // CAR header + at least one block.
        assert!(
            body.len() > 10,
            "CAR should have header + blocks, got {} bytes",
            body.len()
        );
    }

    #[tokio::test]
    async fn get_repo_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.sync.getRepo?did=did:plc:nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_repo_invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.sync.getRepo?did=not-a-did")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_repo_car_root_matches_commit_cid() {
        let (state, did) = setup_account_with_repo().await;

        // Get the expected root CID from the DB.
        let expected_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let app = crate::app::app(state);
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse the CAR using CarStore to verify the root CID.
        use atrium_repo::blockstore::CarStore;
        let car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        let roots: Vec<_> = car.roots().collect();

        assert_eq!(roots.len(), 1, "CAR must have exactly one root");
        assert_eq!(
            roots[0].to_string(),
            expected_root,
            "CAR root CID must match the commit CID"
        );
    }
}
