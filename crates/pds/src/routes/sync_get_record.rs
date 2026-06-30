// pattern: Imperative Shell

//! com.atproto.sync.getRecord - Export a single record with its MST proof as a CAR.
//!
//! Returns the blocks needed to prove the existence *or non-existence* of a record: a present
//! record yields a 200 inclusion-proof CAR; an absent record (in an existing repo) yields a 200
//! exclusion-proof CAR carrying the covering MST nodes. Only an unknown DID/account returns 404.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::export_record_proof_car;

#[derive(Deserialize)]
pub struct SyncGetRecordParams {
    did: String,
    collection: String,
    rkey: String,
}

/// GET /xrpc/com.atproto.sync.getRecord?did=<did>&collection=<nsid>&rkey=<rkey>
///
/// Returns a CARv1 file whose declared root is the signed commit. When the record exists the CAR
/// carries the commit block, the MST node path down to the record (the inclusion proof), and the
/// record block itself; when it does not, the CAR carries the covering MST nodes that prove the
/// key is absent (an exclusion proof) and no record block. A consumer verifies either claim by
/// walking the proof from the commit root. Only an unknown DID/account is a 404 — an absent record
/// in an existing repo is a 200 exclusion proof, matching the reference PDS. Unauthenticated, like
/// the other sync endpoints.
pub async fn sync_get_record(
    State(state): State<AppState>,
    Query(params): Query<SyncGetRecordParams>,
) -> Result<Response, ApiError> {
    let did = &params.did;

    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Look up the repo root CID from the accounts table.
    let root_cid_str = crate::db::accounts::get_repo_root_cid(&state.db, did)
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

    // The MST key is `<collection>/<rkey>`.
    let mst_key = format!("{}/{}", params.collection, params.rkey);

    // Export the record's proof CAR. A present record yields an inclusion proof; an absent record
    // yields an exclusion proof (covering MST nodes, no record block) — both are a 200 here, since
    // the repo exists. A genuinely missing block (corruption) surfaces as an error → 500.
    let mut block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let car_bytes = export_record_proof_car(&mut block_store, root_cid, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to export record proof CAR");
            ApiError::new(ErrorCode::InternalError, "failed to get record")
        })?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, state_with_master_key};

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:syncgetrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    /// PUT a record at `rkey` via the repo.putRecord endpoint.
    async fn put_record(app: &axum::Router, token: &str, did: &str, rkey: &str) -> StatusCode {
        let request = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            rkey,
            serde_json::json!({
                "record": { "text": "hello", "createdAt": "2026-06-26T00:00:00Z" }
            }),
            Some(token),
        );
        app.clone().oneshot(request).await.unwrap().status()
    }

    fn get_request(did: &str, rkey: &str) -> Request<Body> {
        Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.sync.getRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
            ))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn returns_car_with_correct_content_type() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);

        let response = app.oneshot(get_request(&did, "rec1")).await.unwrap();
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
    async fn car_root_is_commit_and_contains_record_block() {
        use atrium_repo::blockstore::CarStore;
        use repo_engine::AsyncBlockStoreRead;

        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);

        // The repo root CID is the commit; it must be the CAR's declared root.
        let expected_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let response = app.oneshot(get_request(&did, "rec1")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let mut car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        let roots: Vec<_> = car.roots().collect();
        assert_eq!(roots.len(), 1, "proof CAR must declare exactly one root");
        assert_eq!(
            roots[0].to_string(),
            expected_root,
            "proof CAR root must be the commit CID"
        );

        // The commit block (root) must be present in the CAR.
        let root_cid = repo_engine::Cid::try_from(expected_root.as_str()).unwrap();
        car.read_block(root_cid)
            .await
            .expect("commit block must be in the proof CAR");
    }

    #[tokio::test]
    async fn nonexistent_record_returns_exclusion_proof_car() {
        use atrium_repo::blockstore::CarStore;
        use repo_engine::AsyncBlockStoreRead;

        // A record that does not exist in an *existing* repo is a 200 exclusion-proof CAR, not a
        // 404: the commit is the declared root, the commit block is present (covering MST nodes
        // prove the key's absence), and the consumer can verify it. (404 is reserved for an
        // unknown account — see `nonexistent_account_returns_404`.)
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state.clone());

        let expected_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let response = app.oneshot(get_request(&did, "ghost")).await.unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let mut car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        let roots: Vec<_> = car.roots().collect();
        assert_eq!(roots.len(), 1, "exclusion-proof CAR must declare one root");
        assert_eq!(
            roots[0].to_string(),
            expected_root,
            "exclusion-proof CAR root must be the commit CID"
        );
        let root_cid = repo_engine::Cid::try_from(expected_root.as_str()).unwrap();
        car.read_block(root_cid)
            .await
            .expect("commit block must be in the exclusion-proof CAR");

        // End-to-end: re-open the returned CAR as the *only* blockstore and walk commit → MST root
        // → … → covering node, confirming the absent key resolves to `None`. The shape checks above
        // would miss a pds-layer regression that drops MST node blocks before sending; this walk
        // fails if any covering node is missing. Mirrors the engine-level exclusion proof test.
        use atrium_repo::repo::Repository;
        let car_store = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("re-parse CAR");
        let mut proof_repo = Repository::open(car_store, root_cid)
            .await
            .expect("commit block must be readable from the exclusion-proof CAR");
        let resolved = proof_repo
            .tree()
            .get("app.bsky.feed.post/ghost")
            .await
            .expect("MST walk must succeed using only the proof blocks");
        assert_eq!(
            resolved, None,
            "exclusion proof must resolve the absent key to None using only the CAR blocks"
        );
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let response = app
            .oneshot(get_request("did:plc:nonexistent", "rec1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.sync.getRecord?did=not-a-did&collection=app.bsky.feed.post&rkey=rec1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
