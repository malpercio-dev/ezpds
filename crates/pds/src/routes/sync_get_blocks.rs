// pattern: Imperative Shell

//! com.atproto.sync.getBlocks - Return requested repo blocks (MST nodes / records) by CID as a CAR.
//!
//! Unlike the `getRepo` / `getRecord` CARs whose declared root is the signed commit, this CAR
//! declares NO root (an empty `roots` array, matching the reference PDS's
//! `blocksToCarStream(null, …)`): a caller asks for specific CIDs and receives exactly those
//! blocks. Ownership is scoped per-account — a block that exists in the store but belongs to a
//! different account is treated as missing ([`ErrorCode::BlockNotFound`]), the same answer the
//! reference PDS's per-actor block store gives for a CID it does not hold.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};
use repo_engine::{build_blocks_car, Cid};

#[derive(Deserialize)]
pub struct GetBlocksParams {
    did: String,
    /// Repeated `cids=` query keys — the one route whose array param previously required a
    /// hand-rolled `RawQuery` parse, now handled generically by `LexiconParams`.
    cids: Vec<String>,
}

/// GET /xrpc/com.atproto.sync.getBlocks?did=<did>&cids=<cid>&cids=<cid>...
///
/// Returns a CARv1 file (Content-Type `application/vnd.ipld.car`) carrying exactly the requested
/// blocks. The CAR's `roots` array is empty (no declared root) — a consumer reads the blocks by
/// the CIDs it asked for, not by walking from a root. Unauthenticated, like the other sync
/// endpoints.
///
/// * Unknown DID/account → `404` (the repo must exist).
/// * A requested CID that is absent from the repo, or that belongs to a different account,
///   → `400` `BlockNotFound`. All such CIDs are reported at once, matching the reference PDS.
/// * A malformed CID (or an empty `cids` list) → `400`.
pub async fn sync_get_blocks(
    State(state): State<AppState>,
    LexiconParams(params): LexiconParams<GetBlocksParams>,
) -> Result<Response, ApiError> {
    let did = &params.did;
    let cids = params.cids;

    // `did`'s format and every `cids` element's format are already lexicon-enforced above. A
    // fully absent `cids` is a lexicon 400 too; an all-empty repeated key (`cids=&cids=`, JS-array
    // truthy but every element filtered) is the one shape that still reaches here as `[]`.
    if cids.is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "no CIDs requested"));
    }

    // The repo must exist. The root CID itself is not used to build the CAR — getBlocks declares
    // no root — but the lookup is the existence/ownership precondition for the account, matching
    // the other sync read routes (RepoNotFound analog).
    let _root_cid_str = crate::db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo root CID");
            ApiError::new(ErrorCode::InternalError, "failed to get blocks")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    // Parse and dedup the requested CIDs. A bare CID string that fails to parse is a client
    // error, not a "missing block".
    let mut requested: Vec<Cid> = Vec::with_capacity(cids.len());
    for s in &cids {
        let cid = Cid::try_from(s.as_str()).map_err(|e| {
            tracing::error!(error = %e, cid = %s, "invalid CID in getBlocks request");
            ApiError::new(ErrorCode::InvalidClaim, "invalid CID format")
        })?;
        requested.push(cid);
    }
    requested.sort();
    requested.dedup();

    // Fetch all requested blocks in one account-scoped DB query. A block that is absent OR
    // belongs to another account is missing from this result set — both surface as
    // `BlockNotFound`, so a caller cannot use a foreign repo's DID to probe whether a CID is
    // stored anywhere on the PDS.
    let requested_strings: Vec<String> = requested.iter().map(Cid::to_string).collect();
    let rows = crate::db::blocks::get_blocks_for_account(&state.db, did, &requested_strings)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query blocks");
            ApiError::new(ErrorCode::InternalError, "failed to get blocks")
        })?;
    let mut rows_by_cid: HashMap<String, Vec<u8>> =
        rows.into_iter().map(|row| (row.cid, row.bytes)).collect();

    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::with_capacity(requested.len());
    let mut missing: Vec<String> = Vec::new();
    for cid in &requested {
        let cid_str = cid.to_string();
        match rows_by_cid.remove(&cid_str) {
            Some(bytes) => blocks.push((*cid, bytes)),
            None => missing.push(cid_str),
        }
    }

    if !missing.is_empty() {
        return Err(ApiError::new(
            ErrorCode::BlockNotFound,
            format!("block not found: {}", missing.join(", ")),
        ));
    }

    let car_bytes = build_blocks_car(blocks).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to build blocks CAR");
        ApiError::new(ErrorCode::InternalError, "failed to get blocks")
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
    use atrium_repo::blockstore::{AsyncBlockStoreRead, CarStore, DAG_CBOR, SHA2_256};
    use axum::body::Body;
    use axum::http::{self, Request};
    use sha2::Digest;
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, seed_account_with_repo, state_with_master_key,
    };

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:syncgetblockstest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    /// PUT a record at `rkey` via the repo.putRecord endpoint; returns the record's block CID.
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

    /// All block CIDs currently stored for `did` (commit, MST nodes, record blocks).
    async fn stored_cids(state: &AppState, did: &str) -> Vec<String> {
        sqlx::query_scalar("SELECT cid FROM block_owners WHERE account_did = ? ORDER BY cid")
            .bind(did)
            .fetch_all(&state.db)
            .await
            .unwrap()
    }

    fn valid_absent_cid(seed: &[u8]) -> String {
        let digest = sha2::Sha256::digest(seed);
        let mh = atrium_repo::Multihash::wrap(SHA2_256, digest.as_slice()).unwrap();
        repo_engine::Cid::new_v1(DAG_CBOR, mh).to_string()
    }

    fn get_request(did: &str, cids: &[&str]) -> Request<Body> {
        let cids_qs = cids
            .iter()
            .map(|c| format!("cids={c}"))
            .collect::<Vec<_>>()
            .join("&");
        Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.sync.getBlocks?did={did}&{cids_qs}"
            ))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn returns_car_with_correct_content_type() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);
        let cids = stored_cids(&state, &did).await;
        let first = cids.first().expect("repo must have stored blocks");

        let response = app
            .oneshot(get_request(&did, &[first.as_str()]))
            .await
            .unwrap();
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
    async fn car_has_no_declared_root_and_contains_all_requested_blocks() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);

        // Request every block the repo stores.
        let cids = stored_cids(&state, &did).await;
        assert!(!cids.is_empty(), "repo must have stored blocks");
        let cid_refs: Vec<&str> = cids.iter().map(String::as_str).collect();

        let response = app.oneshot(get_request(&did, &cid_refs)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let mut car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        // getBlocks declares NO root — the roots array must be empty, matching the reference PDS.
        let roots: Vec<_> = car.roots().collect();
        assert!(
            roots.is_empty(),
            "getBlocks CAR must declare no root, got {roots:?}"
        );

        // Every requested CID must be readable from the returned CAR with the stored bytes.
        for cid_str in &cids {
            let cid = repo_engine::Cid::try_from(cid_str.as_str()).unwrap();
            let mut buf = Vec::new();
            car.read_block_into(cid, &mut buf)
                .await
                .unwrap_or_else(|e| panic!("block {cid_str} must be in the CAR: {e:?}"));
            let stored: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM blocks WHERE cid = ?")
                .bind(cid_str)
                .fetch_one(&state.db)
                .await
                .unwrap();
            assert_eq!(
                buf, stored,
                "returned bytes for {cid_str} must match the store"
            );
        }
    }

    #[tokio::test]
    async fn returns_subset_of_requested_blocks() {
        // Requesting only the commit block (the first stored CID) yields a CAR with just that one.
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);

        let cids = stored_cids(&state, &did).await;
        let commit_cid = cids.first().unwrap().clone();
        let response = app
            .oneshot(get_request(&did, &[commit_cid.as_str()]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        let roots: Vec<_> = car.roots().collect();
        assert!(roots.is_empty());
        let cid = repo_engine::Cid::try_from(commit_cid.as_str()).unwrap();
        let mut buf = Vec::new();
        car.read_block_into(cid, &mut buf)
            .await
            .expect("commit block in CAR");
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);
        let cid = valid_absent_cid(b"nonexistent-account-block");

        let response = app
            .oneshot(get_request("did:plc:nonexistent", &[cid.as_str()]))
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
            .uri("/xrpc/com.atproto.sync.getBlocks?did=not-a-did&cids=bafkreifake")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_cid_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let response = app
            .oneshot(get_request(&did, &["not-a-cid"]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_cids_list_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getBlocks?did={did}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_cids_returns_block_not_found_400() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        // A well-formed CID that the repo does not hold.
        let absent = valid_absent_cid(b"missing-block-a");
        let response = app
            .oneshot(get_request(&did, &[absent.as_str()]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "BlockNotFound");
    }

    #[tokio::test]
    async fn block_belonging_to_other_account_is_block_not_found() {
        let state = state_with_master_key().await;
        let a = "did:plc:blockowner".to_string();
        let b = "did:plc:blockrequester".to_string();
        seed_account_with_repo(&state.db, &a).await;
        seed_account_with_repo(&state.db, &b).await;
        let token = access_jwt(&state.jwt_secret, &a);
        let app = crate::app::app(state.clone());

        // Account A puts a record; we then request one of B's own blocks under A, AND separately
        // request an A-owned block under B. Only the A-owned-block-under-B path is exercised here:
        // asking as B for a CID that exists but belongs to A must be BlockNotFound, not 200.
        assert_eq!(put_record(&app, &token, &a, "rec1").await, StatusCode::OK);
        let a_cids = stored_cids(&state, &a).await;
        let foreign_cid = a_cids.first().unwrap().clone();

        // Sanity: the foreign block is genuinely owned by A, not B.
        let owner: String = sqlx::query_scalar("SELECT account_did FROM blocks WHERE cid = ?")
            .bind(&foreign_cid)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(owner, a, "foreign block must be owned by A");

        let response = app
            .oneshot(get_request(&b, &[foreign_cid.as_str()]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "BlockNotFound");
    }

    #[tokio::test]
    async fn partial_missing_block_reports_all_missing() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());
        assert_eq!(put_record(&app, &token, &did, "rec1").await, StatusCode::OK);

        let present = stored_cids(&state, &did).await;
        let present = present.first().unwrap().clone();
        let absent_a = valid_absent_cid(b"missing-block-a");
        let absent_b = valid_absent_cid(b"missing-block-b");

        let response = app
            .oneshot(get_request(
                &did,
                &[present.as_str(), absent_a.as_str(), absent_b.as_str()],
            ))
            .await
            .unwrap();
        // Any missing block fails the whole request; both absent CIDs are reported.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "BlockNotFound");
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(
            msg.contains(&absent_a),
            "message must report {absent_a}: {msg}"
        );
        assert!(
            msg.contains(&absent_b),
            "message must report {absent_b}: {msg}"
        );
    }
}
