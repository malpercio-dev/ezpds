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
    /// Optional CID selecting a specific version of the record. When omitted, the current
    /// version (the value the MST points to) is returned.
    cid: Option<String>,
}

/// GET /xrpc/com.atproto.repo.getRecord?did=<did>&collection=<collection>&rkey=<rkey>&cid=<cid>
///
/// Read a record from the repository.
///
/// When `cid` is supplied and differs from the current version, the requested version is
/// served directly from the block store — but only if that block is still present. We keep no
/// version index and never resurrect blocks, so a CID that has been garbage-collected (or never
/// belonged to this repo) returns not-found. This matches how the wider network behaves: a PDS
/// is not obligated to retain superseded record versions, so consumers already treat a
/// historical-CID miss as the normal, interoperable outcome.
pub async fn get_record(
    State(state): State<AppState>,
    Query(params): Query<GetRecordParams>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.did;
    let collection = &params.collection;
    let rkey = &params.rkey;

    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Look up the repo root CID.
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

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to get record")
    })?;

    // Build the MST key: collection/rkey
    let mst_key = format!("{collection}/{rkey}");
    let uri = format!("at://{did}/{collection}/{rkey}");

    // The MST maps the key directly to the current record block's CID.
    let current_cid = repo_engine::get_record_cid(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to get record cid");
            ApiError::new(ErrorCode::InternalError, "failed to get record")
        })?
        .map(|c| c.to_string());

    // A requested CID that matches the current version (or no CID at all) is served from the
    // MST. Any other requested CID is a historical version fetched directly from the block store.
    let wants_historical = params
        .cid
        .as_deref()
        .is_some_and(|requested| current_cid.as_deref() != Some(requested));

    if wants_historical {
        let requested = params
            .cid
            .as_deref()
            .expect("historical implies cid present");
        // Scope the lookup to this repo: a block is only "this record's" history if it belongs
        // to this account. Blocks are content-addressed, so the stored bytes hash to the CID.
        let block = crate::db::blocks::get_block(&state.db, requested)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, cid = %requested, "failed to query block");
                ApiError::new(ErrorCode::InternalError, "failed to get record")
            })?
            .filter(|b| b.account_did == *did)
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "record not found"))?;

        let value = repo_engine::decode_record_block(&block.bytes).map_err(|e| {
            tracing::error!(error = %e, did = %did, cid = %requested, "failed to decode record block");
            ApiError::new(ErrorCode::InternalError, "failed to get record")
        })?;

        return Ok((
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "uri": uri,
                "cid": requested,
                "value": value,
            })),
        )
            .into_response());
    }

    // Current version. `current_cid` is None exactly when the record does not exist.
    let Some(cid) = current_cid else {
        return Err(ApiError::new(ErrorCode::NotFound, "record not found"));
    };

    // Read the record (the stored ATProto data model is mapped back to JSON:
    // CID links → {"$link": ...}, byte strings → {"$bytes": ...}).
    let value = repo_engine::get_record_json(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to get record");
            ApiError::new(ErrorCode::InternalError, "failed to get record")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "record not found"))?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "uri": uri,
            "cid": cid,
            "value": value,
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use serde_json::json;
    use tower::ServiceExt;

    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, state_with_master_key};

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:getrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
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

    #[tokio::test]
    async fn get_record_preserves_cid_link() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let cid = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let record = serde_json::json!({ "embed": { "$link": cid } });
        let put = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey=link1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "record": record })).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );

        let get = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=link1"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The CID link survives as {"$link": ...}, proving it was stored as a canonical
        // DAG-CBOR CID tag (not a plain map).
        assert_eq!(json["value"]["embed"]["$link"], cid);
    }

    /// PUT a record at `rkey`, returning `(status, body)`. Body carries `cid` on success.
    async fn put_record(
        app: &axum::Router,
        token: &str,
        did: &str,
        rkey: &str,
        record: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "record": record })).unwrap(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// GET a record, optionally pinning a `cid`. Returns `(status, body)`.
    async fn get(
        app: &axum::Router,
        did: &str,
        rkey: &str,
        cid: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut uri = format!(
            "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
        );
        if let Some(cid) = cid {
            uri.push_str(&format!("&cid={cid}"));
        }
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn get_record_response_includes_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let (status, put) = put_record(&app, &token, &did, "cidcheck", json!({"n": 1})).await;
        assert_eq!(status, StatusCode::OK);
        let put_cid = put["cid"].as_str().unwrap();

        // No cid param → current version, and the response echoes the record's CID.
        let (status, body) = get(&app, &did, "cidcheck", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], put_cid);
        assert_eq!(body["value"]["n"], 1);
    }

    #[tokio::test]
    async fn get_record_pinned_current_cid_returns_current() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let (status, put) = put_record(&app, &token, &did, "pin", json!({"n": 7})).await;
        assert_eq!(status, StatusCode::OK);
        let cur_cid = put["cid"].as_str().unwrap().to_string();

        // Pinning the current CID resolves to the current version.
        let (status, body) = get(&app, &did, "pin", Some(&cur_cid)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], cur_cid);
        assert_eq!(body["value"]["n"], 7);
    }

    #[tokio::test]
    async fn get_record_superseded_cid_is_gced_and_returns_404() {
        // putRecord runs post-commit GC, so overwriting a record reclaims the prior block.
        // Pinning the superseded CID therefore returns not-found — the retention contract
        // ("serve only still-stored CIDs") and exactly how the wider network behaves.
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let (status, v1) = put_record(&app, &token, &did, "hist", json!({"n": 1})).await;
        assert_eq!(status, StatusCode::OK);
        let v1_cid = v1["cid"].as_str().unwrap().to_string();

        let (status, v2) = put_record(&app, &token, &did, "hist", json!({"n": 2})).await;
        assert_eq!(status, StatusCode::OK);
        let v2_cid = v2["cid"].as_str().unwrap().to_string();
        assert_ne!(v1_cid, v2_cid);

        // The superseded version was garbage-collected → not found.
        let (status, _) = get(&app, &did, "hist", Some(&v1_cid)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The current version is still served, with and without an explicit CID.
        let (status, body) = get(&app, &did, "hist", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], v2_cid);
        assert_eq!(body["value"]["n"], 2);
    }

    #[tokio::test]
    async fn get_record_stored_historical_block_is_served() {
        // The positive historical path: when a non-current record block is *still present* in
        // this repo's store, pinning its CID decodes and returns it directly (bypassing the MST).
        // We seed the block to exercise the path deterministically, independent of GC timing.
        use atrium_repo::blockstore::{AsyncBlockStoreWrite, DAG_CBOR, SHA2_256};

        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        // A current record exists at the key…
        let (status, _) = put_record(&app, &token, &did, "ver", json!({"n": 2})).await;
        assert_eq!(status, StatusCode::OK);

        // …and a prior version's block is still stored (written content-addressed, exactly as
        // a real commit would have written it).
        let prior = json!({"n": 1});
        let ipld = repo_engine::json_to_record_value(&prior).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        let mut bs = crate::db::blocks::SqliteBlockStore::new(state.db.clone(), did.clone());
        let prior_cid = bs
            .write_block(DAG_CBOR, SHA2_256, &bytes)
            .await
            .unwrap()
            .to_string();

        let (status, body) = get(&app, &did, "ver", Some(&prior_cid)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], prior_cid);
        assert_eq!(body["value"]["n"], 1);
    }

    #[tokio::test]
    async fn get_record_unknown_cid_returns_404() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let (status, _) = put_record(&app, &token, &did, "unknown", json!({"n": 1})).await;
        assert_eq!(status, StatusCode::OK);

        // A well-formed CID that was never stored for this record → not found.
        let bogus = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let (status, _) = get(&app, &did, "unknown", Some(bogus)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
