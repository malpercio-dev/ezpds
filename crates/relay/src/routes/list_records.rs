// pattern: Imperative Shell

//! com.atproto.repo.listRecords - List records in a collection with pagination.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct ListRecordsParams {
    repo: String,
    collection: String,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    reverse: bool,
}

/// GET /xrpc/com.atproto.repo.listRecords?repo=<did>&collection=<nsid>&limit=50&cursor=<rkey>&reverse=false
///
/// List the records in a collection, in MST (rkey) order, with cursor-based pagination.
/// No authentication required (public data).
pub async fn list_records(
    State(state): State<AppState>,
    Query(params): Query<ListRecordsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &params.repo;
    let collection = &params.collection;

    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Validate the collection is a syntactically valid NSID. Without this, a malformed
    // collection would silently match nothing and return an empty 200 rather than a 400.
    if repo_engine::validate_collection(collection).is_err() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid collection NSID",
        ));
    }

    // Clamp the page size to the documented bounds (default 50, max 100, min 1).
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // Look up the repo root CID.
    let root_cid_str = crate::db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo root CID");
            ApiError::new(ErrorCode::InternalError, "failed to list records")
        })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to list records")
    })?;

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to list records")
    })?;

    let page = repo_engine::list_records_json(
        &mut repo,
        collection,
        limit,
        params.cursor.as_deref(),
        params.reverse,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, collection = %collection, "failed to list records");
        ApiError::new(ErrorCode::InternalError, "failed to list records")
    })?;

    let records: Vec<serde_json::Value> = page
        .records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "uri": format!("at://{did}/{collection}/{}", r.rkey),
                "cid": r.cid.to_string(),
                "value": r.value,
            })
        })
        .collect();

    let mut body = serde_json::json!({ "records": records });
    if let Some(cursor) = page.cursor {
        body["cursor"] = serde_json::Value::String(cursor);
    }

    Ok((StatusCode::OK, axum::Json(body)).into_response())
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
        let did = "did:plc:listrecordstest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    /// Put a record via the putRecord handler (keeps the test honest: real write path).
    async fn put(app: &axum::Router, token: &str, did: &str, rkey: &str, value: serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "record": value })).unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "putRecord {rkey} should succeed"
        );
    }

    async fn list(app: &axum::Router, query: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.repo.listRecords?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, json)
    }

    #[tokio::test]
    async fn empty_collection_returns_empty_array() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let (status, json) = list(&app, &format!("repo={did}&collection=app.bsky.feed.post")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["records"].as_array().unwrap().len(), 0);
        assert!(json.get("cursor").is_none());
    }

    #[tokio::test]
    async fn lists_records_in_collection_with_uri_and_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        put(
            &app,
            &token,
            &did,
            "aaa",
            serde_json::json!({ "text": "first" }),
        )
        .await;
        put(
            &app,
            &token,
            &did,
            "bbb",
            serde_json::json!({ "text": "second" }),
        )
        .await;

        let (status, json) = list(&app, &format!("repo={did}&collection=app.bsky.feed.post")).await;
        assert_eq!(status, StatusCode::OK);

        let records = json["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        // MST order is ascending by rkey.
        assert_eq!(
            records[0]["uri"],
            format!("at://{did}/app.bsky.feed.post/aaa")
        );
        assert_eq!(records[0]["value"]["text"], "first");
        assert_eq!(
            records[1]["uri"],
            format!("at://{did}/app.bsky.feed.post/bbb")
        );
        assert!(records[0]["cid"].as_str().unwrap().starts_with("bafy"));
    }

    #[tokio::test]
    async fn only_returns_records_in_requested_collection() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        put(
            &app,
            &token,
            &did,
            "post1",
            serde_json::json!({ "text": "a post" }),
        )
        .await;
        // A record in a different collection must not leak into the listing.
        let like_request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.like&rkey=like1"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "record": { "subject": "x" } })).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(like_request).await.unwrap().status(),
            StatusCode::OK
        );

        let (_, json) = list(&app, &format!("repo={did}&collection=app.bsky.feed.post")).await;
        let records = json["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["uri"],
            format!("at://{did}/app.bsky.feed.post/post1")
        );
    }

    #[tokio::test]
    async fn cursor_paginates_forward() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        for rkey in ["k1", "k2", "k3"] {
            put(
                &app,
                &token,
                &did,
                rkey,
                serde_json::json!({ "text": rkey }),
            )
            .await;
        }

        // First page: limit 2 → k1, k2, with a cursor pointing past k2.
        let (_, page1) = list(
            &app,
            &format!("repo={did}&collection=app.bsky.feed.post&limit=2"),
        )
        .await;
        let r1 = page1["records"].as_array().unwrap();
        assert_eq!(r1.len(), 2);
        assert_eq!(r1[0]["uri"], format!("at://{did}/app.bsky.feed.post/k1"));
        assert_eq!(r1[1]["uri"], format!("at://{did}/app.bsky.feed.post/k2"));
        let cursor = page1["cursor"].as_str().expect("cursor for next page");
        assert_eq!(cursor, "k2");

        // Second page: the remaining record, no further cursor.
        let (_, page2) = list(
            &app,
            &format!("repo={did}&collection=app.bsky.feed.post&limit=2&cursor={cursor}"),
        )
        .await;
        let r2 = page2["records"].as_array().unwrap();
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0]["uri"], format!("at://{did}/app.bsky.feed.post/k3"));
        assert!(page2.get("cursor").is_none(), "listing is exhausted");
    }

    #[tokio::test]
    async fn reverse_returns_descending_order() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        for rkey in ["k1", "k2", "k3"] {
            put(
                &app,
                &token,
                &did,
                rkey,
                serde_json::json!({ "text": rkey }),
            )
            .await;
        }

        let (_, json) = list(
            &app,
            &format!("repo={did}&collection=app.bsky.feed.post&reverse=true"),
        )
        .await;
        let records = json["records"].as_array().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[0]["uri"],
            format!("at://{did}/app.bsky.feed.post/k3")
        );
        assert_eq!(
            records[2]["uri"],
            format!("at://{did}/app.bsky.feed.post/k1")
        );
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, _) = list(&app, "repo=not-a-did&collection=app.bsky.feed.post").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_collection_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        // "app.bsky" is only two segments — not a valid NSID. Must be rejected, not
        // silently matched as an empty collection.
        let (status, _) = list(&app, &format!("repo={did}&collection=app.bsky")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, _) = list(
            &app,
            "repo=did:plc:nonexistent&collection=app.bsky.feed.post",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
