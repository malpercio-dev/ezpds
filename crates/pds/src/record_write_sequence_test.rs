// pattern: Imperative Shell

//! The authorized, locked opening sequence every repo writer runs through
//! (`record_write::authorize` → `Authorized::lock`), tested once at the helper and once over
//! every write route that uses it.

use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use common::ErrorCode;
use tower::ServiceExt;

use crate::app::AppState;
use crate::routes::test_utils::{
    access_jwt, delete_record_request, post_req, put_record_request, seed_account_with_repo,
    state_with_master_key,
};

const DID: &str = "did:plc:writesequence";
const OTHER_DID: &str = "did:plc:writesequenceother";

async fn seeded_state() -> AppState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, DID).await;
    seed_account_with_repo(&state.db, OTHER_DID).await;
    state
}

async fn deactivate(state: &AppState, did: &str) {
    sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

fn authorize(
    state: &AppState,
    token: &str,
    did: &str,
) -> Result<crate::record_write::Authorized, common::ApiError> {
    let uri: Uri = "/xrpc/com.atproto.repo.putRecord".parse().unwrap();
    crate::record_write::authorize(state, &bearer(token), &Method::POST, &uri, did)
}

// ── The helper ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn authorize_refuses_a_token_for_another_repo() {
    let state = seeded_state().await;
    let token = access_jwt(&state.jwt_secret, OTHER_DID);
    let err = authorize(&state, &token, DID).err().unwrap();
    assert_eq!(err.code(), &ErrorCode::Forbidden);
}

#[tokio::test]
async fn authorize_refuses_an_invalid_did() {
    let state = seeded_state().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let err = authorize(&state, &token, "not-a-did").err().unwrap();
    assert_eq!(err.code(), &ErrorCode::InvalidClaim);
}

#[tokio::test]
async fn lock_refuses_an_inactive_repo() {
    let state = seeded_state().await;
    deactivate(&state, DID).await;
    let token = access_jwt(&state.jwt_secret, DID);
    let authorized = authorize(&state, &token, DID).unwrap();
    let err = authorized.lock(&state).await.err().unwrap();
    assert_eq!(err.code(), &ErrorCode::Forbidden);
}

#[tokio::test]
async fn locked_repo_holds_the_repo_write_lock_until_dropped() {
    let state = seeded_state().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let locked = authorize(&state, &token, DID)
        .unwrap()
        .lock(&state)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), state.repo_write_locks.lock(DID))
            .await
            .is_err(),
        "a second writer must wait while the locked repo is alive"
    );
    drop(locked);
    tokio::time::timeout(Duration::from_secs(5), state.repo_write_locks.lock(DID))
        .await
        .expect("the lock must be released when the locked repo drops");
}

// ── Every write route ────────────────────────────────────────────────────────

/// One request per write operation, targeting `did` with `token`.
fn write_requests(did: &str, token: &str) -> Vec<(&'static str, Request<Body>)> {
    let record = serde_json::json!({"text": "sequence"});
    vec![
        (
            "createRecord",
            post_req(
                "/xrpc/com.atproto.repo.createRecord",
                Some(token),
                Some(serde_json::json!({
                    "repo": did, "collection": "app.bsky.feed.post",
                    "record": record, "validate": false,
                })),
            ),
        ),
        (
            "putRecord",
            put_record_request(
                did,
                "app.bsky.feed.post",
                "seqput",
                serde_json::json!({"record": record}),
                Some(token),
            ),
        ),
        (
            "deleteRecord",
            delete_record_request(
                did,
                "app.bsky.feed.post",
                // The record putRecord wrote just before, so the delete reaches its commit.
                "seqput",
                serde_json::json!({}),
                Some(token),
            ),
        ),
        (
            "applyWrites",
            post_req(
                "/xrpc/com.atproto.repo.applyWrites",
                Some(token),
                Some(serde_json::json!({
                    "repo": did, "validate": false,
                    "writes": [{
                        "$type": "com.atproto.repo.applyWrites#create",
                        "collection": "app.bsky.feed.post", "value": record,
                    }],
                })),
            ),
        ),
    ]
}

#[tokio::test]
async fn every_write_waits_for_the_repo_write_lock() {
    let state = seeded_state().await;
    let token = access_jwt(&state.jwt_secret, DID);
    for (route, request) in write_requests(DID, &token) {
        let guard = state.repo_write_locks.lock(DID).await;
        let app = crate::app::app(state.clone());
        let mut call = tokio::spawn(app.oneshot(request));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "{route} must not complete while another writer holds the repo lock"
        );
        drop(guard);
        let response = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .unwrap_or_else(|_| panic!("{route} must complete once the lock is released"))
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{route}");
    }
}

#[tokio::test]
async fn every_write_refuses_an_inactive_repo() {
    let state = seeded_state().await;
    deactivate(&state, DID).await;
    let token = access_jwt(&state.jwt_secret, DID);
    for (route, request) in write_requests(DID, &token) {
        let response = crate::app::app(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{route}");
    }
}

#[tokio::test]
async fn every_write_refuses_a_token_for_another_repo() {
    let state = seeded_state().await;
    let token = access_jwt(&state.jwt_secret, OTHER_DID);
    for (route, request) in write_requests(DID, &token) {
        let response = crate::app::app(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{route}");
    }
}
