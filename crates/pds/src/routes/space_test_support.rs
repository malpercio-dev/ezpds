// Shared HTTP request-building helpers for the space/simplespace end-to-end test modules
// (`space_routes_test`, `space_lifecycle_test`, `space_notify_routes_test`,
// `space_sync_routes_test`, `space_takedown_test`, `simplespace_routes_test`). Sibling of
// `test_utils.rs` and exempt from the "routes may not import one another" rule the same way —
// it holds nothing route-specific, only the request/response plumbing every space test module
// re-derived on its own before.
//
// What stays file-local on purpose, because it genuinely differs rather than merely being
// spelled differently: each module's `setup()` (different fixtures per surface), `write_one`
// (`space_notify_routes_test`'s fans a write out to registered subscribers,
// `space_sync_routes_test`'s does not), and `simplespace_routes_test::create_body` (builds a
// space *declaration*, not a record write).

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::app::{app, AppState};
use crate::routes::test_utils::body_json;

/// A GET at an exact path, bearer-authenticated — the primitive every space test module's `get`
/// reduces to.
pub(crate) fn path_get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// A JSON POST at an exact path, bearer-authenticated.
pub(crate) fn path_post(path: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A GET against `/xrpc/<lexicon id>`.
pub(crate) fn xrpc_get(method: &str, token: &str) -> Request<Body> {
    path_get(&format!("/xrpc/{method}"), token)
}

/// A JSON POST against `/xrpc/<lexicon id>`.
pub(crate) fn xrpc_post(method: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    path_post(&format!("/xrpc/{method}"), token, body)
}

/// Run a request through the real router and decode the JSON response body.
pub(crate) async fn send(
    state: &AppState,
    request: Request<Body>,
) -> (StatusCode, serde_json::Value) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// `send`, keeping only the status — for call sites that never read the body.
pub(crate) async fn send_status(state: &AppState, request: Request<Body>) -> StatusCode {
    send(state, request).await.0
}

/// A `com.atproto.space.createRecord` request body. Space, repo and collection vary per test
/// fixture; only the shape is shared.
pub(crate) fn space_record_body(
    space: &str,
    repo: &str,
    collection: &str,
    rkey: &str,
    text: &str,
) -> serde_json::Value {
    serde_json::json!({
        "space": space,
        "repo": repo,
        "collection": collection,
        "rkey": rkey,
        "record": {"text": text},
    })
}
