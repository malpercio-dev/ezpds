//! Fixtures for tests that drive the agents surface: everything in `custos_core::test_support`
//! (re-exported below) plus the router the tests send through ([`test_app`]).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;
use tower::ServiceExt;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Both agent routers over `state`, wrapped the way `pds` wraps them: the shared layer stack on
/// each group, plus the XRPC error dialect and permissive CORS on the public one. The rest of the
/// `pds` app is absent, so a path no agents route claims is a plain 404 here.
pub fn test_app(state: CoreState) -> Router {
    let public = custos_core::apply_shared_layers(crate::router::<CoreState>(), &state)
        .layer(axum::middleware::from_fn(
            custos_core::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(tower_http::cors::CorsLayer::permissive());
    let internal = custos_core::apply_shared_layers(crate::internal_router::<CoreState>(), &state);
    public.merge(internal).with_state(state)
}

/// [`custos_core::test_support::post_json_with_bearer`] against a fresh [`test_app`] router.
pub async fn post_json_with_bearer(
    state: CoreState,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    custos_core::test_support::post_json_with_bearer(test_app(state), uri, body, token).await
}

// ── Sovereign child fixtures, shared with `pds`'s account-reaper test ─────────────────

/// A test state whose plc.directory is a mock accepting every genesis op, with a master key and
/// `example.com` handles: what a child mint needs.
///
/// Callers must keep the returned `MockServer` alive for the whole test. `MockServer::start`
/// hands out servers from wiremock's shared process-wide pool; dropping the guard returns the
/// server to the pool while its listener stays up, and the next test to check it out *resets*
/// it — silently unmounting the plc mock under a state that still points at its URL, so a
/// mid-test mint's plc POST 404s and surfaces as a 502 (observed as a parallel-load CI flake).
pub async fn state_with_plc() -> (CoreState, MockServer) {
    let plc = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&plc)
        .await;
    let base = test_state_with_plc_url(plc.uri()).await;
    let mut config = (*base.config).clone();
    config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
        test_master_key(),
    )));
    config.available_user_domains = vec!["example.com".to_string()];
    (
        CoreState {
            config: Arc::new(config),
            ..base
        },
        plc,
    )
}

pub fn child_request(uri: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

pub fn get_request(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// A `state_with_plc()` whose child-deletion grace window is overridden — `0` makes the next
/// reaper run purge, a large value keeps a scheduled child parked in its window.
pub async fn state_with_grace(grace_secs: u64) -> (CoreState, MockServer) {
    let (base, plc) = state_with_plc().await;
    let mut config = (*base.config).clone();
    config.accounts.child_deletion_grace_secs = grace_secs;
    (
        CoreState {
            config: Arc::new(config),
            ..base
        },
        plc,
    )
}

/// Mint a sovereign child of `parent` and return its DID. Reserves a fresh repo key and drives
/// the real `POST /agent/child` path so the child has an account, repo, handle, provisioning
/// row, and a claimed capability — exactly what a delete must later unwind.
pub async fn mint_child_for(state: &CoreState, handle: &str, token: &str) -> String {
    let repo_key = reserve_repo_key(&state.db).await;
    let op = child_genesis_op(handle, &state.config.public_url, &repo_key.key_id.0);
    let response = test_app(state.clone())
        .oneshot(child_request(
            "/agent/child",
            Some(token),
            serde_json::json!({"handle": handle, "plcOp": op}),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "child mint should succeed"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
    minted["did"].as_str().unwrap().to_string()
}
