// pattern: Imperative Shell

//! Rate-limit middleware tests that drive the full `app()` router: the throttled response's CORS
//! headers, the `getRepo` exemption, and per-endpoint caps need the real route table, which lives
//! in `pds`. The limiter's unit tests stay beside it in `custos_core::rate_limit`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::RateLimitConfig;
use tower::ServiceExt;

use crate::app::{app, test_state, AppState};
use crate::rate_limit::*;

async fn state_with_global_cap(max: u64) -> AppState {
    let mut state = test_state().await;
    state.core.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&RateLimitConfig {
        enabled: true,
        global_ip_per_5min: max,
        ..RateLimitConfig::default()
    }));
    state
}

fn describe_req(ip: &str) -> Request<Body> {
    Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .header("x-forwarded-for", ip)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn global_limit_rejects_over_cap_with_headers() {
    let state = state_with_global_cap(2).await;
    let metrics = state.metrics.clone();
    let router = app(state);

    // First two from the same IP pass and carry RateLimit headers.
    for _ in 0..2 {
        let resp = router
            .clone()
            .oneshot(describe_req("203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("ratelimit-limit"));
    }

    // Third is throttled with a 429, RateLimited body, and Retry-After.
    let resp = router
        .clone()
        .oneshot(describe_req("203.0.113.1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // An XRPC path: the 429 leaves in the flat XRPC dialect.
    assert_eq!(json["error"], "RateLimitExceeded");

    // The rejection is counted against the limiter that tripped.
    let rendered = metrics.render().unwrap().unwrap();
    assert!(
        rendered.contains("rate_limit_rejections_total")
            && rendered.contains(r#"limiter="global_ip""#),
        "missing global_ip rejection count in:\n{rendered}"
    );

    // A different IP is unaffected.
    let resp = router.oneshot(describe_req("203.0.113.2")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn throttled_response_carries_cors_headers() {
    // CORS is layered outside the rate limiter, so a cross-origin client can still read a 429.
    let router = app(state_with_global_cap(1).await);
    let cors_req = |ip: &str| {
        Request::builder()
            .uri("/xrpc/com.atproto.server.describeServer")
            .header("x-forwarded-for", ip)
            .header("origin", "https://example.com")
            .body(Body::empty())
            .unwrap()
    };
    // Exhaust the cap, then the throttled response must still carry the CORS allow-origin header.
    let _ = router
        .clone()
        .oneshot(cors_req("203.0.113.5"))
        .await
        .unwrap();
    let resp = router.oneshot(cors_req("203.0.113.5")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp.headers().contains_key("access-control-allow-origin"),
        "429 must carry CORS headers so cross-origin clients can read it"
    );
}

#[tokio::test]
async fn sync_get_repo_is_exempt_from_global_cap() {
    let router = app(state_with_global_cap(1).await);
    // getRepo would 400 (missing params) but must never be throttled — many calls, no 429.
    for _ in 0..5 {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.getRepo")
                    .header("x-forwarded-for", "203.0.113.9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

async fn state_with_transfer_accept_cap(max: u64) -> AppState {
    let mut state = test_state().await;
    state.core.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&RateLimitConfig {
        enabled: true,
        transfer_accept_per_5min: max,
        ..RateLimitConfig::default()
    }));
    state
}

fn transfer_accept_req(ip: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/transfer/accept")
        .header("x-forwarded-for", ip)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

#[tokio::test]
async fn transfer_accept_endpoint_cap_rejects_over_budget_with_headers() {
    // `/v1/transfer/accept` authenticates on a bare 6-char code, so it lives in the tight
    // per-endpoint limiter. The global cap stays at its high default here, so only the
    // per-endpoint budget can trip.
    let state = state_with_transfer_accept_cap(2).await;
    let metrics = state.metrics.clone();
    let router = app(state);

    // The first two pass the limiter. The handler itself rejects the bogus code (some 4xx),
    // but never with a 429 — that is the limiter's signal alone.
    for _ in 0..2 {
        let resp = router
            .clone()
            .oneshot(transfer_accept_req("203.0.113.20"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // The third trips the per-endpoint cap: 429 with the standard envelope + RateLimit-* /
    // Retry-After headers, matching the other limited endpoints.
    let resp = router
        .clone()
        .oneshot(transfer_accept_req("203.0.113.20"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
    assert!(resp.headers().contains_key("ratelimit-limit"));
    assert!(resp.headers().contains_key("ratelimit-remaining"));
    assert!(resp.headers().contains_key("ratelimit-reset"));
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "RATE_LIMITED");

    // The rejection is counted against the endpoint_ip limiter.
    let rendered = metrics.render().unwrap().unwrap();
    assert!(
        rendered.contains("rate_limit_rejections_total")
            && rendered.contains(r#"limiter="endpoint_ip""#),
        "missing endpoint_ip rejection count in:\n{rendered}"
    );

    // A different IP has its own budget and is unaffected.
    let resp = router
        .oneshot(transfer_accept_req("203.0.113.21"))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn disabled_limiter_is_passthrough() {
    let mut state = test_state().await;
    state.core.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&RateLimitConfig {
        enabled: false,
        ..RateLimitConfig::default()
    }));
    let router = app(state);
    for _ in 0..50 {
        let resp = router
            .clone()
            .oneshot(describe_req("203.0.113.3"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
