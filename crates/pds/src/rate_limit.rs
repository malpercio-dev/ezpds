// pattern: Imperative Shell

//! Request rate limiting: the shared limiter state and the Axum middleware that enforces it.
//!
//! The pure sliding-window algorithm lives in [`crate::auth::rate_limit`] (a Functional Core); this
//! module owns the process-level mutable state (one `Mutex<MultiWindowLimiter>` per limiter) and
//! the HTTP glue — client-IP resolution, exempt paths, and the standard `RateLimit-*` /
//! `Retry-After` response headers.
//!
//! Three limiter families, mirroring the reference PDS (`packages/pds/src/rate-limits.ts`):
//!
//! 1. **Global per-IP** — every request costs 1 point against its client IP; `getRepo`,
//!    `subscribeRepos`, and `_health` are exempt so relay backfill/firehose and platform health
//!    checks are never throttled.
//! 2. **Per-endpoint per-IP** — tighter caps on the sensitive auth/account endpoints
//!    (`createAccount`/`createSession`/`resetPassword`/`updateHandle`) plus the short-code-
//!    authenticated `/v1/transfer/accept`, keyed by client IP.
//! 3. **Per-account write points** — the four repo-write routes spend create=3/update=2/delete=1
//!    points against the *authenticated* DID over an hourly and a daily window. Enforced in
//!    [`crate::record_write::commit_repo_write`] where the verified DID is known (keying on an
//!    unverified token subject would let anyone drain a victim's budget).
//!
//! All limiters are pure pass-throughs when `[rate_limit] enabled = false` (the test harness sets
//! this so unit tests are never throttled).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode, RateLimitConfig};

use crate::app::AppState;
use crate::auth::rate_limit::{MultiWindowLimiter, RateLimitDecision, Window};

const FIVE_MIN: Duration = Duration::from_secs(5 * 60);
const ONE_HOUR: Duration = Duration::from_secs(60 * 60);
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Point cost of each repo-write action, matching the reference PDS write-point model.
pub const WRITE_COST_CREATE: u64 = 3;
pub const WRITE_COST_UPDATE: u64 = 2;
pub const WRITE_COST_DELETE: u64 = 1;

/// Paths exempt from the global per-IP cap: high-volume relay sync (never abuse) and the platform
/// health probe (must not be throttled or the host looks unhealthy under load).
fn is_global_exempt(path: &str) -> bool {
    matches!(
        path,
        "/xrpc/com.atproto.sync.getRepo"
            | "/xrpc/com.atproto.sync.subscribeRepos"
            | "/xrpc/_health"
    )
}

/// Shared rate-limiter state, held in [`AppState`] behind an `Arc`.
///
/// Each limiter is an independent `Mutex<MultiWindowLimiter>`; the critical section is a few
/// microseconds of in-memory bookkeeping and never awaits, so a `std::sync::Mutex` is correct
/// (and cheaper than an async lock).
pub struct RateLimiterState {
    enabled: bool,
    global_ip: Mutex<MultiWindowLimiter>,
    /// Per-endpoint IP limiters keyed by exact request path. Values are `Arc`-shared so several
    /// paths that must draw from one budget (the account-creation entry points) can point at the
    /// same limiter instance.
    endpoints: HashMap<&'static str, Arc<Mutex<MultiWindowLimiter>>>,
    write_points: Mutex<MultiWindowLimiter>,
}

impl RateLimiterState {
    /// Build the limiter set from configuration. A knob of `0` disables that limiter (see
    /// [`MultiWindowLimiter::new`], which drops zero-max windows).
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let per_5min = |max: u64| {
            Arc::new(Mutex::new(MultiWindowLimiter::new([Window {
                window: FIVE_MIN,
                max_points: max,
            }])))
        };

        // The account-creation cap applies to the reference XRPC path and to the
        // native provisioning routes. All three share *one* limiter instance so the
        // IP-keyed budget is enforced across every entry point — otherwise a client could triple its
        // allowance by rotating between paths.
        let mut endpoints: HashMap<&'static str, Arc<Mutex<MultiWindowLimiter>>> = HashMap::new();
        let create_account = per_5min(cfg.create_account_per_5min);
        for path in [
            "/xrpc/com.atproto.server.createAccount",
            "/v1/accounts",
            "/v1/accounts/mobile",
        ] {
            endpoints.insert(path, create_account.clone());
        }
        // Password and sovereign session creation share one per-IP budget. They mint the same
        // full-access credential, so alternating authentication mechanisms must not double it.
        let create_session = per_5min(cfg.create_session_per_5min);
        endpoints.insert(
            "/xrpc/com.atproto.server.createSession",
            create_session.clone(),
        );
        endpoints.insert("/v1/sessions/sovereign", create_session);
        endpoints.insert(
            "/xrpc/com.atproto.server.resetPassword",
            per_5min(cfg.reset_password_per_5min),
        );
        endpoints.insert(
            "/xrpc/com.atproto.identity.updateHandle",
            per_5min(cfg.update_handle_per_5min),
        );
        // Pattern: endpoints authenticated by a bare short code (rather than a session or bearer
        // token) belong in this tight per-endpoint limiter by default — the code *is* the
        // credential, so the generous global cap alone leaves too much room to brute-force it.
        // `/v1/transfer/accept` (a 6-char transfer code) was the first; the claim-ceremony
        // confirm endpoint carries the same 6-digit-code guessing surface (its session auth
        // gates *who* may confirm, not *how many* codes they can try).
        endpoints.insert(
            "/v1/transfer/accept",
            per_5min(cfg.transfer_accept_per_5min),
        );
        // The preview endpoint shares the confirm limiter *instance* (like the createAccount
        // trio): both validate the same guessable 6-digit user_code, so splitting the budget
        // would double an attacker's guess allowance by alternating endpoints.
        let claim_confirm = per_5min(cfg.agent_claim_confirm_per_5min);
        endpoints.insert("/agent/identity/claim/confirm", claim_confirm.clone());
        endpoints.insert("/v1/agents/claim-preview", claim_confirm);
        // The escrow-recovery pair. `release` validates an emailed OTP (the guessable-credential
        // class), and `initiate` mints one; they **share one limiter instance** so alternating the
        // two endpoints can't double an attacker's per-IP OTP-guess budget — the same reasoning as
        // the claim confirm/preview pair above.
        let recovery = per_5min(cfg.recovery_per_5min);
        endpoints.insert("/v1/recovery/initiate", recovery.clone());
        endpoints.insert("/v1/recovery/release", recovery);

        Self {
            enabled: cfg.enabled,
            global_ip: Mutex::new(MultiWindowLimiter::new([Window {
                window: FIVE_MIN,
                max_points: cfg.global_ip_per_5min,
            }])),
            endpoints,
            write_points: Mutex::new(MultiWindowLimiter::new([
                Window {
                    window: ONE_HOUR,
                    max_points: cfg.write_points_hourly,
                },
                Window {
                    window: ONE_DAY,
                    max_points: cfg.write_points_daily,
                },
            ])),
        }
    }

    /// Charge `cost` write points to `did`'s repo-write budget. Returns
    /// [`ErrorCode::RateLimited`] (429) when the hourly or daily budget is exhausted, so the four
    /// repo-write handlers surface the standard error envelope. A no-op when disabled.
    pub fn check_write_points(&self, did: &str, cost: u64) -> Result<(), ApiError> {
        if !self.enabled {
            return Ok(());
        }
        let decision = lock(&self.write_points).check(did, cost, Instant::now());
        if decision.allowed {
            Ok(())
        } else {
            // Carry the same Retry-After / RateLimit-* headers the middleware sets, so a client
            // hitting the write budget learns when to retry (the error envelope alone can't).
            Err(ApiError::new(
                ErrorCode::RateLimited,
                "repo write rate limit exceeded; slow down and retry later",
            )
            .with_header("retry-after", decision.reset_after_secs.to_string())
            .with_header("ratelimit-limit", decision.limit.to_string())
            .with_header("ratelimit-remaining", decision.remaining.to_string())
            .with_header("ratelimit-reset", decision.reset_after_secs.to_string()))
        }
    }
}

/// Recover a `Mutex` guard even if a previous holder panicked: rate-limit accounting is
/// self-healing (a poisoned map is still valid data), so we prefer availability over propagating
/// the poison and turning every subsequent request into a 500.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Resolve the client IP for keying. Behind the production edge proxy (Railway) the TCP peer is the
/// proxy, so the real client is read from `X-Forwarded-For` (leftmost entry = original client),
/// falling back to the TCP peer and finally a shared `"unknown"` bucket.
///
/// **Assumption:** the edge proxy is trusted to set `X-Forwarded-For`. A client can prepend a
/// spoofed value, which is the well-known limitation of any XFF-keyed limiter; the global cap is
/// defence-in-depth, not an authentication boundary.
fn client_ip(headers: &HeaderMap, connect_info: Option<&ConnectInfo<SocketAddr>>) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff
            .split(',')
            .map(str::trim)
            .find(|s| s.parse::<IpAddr>().is_ok())
        {
            return first.to_string();
        }
    }
    if let Some(ConnectInfo(addr)) = connect_info {
        return addr.ip().to_string();
    }
    "unknown".to_string()
}

/// Attach `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` to a response from a
/// limiter decision. `RateLimit-Reset` is a *delta-seconds* value (seconds until capacity frees),
/// per the IETF `RateLimit` header fields draft, so it's consistent with `Retry-After` — not an
/// absolute Unix timestamp.
fn apply_rate_limit_headers(resp: &mut Response, decision: &RateLimitDecision) {
    let headers = resp.headers_mut();
    headers.insert("ratelimit-limit", HeaderValue::from(decision.limit));
    headers.insert("ratelimit-remaining", HeaderValue::from(decision.remaining));
    headers.insert(
        "ratelimit-reset",
        HeaderValue::from(decision.reset_after_secs),
    );
}

/// Count one 429 into `rate_limit_rejections_total{limiter=...}`. The write-points limiter
/// counts at its call site in `record_write` (it rejects deep in the write path, not here).
fn count_rejection(state: &AppState, limiter: &'static str) {
    state.metrics.rate_limit_rejections.add(
        1,
        &[crate::metrics::label(
            crate::metrics::names::LABEL_LIMITER,
            limiter,
        )],
    );
}

/// Build the 429 response for a rejected request: the standard error envelope plus the
/// `RateLimit-*` headers and a `Retry-After` delta.
fn rate_limited_response(decision: &RateLimitDecision, scope: &str) -> Response {
    let mut resp = ApiError::new(
        ErrorCode::RateLimited,
        format!("rate limit exceeded ({scope}); slow down and retry later"),
    )
    .into_response();
    apply_rate_limit_headers(&mut resp, decision);
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from(decision.reset_after_secs),
    );
    resp
}

/// Axum middleware enforcing the global per-IP and per-endpoint per-IP limits.
///
/// `ConnectInfo` is optional so the router still works in tests driven without a connected socket
/// (`oneshot`); production always has it via `into_make_service_with_connect_info`. Per-account
/// write points are enforced deeper in the write path, not here (see the module docs).
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // axum 0.8 dropped the blanket `Option<T>` extractor; ConnectInfo lives in the
    // request extensions, so read it there (absent under `oneshot` test harnesses).
    let connect_info = req.extensions().get::<ConnectInfo<SocketAddr>>().copied();
    let limiter = &state.rate_limiter;
    if !limiter.enabled {
        return next.run(req).await;
    }

    let now = Instant::now();
    let path = req.uri().path().to_string();
    let ip = client_ip(req.headers(), connect_info.as_ref());

    // Track the tightest applicable decision so its headers ride on the eventual success response.
    let mut tightest: Option<RateLimitDecision> = None;

    if !is_global_exempt(&path) {
        let decision = lock(&limiter.global_ip).check(&ip, 1, now);
        if !decision.allowed {
            count_rejection(&state, "global_ip");
            return rate_limited_response(&decision, "global");
        }
        tightest = Some(decision);
    }

    if let Some(endpoint) = limiter.endpoints.get(path.as_str()) {
        let decision = lock(endpoint).check(&ip, 1, now);
        if !decision.allowed {
            count_rejection(&state, "endpoint_ip");
            return rate_limited_response(&decision, "endpoint");
        }
        tightest = Some(match tightest {
            Some(prev) if prev.remaining <= decision.remaining => prev,
            _ => decision,
        });
    }

    let mut response = next.run(req).await;
    if let Some(decision) = tightest {
        apply_rate_limit_headers(&mut response, &decision);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{app, test_state};
    use axum::body::Body;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    fn cfg(enabled: bool) -> RateLimitConfig {
        RateLimitConfig {
            enabled,
            ..RateLimitConfig::default()
        }
    }

    #[test]
    fn client_ip_prefers_xff_leftmost() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h, None), "203.0.113.7");
    }

    #[test]
    fn client_ip_skips_garbage_xff_entries() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "garbage, 198.51.100.9".parse().unwrap());
        assert_eq!(client_ip(&h, None), "198.51.100.9");
    }

    #[test]
    fn client_ip_falls_back_to_connect_info_then_unknown() {
        let h = HeaderMap::new();
        let ci = ConnectInfo("192.0.2.5:1234".parse::<SocketAddr>().unwrap());
        assert_eq!(client_ip(&h, Some(&ci)), "192.0.2.5");
        assert_eq!(client_ip(&h, None), "unknown");
    }

    #[test]
    fn write_points_disabled_never_limits() {
        let rl = RateLimiterState::new(&cfg(false));
        for _ in 0..10_000 {
            assert!(rl
                .check_write_points("did:plc:x", WRITE_COST_CREATE)
                .is_ok());
        }
    }

    #[test]
    fn write_points_exhaust_daily_budget() {
        let rl = RateLimiterState::new(&RateLimitConfig {
            enabled: true,
            write_points_hourly: 0, // disable hourly; test the daily budget alone
            write_points_daily: 5,
            ..RateLimitConfig::default()
        });
        // create=3 then create=3 would be 6 > 5 → second rejected.
        assert!(rl
            .check_write_points("did:plc:a", WRITE_COST_CREATE)
            .is_ok());
        assert!(rl
            .check_write_points("did:plc:a", WRITE_COST_CREATE)
            .is_err());
        // A different account has its own budget.
        assert!(rl
            .check_write_points("did:plc:b", WRITE_COST_CREATE)
            .is_ok());
    }

    async fn state_with_global_cap(max: u64) -> AppState {
        let mut state = test_state().await;
        state.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&RateLimitConfig {
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
        assert_eq!(json["error"]["code"], "RATE_LIMITED");

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
        state.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&RateLimitConfig {
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
        state.rate_limiter = std::sync::Arc::new(RateLimiterState::new(&cfg(false)));
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
}
