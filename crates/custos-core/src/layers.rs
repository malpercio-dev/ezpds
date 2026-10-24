// pattern: Imperative Shell

//! The middleware stack every route group shares: tracing (joined to an incoming W3C trace
//! context), HTTP metrics, and rate limiting. [`public_surface`] and [`internal_surface`] are the
//! only ways to apply it, so `pds::app` and every feature crate's `test_app` run one stack.

use axum::{http::Request, Router};
use opentelemetry::propagation::Extractor;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::CoreState;

/// Wraps an `axum::http::HeaderMap` as an OTel text-map [`Extractor`] so that
/// the W3C `traceparent` and `tracestate` headers can be read by the global propagator.
struct HeaderMapCarrier<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderMapCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| {
            v.to_str().map_or_else(
                |_| {
                    tracing::debug!(
                        header = key,
                        "trace propagation header contains non-UTF-8 bytes; ignoring"
                    );
                    None
                },
                Some,
            )
        })
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Custom `MakeSpan` for [`TraceLayer`] that:
///  1. Creates an `info_span` with standard HTTP attributes pre-declared.
///  2. Extracts an incoming W3C `traceparent` header and sets it as the parent context
///     on the new span so upstream traces are joined correctly.
#[derive(Clone, Default)]
struct OtelMakeSpan;

impl<B> tower_http::trace::MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> tracing::Span {
        let span = tracing::info_span!(
            "HTTP request",
            http.method = %request.method(),
            http.target = request.uri().path_and_query().map_or("", |pq| pq.as_str()),
            http.status_code = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        );

        // Inject parent trace context from incoming W3C traceparent/tracestate headers.
        // When telemetry is disabled the global propagator is a no-op, so this is free.
        let parent_cx = opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&HeaderMapCarrier(request.headers()))
        });
        // set_parent only errs when the span has no OTel layer attached (telemetry
        // disabled) — the request must still be served, just without a joined trace.
        if let Err(e) = span.set_parent(parent_cx) {
            tracing::trace!(error = %e, "could not attach parent trace context to span");
        }
        span
    }
}

/// The public surface (landing, `.well-known`, OAuth, agent registration, all XRPC, static
/// assets): the shared stack, then the XRPC error dialect, then permissive CORS outermost.
///
/// The error-dialect boundary sits outside the shared layers, so a rate-limit 429 is re-shaped
/// too, but inside CORS: `/xrpc/*` errors leave in the flat AT Protocol shape atproto clients
/// dispatch on, while every other path keeps the nested provisioning envelope (see
/// [`crate::xrpc_error_shape`]). Permissive CORS is safe ONLY because authentication is never
/// cookie-based (all Bearer/DPoP/signed-request); see the invariant in `crates/pds/AGENTS.md`.
pub fn public_surface<S>(router: Router<S>, state: &CoreState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    internal_surface(router, state)
        .layer(axum::middleware::from_fn(
            crate::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(CorsLayer::permissive())
}

/// The admin (`/v1/admin/*`) and provisioning (`/v1/*`) surface, and the stack every surface
/// shares, in the order axum layers them (outermost → inner): Trace, then HTTP metrics, then rate
/// limiting. These routes are called same-origin by first-party native clients and operators,
/// never by a browser on another origin, so they get no CORS layer.
///
/// [`public_surface`] wraps this stack in CORS, so preflight `OPTIONS` are answered before
/// throttling and a 429 still carries the CORS headers a cross-origin client needs to read it.
/// Trace stays outside the rate limiter so throttled requests are still traced; the metrics
/// counter sits outside the rate limiter so a 429 still lands in `http_requests_total`, but
/// inside CORS so short-circuited preflights don't pollute the series. `from_fn_with_state`
/// needs its own state clone; the middleware reads only `CoreState`, so a router over any state
/// that embeds it takes the same stack.
pub fn internal_surface<S>(router: Router<S>, state: &CoreState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::metrics::http_metrics_middleware,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(OtelMakeSpan))
}

#[cfg(test)]
mod header_carrier_tests {
    use super::*;
    use axum::http::HeaderMap;
    use opentelemetry::propagation::Extractor;

    #[test]
    fn get_returns_ascii_header_value() {
        let mut map = HeaderMap::new();
        map.insert("traceparent", "00-abc123-def456-01".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        assert_eq!(carrier.get("traceparent"), Some("00-abc123-def456-01"));
    }

    #[test]
    fn get_returns_none_for_absent_header() {
        let map = HeaderMap::new();
        let carrier = HeaderMapCarrier(&map);
        assert_eq!(carrier.get("traceparent"), None);
    }

    #[test]
    fn get_is_case_insensitive_via_header_map() {
        let mut map = HeaderMap::new();
        // HTTP/2 headers are lower-case; HeaderMap normalises on insert.
        map.insert("tracestate", "vendor=value".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        // HeaderMap normalises to lower-case, so look-up is case-insensitive.
        assert_eq!(carrier.get("tracestate"), Some("vendor=value"));
    }

    #[test]
    fn keys_returns_all_header_names() {
        let mut map = HeaderMap::new();
        map.insert("traceparent", "value1".parse().unwrap());
        map.insert("tracestate", "value2".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        let keys = carrier.keys();
        assert!(keys.contains(&"traceparent"));
        assert!(keys.contains(&"tracestate"));
        assert_eq!(keys.len(), 2);
    }
}

#[cfg(test)]
mod surface_tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use common::{ApiError, ErrorCode};
    use tower::ServiceExt;

    async fn failing() -> Result<&'static str, ApiError> {
        Err(ApiError::new(ErrorCode::TokenExpired, "token has expired"))
    }

    async fn call(router: Router, method: &str, path: &str) -> axum::response::Response {
        router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn surface(
        wrap: fn(Router<CoreState>, &CoreState) -> Router<CoreState>,
        state: CoreState,
    ) -> Router {
        let routes = Router::new().route("/xrpc/com.example.method", get(failing));
        wrap(routes, &state).with_state(state)
    }

    #[tokio::test]
    async fn public_surface_flattens_xrpc_errors_and_answers_cors() {
        let state = crate::test_support::test_state().await;
        let app = surface(public_surface, state);

        let preflight = call(app.clone(), "OPTIONS", "/xrpc/com.example.method").await;
        assert!(preflight
            .headers()
            .contains_key("access-control-allow-origin"));

        let body = json(call(app, "GET", "/xrpc/com.example.method").await).await;
        assert_eq!(body["error"], "ExpiredToken", "flat XRPC shape");
    }

    /// Feature suites get lexicon output validation from `test_support::test_app`: a registered
    /// XRPC output missing its required fields panics the route test.
    #[tokio::test]
    #[should_panic(expected = "Output must have the property \"accessJwt\"")]
    async fn test_app_validates_xrpc_output() {
        async fn drifted() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({}))
        }
        let state = crate::test_support::test_state().await;
        let routes = Router::new().route("/xrpc/com.atproto.server.createSession", get(drifted));
        let app = crate::test_support::test_app(routes, Router::new(), state);
        call(app, "GET", "/xrpc/com.atproto.server.createSession").await;
    }

    #[tokio::test]
    async fn internal_surface_has_no_cors_and_keeps_nested_errors() {
        let state = crate::test_support::test_state().await;
        let app = surface(internal_surface, state);

        let preflight = call(app.clone(), "OPTIONS", "/xrpc/com.example.method").await;
        assert!(!preflight
            .headers()
            .contains_key("access-control-allow-origin"));

        let body = json(call(app, "GET", "/xrpc/com.example.method").await).await;
        assert_eq!(body["error"]["code"], "TOKEN_EXPIRED", "nested envelope");
    }
}
