// pattern: Imperative Shell

//! The middleware stack every route group shares: tracing (joined to an incoming W3C trace
//! context), HTTP metrics, and rate limiting.

use axum::{http::Request, Router};
use opentelemetry::propagation::Extractor;
use tower_http::trace::TraceLayer;
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

/// Apply the middleware every route group shares, in the order axum layers them (outermost →
/// inner): Trace, then HTTP metrics, then rate limiting. Applied to each group *before* that
/// group's own (optional) CORS layer, so CORS — where present — stays the outermost layer:
/// preflight `OPTIONS` are answered before throttling, and a 429 still carries the CORS headers a
/// cross-origin client needs to read it. Trace stays outside the rate limiter so throttled
/// requests are still traced; the metrics counter sits outside the rate limiter so a 429 still
/// lands in `http_requests_total`, but inside CORS so short-circuited preflights don't pollute the
/// series. `from_fn_with_state` needs its own state clone; the middleware reads only `CoreState`,
/// so a router over any state that embeds it takes the same stack.
pub fn apply_shared_layers<S>(router: Router<S>, state: &CoreState) -> Router<S>
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
