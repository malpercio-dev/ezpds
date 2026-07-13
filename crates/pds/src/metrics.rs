// pattern: Imperative Shell

//! OTel metrics meter + Prometheus registry behind `GET /metrics`.
//!
//! One [`Metrics`] value lives in `AppState` for the process lifetime and exposes a typed
//! handle per instrument — call sites record measurements through these fields rather than
//! looking instruments up by name. The meter rides the same `opentelemetry` 0.32 line as the
//! trace pipeline in `telemetry.rs`; the `opentelemetry-prometheus` bridge collects into a
//! `prometheus::Registry` that [`Metrics::render`] encodes as text exposition format.
//!
//! When `[telemetry] metrics_enabled = false`, [`Metrics::disabled`] builds the same typed
//! handles against a reader-less meter provider: measurements are dropped at the SDK
//! boundary, no registry exists, and `app()` never registers the route — so call sites stay
//! unconditional while the endpoint 404s.
//!
//! Instrument names and label keys live in [`names`] — the single source of truth the
//! documentation table in `crates/pds/AGENTS.md` mirrors. Counters are named **without**
//! the `_total` suffix: the Prometheus exporter appends it per the OpenTelemetry
//! Prometheus-compatibility spec (the unit test below pins the rendered names so drift or
//! a double suffix fails fast).

use anyhow::Context;
use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::metrics::{Counter, Gauge, Histogram, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
use prometheus::{Encoder, TextEncoder};

use crate::app::AppState;

/// Instrument names (as constructed on the meter; counters gain `_total` when rendered)
/// and label keys. Keep this module in lockstep with the table in `crates/pds/AGENTS.md`.
pub mod names {
    /// Gauge: currently connected `subscribeRepos` WebSocket subscribers.
    pub const FIREHOSE_SUBSCRIBERS: &str = "firehose_subscribers";
    /// Counter (`_total`): firehose frames emitted, by [`LABEL_FRAME`].
    pub const FIREHOSE_EVENTS: &str = "firehose_events";
    /// Gauge: age in seconds of the oldest retained `repo_seq` event (replay window depth).
    pub const FIREHOSE_BACKFILL_WINDOW_SECONDS: &str = "firehose_backfill_window_seconds";
    /// Counter (`_total`): outbound `requestCrawl` attempts, by [`LABEL_OUTCOME`].
    pub const RELAY_CRAWL_REQUESTS: &str = "relay_crawl_requests";
    /// Counter (`_total`): proxied upstream requests, by [`LABEL_UPSTREAM`] + [`LABEL_STATUS_CLASS`].
    pub const PROXY_REQUESTS: &str = "proxy_requests";
    /// Histogram: read-after-write upstream lag in seconds (from `Atproto-Upstream-Lag`).
    pub const PROXY_UPSTREAM_LAG_SECONDS: &str = "proxy_upstream_lag_seconds";
    /// Counter (`_total`): blobs deleted by the blob-GC sweep.
    pub const BLOB_GC_SWEPT: &str = "blob_gc_swept";
    /// Gauge: unix timestamp (seconds) of the last completed blob-GC run.
    pub const BLOB_GC_LAST_RUN_TIMESTAMP: &str = "blob_gc_last_run_timestamp";
    /// Counter (`_total`): accounts permanently deleted by the account reaper.
    pub const ACCOUNT_REAPER_SWEPT: &str = "account_reaper_swept";
    /// Gauge: unix timestamp (seconds) of the last completed account-reaper run.
    pub const ACCOUNT_REAPER_LAST_RUN_TIMESTAMP: &str = "account_reaper_last_run_timestamp";
    /// Counter (`_total`): claim attempts marked expired by the agent-claim sweep.
    pub const AGENT_CLAIM_SWEEP_SWEPT: &str = "agent_claim_sweep_swept";
    /// Gauge: unix timestamp (seconds) of the last completed agent-claim-sweep run.
    pub const AGENT_CLAIM_SWEEP_LAST_RUN_TIMESTAMP: &str = "agent_claim_sweep_last_run_timestamp";
    /// Counter (`_total`): stale `admin_nonces` rows deleted by the admin-nonce sweep.
    pub const ADMIN_NONCE_SWEEP_SWEPT: &str = "admin_nonce_sweep_swept";
    /// Gauge: unix timestamp (seconds) of the last completed admin-nonce-sweep run.
    pub const ADMIN_NONCE_SWEEP_LAST_RUN_TIMESTAMP: &str = "admin_nonce_sweep_last_run_timestamp";
    /// Counter (`_total`): `repo_seq` rows pruned by the firehose-GC sweep.
    pub const FIREHOSE_GC_SWEPT: &str = "firehose_gc_swept";
    /// Gauge: unix timestamp (seconds) of the last completed firehose-GC run.
    pub const FIREHOSE_GC_LAST_RUN_TIMESTAMP: &str = "firehose_gc_last_run_timestamp";
    /// Counter (`_total`): requests rejected with 429, by [`LABEL_LIMITER`].
    pub const RATE_LIMIT_REJECTIONS: &str = "rate_limit_rejections";
    /// Counter (`_total`): HTTP requests served, by [`LABEL_ROUTE`] + [`LABEL_STATUS_CLASS`].
    pub const HTTP_REQUESTS: &str = "http_requests";
    /// Counter (`_total`): `importRepo` migration imports, by [`LABEL_OUTCOME`].
    pub const MIGRATION_IMPORTS: &str = "migration_imports";

    /// Firehose frame type: `commit`, `sync`, `account`, `identity`.
    pub const LABEL_FRAME: &str = "frame";
    /// Operation outcome: `ok` or `error` (crawl also uses `rate_limited`).
    pub const LABEL_OUTCOME: &str = "outcome";
    /// Proxy upstream family: `appview`, `chat`, `moderation`, or `header_target` (an
    /// `app.bsky.*`/`chat.bsky.*` request whose caller-supplied `atproto-proxy` header
    /// overrode the namespace's default — the raw target DID/hostname is never a label
    /// value, per the cardinality rule).
    pub const LABEL_UPSTREAM: &str = "upstream";
    /// HTTP status class: `1xx` … `5xx`.
    pub const LABEL_STATUS_CLASS: &str = "status_class";
    /// Which limiter rejected: `global_ip`, `endpoint_ip`, `account_writes`.
    pub const LABEL_LIMITER: &str = "limiter";
    /// Matched route template (never the raw URI — cardinality stays bounded by the route
    /// table). Requests that match no route are labelled `unmatched`.
    pub const LABEL_ROUTE: &str = "route";
}

/// Lag histogram bucket boundaries in seconds. Chosen for the read-after-write path where
/// AppView indexing lag runs from tens of milliseconds (healthy) to minutes (upstream
/// incident); the tail buckets exist so a stuck upstream is distinguishable from a slow one.
/// Boundaries are baked into every stored series — changing them later breaks continuity
/// of recorded data, so extend deliberately.
const LAG_BUCKETS_SECONDS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

/// Typed handles for every instrument the PDS records, plus the Prometheus registry that
/// `GET /metrics` renders. Cheap to share via `Arc`; individual instruments are internally
/// reference-counted and thread-safe.
pub struct Metrics {
    /// `Some` only when metrics are enabled; `None` means measurements are dropped and
    /// there is nothing to render.
    registry: Option<prometheus::Registry>,
    /// Owns the metric pipeline; dropped with `AppState` at process exit. A scrape-driven
    /// pull exporter needs no explicit shutdown flush (unlike the span exporter's
    /// `OtelGuard`).
    _provider: SdkMeterProvider,

    pub firehose_subscribers: UpDownCounter<i64>,
    pub firehose_events: Counter<u64>,
    pub firehose_backfill_window_seconds: Gauge<f64>,
    pub relay_crawl_requests: Counter<u64>,
    pub proxy_requests: Counter<u64>,
    pub proxy_upstream_lag_seconds: Histogram<f64>,
    pub blob_gc_swept: Counter<u64>,
    pub blob_gc_last_run_timestamp: Gauge<f64>,
    pub account_reaper_swept: Counter<u64>,
    pub account_reaper_last_run_timestamp: Gauge<f64>,
    pub agent_claim_sweep_swept: Counter<u64>,
    pub agent_claim_sweep_last_run_timestamp: Gauge<f64>,
    pub admin_nonce_sweep_swept: Counter<u64>,
    pub admin_nonce_sweep_last_run_timestamp: Gauge<f64>,
    pub firehose_gc_swept: Counter<u64>,
    pub firehose_gc_last_run_timestamp: Gauge<f64>,
    pub rate_limit_rejections: Counter<u64>,
    pub http_requests: Counter<u64>,
    pub migration_imports: Counter<u64>,
}

impl Metrics {
    /// Build the enabled pipeline: meter provider → Prometheus bridge → registry.
    pub fn new(service_name: &str) -> anyhow::Result<Self> {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .context("failed to build Prometheus metrics exporter")?;
        let provider = SdkMeterProvider::builder()
            .with_reader(exporter)
            .with_resource(
                Resource::builder()
                    .with_service_name(service_name.to_string())
                    .build(),
            )
            .build();
        Ok(Self::from_parts(Some(registry), provider))
    }

    /// Build the disabled pipeline: same typed handles, no reader, nothing to render.
    /// Measurements recorded through these instruments are dropped by the SDK.
    pub fn disabled() -> Self {
        Self::from_parts(None, SdkMeterProvider::builder().build())
    }

    fn from_parts(registry: Option<prometheus::Registry>, provider: SdkMeterProvider) -> Self {
        use opentelemetry::metrics::MeterProvider as _;
        let meter = provider.meter("pds");
        Self {
            firehose_subscribers: meter
                .i64_up_down_counter(names::FIREHOSE_SUBSCRIBERS)
                .build(),
            firehose_events: meter.u64_counter(names::FIREHOSE_EVENTS).build(),
            firehose_backfill_window_seconds: meter
                .f64_gauge(names::FIREHOSE_BACKFILL_WINDOW_SECONDS)
                .build(),
            relay_crawl_requests: meter.u64_counter(names::RELAY_CRAWL_REQUESTS).build(),
            proxy_requests: meter.u64_counter(names::PROXY_REQUESTS).build(),
            proxy_upstream_lag_seconds: meter
                .f64_histogram(names::PROXY_UPSTREAM_LAG_SECONDS)
                .with_boundaries(LAG_BUCKETS_SECONDS.to_vec())
                .build(),
            blob_gc_swept: meter.u64_counter(names::BLOB_GC_SWEPT).build(),
            blob_gc_last_run_timestamp: meter.f64_gauge(names::BLOB_GC_LAST_RUN_TIMESTAMP).build(),
            account_reaper_swept: meter.u64_counter(names::ACCOUNT_REAPER_SWEPT).build(),
            account_reaper_last_run_timestamp: meter
                .f64_gauge(names::ACCOUNT_REAPER_LAST_RUN_TIMESTAMP)
                .build(),
            agent_claim_sweep_swept: meter.u64_counter(names::AGENT_CLAIM_SWEEP_SWEPT).build(),
            agent_claim_sweep_last_run_timestamp: meter
                .f64_gauge(names::AGENT_CLAIM_SWEEP_LAST_RUN_TIMESTAMP)
                .build(),
            admin_nonce_sweep_swept: meter.u64_counter(names::ADMIN_NONCE_SWEEP_SWEPT).build(),
            admin_nonce_sweep_last_run_timestamp: meter
                .f64_gauge(names::ADMIN_NONCE_SWEEP_LAST_RUN_TIMESTAMP)
                .build(),
            firehose_gc_swept: meter.u64_counter(names::FIREHOSE_GC_SWEPT).build(),
            firehose_gc_last_run_timestamp: meter
                .f64_gauge(names::FIREHOSE_GC_LAST_RUN_TIMESTAMP)
                .build(),
            rate_limit_rejections: meter.u64_counter(names::RATE_LIMIT_REJECTIONS).build(),
            http_requests: meter.u64_counter(names::HTTP_REQUESTS).build(),
            migration_imports: meter.u64_counter(names::MIGRATION_IMPORTS).build(),
            registry,
            _provider: provider,
        }
    }

    /// Encode the current registry contents as Prometheus text exposition format.
    /// Returns `None` when metrics are disabled (the route is not registered in that
    /// case, so in practice this is only `None` for direct callers in tests).
    pub fn render(&self) -> Option<anyhow::Result<String>> {
        let registry = self.registry.as_ref()?;
        let mut buf = Vec::new();
        let result = TextEncoder::new()
            .encode(&registry.gather(), &mut buf)
            .context("failed to encode metrics")
            .and_then(|()| String::from_utf8(buf).context("metrics output was not UTF-8"));
        Some(result)
    }
}

/// Record one measurement with a single label — the dominant call shape.
pub fn label(key: &'static str, value: impl Into<opentelemetry::Value>) -> KeyValue {
    KeyValue::new(key, value.into())
}

/// Current unix time in seconds, for the `*_last_run_timestamp` gauges.
pub fn unix_now() -> f64 {
    chrono::Utc::now().timestamp() as f64
}

/// RAII guard for the `firehose_subscribers` gauge: `+1` on construction, `−1` on drop.
///
/// The WebSocket handler holds one for the life of the connection, so every exit path —
/// clean close, lagged disconnect, error frame, task abort — decrements exactly once and
/// the gauge cannot drift from the true connection count.
pub struct SubscriberGuard(std::sync::Arc<Metrics>);

impl SubscriberGuard {
    pub fn connect(metrics: std::sync::Arc<Metrics>) -> Self {
        metrics.firehose_subscribers.add(1, &[]);
        Self(metrics)
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.0.firehose_subscribers.add(-1, &[]);
    }
}

/// Count every routed request into `http_requests_total` by route template + status class.
///
/// The route label comes from axum's [`MatchedPath`] — the template (`/xrpc/{method}`),
/// never the raw URI — so series cardinality is bounded by the route table. Requests that
/// match no route fall into a single `unmatched` series. Layered outside the rate limiter
/// (so 429s are counted) and inside CORS (so short-circuited preflights are not).
pub async fn http_metrics_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let response = next.run(req).await;
    state.metrics.http_requests.add(
        1,
        &[
            label(names::LABEL_ROUTE, route),
            label(
                names::LABEL_STATUS_CLASS,
                status_class(response.status().as_u16()),
            ),
        ],
    );
    response
}

/// Collapse an HTTP status code into its class label value (`2xx`, `4xx`, …).
pub fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the rendered Prometheus names: the exporter must append `_total` to counters
    /// exactly once, and gauges keep their bare names. A change in exporter suffix
    /// behaviour (or an accidental `_total` in `names::*`) fails here, not in production
    /// dashboards.
    #[test]
    fn rendered_names_match_prometheus_conventions() {
        let metrics = Metrics::new("test-pds").unwrap();
        metrics.http_requests.add(
            1,
            &[
                label(names::LABEL_ROUTE, "/xrpc/_health"),
                label(names::LABEL_STATUS_CLASS, "2xx"),
            ],
        );
        metrics.firehose_subscribers.add(1, &[]);
        metrics
            .firehose_events
            .add(1, &[label(names::LABEL_FRAME, "commit")]);
        metrics.proxy_upstream_lag_seconds.record(0.2, &[]);
        metrics
            .blob_gc_last_run_timestamp
            .record(1_700_000_000.0, &[]);

        let rendered = metrics.render().unwrap().unwrap();

        assert!(
            rendered.contains("http_requests_total{"),
            "missing/mis-suffixed http_requests_total in:\n{rendered}"
        );
        assert!(
            !rendered.contains("http_requests_total_total"),
            "double _total suffix in:\n{rendered}"
        );
        assert!(
            rendered.contains("firehose_subscribers"),
            "missing firehose_subscribers gauge in:\n{rendered}"
        );
        assert!(
            rendered.contains("firehose_events_total{"),
            "missing firehose_events_total in:\n{rendered}"
        );
        assert!(
            rendered.contains("proxy_upstream_lag_seconds_bucket"),
            "missing lag histogram buckets in:\n{rendered}"
        );
        assert!(
            rendered.contains("blob_gc_last_run_timestamp"),
            "missing blob_gc_last_run_timestamp gauge in:\n{rendered}"
        );
    }

    #[test]
    fn disabled_metrics_render_nothing_and_drop_measurements() {
        let metrics = Metrics::disabled();
        metrics.http_requests.add(1, &[]);
        assert!(metrics.render().is_none());
    }

    #[test]
    fn status_class_covers_all_classes() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(429), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(101), "1xx");
        assert_eq!(status_class(302), "3xx");
        assert_eq!(status_class(999), "other");
    }
}
