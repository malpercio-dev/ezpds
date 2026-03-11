use anyhow::Context;
use common::TelemetryConfig;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Holds the OTel tracer provider and shuts it down (flushing all pending spans) on drop.
///
/// Keep this value alive for the full process lifetime. It is returned by
/// [`init_subscriber`] when telemetry is enabled and should be stored in `main` before
/// the server starts and dropped after the server completes its graceful shutdown.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("failed to flush OTel spans on shutdown: {e:?}");
        }
    }
}

/// Initialize the global tracing subscriber.
///
/// When `telemetry.enabled` is `true`, installs a layered subscriber that writes to both
/// stdout (the `fmt` layer, keeping existing log behaviour) and an OTLP-compatible
/// backend (the `opentelemetry` layer). Also registers the W3C Trace Context propagator
/// globally so that incoming `traceparent`/`tracestate` headers are honoured.
///
/// When `telemetry.enabled` is `false` (the default), only the `fmt` layer is installed —
/// identical to the previous behaviour with zero OTel overhead.
///
/// Returns an [`OtelGuard`] when telemetry is enabled. Drop it after the server shuts
/// down to guarantee all buffered spans are flushed before the process exits.
pub fn init_subscriber(telemetry: &TelemetryConfig) -> anyhow::Result<Option<OtelGuard>> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    if !telemetry.enabled {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;
        return Ok(None);
    }

    let resource = Resource::builder()
        .with_service_name(telemetry.service_name.clone())
        .build();

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&telemetry.otlp_endpoint)
        .build()
        .context("failed to build OTLP span exporter")?;

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    // W3C Trace Context propagator: extracts/injects `traceparent` and `tracestate` headers.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    opentelemetry::global::set_tracer_provider(provider.clone());

    let tracer = provider.tracer("relay");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    Ok(Some(OtelGuard { provider }))
}
