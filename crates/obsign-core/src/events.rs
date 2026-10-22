//! Events from the core to the UI: the [`EventSink`] trait a shell implements, and [`emit`].
//!
//! Fire-and-forget. An event no UI is listening for is not an error the core can act on, so
//! an uninstalled sink drops it (tests never install one).

use std::sync::OnceLock;

use serde::Serialize;

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

static INSTALLED: OnceLock<Box<dyn EventSink>> = OnceLock::new();

/// Install the process-wide sink. The second and later calls are refused and hand the sink
/// back.
pub fn install(sink: Box<dyn EventSink>) -> Result<(), Box<dyn EventSink>> {
    INSTALLED.set(sink)
}

/// Send `event` with `payload` to the UI, if a sink is installed.
pub fn emit(event: &str, payload: impl Serialize) {
    let Some(sink) = INSTALLED.get() else {
        tracing::debug!(event, "no event sink installed; event dropped");
        return;
    };
    match serde_json::to_value(payload) {
        Ok(value) => sink.emit(event, value),
        Err(e) => tracing::warn!(event, error = %e, "event payload did not serialize"),
    }
}
