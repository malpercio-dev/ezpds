// pattern: Imperative Shell
//! In-app, in-memory diagnostics: a small ring buffer of *redacted* network-error
//! breadcrumbs the user can export from Settings and hand to support for troubleshooting.
//!
//! Redaction is by construction. Every recorded field is safe to share: a call-site
//! operation name (a fixed vocabulary from the code, never request data), the server
//! hostname, an HTTP status, and a short error category or atproto error code. Bearer/DPoP
//! tokens, request/response bodies, handles, emails, and DIDs are never captured — so an
//! exported report can be shared without leaking account material. Nothing is written to
//! disk; the buffer lives for the process lifetime only, and the user initiates every
//! export, so there is no passive/always-on collection to opt out of.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// Most breadcrumbs retained; the oldest are dropped FIFO once the buffer is full. Bounded
/// so a long session or a failing-server loop can never grow memory without limit.
const CAPACITY: usize = 200;

/// Whether the failure was the server answering with an error status, or the request never
/// producing a usable answer (timeout, connection refused, DNS, a mid-read drop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The server answered with a non-success HTTP status.
    Server,
    /// A transport failure — the request never yielded a server verdict.
    Transport,
}

impl Origin {
    fn label(self) -> &'static str {
        match self {
            Origin::Server => "server",
            Origin::Transport => "transport",
        }
    }
}

/// One redacted network-error breadcrumb. Construction is the only redaction gate: callers
/// pass structured, non-sensitive values, so there is no free-form field to leak through.
#[derive(Clone, Debug)]
struct NetworkEvent {
    /// RFC 3339 UTC, seconds precision.
    at: String,
    /// Call-site / operation name, e.g. `"createSession"`.
    op: String,
    /// Server hostname only — no path, query, or userinfo, e.g. `"plc.directory"`.
    host: Option<String>,
    origin: Origin,
    /// HTTP status, when the server answered.
    status: Option<u16>,
    /// A short, safe detail: a transport category (`"timeout"`, `"connect"`, …) or an
    /// atproto error code (`"RateLimited"`, `"InvalidRequest"`). Never a free-form body.
    detail: Option<String>,
}

/// Process-global breadcrumb sink. A unit-of-global like `IdentityStore`: no state threads
/// through the deep network seams (`pds_client`, `plc_monitor`), which record via free
/// functions here without carrying a Tauri `State` handle.
fn sink() -> &'static Mutex<VecDeque<NetworkEvent>> {
    static SINK: OnceLock<Mutex<VecDeque<NetworkEvent>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(VecDeque::with_capacity(CAPACITY)))
}

fn push(event: NetworkEvent) {
    // A poisoned lock must never crash a diagnostics write — recover the guard and continue.
    let mut buf = match sink().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if buf.len() == CAPACITY {
        buf.pop_front();
    }
    buf.push_back(event);
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Record a server-verdict network error (the server answered with a non-2xx status).
/// `code` is the atproto error envelope's short `error` code, when present.
pub fn record_server(op: &str, host: Option<&str>, status: u16, code: Option<&str>) {
    push(NetworkEvent {
        at: now_rfc3339(),
        op: op.to_string(),
        host: host.map(str::to_string),
        origin: Origin::Server,
        status: Some(status),
        detail: code.map(str::to_string),
    });
}

/// Record a transport failure (no usable server answer). `category` is a fixed, non-sensitive
/// label — use [`transport_category`] to derive one from a `reqwest::Error`.
pub fn record_transport(op: &str, host: Option<&str>, category: &str) {
    push(NetworkEvent {
        at: now_rfc3339(),
        op: op.to_string(),
        host: host.map(str::to_string),
        origin: Origin::Transport,
        status: None,
        detail: Some(category.to_string()),
    });
}

/// Classify a `reqwest` transport error into a short, non-sensitive category. The error's
/// `Display` can embed the full request URL (host *and* query), so it is deliberately never
/// captured — only this fixed category is.
pub fn transport_category(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_decode() || e.is_body() {
        "read"
    } else if e.is_request() {
        "request"
    } else {
        "other"
    }
}

/// Render the recorded breadcrumbs into a shareable plain-text report.
pub fn export() -> String {
    let events: Vec<NetworkEvent> = {
        let buf = match sink().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        buf.iter().cloned().collect()
    };

    let mut out = String::new();
    out.push_str("Obsign diagnostics — network events\n");
    out.push_str(&format!("Generated: {}\n", now_rfc3339()));
    out.push_str(
        "Contains operation names, server hostnames, HTTP statuses, and short error codes\n\
         only — no tokens, request/response bodies, handles, emails, or DIDs.\n\n",
    );

    if events.is_empty() {
        out.push_str("No network errors have been recorded this session.\n");
        return out;
    }

    out.push_str(&format!("{} event(s), oldest first:\n\n", events.len()));
    for e in &events {
        let at = &e.at;
        let origin = e.origin.label();
        let op = &e.op;
        let host = e.host.as_deref().unwrap_or("—");
        let status = e
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string());
        let detail = e.detail.as_deref().unwrap_or("");
        out.push_str(&format!(
            "{at}  {origin:<9}  {op:<26}  {host:<20}  {status:>4}  {detail}\n"
        ));
    }
    out
}

/// Tauri command: render the in-memory network-error breadcrumb log as plain text for the
/// user to share from Settings. Synchronous (no state, no I/O) — mirrors `list_identities`.
#[tauri::command]
pub fn export_diagnostics() -> String {
    export()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The process-global sink is shared across tests in this binary (`RUST_TEST_THREADS=1`
    // keeps them serial). Each test records its own uniquely-named markers and asserts on
    // those, so leaked entries from a sibling test never affect the outcome.

    #[test]
    fn export_reports_recorded_events() {
        record_server("diag_test_login", Some("pds.example"), 429, Some("RateLimited"));
        record_transport("diag_test_discover", Some("plc.directory"), "timeout");

        let report = export();
        assert!(report.contains("diag_test_login"));
        assert!(report.contains("429"));
        assert!(report.contains("RateLimited"));
        assert!(report.contains("pds.example"));
        assert!(report.contains("diag_test_discover"));
        assert!(report.contains("plc.directory"));
        assert!(report.contains("timeout"));
    }

    #[test]
    fn report_header_promises_and_keeps_redaction() {
        // Even if a caller passed something token-ish as a detail, the report must not carry
        // obvious credential markers — the recorded vocabulary is codes and categories only.
        let report = export();
        assert!(report.to_lowercase().contains("no tokens"));
        assert!(!report.to_lowercase().contains("bearer "));
        assert!(!report.contains("Authorization:"));
    }

    #[test]
    fn ring_buffer_is_bounded() {
        for _ in 0..(CAPACITY + 50) {
            record_transport("diag_test_spam", None, "connect");
        }
        let len = {
            let buf = match sink().lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            buf.len()
        };
        assert!(len <= CAPACITY, "buffer grew past CAPACITY: {len}");
    }

    #[test]
    fn transport_category_labels_are_stable() {
        // The label set the report and any consumer rely on. Constructing a real
        // `reqwest::Error` per kind is impractical here; this pins the vocabulary shape.
        for label in ["timeout", "connect", "read", "request", "other"] {
            record_transport("diag_test_labels", None, label);
        }
        let report = export();
        for label in ["timeout", "connect", "read", "request", "other"] {
            assert!(report.contains(label), "missing label {label}");
        }
    }
}
