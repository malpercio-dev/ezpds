// pattern: Imperative Shell
//! In-memory, operator-exported network diagnostics.
//!
//! Redaction is structural: callers can record only a fixed operation, a relay URL whose
//! hostname is extracted here, and one of two fixed relay error codes. Request bodies,
//! signed headers, device-key material, admin credentials, and claim/invite codes never
//! enter this module. Events live only for the current process and are bounded FIFO.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const CAPACITY: usize = 200;

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    PairDevice,
    SignedRelayRequest,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::PairDevice => "pair_device",
            Self::SignedRelayRequest => "signed_relay_request",
        }
    }
}

#[derive(Clone, Debug)]
struct NetworkEvent {
    at: String,
    op: Operation,
    host: String,
    code: &'static str,
    status: Option<u16>,
}

fn sink() -> &'static Mutex<VecDeque<NetworkEvent>> {
    static SINK: OnceLock<Mutex<VecDeque<NetworkEvent>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(VecDeque::with_capacity(CAPACITY)))
}

fn push(event: NetworkEvent) {
    let mut events = match sink().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if events.len() == CAPACITY {
        events.pop_front();
    }
    events.push_back(event);
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn relay_host(relay_url: &str) -> String {
    reqwest::Url::parse(relay_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown-relay".to_string())
}

pub fn record_unreachable(op: Operation, relay_url: &str) {
    push(NetworkEvent {
        at: now_rfc3339(),
        op,
        host: relay_host(relay_url),
        code: "UNREACHABLE",
        status: None,
    });
}

pub fn record_relay_rejected(op: Operation, relay_url: &str, status: u16) {
    push(NetworkEvent {
        at: now_rfc3339(),
        op,
        host: relay_host(relay_url),
        code: "RELAY_REJECTED",
        status: Some(status),
    });
}

pub fn export() -> String {
    let events: Vec<NetworkEvent> = {
        let events = match sink().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        events.iter().cloned().collect()
    };

    let mut out = String::from("Brass Console diagnostics — network events\n");
    out.push_str(&format!("Generated: {}\n", now_rfc3339()));
    out.push_str(
        "Contains operation names, relay hostnames, HTTP statuses, and short error codes only —\n\
         no signed envelopes, device keys, admin credentials, claim codes, or invite codes.\n\n",
    );

    if events.is_empty() {
        out.push_str("No network errors have been recorded this session.\n");
        return out;
    }

    out.push_str(&format!("{} event(s), oldest first:\n\n", events.len()));
    for event in events {
        let status = event
            .status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "—".to_string());
        out.push_str(&format!(
            "{}  {:<21}  {:<28}  {:>4}  {}\n",
            event.at,
            event.op.label(),
            event.host,
            status,
            event.code,
        ));
    }
    out
}

#[tauri::command]
pub fn export_diagnostics() -> String {
    export()
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_sink() {
        sink().lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    #[test]
    fn unreachable_and_rejected_include_only_relay_host_and_fixed_codes() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sink();
        let credential = "admin-token-super-secret";
        let claim_code = "claim-code-super-secret";
        let envelope = "X-Admin-Signature: signed-envelope-super-secret";
        let device_key = "did:key:device-key-super-secret";
        let unreachable_url = format!(
            "https://user:{credential}@unreachable.example/v1/admin/devices?code={claim_code}&envelope={envelope}&key={device_key}"
        );
        let rejected_url = format!(
            "https://user:{credential}@rejected.example/v1/admin/devices?code={claim_code}&envelope={envelope}&key={device_key}"
        );

        record_unreachable(Operation::PairDevice, &unreachable_url);
        record_relay_rejected(Operation::SignedRelayRequest, &rejected_url, 403);

        let report = export();
        assert_eq!(report.matches("unreachable.example").count(), 1);
        assert_eq!(report.matches("rejected.example").count(), 1);
        assert!(report.contains("UNREACHABLE"));
        assert!(report.contains("RELAY_REJECTED"));
        assert!(report.contains("403"));
        for secret in [credential, claim_code, envelope, device_key] {
            assert!(!report.contains(secret), "diagnostics leaked {secret}");
        }
    }

    #[test]
    fn ring_buffer_is_bounded() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sink();
        for _ in 0..CAPACITY + 50 {
            record_unreachable(Operation::SignedRelayRequest, "https://relay.example");
        }
        let len = sink().lock().unwrap_or_else(|e| e.into_inner()).len();
        assert_eq!(len, CAPACITY);
    }
}
