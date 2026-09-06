// pattern: Mixed (unavoidable)

//! Re-exports [`custos_client::CustosClient`] — the HTTP client for the *one* PDS the user
//! configured — and owns the two things that name the wallet itself and so stay out of that
//! Tauri-free crate: the compile-time default base URL, and [`new_configured`], which wires
//! the wallet's diagnostics observer.
//!
//! Discovery and XRPC against arbitrary endpoints (plc.directory, a claim source, a migration
//! destination) live in `pds_client.rs`; this client only ever addresses the configured
//! Custos, which is why it holds a base URL where `PdsClient` is stateless.
//!
//! The base URL is runtime-configured: the user sets it on first launch
//! (`PdsConfigScreen`), it persists to the Keychain, and later launches restore it via
//! `AppState::set_custos_client`. The compile-time default
//! (`#[cfg(debug_assertions)]`: `http://localhost:8080` debug, `https://pds.obsign.org`
//! release) is only the pre-filled value in that configuration UI, and the fallback when
//! nothing was ever configured.

pub use custos_client::{CustosClient, ParResponse, TokenErrorResponse, TokenResponse};

#[cfg(debug_assertions)]
const CUSTOS_BASE_URL: &str = "http://localhost:8080";
#[cfg(not(debug_assertions))]
const CUSTOS_BASE_URL: &str = "https://pds.obsign.org";

/// Returns the compile-time default PDS base URL.
///
/// Used by integration tests that need the default URL to construct expected
/// endpoint strings. The PDS configuration UI hardcodes the same default string as its
/// fallback, and additionally seeds the field from the saved URL (via `get_pds_url`) on mount.
pub fn default_pds_url() -> &'static str {
    CUSTOS_BASE_URL
}

/// Build a [`CustosClient`] for `base_url`, wired to the wallet's diagnostics observer.
pub fn new_configured(base_url: String) -> CustosClient {
    CustosClient::new_with_url(base_url, crate::oauth_client::diagnostics_observer())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `new_configured` must wire the wallet's real diagnostics observer, not
    /// `custos_client::NoopObserver` — a network failure on a client built this way must leave
    /// a breadcrumb in the exportable diagnostics log (the pre-extraction behavior this
    /// function preserves).
    #[tokio::test]
    async fn new_configured_records_a_redacted_breadcrumb_on_transport_failure() {
        let client = new_configured("http://127.0.0.1:1".to_string());
        let marker = "create-flow-secret@example.com";
        let before = crate::diagnostics::export().matches("custosPost").count();

        let error = client
            .post(
                "/v1/accounts/mobile?claim=diagnostic-secret",
                &serde_json::json!({"email": marker, "handle": "private.example"}),
            )
            .await
            .unwrap_err();
        let displayed_error = error.to_string();
        assert!(!displayed_error.contains("diagnostic-secret"));
        assert!(!displayed_error.contains("/v1/accounts/mobile"));

        let report = crate::diagnostics::export();
        assert_eq!(report.matches("custosPost").count(), before + 1);
        assert!(report.contains("127.0.0.1"));
        assert!(!report.contains(marker));
        assert!(!report.contains("diagnostic-secret"));
        assert!(!report.contains("private.example"));
    }
}
