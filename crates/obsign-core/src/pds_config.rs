// pattern: Imperative Shell

//! The configured PDS: its Keychain-persisted base URL ([`PDS_URL_ACCOUNT`]) and what that host
//! advertises. `save_pds_url` validates, probes `/xrpc/_health`, persists, initialises the
//! runtime client, and re-probes capabilities; `get_pds_url` reads the stored value past
//! [`migrate_retired_apex`]; `get_pds_capabilities` answers from the per-host cache, and an
//! unreachable host reports an empty list, never an error. The compile-time default lives in
//! `http`; the stored URL only overrides it.

use crate::keystore::{self, KeyStoreError};
use crate::oauth::Core;
use crate::{http, pds_capabilities};
use serde::Serialize;

/// The configured PDS base URL.
pub const PDS_URL_ACCOUNT: &str = "relay-base-url";

/// Persist the user-configured PDS base URL to the Keychain.
///
/// Overwrites any previously stored URL.
pub fn store_pds_url(url: &str) -> Result<(), KeyStoreError> {
    keystore::store_item(PDS_URL_ACCOUNT, url.as_bytes())
}

/// Retrieve the user-configured PDS base URL from the Keychain.
///
/// Returns `None` if no URL has been saved yet (first run or after logout).
pub fn load_pds_url() -> Option<String> {
    match keystore::get_item(PDS_URL_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|e| {
                tracing::error!(error = ?e, "PDS URL in Keychain is not valid UTF-8; treating as absent");
            })
            .ok(),
        Err(e) if keystore::is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading PDS URL");
            None
        }
    }
}

/// Remove the PDS URL from the Keychain. Test-only; used to reset state
/// between tests that share the Keychain mock store.
#[cfg(test)]
pub fn delete_pds_url_test_only() {
    let _ = keystore::delete_item(PDS_URL_ACCOUNT);
}

/// Error returned by PDS URL configuration commands.
///
/// Serializes as `{ "code": "INVALID_URL" | "UNREACHABLE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PdsConfigError {
    #[error("invalid PDS URL: must be http or https with a non-empty host")]
    InvalidUrl,
    #[error("PDS is unreachable or did not return a success response")]
    Unreachable,
    #[error("failed to save PDS URL to device storage")]
    KeychainError,
}

/// Validate a PDS URL: must parse as http or https with a non-empty host.
/// Strips any trailing slash and returns the normalized URL string.
fn normalize_pds_url(url: &str) -> Result<String, PdsConfigError> {
    let parsed = url::Url::parse(url).map_err(|_| PdsConfigError::InvalidUrl)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(PdsConfigError::InvalidUrl),
    }
    if parsed.host().is_none() {
        return Err(PdsConfigError::InvalidUrl);
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(PdsConfigError::InvalidUrl);
    }
    Ok(url.trim_end_matches('/').to_string())
}

/// Rewrite the retired `obsign.org` apex to the host that actually serves the PDS.
///
/// The apex stopped answering XRPC at the 2026-07-24 `pds.obsign.org` migration — it 404s every
/// path — but an install configured before that date still holds it in the Keychain, and nothing
/// corrects it: the URL is read once at launch into a `OnceLock`, and the only screen that can
/// rewrite it sits behind "create new identity". Rewriting on read rather than writing back keeps
/// this idempotent and failure-free; a later deliberate save replaces the stored value normally.
fn migrate_retired_apex(url: String) -> String {
    if url.trim_end_matches('/') == "https://obsign.org" {
        return "https://pds.obsign.org".to_string();
    }
    url
}

/// The configured PDS base URL as every reader should see it — the stored value past
/// [`migrate_retired_apex`]. `None` when the wallet was never configured.
pub fn configured_pds_url() -> Option<String> {
    load_pds_url().map(migrate_retired_apex)
}

/// Return the saved PDS base URL, or `None` if not yet configured.
///
/// The frontend calls this on mount to decide whether to show the PDS
/// configuration screen.
pub fn get_pds_url() -> Option<String> {
    configured_pds_url()
}

/// Validate `url`, confirm the PDS is reachable, save to Keychain, and
/// initialize the runtime PDS client.
///
/// After this call succeeds, all subsequent IPC commands that use the PDS
/// will use the saved URL for the remainder of the app session and on all
/// future launches.
pub async fn save_pds_url(state: &Core, url: String) -> Result<(), PdsConfigError> {
    let normalized = normalize_pds_url(&url)?;
    let resp = http::new_configured(normalized.clone())
        .get("/xrpc/_health")
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, url = %normalized, "PDS health check failed");
            PdsConfigError::Unreachable
        })?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            url = %normalized,
            "PDS health check returned non-success status"
        );
        // Both transport failures (DNS, TLS, timeout) and non-2xx HTTP responses
        // map to Unreachable — the frontend only needs to know "can't use this URL".
        return Err(PdsConfigError::Unreachable);
    }
    store_pds_url(&normalized).map_err(|e| {
        tracing::error!(error = %e, "failed to save PDS URL to Keychain");
        PdsConfigError::KeychainError
    })?;
    state.set_custos_client(normalized.clone());

    // Re-read what this host offers rather than trusting a cached answer: the user has
    // just deliberately pointed the wallet at it, which is exactly when a stale verdict
    // (from an earlier configuration of the same host, or a probe made while it was down)
    // would be wrong. Best-effort — an unreachable host here only costs a later re-probe,
    // and the health check above already established the URL is usable.
    pds_capabilities::forget(&normalized);
    let capabilities = pds_capabilities::probe(state.pds_client(), &normalized).await;
    tracing::info!(
        url = %normalized,
        version = ?capabilities.version,
        capabilities = ?capabilities.capabilities,
        "configured PDS capabilities"
    );

    Ok(())
}

/// Report what the configured PDS advertises, so the frontend can offer only the features
/// that host actually supports.
///
/// Answers from the per-host cache when it has one (populated by `save_pds_url` and by
/// every other describeServer call the wallet makes), otherwise describes the server once.
///
/// A host that advertises nothing — every PDS that is not Custos, and a Custos deployment
/// with capabilities switched off — reports an empty list rather than failing. **A host
/// that cannot be reached reports the same empty list**: the caller learns "no capabilities
/// to offer", which is the safe way to degrade, not "this feature is definitively absent".
pub async fn get_pds_capabilities(
    state: &Core,
    pds_url: Option<String>,
) -> Result<pds_capabilities::ServerCapabilities, PdsConfigError> {
    let url = match pds_url {
        Some(url) => normalize_pds_url(&url)?,
        None => match load_pds_url() {
            Some(url) => url,
            None => {
                // No PDS configured yet: nothing to ask, and no error to report — the
                // frontend is in exactly the state where it offers no host-gated features.
                return Ok(pds_capabilities::ServerCapabilities::none());
            }
        },
    };

    Ok(pds_capabilities::probe(state.pds_client(), &url).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- PdsConfigError serialization (one test per variant) --
    #[test]
    fn pds_config_error_invalid_url_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::InvalidUrl).unwrap();
        assert_eq!(json["code"], "INVALID_URL");
    }

    #[test]
    fn pds_config_error_unreachable_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::Unreachable).unwrap();
        assert_eq!(json["code"], "UNREACHABLE");
    }

    #[test]
    fn pds_config_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- normalize_pds_url --

    #[test]
    fn normalize_pds_url_strips_trailing_slash() {
        assert_eq!(
            normalize_pds_url("https://PDS.example.com/").unwrap(),
            "https://PDS.example.com"
        );
    }

    #[test]
    fn normalize_pds_url_accepts_http_and_https() {
        assert!(normalize_pds_url("https://PDS.example.com").is_ok());
        assert!(normalize_pds_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn normalize_pds_url_rejects_non_http_schemes() {
        assert!(matches!(
            normalize_pds_url("ftp://PDS.example.com").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_pds_url("ws://PDS.example.com").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_pds_url_rejects_malformed_input() {
        assert!(matches!(
            normalize_pds_url("not-a-url").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_pds_url("").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_pds_url_rejects_urls_with_paths() {
        assert!(matches!(
            normalize_pds_url("https://PDS.example.com/api/v1").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    /// The retired apex is rewritten to the serving host; every other configured URL —
    /// including a self-hosted Custos and the localhost default — passes through untouched.
    #[test]
    fn retired_apex_is_rewritten_and_nothing_else_is() {
        assert_eq!(
            migrate_retired_apex("https://obsign.org".to_string()),
            "https://pds.obsign.org"
        );
        assert_eq!(
            migrate_retired_apex("https://obsign.org/".to_string()),
            "https://pds.obsign.org"
        );
        for untouched in [
            "https://pds.obsign.org",
            "https://custos.example.com",
            "http://localhost:8080",
        ] {
            assert_eq!(migrate_retired_apex(untouched.to_string()), untouched);
        }
    }

    // -- get_pds_url / load_pds_url round-trip --

    #[test]
    fn get_pds_url_returns_none_before_save() {
        // Relies on the keychain mock starting empty for this key. The sibling test
        // pds_url_round_trips_through_keychain cleans up via delete_pds_url_test_only(),
        // so ordering is not a concern as long as both tests run in the same process.
        assert!(get_pds_url().is_none());
    }

    #[test]
    fn pds_url_round_trips_through_keychain() {
        let url = "https://PDS.example.com";
        store_pds_url(url).unwrap();
        let loaded = load_pds_url().unwrap();
        assert_eq!(loaded, url);
        // Clean up so this test doesn't affect others sharing the mock store.
        delete_pds_url_test_only();
    }
}
