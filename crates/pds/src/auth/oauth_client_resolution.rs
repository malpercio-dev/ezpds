// pattern: Mixed (unavoidable)

//! The ATProto OAuth client resolver: `client_id` URL policy + client-metadata-document fetch.
//!
//! Gathers: a URL-shaped OAuth `client_id` + the shared outbound HTTP client.
//! Processes: URL policy validation (pure) → metadata-document fetch (shell) →
//! document validation (pure).
//! Returns: the raw client-metadata JSON for the caller to cache, or a typed refusal.
//!
//! ATProto OAuth clients identify themselves by the URL of their client-metadata
//! document; authorization servers resolve unknown client_ids by fetching that URL
//! (<https://atproto.com/specs/oauth>). The fetched URL is caller-controlled, so the
//! policy check runs before any network I/O: https is required everywhere except
//! loopback hosts, which may use plain http (the spec's local-development exception —
//! also what lets tests serve metadata from 127.0.0.1). Failed resolutions land in a
//! process-local 60s negative cache (bounded, oldest-evicted) so replaying one failing
//! client_id against the unauthenticated PAR/authorize endpoints can't loop outbound
//! fetches.
//!
//! Also owns `validate_private_use_redirect`, the reverse-FQDN redirect rule both
//! request surfaces enforce. Consumers: `routes/oauth_par.rs` and
//! `routes/oauth_authorize.rs` (`resolve_client_metadata`), and
//! `routes/oauth_client_metadata.rs` (`url_is_loopback`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use url::{Host, Url};

/// Upper bound on an accepted client-metadata document. Real documents are well under
/// 4 KiB; the cap only exists so a hostile URL can't stream an unbounded body into memory.
const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Fetch timeout for the metadata document, independent of (and tighter than) the shared
/// client's default: PAR is interactive and a slow metadata host shouldn't hold it long.
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a failed resolution is remembered before the same client_id may trigger
/// another outbound fetch. Long enough to blunt replaying one failing URL against the
/// unauthenticated PAR/authorize endpoints; short enough that a client developer fixing
/// their metadata document isn't locked out meaningfully.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Bound on remembered failures so an attacker rotating client_ids can't grow the map
/// without limit; on overflow the oldest entry is evicted (the one closest to expiry).
const NEGATIVE_CACHE_MAX: usize = 1024;

/// Recently failed resolutions, keyed by client_id. Process-local by design: this is a
/// throttle on *our own outbound fetches*, not a correctness cache, so losing it on
/// restart costs nothing. Successful resolutions are cached durably by the callers
/// (`oauth_clients` rows); only failures need remembering here.
fn negative_cache() -> &'static Mutex<HashMap<String, Instant>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether this client_id failed to resolve within the negative-cache TTL.
fn recently_failed(client_id: &str) -> bool {
    let cache = negative_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache
        .get(client_id)
        .is_some_and(|at| at.elapsed() < NEGATIVE_CACHE_TTL)
}

/// Record a failed resolution, expiring stale entries and evicting the oldest on overflow.
fn record_failure(client_id: &str) {
    let mut cache = negative_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, at| at.elapsed() < NEGATIVE_CACHE_TTL);
    if cache.len() >= NEGATIVE_CACHE_MAX {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(client_id.to_string(), Instant::now());
}

/// Why a URL client_id could not be resolved to a usable client-metadata document.
///
/// The `Display` text becomes the OAuth `error_description`, so each message names the
/// problem from the client developer's point of view.
#[derive(Debug, thiserror::Error)]
pub enum ClientResolutionError {
    #[error("client_id is not a valid URL")]
    InvalidUrl,

    #[error("client_id must be an https URL (plain http is allowed for loopback hosts only)")]
    InsecureUrl,

    #[error("client_id URL must not contain credentials or a fragment")]
    ForbiddenUrlParts,

    #[error("failed to fetch client metadata: {0}")]
    Fetch(String),

    #[error("client metadata document exceeds {MAX_METADATA_BYTES} bytes")]
    TooLarge,

    #[error("client metadata document is not valid JSON")]
    InvalidJson,

    #[error(
        "client metadata client_id mismatch (the document must declare the URL it is served from)"
    )]
    ClientIdMismatch,

    #[error("client metadata resolution for this client_id recently failed; retry shortly")]
    RecentlyFailed,
}

/// Validate the URL policy for a metadata-URL client_id (pure; no I/O).
///
/// Rules: parseable; https (http only for loopback hosts); no userinfo; no fragment.
fn validate_client_id_url(client_id: &str) -> Result<Url, ClientResolutionError> {
    let url = Url::parse(client_id).map_err(|_| ClientResolutionError::InvalidUrl)?;

    match url.scheme() {
        "https" => {}
        "http" if host_is_loopback(&url) => {}
        _ => return Err(ClientResolutionError::InsecureUrl),
    }

    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ClientResolutionError::ForbiddenUrlParts);
    }

    Ok(url)
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether a URL string's host is loopback (pure; unparseable → false). Shared policy
/// point: loopback is the one place plain-http client_ids and locally-derived (rather
/// than canonical) wallet client_ids are acceptable.
pub(crate) fn url_is_loopback(url: &str) -> bool {
    Url::parse(url)
        .map(|u| host_is_loopback(&u))
        .unwrap_or(false)
}

/// Validate a fetched metadata document against the client_id it was fetched from (pure).
///
/// Per the ATProto OAuth spec the document MUST declare its own URL as `client_id` —
/// this is what stops one origin from impersonating another origin's client.
fn validate_metadata_document(client_id: &str, body: &str) -> Result<(), ClientResolutionError> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|_| ClientResolutionError::InvalidJson)?;

    if doc.get("client_id").and_then(|v| v.as_str()) != Some(client_id) {
        return Err(ClientResolutionError::ClientIdMismatch);
    }

    Ok(())
}

/// atproto OAuth: for a discoverable (URL) client_id, a private-use-scheme redirect
/// URI's scheme must be the client_id host's FQDN in reverse order (e.g. client_id
/// host `identitywallet.obsign.org` ⇒ scheme `org.obsign.identitywallet`). This binds
/// the custom scheme to a domain the client demonstrably controls — without it, any
/// app could register a metadata document listing another app's callback scheme.
///
/// The rule only applies to https client_ids (discoverable metadata): loopback-http
/// client_ids are the spec's local-development exception with no meaningful domain,
/// non-URL client_ids are operator-registered rows the rule predates, and http(s)
/// redirect URIs are not private-use schemes.
///
/// Shared policy point for both request surfaces that validate a redirect target —
/// `routes/oauth_par.rs` and `routes/oauth_authorize.rs` (routes cannot import each
/// other, and a security check restated per route is a check that drifts per route).
pub(crate) fn validate_private_use_redirect(
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), String> {
    let Ok(client_url) = Url::parse(client_id) else {
        return Ok(());
    };
    if client_url.scheme() != "https" {
        return Ok(());
    }
    let Ok(redirect_url) = Url::parse(redirect_uri) else {
        return Ok(());
    };
    let scheme = redirect_url.scheme();
    if scheme == "http" || scheme == "https" {
        return Ok(());
    }
    let Some(host) = client_url.host_str() else {
        return Ok(());
    };
    let reversed = host.split('.').rev().collect::<Vec<_>>().join(".");
    if scheme.eq_ignore_ascii_case(&reversed) {
        Ok(())
    } else {
        Err(format!(
            "Private-Use URI Scheme redirect URI, for discoverable client metadata, \
             must be the fully qualified domain name (FQDN) of the client_id, \
             in reverse order ({reversed}:)"
        ))
    }
}

/// Resolve a URL client_id to its raw client-metadata JSON (validate URL → fetch →
/// validate document). The caller decides whether/when to cache the returned JSON.
pub async fn resolve_client_metadata(
    http: &reqwest::Client,
    client_id: &str,
) -> Result<String, ClientResolutionError> {
    // URL-policy failures are pure and cost nothing — only fetch-path failures are worth
    // remembering. Both callers (`/oauth/par`, `/oauth/authorize`) are unauthenticated,
    // so without the negative cache, replaying one failing client_id would trigger a
    // fresh outbound request every time (bounded only by the per-IP limiter and the
    // fetch timeout).
    let url = validate_client_id_url(client_id)?;

    if recently_failed(client_id) {
        return Err(ClientResolutionError::RecentlyFailed);
    }

    match fetch_and_validate(http, client_id, url).await {
        Ok(body) => Ok(body),
        Err(e) => {
            record_failure(client_id);
            Err(e)
        }
    }
}

/// The fetch + validation pipeline behind [`resolve_client_metadata`], separated so the
/// caller can record any failure into the negative cache in one place.
async fn fetch_and_validate(
    http: &reqwest::Client,
    client_id: &str,
    url: Url,
) -> Result<String, ClientResolutionError> {
    let response = http
        .get(url)
        .header("Accept", "application/json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| ClientResolutionError::Fetch(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(ClientResolutionError::Fetch(format!("HTTP {status}")));
    }

    if response
        .content_length()
        .is_some_and(|l| l > MAX_METADATA_BYTES as u64)
    {
        return Err(ClientResolutionError::TooLarge);
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| ClientResolutionError::Fetch(e.to_string()))?;
    if body.len() > MAX_METADATA_BYTES {
        return Err(ClientResolutionError::TooLarge);
    }

    let body = String::from_utf8(body.to_vec()).map_err(|_| ClientResolutionError::InvalidJson)?;
    validate_metadata_document(client_id, &body)?;

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_passes_policy() {
        assert!(validate_client_id_url("https://app.example.com/client-metadata.json").is_ok());
    }

    #[test]
    fn plain_http_is_loopback_only() {
        assert!(validate_client_id_url("http://127.0.0.1:8080/m.json").is_ok());
        assert!(validate_client_id_url("http://localhost/m.json").is_ok());
        assert!(matches!(
            validate_client_id_url("http://app.example.com/m.json"),
            Err(ClientResolutionError::InsecureUrl)
        ));
    }

    #[test]
    fn credentials_and_fragments_are_rejected() {
        assert!(matches!(
            validate_client_id_url("https://user@app.example.com/m.json"),
            Err(ClientResolutionError::ForbiddenUrlParts)
        ));
        assert!(matches!(
            validate_client_id_url("https://app.example.com/m.json#frag"),
            Err(ClientResolutionError::ForbiddenUrlParts)
        ));
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        assert!(matches!(
            validate_client_id_url("ftp://app.example.com/m.json"),
            Err(ClientResolutionError::InsecureUrl)
        ));
    }

    /// A failed resolution is negatively cached: the second attempt for the same
    /// client_id inside the TTL short-circuits without an outbound request. Both callers
    /// are unauthenticated, so this is what keeps a replayed failing client_id from
    /// turning the server into a fetch loop.
    #[tokio::test]
    async fn failed_resolution_is_negatively_cached() {
        // Bind then drop a listener: a loopback port that deterministically refuses.
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let client_id = format!("http://127.0.0.1:{port}/oauth/client-metadata.json");
        let http = reqwest::Client::new();

        let first = resolve_client_metadata(&http, &client_id).await;
        assert!(
            matches!(first, Err(ClientResolutionError::Fetch(_))),
            "first attempt reports the real fetch failure: {first:?}"
        );

        let second = resolve_client_metadata(&http, &client_id).await;
        assert!(
            matches!(second, Err(ClientResolutionError::RecentlyFailed)),
            "second attempt inside the TTL must short-circuit: {second:?}"
        );
    }

    // ── Reverse-FQDN rule for private-use-scheme redirect URIs ─────────────────

    #[test]
    fn private_use_redirect_scheme_must_reverse_client_id_host() {
        // Matching reverse-FQDN passes.
        assert!(validate_private_use_redirect(
            "https://identitywallet.obsign.org/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());

        // Mismatched scheme is rejected, naming the required scheme.
        let err = validate_private_use_redirect(
            "https://ezpds-staging.up.railway.app/oauth/client-metadata.json",
            "dev.malpercio.identitywallet:/oauth/callback",
        )
        .unwrap_err();
        assert!(
            err.contains("app.railway.up.ezpds-staging:"),
            "the error must name the required reverse-FQDN scheme, got: {err}"
        );

        // Scheme comparison is case-insensitive.
        assert!(validate_private_use_redirect(
            "https://IdentityWallet.Obsign.Org/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());
    }

    #[test]
    fn private_use_redirect_rule_exemptions() {
        // https redirect URIs are not private-use schemes.
        assert!(validate_private_use_redirect(
            "https://app.example.com/client-metadata.json",
            "https://app.example.com/callback",
        )
        .is_ok());

        // Loopback-http client_ids (local development) are exempt.
        assert!(validate_private_use_redirect(
            "http://localhost:8080/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());

        // Non-URL client_ids (operator-registered rows) are exempt.
        assert!(validate_private_use_redirect(
            "dev.malpercio.identitywallet",
            "dev.malpercio.identitywallet:/oauth/callback",
        )
        .is_ok());
    }

    #[test]
    fn document_must_declare_its_own_url() {
        let url = "https://app.example.com/client-metadata.json";
        assert!(validate_metadata_document(
            url,
            r#"{"client_id":"https://app.example.com/client-metadata.json"}"#
        )
        .is_ok());
        assert!(matches!(
            validate_metadata_document(url, r#"{"client_id":"https://evil.example.com/m.json"}"#),
            Err(ClientResolutionError::ClientIdMismatch)
        ));
        assert!(matches!(
            validate_metadata_document(url, "not json"),
            Err(ClientResolutionError::InvalidJson)
        ));
    }
}
