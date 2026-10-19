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
//! also what lets tests serve metadata from 127.0.0.1), and an IP-literal https host must
//! be a public address (see `validate_client_id_url`'s doc — an IP literal bypasses the
//! hardened client's own connect-time guard). Failed resolutions land in a process-local
//! 60s negative cache (bounded, oldest-evicted) so replaying one failing client_id
//! against the unauthenticated PAR endpoint can't loop outbound fetches.
//!
//! The fetch itself is caller-influenced by construction, so every call site must pass
//! `AppState::hardened_http_client`, never the plain `http_client`
//! (`scripts/ssrf-client-check.sh` guards this).
//!
//! Also owns `validate_private_use_redirect`, the reverse-FQDN redirect rule both
//! request surfaces enforce. Consumers: `routes/oauth_par.rs` and
//! `auth::client_attestation` (`resolve_client_metadata`); `routes/oauth_authorize.rs`
//! (`validate_private_use_redirect` only — its client lookup is cache-only, never a live
//! fetch); `routes/oauth_client_metadata.rs` (`url_is_loopback`).

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

    #[error("client_id must not target a private, loopback, or link-local address")]
    ForbiddenAddress,

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

    /// A loopback client_id encodes its own metadata, so a malformed one is rejected here
    /// rather than at a fetch that never happens.
    #[error("invalid loopback client_id: {0}")]
    InvalidDocument(&'static str),
}

/// Validate the URL policy for a metadata-URL client_id (pure; no I/O).
///
/// Rules: parseable; https (http only for loopback hosts); no userinfo; no fragment; an
/// IP-literal https host must be a public address.
///
/// The last rule exists because an IP-literal host bypasses the hardened client's connect-time
/// `SsrfResolver` entirely — hyper only consults a `dns::Resolve` for a hostname that actually
/// needs resolving (see `identity::proxy`'s module doc) — so `https://169.254.169.254/...` would
/// otherwise sail straight past it. This is the same IP-literal gap
/// [`crate::identity::proxy::validate_proxy_endpoint`] closes for the `atproto-proxy` target, and
/// [`crate::identity::proxy::ip_allowed`] is the shared allowlist behind both. A domain host's
/// addresses are still only checked at connect time.
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

    let literal_ip = match url.host() {
        Some(Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    };
    if url.scheme() == "https" {
        if let Some(ip) = literal_ip {
            if !crate::identity::proxy::ip_allowed(ip, false) {
                return Err(ClientResolutionError::ForbiddenAddress);
            }
        }
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

/// The origin an atproto loopback client_id is built on.
const LOOPBACK_CLIENT_ID_ORIGIN: &str = "http://localhost";

/// The redirect URIs a loopback client gets when its client_id names none.
const DEFAULT_LOOPBACK_REDIRECT_URIS: [&str; 2] = ["http://127.0.0.1/", "http://[::1]/"];

/// Whether `client_id` is an atproto **loopback client** identifier.
///
/// These are the development-time clients the spec defines: `http://localhost`, optionally
/// with a query string carrying `scope` and repeated `redirect_uri`. There is no document to
/// fetch — the identifier *is* the metadata — which is why they need their own path here.
pub(crate) fn is_loopback_client_id(client_id: &str) -> bool {
    let Some(rest) = client_id.strip_prefix(LOOPBACK_CLIENT_ID_ORIGIN) else {
        return false;
    };
    // A hash component is never part of a client_id, and anything other than an immediate
    // `/` or `?` means a different host (`http://localhost.evil.example`).
    !rest.contains('#') && matches!(rest.chars().next(), None | Some('/') | Some('?'))
}

/// Whether a loopback client's `redirect_uri` is one it may actually receive a code on.
///
/// Plain http on the loopback **IP literal** only. `localhost` is deliberately refused even
/// though it resolves to the same place: RFC 8252 §8.3 advises against it because the name can
/// resolve to a non-loopback interface through a hosts-file entry or DNS misconfiguration, at
/// which point the "loopback" client is listening somewhere else entirely. The atproto client
/// libraries enforce the same narrowing, so a client that works against the reference
/// implementation works here.
fn is_loopback_redirect_uri(redirect_uri: &str) -> bool {
    let Ok(url) = Url::parse(redirect_uri) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        // Includes `localhost` — see above.
        _ => false,
    }
}

/// Synthesize the client metadata document a loopback client_id encodes (pure).
///
/// The fields that are not encoded in the identifier are fixed by the spec rather than
/// chosen here: `response_types: ["code"]`, `grant_types: [authorization_code,
/// refresh_token]`, `token_endpoint_auth_method: "none"`, `application_type: "native"`,
/// `dpop_bound_access_tokens: true`. A loopback client that omits `redirect_uri` gets
/// [`DEFAULT_LOOPBACK_REDIRECT_URIS`], and one that omits `scope` gets `atproto`.
///
/// The `atproto` scope is mandatory: a loopback identifier that asks for something else has
/// not asked for an atproto session at all, and honoring it would mint a token no atproto
/// client could use.
pub(crate) fn loopback_client_metadata(client_id: &str) -> Result<String, ClientResolutionError> {
    let url = Url::parse(client_id).map_err(|_| ClientResolutionError::InvalidUrl)?;

    let mut redirect_uris: Vec<String> = Vec::new();
    let mut scope: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "redirect_uri" => {
                // A loopback client_id is unregistered and self-describing: anyone can mint
                // one, and whatever it names here lands in `redirect_uris`, which is the list
                // the PAR endpoint checks the requested redirect against. Copying the value
                // through unvalidated would let `http://localhost?redirect_uri=https://
                // attacker.example/cb` carry an authorization code off the machine — and the
                // reverse-FQDN rule cannot catch it, since that check exempts non-https
                // client_ids. The redirect target is the *only* part of this document an
                // attacker controls, so it is the part that has to be constrained.
                if !is_loopback_redirect_uri(&value) {
                    return Err(ClientResolutionError::InvalidDocument(
                        "loopback client_id redirect_uri must be http on 127.0.0.1 or [::1]",
                    ));
                }
                redirect_uris.push(value.into_owned());
            }
            "scope" => scope = Some(value.into_owned()),
            // Unknown parameters are ignored rather than rejected, matching how the rest of
            // this server treats forward-compatible extras in client documents.
            _ => {}
        }
    }
    if redirect_uris.is_empty() {
        redirect_uris = DEFAULT_LOOPBACK_REDIRECT_URIS
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    let scope = scope.unwrap_or_else(|| "atproto".to_string());
    if !scope.split_whitespace().any(|token| token == "atproto") {
        return Err(ClientResolutionError::InvalidDocument(
            "loopback client_id scope must include \"atproto\"",
        ));
    }

    serde_json::to_string(&serde_json::json!({
        "client_id": client_id,
        "client_name": "Loopback client",
        "redirect_uris": redirect_uris,
        "scope": scope,
        "response_types": ["code"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
        "dpop_bound_access_tokens": true,
    }))
    .map_err(|_| ClientResolutionError::InvalidDocument("failed to build loopback metadata"))
}

/// Resolve a URL client_id to its raw client-metadata JSON (validate URL → fetch →
/// validate document). The caller decides whether/when to cache the returned JSON.
///
/// A loopback client_id short-circuits the fetch: its metadata is synthesized from the
/// identifier itself, because there is no document to retrieve.
pub async fn resolve_client_metadata(
    http: &reqwest::Client,
    client_id: &str,
) -> Result<String, ClientResolutionError> {
    if is_loopback_client_id(client_id) {
        return loopback_client_metadata(client_id);
    }
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

    /// An IP-literal https client_id at a private/link-local address must be refused by the URL
    /// policy itself — before any fetch — since that address would otherwise bypass the hardened
    /// client's own connect-time guard (only consulted for names needing DNS resolution).
    #[test]
    fn https_ip_literal_client_id_must_be_a_public_address() {
        for hostile in [
            "https://169.254.169.254/client-metadata.json", // cloud-metadata (link-local)
            "https://10.0.0.1/client-metadata.json",        // RFC 1918 private
            "https://127.0.0.1/client-metadata.json",       // loopback (not the http exception)
        ] {
            assert!(
                matches!(
                    validate_client_id_url(hostile),
                    Err(ClientResolutionError::ForbiddenAddress)
                ),
                "must refuse {hostile}"
            );
        }
        // A public IP literal is unaffected.
        assert!(validate_client_id_url("https://1.2.3.4/client-metadata.json").is_ok());
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

    /// The atproto loopback-client shape: `http://localhost`, optionally with a query string.
    /// A host that merely *starts with* localhost is a different origin and must not match.
    #[test]
    fn recognizes_loopback_client_ids() {
        assert!(is_loopback_client_id("http://localhost"));
        assert!(is_loopback_client_id("http://localhost/"));
        assert!(is_loopback_client_id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&scope=atproto"
        ));
        assert!(!is_loopback_client_id("http://localhost.evil.example"));
        assert!(!is_loopback_client_id("http://127.0.0.1"));
        assert!(!is_loopback_client_id(
            "https://app.example.com/metadata.json"
        ));
        assert!(!is_loopback_client_id("http://localhost#frag"));
    }

    /// A bare loopback client_id carries no parameters, so every field comes from the spec's
    /// defaults — including the two default redirect URIs.
    #[test]
    fn bare_loopback_client_gets_spec_defaults() {
        let json = loopback_client_metadata("http://localhost").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["client_id"], "http://localhost");
        assert_eq!(doc["scope"], "atproto");
        assert_eq!(doc["token_endpoint_auth_method"], "none");
        assert_eq!(doc["application_type"], "native");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
        assert_eq!(
            doc["redirect_uris"],
            serde_json::json!(["http://127.0.0.1/", "http://[::1]/"])
        );
    }

    /// The query string is the metadata: repeated `redirect_uri` values all count, and an
    /// explicit `scope` replaces the default.
    #[test]
    fn loopback_client_reads_redirect_uris_and_scope_from_the_query() {
        let json = loopback_client_metadata(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcb\
             &redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%3A9000%2Fcb\
             &scope=atproto+transition%3Ageneric",
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["scope"], "atproto transition:generic");
        assert_eq!(
            doc["redirect_uris"],
            serde_json::json!(["http://127.0.0.1:9000/cb", "http://[::1]:9000/cb"])
        );
    }

    /// The redirect target is the only attacker-controlled part of a synthesized loopback
    /// document, and the PAR endpoint trusts that list. A remote target would carry the
    /// authorization code off the machine, and the reverse-FQDN rule cannot catch it because
    /// that check exempts non-https client_ids.
    #[test]
    fn loopback_client_refuses_a_non_loopback_redirect_uri() {
        for hostile in [
            "http://localhost?redirect_uri=https%3A%2F%2Fattacker.example%2Fcb",
            "http://localhost?redirect_uri=http%3A%2F%2Fattacker.example%2Fcb",
            // `localhost` resolves to loopback today but can be repointed by a hosts entry
            // or DNS, so RFC 8252 §8.3 rules it out as a redirect host.
            "http://localhost?redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb",
            // A loopback-looking prefix on someone else's domain.
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1.attacker.example%2Fcb",
            // https on loopback is not the shape the spec defines either.
            "http://localhost?redirect_uri=https%3A%2F%2F127.0.0.1%3A9000%2Fcb",
        ] {
            assert!(
                loopback_client_metadata(hostile).is_err(),
                "must refuse {hostile}"
            );
        }

        // The two shapes a real loopback client uses are still accepted.
        assert!(loopback_client_metadata(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcb"
        )
        .is_ok());
        assert!(loopback_client_metadata(
            "http://localhost?redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%2Fcb"
        )
        .is_ok());
    }

    /// A loopback client asking for something other than an atproto session has not asked for
    /// one at all; honoring it would mint a token no atproto client could use.
    #[test]
    fn loopback_client_scope_must_include_atproto() {
        assert!(loopback_client_metadata("http://localhost?scope=email").is_err());
        assert!(loopback_client_metadata("http://localhost?scope=atproto").is_ok());
    }
}
