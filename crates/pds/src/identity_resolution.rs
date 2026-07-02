// pattern: Imperative Shell
//
// Shared ATProto identity-resolution helpers. Routes gather query/body parameters and delegate the
// actual handle/DID lookup here so resolveHandle, resolveIdentity, refreshIdentity, and resolveDid
// all use the same local → network fallback rules. Also resolves a caller-supplied `atproto-proxy`
// header to an upstream service endpoint, for XRPC namespaces with no single configured default
// (see `resolve_atproto_proxy_target`, used by the `com.atproto.moderation.*` proxy branch).

use std::net::IpAddr;

use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;

pub const INVALID_HANDLE: &str = "handle.invalid";

/// Resolve a handle to a DID using ezpds' ATProto handle-resolution chain:
/// local handles table → DNS TXT `_atproto.<handle>` → HTTP `.well-known/atproto-did`.
///
/// Infrastructure errors in DNS / well-known are logged and treated as misses so later fallbacks
/// still get a chance to resolve the handle. Database errors fail closed.
pub async fn resolve_handle_to_did(
    state: &AppState,
    handle: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    if let Some((did,)) = row {
        return Ok(Some(did));
    }

    if let Some(resolver) = &state.txt_resolver {
        let name = format!("_atproto.{handle}");
        match resolver.txt_lookup(&name).await {
            Ok(records) => {
                for record in records {
                    if let Some(did) = record.strip_prefix("did=") {
                        return Ok(Some(did.to_string()));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "DNS TXT lookup failed; falling through to well-known"
                );
            }
        }
    }

    if let Some(resolver) = &state.well_known_resolver {
        match resolver.resolve(handle).await {
            Ok(Some(did)) => return Ok(Some(did)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "HTTP well-known lookup failed"
                );
            }
        }
    }

    Ok(None)
}

/// Resolve a DID to its current DID document.
///
/// Local cached documents are preferred. Unknown `did:plc` values are proxied to the configured PLC
/// directory; unknown `did:web` values are resolved through the method's `did.json` URL. Returned
/// documents must assert the requested DID in their `id` field.
pub async fn resolve_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    if let Some(doc) = crate::db::dids::get_did_document(&state.db, did).await? {
        return validate_did_doc_id(doc, did, ErrorCode::InternalError);
    }

    if did.starts_with("did:plc:") {
        return resolve_plc_did_document(state, did).await;
    }

    if did.starts_with("did:web:") {
        return resolve_web_did_document(state, did).await;
    }

    Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"))
}

/// Return the verified handle for `did` and `did_doc`, or `handle.invalid` when the document's
/// `alsoKnownAs` handles do not resolve back to the DID.
pub async fn verified_handle_for_did(
    state: &AppState,
    did: &str,
    did_doc: &Value,
) -> Result<String, ApiError> {
    for handle in also_known_as_handles(did_doc) {
        if resolve_handle_to_did(state, &handle).await?.as_deref() == Some(did) {
            return Ok(handle);
        }
    }

    Ok(INVALID_HANDLE.to_string())
}

/// Verify a caller-provided handle against a DID document and the handle-resolution chain.
pub async fn verified_handle_for_identifier(
    state: &AppState,
    did: &str,
    did_doc: &Value,
    handle: &str,
) -> Result<String, ApiError> {
    let asserted = also_known_as_handles(did_doc)
        .into_iter()
        .any(|candidate| candidate == handle);
    if !asserted {
        return Ok(INVALID_HANDLE.to_string());
    }

    if resolve_handle_to_did(state, handle).await?.as_deref() == Some(did) {
        Ok(handle.to_string())
    } else {
        Ok(INVALID_HANDLE.to_string())
    }
}

/// A validated `atproto-proxy` target, ready to hand to `proxy_xrpc`.
#[derive(Debug)]
pub struct ProxyTarget {
    /// The service base URL: validated http(s) scheme, no userinfo/query/fragment, and a host
    /// confirmed to resolve only to public (non-loopback/private/link-local/metadata) addresses.
    pub url: String,
    /// The original `atproto-proxy` header value, echoed back verbatim as the outbound header.
    pub header_value: String,
    /// Present when `url`'s host is a domain name: the exact addresses it was validated against.
    /// `proxy_xrpc` pins the outbound connection to these (rather than letting the HTTP client
    /// re-resolve the domain at connect time), so a second DNS answer can't substitute an address
    /// that was never checked (DNS-rebinding TOCTOU).
    pub pinned: Option<PinnedResolution>,
}

/// A domain name plus the specific addresses an outbound connection to it must be pinned to.
#[derive(Debug)]
pub struct PinnedResolution {
    pub domain: String,
    pub addrs: Vec<std::net::SocketAddr>,
}

/// Resolve an inbound `atproto-proxy` header (`<did>#<serviceId>`) to the upstream service it
/// names.
///
/// Unlike `app.bsky.*`/`chat.bsky.*` — which proxy to one configured default (the AppView / chat
/// service) — a namespace like `com.atproto.moderation.*` has no single upstream: the client picks
/// which labeler to report to via this header. Resolves the DID document, then looks up a
/// `service` entry whose `id` matches the header's fragment (either the abbreviated `#serviceId`
/// form or the fully-qualified `did#serviceId` form — both appear in the wild), and validates the
/// advertised `serviceEndpoint` before it's ever handed to the HTTP client: since the target DID
/// is caller-chosen, an attacker can make its DID document advertise anything — this is the only
/// thing standing between an authenticated report and an SSRF into the PDS's private network.
pub async fn resolve_atproto_proxy_target(
    state: &AppState,
    header_value: &str,
) -> Result<ProxyTarget, ApiError> {
    let (did, service_id) = header_value.split_once('#').ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "atproto-proxy header must be of the form did#serviceId",
        )
    })?;
    if !did.starts_with("did:") || service_id.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "atproto-proxy header must be of the form did#serviceId",
        ));
    }

    let doc = resolve_did_document(state, did).await?;
    let abbreviated_id = format!("#{service_id}");
    let endpoint = doc
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| {
            matches!(entry.get("id").and_then(Value::as_str), Some(id) if id == abbreviated_id || id == header_value)
        })
        .and_then(|entry| entry.get("serviceEndpoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "atproto-proxy target does not advertise a usable service endpoint",
            )
        })?;

    let pinned = validate_proxy_endpoint(endpoint, state.allow_loopback_proxy_targets).await?;

    Ok(ProxyTarget {
        url: endpoint.to_string(),
        header_value: header_value.to_string(),
        pinned,
    })
}

/// Parse and validate a caller-influenced proxy endpoint URL, resolving its host to concrete
/// addresses so the connection can later be pinned against exactly what was checked here.
///
/// Rejects: non-http(s) schemes, userinfo (`user:pass@host`), a query or fragment (both
/// meaningless on a base URL `proxy_xrpc` only ever appends `/xrpc/{nsid}` to, and a vector for
/// smuggling tricks past a naive parser), and any host — whether given as a literal IP or
/// resolved from a domain name — that isn't a public address (loopback, RFC 1918 private,
/// link-local/cloud-metadata, unique-local IPv6, unspecified, multicast, broadcast, or
/// documentation ranges are all rejected, for both IPv4 and IPv4-mapped-into-IPv6 forms).
///
/// Returns `Some(PinnedResolution)` when the host is a domain name (the validated addresses to
/// pin at connect time); `None` when the host is already an IP literal, so there is no separate
/// resolution step for a later DNS answer to race.
///
/// `allow_loopback` is a test-only relaxation (see `AppState::allow_loopback_proxy_targets`):
/// production always passes `false`.
async fn validate_proxy_endpoint(
    endpoint: &str,
    allow_loopback: bool,
) -> Result<Option<PinnedResolution>, ApiError> {
    let bad_target = || {
        ApiError::new(
            ErrorCode::ServiceUnavailable,
            "atproto-proxy target is not a usable public service endpoint",
        )
    };
    let ip_allowed = |ip: IpAddr| is_global_ip(ip) || (allow_loopback && ip.is_loopback());

    let url = reqwest::Url::parse(endpoint).map_err(|_| bad_target())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(bad_target());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad_target());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad_target());
    }

    let host = url.host().ok_or_else(bad_target)?;
    let port = url.port_or_known_default().ok_or_else(bad_target)?;

    match host {
        url::Host::Ipv4(ip) => {
            if !ip_allowed(IpAddr::V4(ip)) {
                return Err(bad_target());
            }
            Ok(None)
        }
        url::Host::Ipv6(ip) => {
            if !ip_allowed(IpAddr::V6(ip)) {
                return Err(bad_target());
            }
            Ok(None)
        }
        url::Host::Domain(domain) => {
            let domain = domain.to_string();
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((domain.as_str(), port))
                .await
                .map_err(|_| bad_target())?
                .collect();
            if addrs.is_empty() || !addrs.iter().all(|addr| ip_allowed(addr.ip())) {
                return Err(bad_target());
            }
            Ok(Some(PinnedResolution { domain, addrs }))
        }
    }
}

/// Whether `ip` is a public, routable address — i.e. not loopback, private, link-local
/// (including the `169.254.169.254` cloud-metadata address, which falls in that range),
/// unspecified, multicast, broadcast, documentation, or IPv6 unique-local.
fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // An IPv4-mapped IPv6 address (::ffff:a.b.c.d) must pass the same IPv4 checks —
            // otherwise it's a bypass for every rule below (e.g. ::ffff:127.0.0.1).
            Some(v4) => is_global_ipv4(v4),
            None => is_global_ipv6(v6),
        },
    }
}

fn is_global_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_shared_address_space(ip))
}

/// `100.64.0.0/10` (RFC 6598 carrier-grade NAT) — not covered by `Ipv4Addr::is_private`.
fn is_shared_address_space(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

fn is_global_ipv6(ip: std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let first_segment = ip.segments()[0];
    // fc00::/7 — unique local addresses (RFC 4193).
    if (first_segment & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 — link-local.
    if (first_segment & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}

async fn resolve_plc_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    let plc_url = format!(
        "{}/{}",
        state.config.plc_directory_url.trim_end_matches('/'),
        did
    );
    let response = state.http_client.get(&plc_url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, plc_url = %plc_url, "failed to contact plc.directory");
        ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::debug!(did = %did, "DID not found in plc.directory");
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated in plc.directory");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "plc.directory returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "plc.directory returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse plc.directory response");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "invalid response from plc.directory",
        )
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

async fn resolve_web_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    let url = did_web_document_url(did)?;
    let response = state.http_client.get(&url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, url = %url, "failed to resolve did:web document");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to resolve did:web document",
        )
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated at did:web endpoint");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "did:web endpoint returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "did:web endpoint returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse did:web response");
        ApiError::new(ErrorCode::PlcDirectoryError, "invalid did:web response")
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

fn validate_did_doc_id(doc: Value, did: &str, error_code: ErrorCode) -> Result<Value, ApiError> {
    if doc.get("id").and_then(Value::as_str) == Some(did) {
        Ok(doc)
    } else {
        tracing::warn!(did = %did, doc_id = ?doc.get("id"), "DID document id mismatch");
        Err(ApiError::new(error_code, "DID document id mismatch"))
    }
}

const ERROR_BODY_PREVIEW_BYTES: usize = 2048;

async fn bounded_body_preview(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    while body.len() < ERROR_BODY_PREVIEW_BYTES {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => break,
        };
        let remaining = ERROR_BODY_PREVIEW_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }

    safe_body_preview(&String::from_utf8_lossy(&body))
}

fn safe_body_preview(body: &str) -> String {
    body.chars().take(500).collect()
}

fn did_web_document_url(did: &str) -> Result<String, ApiError> {
    let method_specific = did
        .strip_prefix("did:web:")
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))?;
    if method_specific.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    let segments = method_specific
        .split(':')
        .map(|segment| {
            urlencoding::decode(segment)
                .map(|decoded| decoded.into_owned())
                .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let Some(host) = segments.first() else {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    };
    if host.is_empty()
        || forbidden_did_web_authority(host)
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.contains('/')
                || segment.contains('\\')
                || segment.contains('?')
                || segment.contains('#')
        })
    {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    if segments.len() == 1 {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        let path = segments[1..].join("/");
        Ok(format!("https://{host}/{path}/did.json"))
    }
}

fn forbidden_did_web_authority(authority: &str) -> bool {
    if authority.contains('@') || authority.contains('[') || authority.contains(']') {
        return true;
    }

    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => host,
        Some(_) => return true,
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok()
}

fn also_known_as_handles(did_doc: &Value) -> Vec<String> {
    did_doc
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|alias| alias.strip_prefix("at://"))
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        did_web_document_url, resolve_atproto_proxy_target, safe_body_preview,
        validate_proxy_endpoint,
    };
    use crate::app::test_state;
    use crate::routes::test_utils::seed_did_document;

    // IP literals (not domain names) throughout: they exercise the exact same validation as a
    // resolved domain without depending on live DNS, keeping these tests hermetic and fast.
    // `1.2.3.4` stands in for "some public IP" in the happy-path cases below.

    #[tokio::test]
    async fn resolves_service_by_abbreviated_id() {
        let state = test_state().await;
        seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": "https://1.2.3.4:8443",
                }],
            }),
        )
        .await;

        let target = resolve_atproto_proxy_target(&state, "did:plc:labeler123#atproto_labeler")
            .await
            .unwrap();
        assert_eq!(target.url, "https://1.2.3.4:8443");
        assert_eq!(target.header_value, "did:plc:labeler123#atproto_labeler");
        // An IP literal has no separate DNS-resolution step, so there's nothing to pin.
        assert!(target.pinned.is_none());
    }

    #[tokio::test]
    async fn resolves_service_by_fully_qualified_id() {
        let state = test_state().await;
        seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "did:plc:labeler123#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": "https://1.2.3.4:8443",
                }],
            }),
        )
        .await;

        let target = resolve_atproto_proxy_target(&state, "did:plc:labeler123#atproto_labeler")
            .await
            .unwrap();
        assert_eq!(target.url, "https://1.2.3.4:8443");
    }

    #[tokio::test]
    async fn rejects_header_missing_fragment() {
        let state = test_state().await;
        let err = resolve_atproto_proxy_target(&state, "did:plc:labeler123")
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn rejects_non_http_service_endpoint() {
        let state = test_state().await;
        seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": "ftp://1.2.3.4",
                }],
            }),
        )
        .await;

        let err = resolve_atproto_proxy_target(&state, "did:plc:labeler123#atproto_labeler")
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 503);
    }

    // --- validate_proxy_endpoint: SSRF-guard matrix (all IP-literal, no live DNS needed) ---

    #[tokio::test]
    async fn accepts_public_ipv4_and_ipv6() {
        assert!(validate_proxy_endpoint("https://1.2.3.4", false)
            .await
            .unwrap()
            .is_none());
        assert!(
            validate_proxy_endpoint("https://[2606:4700:4700::1111]", false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_userinfo_in_url() {
        let err = validate_proxy_endpoint("https://user:pass@1.2.3.4", false)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 503);
    }

    #[tokio::test]
    async fn rejects_query_and_fragment() {
        assert!(validate_proxy_endpoint("https://1.2.3.4/?a=b", false)
            .await
            .is_err());
        assert!(validate_proxy_endpoint("https://1.2.3.4/#frag", false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_loopback_by_default_but_allows_it_when_relaxed() {
        assert!(validate_proxy_endpoint("http://127.0.0.1:8080", false)
            .await
            .is_err());
        assert!(validate_proxy_endpoint("http://127.0.0.1:8080", true)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rejects_private_link_local_and_metadata_ipv4() {
        for host in [
            "10.0.0.5",        // RFC 1918 private
            "172.16.0.5",      // RFC 1918 private
            "192.168.1.5",     // RFC 1918 private
            "169.254.169.254", // cloud-metadata (link-local range)
            "100.64.0.5",      // RFC 6598 carrier-grade NAT
            "0.0.0.0",         // unspecified
            "255.255.255.255", // broadcast
        ] {
            let err = validate_proxy_endpoint(&format!("http://{host}"), false)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), 503, "expected {host} to be rejected");
        }
    }

    #[tokio::test]
    async fn rejects_ipv6_loopback_unique_local_and_mapped_ipv4() {
        for host in [
            "[::1]",                // loopback
            "[fc00::1]",            // unique-local (RFC 4193)
            "[fe80::1]",            // link-local
            "[::ffff:127.0.0.1]",   // IPv4-mapped loopback — must not bypass the IPv4 checks
            "[::ffff:169.254.1.1]", // IPv4-mapped link-local/metadata range
        ] {
            let err = validate_proxy_endpoint(&format!("http://{host}"), false)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), 503, "expected {host} to be rejected");
        }
    }

    // The only test that touches live DNS: confirms the domain-resolution branch actually wires
    // up (pins to the addresses it validated), not just the IP-literal fast path exercised above.
    #[tokio::test]
    async fn resolves_and_pins_a_real_domain() {
        let pinned = validate_proxy_endpoint("https://example.com", false)
            .await
            .unwrap()
            .expect("example.com is a domain name, not an IP literal");
        assert_eq!(pinned.domain, "example.com");
        assert!(!pinned.addrs.is_empty());
    }

    #[test]
    fn did_web_url_uses_well_known_for_bare_domain() {
        assert_eq!(
            did_web_document_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_uses_path_segments_when_present() {
        assert_eq!(
            did_web_document_url("did:web:example.com:users:alice").unwrap(),
            "https://example.com/users/alice/did.json"
        );
    }

    #[test]
    fn did_web_url_decodes_percent_encoded_host_port() {
        assert_eq!(
            did_web_document_url("did:web:example.com%3A8443").unwrap(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_rejects_path_separator_inside_segment() {
        assert!(did_web_document_url("did:web:example.com:%2Fadmin").is_err());
    }

    #[test]
    fn did_web_url_rejects_userinfo_loopback_and_ip_literals() {
        assert!(did_web_document_url("did:web:user%40example.com").is_err());
        assert!(did_web_document_url("did:web:localhost").is_err());
        assert!(did_web_document_url("did:web:sub.localhost").is_err());
        assert!(did_web_document_url("did:web:127.0.0.1").is_err());
        assert!(did_web_document_url("did:web:10.0.0.1%3A8443").is_err());
        assert!(did_web_document_url("did:web:%5B%3A%3A1%5D").is_err());
        assert!(did_web_document_url("did:web:%3A443").is_err());
        assert!(did_web_document_url("did:web:example.com%3A99999").is_err());
    }

    #[test]
    fn safe_body_preview_truncates_on_char_boundary() {
        let preview = safe_body_preview(&"é".repeat(600));
        assert_eq!(preview.chars().count(), 500);
        assert!(preview.is_char_boundary(preview.len()));
    }
}
