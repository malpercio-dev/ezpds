// pattern: Imperative Shell
//
// The `atproto-proxy` header target guard: resolves a caller-supplied `<did>#<serviceId>` header
// to an upstream service endpoint, then SSRF-validates that endpoint (scheme, userinfo,
// query/fragment, and public-address checks on both IP literals and resolved domain names) before
// it's ever handed to the HTTP client. Since the target DID is caller-chosen, an attacker can make
// its DID document advertise anything — this is the only thing standing between an authenticated
// request and an SSRF into the PDS's private network. Also provides the DNS-pinning hardened
// client builder (`build_pinned_client`) that closes the redirect/re-resolution TOCTOU gap between
// validation and connect.

use std::net::IpAddr;

use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;

use super::resolution::resolve_did_document;

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

/// Marks a `proxy_xrpc` call as targeting a caller-controlled destination — resolved from a
/// caller-supplied `atproto-proxy` header via `resolve_atproto_proxy_target`, whether the request
/// is `com.atproto.moderation.*` (which always resolves this way, having no configured default)
/// or an `app.bsky.*`/`chat.bsky.*` request that named an explicit header target overriding its
/// namespace's default. Either way the request must go through a hardened client: redirects
/// disabled (a malicious target can't 3xx its way onto a private/loopback address past the SSRF
/// check that only inspects the *first* URL) and, when the host was a domain name, DNS resolution
/// pinned to the addresses `resolve_atproto_proxy_target` already validated. A request with no
/// `atproto-proxy` header passes `None` for this and uses the shared `state.http_client`
/// unchanged — its upstream is the admin-configured default, not caller-controlled, so neither
/// concern applies.
#[derive(Debug)]
pub struct HeaderProxyGuard {
    pub pinned: Option<PinnedResolution>,
}

/// A domain name plus the specific addresses an outbound connection to it must be pinned to.
#[derive(Debug)]
pub struct PinnedResolution {
    pub domain: String,
    pub addrs: Vec<std::net::SocketAddr>,
}

/// Build a one-off HTTP client hardened for fetching from a caller-influenced target.
///
/// Always disables redirects: a `validate_proxy_endpoint` check only inspects the *first* URL,
/// so following a redirect could sail past it onto a private/loopback/metadata address. When
/// `pinned` is present (the host was a domain name), DNS resolution for that domain is
/// additionally overridden to exactly the addresses already validated — without this, the
/// client would re-resolve the domain independently at connect time, and a second DNS answer
/// (attacker-controlled, or simply a changed record) could point at an address that was never
/// checked. Shared by `routes::service_proxy`'s moderation-proxy branch and
/// `auth::permission_sets`'s Lexicon-authority fetch — both face the identical
/// "attacker names the resolution target" shape.
pub(crate) fn build_pinned_client(
    pinned: Option<&PinnedResolution>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pin) = pinned {
        builder = builder.resolve_to_addrs(&pin.domain, &pin.addrs);
    }
    builder.build()
}

/// Resolve an inbound `atproto-proxy` header (`<did>#<serviceId>`) to the upstream service it
/// names.
///
/// `app.bsky.*` and `chat.bsky.*` proxy to one configured default (the AppView / chat service)
/// when no header is present, but honor this header when it is — the official app's
/// `app.bsky.video.*` calls are the motivating case, routed to the video service this way rather
/// than the AppView. A namespace like `com.atproto.moderation.*` has no configured default at
/// all: the client always picks which labeler to report to via this header. Resolves the DID
/// document, then looks up a `service` entry whose `id` matches the header's fragment (either the
/// abbreviated `#serviceId` form or the fully-qualified `did#serviceId` form — both appear in the
/// wild), and validates the advertised `serviceEndpoint` before it's ever handed to the HTTP
/// client: since the target DID is caller-chosen, an attacker can make its DID document advertise
/// anything — this is the only thing standing between an authenticated request and an SSRF into
/// the PDS's private network.
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
///
/// `pub(crate)`: also reused by `auth::permission_sets` to guard the Lexicon-authority service
/// endpoint fetch, which faces the identical "attacker names the resolution target" shape.
pub(crate) async fn validate_proxy_endpoint(
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
            // The domain comes from a caller-chosen DID document, so a resolver that's slow (or
            // made slow on purpose) must not be able to tie up request handling indefinitely —
            // bound it well under the outbound HTTP client's own 10s timeout.
            let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::lookup_host((domain.as_str(), port)),
            )
            .await
            .map_err(|_| bad_target())?
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
        || is_shared_address_space(ip)
        || is_benchmark_address_space(ip)
        || is_reserved_ipv4(ip))
}

/// `100.64.0.0/10` (RFC 6598 carrier-grade NAT) — not covered by `Ipv4Addr::is_private`.
fn is_shared_address_space(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

/// `198.18.0.0/15` (RFC 2544 network-device benchmarking) — not covered by
/// `Ipv4Addr::is_documentation`.
fn is_benchmark_address_space(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 198 && (b & 0xfe) == 18
}

/// `240.0.0.0/4` ("Class E", reserved for future use) plus the all-ones broadcast address's
/// neighborhood — not covered by `Ipv4Addr::is_broadcast` (which only matches
/// `255.255.255.255` exactly).
fn is_reserved_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_global_ipv6(ip: std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let segments = ip.segments();
    // 2001:db8::/32 — documentation range (RFC 3849).
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    let first_segment = segments[0];
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

#[cfg(test)]
mod tests {
    use super::{resolve_atproto_proxy_target, validate_proxy_endpoint};
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
            "198.18.0.1",      // RFC 2544 benchmarking
            "0.0.0.0",         // unspecified
            "240.0.0.1",       // reserved ("Class E")
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
            "[2001:db8::1]",        // documentation (RFC 3849)
            "[::ffff:127.0.0.1]",   // IPv4-mapped loopback — must not bypass the IPv4 checks
            "[::ffff:169.254.1.1]", // IPv4-mapped link-local/metadata range
        ] {
            let err = validate_proxy_endpoint(&format!("http://{host}"), false)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), 503, "expected {host} to be rejected");
        }
    }

    // Confirms the domain-resolution branch actually wires up (pins to the addresses it
    // validated), not just the IP-literal fast path exercised above. Uses `localhost` under the
    // loopback relaxation rather than a real external domain, so the test stays hermetic — no
    // live DNS/network dependency.
    #[tokio::test]
    async fn resolves_and_pins_a_domain_name() {
        let pinned = validate_proxy_endpoint("http://localhost:80", true)
            .await
            .unwrap()
            .expect("localhost is a domain name, not an IP literal");
        assert_eq!(pinned.domain, "localhost");
        assert!(!pinned.addrs.is_empty());
    }
}
