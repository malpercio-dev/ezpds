// pattern: Imperative Shell
//
// The `atproto-proxy` header target guard: resolves a caller-supplied `<did>#<serviceId>` header
// to an upstream service endpoint, then SSRF-validates that endpoint (scheme, userinfo,
// query/fragment, and a public-address check on IP-literal hosts) before it's ever handed to the
// HTTP client. Since the target DID is caller-chosen, an attacker can make its DID document
// advertise anything — this is the only thing standing between an authenticated request and an
// SSRF into the PDS's private network. Also provides the SSRF-hardened HTTP client
// (`build_hardened_client`), a single shared/pooled client whose custom DNS resolver
// (`SsrfResolver`) re-applies the same allowlist to every resolved address at connect time — the
// domain-name half of the guard, closing the redirect/re-resolution TOCTOU gap without a fresh
// client per request.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;

use super::resolution::resolve_did_document;

/// A validated `atproto-proxy` target, ready to hand to `proxy_xrpc`.
#[derive(Debug)]
pub struct ProxyTarget {
    /// The service base URL: validated http(s) scheme, no userinfo/query/fragment, and — for an
    /// IP-literal host — a public (non-loopback/private/link-local/metadata) address. A domain
    /// host's addresses are validated at connect time by the hardened client's [`SsrfResolver`].
    pub url: String,
    /// The original `atproto-proxy` header value, echoed back verbatim as the outbound header.
    pub header_value: String,
}

/// The read timeout applied to every outbound fetch to a caller-influenced target, and the bound
/// on a single DNS resolution inside [`SsrfResolver`] (kept well under it so a slow/hostile
/// resolver for a caller-chosen host can't tie up request handling).
const HARDENED_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const HARDENED_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// A [`reqwest::dns::Resolve`] that enforces the SSRF allowlist on every address it hands back.
///
/// Installed on the shared hardened client ([`build_hardened_client`]). hyper only consults it for
/// hostnames that need DNS resolution — a URL whose host is already an IP literal bypasses it
/// entirely, which is exactly why [`validate_proxy_endpoint`] still checks IP literals itself. For
/// a domain, it resolves the name and rejects the *whole* resolution unless every returned address
/// is public and routable, so a second DNS answer at connect time (DNS-rebinding TOCTOU, or simply
/// a record that changed since the request began) can never substitute an address that was never
/// checked. This is the domain-name half of the guard the per-request `resolve_to_addrs` pin used
/// to provide; folding it into a resolver lets one pooled client serve every SSRF-guarded call
/// site instead of a fresh client (and TLS handshake) per request.
///
/// `allow_loopback` mirrors [`AppState::allow_loopback_proxy_targets`]: baked in when the client is
/// built (`false` in production, `true` only under the test harness). The one test that flips the
/// flag after construction targets an IP literal, so it never reaches this resolver.
#[derive(Debug)]
struct SsrfResolver {
    allow_loopback: bool,
}

impl reqwest::dns::Resolve for SsrfResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            type BoxError = Box<dyn std::error::Error + Send + Sync>;
            let host = name.as_str().to_owned();
            // Port 0: the resolved SocketAddrs' ports are overridden by the URL's port at connect
            // time (see the `reqwest::dns::Resolve` contract), so the port is irrelevant here — we
            // only care about the IPs to validate them.
            let addrs: Vec<SocketAddr> = match tokio::time::timeout(
                HARDENED_RESOLVE_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), 0)),
            )
            .await
            {
                Ok(Ok(iter)) => iter.collect(),
                Ok(Err(e)) => return Err(Box::new(e) as BoxError),
                Err(_) => return Err(format!("DNS resolution for {host:?} timed out").into()),
            };

            if addrs.is_empty() {
                return Err(format!("no addresses resolved for {host:?}").into());
            }
            // Fail closed: reject the entire resolution if *any* address is non-public, so a mixed
            // answer can't smuggle a private target past the guard.
            if !addrs
                .iter()
                .all(|addr| ip_allowed(addr.ip(), allow_loopback))
            {
                return Err(format!(
                    "refusing to connect to {host:?}: it resolves to a non-public address"
                )
                .into());
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Build the shared HTTP client used for every fetch to a caller-influenced target — the
/// `atproto-proxy` header target (`routes::service_proxy`), a did:web document
/// (`identity::resolution`), and a Lexicon-authority permission-set record
/// (`auth::permission_sets`). Built once and stored in [`AppState::hardened_http_client`], so all
/// four SSRF-guarded call sites share one connection pool + TLS context instead of constructing a
/// fresh client (and handshaking anew) per request.
///
/// Three hardenings, all always on:
///   * **Redirects disabled** — a [`validate_proxy_endpoint`] check only inspects the *first* URL,
///     so following a 3xx could sail past it onto a private/loopback/metadata address.
///   * **[`SsrfResolver`] DNS** — every domain-name resolution is re-checked against the allowlist
///     at connect time, so a second DNS answer can't substitute an address that was never checked.
///   * **Env proxies ignored** (`no_proxy`) — reqwest otherwise honors `HTTP_PROXY`/`HTTPS_PROXY`/
///     `ALL_PROXY`, which would tunnel the request through an intermediary that resolves the target
///     host itself, bypassing `SsrfResolver` entirely. The whole point of this client is to control
///     exactly which address a caller-influenced fetch connects to, so it must not delegate that to
///     a proxy. (The plain `http_client`, which only talks to trusted admin-configured upstreams,
///     deliberately still honors an operator's egress proxy.)
///
/// `allow_loopback` is baked into the resolver (see [`SsrfResolver`]); production always passes
/// `false`.
pub(crate) fn build_hardened_client(
    allow_loopback: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(HARDENED_CLIENT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(SsrfResolver { allow_loopback }))
        .build()
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

    validate_proxy_endpoint(endpoint, state.allow_loopback_proxy_targets).await?;

    Ok(ProxyTarget {
        url: endpoint.to_string(),
        header_value: header_value.to_string(),
    })
}

/// Parse and validate the URL shape of a caller-influenced proxy endpoint, plus the address of an
/// IP-literal host.
///
/// Rejects: non-http(s) schemes, userinfo (`user:pass@host`), a query or fragment (both
/// meaningless on a base URL `proxy_xrpc` only ever appends `/xrpc/{nsid}` to, and a vector for
/// smuggling tricks past a naive parser), and an IP-literal host that isn't a public address
/// (loopback, RFC 1918 private, link-local/cloud-metadata, unique-local IPv6, unspecified,
/// multicast, broadcast, or documentation ranges are all rejected, for both IPv4 and
/// IPv4-mapped-into-IPv6 forms).
///
/// A **domain-name** host is not resolved here: the hardened client's [`SsrfResolver`] applies the
/// identical allowlist to whatever the domain resolves to at connect time. Doing the check there —
/// against the answer actually connected to — is what lets one shared, pooled client replace the
/// old per-request pinned client while keeping the DNS-rebinding TOCTOU closed. This function's job
/// on a domain host is therefore only the URL-shape checks; the address check is the resolver's.
///
/// `allow_loopback` is a test-only relaxation (see `AppState::allow_loopback_proxy_targets`):
/// production always passes `false`.
///
/// `pub(crate)`: also reused by `auth::permission_sets` to guard the Lexicon-authority service
/// endpoint fetch, which faces the identical "attacker names the resolution target" shape.
pub(crate) async fn validate_proxy_endpoint(
    endpoint: &str,
    allow_loopback: bool,
) -> Result<(), ApiError> {
    let bad_target = || {
        ApiError::new(
            ErrorCode::ServiceUnavailable,
            "atproto-proxy target is not a usable public service endpoint",
        )
    };

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

    match host {
        // An IP-literal host never reaches the hardened client's `SsrfResolver` (hyper connects to
        // the literal directly), so its address must be checked here.
        url::Host::Ipv4(ip) if !ip_allowed(IpAddr::V4(ip), allow_loopback) => Err(bad_target()),
        url::Host::Ipv6(ip) if !ip_allowed(IpAddr::V6(ip), allow_loopback) => Err(bad_target()),
        // A domain host's addresses are validated at connect time by `SsrfResolver`.
        _ => Ok(()),
    }
}

/// Whether `ip` may be connected to for a caller-influenced target: a public, routable address, or
/// loopback when the test-only relaxation is in effect. Shared by [`validate_proxy_endpoint`]'s
/// IP-literal branch and [`SsrfResolver`]'s connect-time domain check, so both enforce one
/// allowlist.
fn ip_allowed(ip: IpAddr, allow_loopback: bool) -> bool {
    is_global_ip(ip) || (allow_loopback && ip.is_loopback())
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
    // 2001::/32 — Teredo tunneling (RFC 4380): can carry an obfuscated IPv4 address, a bypass
    // for the IPv4 checks below if left unrejected.
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return false;
    }
    // 2002::/16 — 6to4 (RFC 3056): embeds a raw IPv4 address in the next 32 bits, the same
    // bypass shape as Teredo above.
    if segments[0] == 0x2002 {
        return false;
    }
    // 64:ff9b::/96 (well-known) and 64:ff9b:1::/48 (local-use) — NAT64 (RFC 6052/8215): embed a
    // raw IPv4 address in the low bits.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && (segments[2] == 0x0001
            || (segments[2] == 0x0000
                && segments[3] == 0x0000
                && segments[4] == 0x0000
                && segments[5] == 0x0000))
    {
        return false;
    }
    // ::/96 — IPv4-compatible (deprecated, RFC 4291 §2.5.5.1): embeds a raw IPv4 address in the
    // low 32 bits. `::` and `::1` are already excluded above by is_unspecified/is_loopback.
    if segments[..6].iter().all(|&s| s == 0) {
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
    use std::str::FromStr;

    use super::{ip_allowed, resolve_atproto_proxy_target, validate_proxy_endpoint, SsrfResolver};
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
            .is_ok());
        assert!(
            validate_proxy_endpoint("https://[2606:4700:4700::1111]", false)
                .await
                .is_ok()
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
            .is_ok());
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
            "[::1]",                  // loopback
            "[fc00::1]",              // unique-local (RFC 4193)
            "[fe80::1]",              // link-local
            "[2001:db8::1]",          // documentation (RFC 3849)
            "[::ffff:127.0.0.1]",     // IPv4-mapped loopback — must not bypass the IPv4 checks
            "[::ffff:169.254.1.1]",   // IPv4-mapped link-local/metadata range
            "[2001::1]",              // Teredo (RFC 4380) — can carry an obfuscated IPv4 address
            "[2002:7f00:1::]",        // 6to4 (RFC 3056) — embeds 127.0.0.1 in the next 32 bits
            "[64:ff9b::127.0.0.1]",   // NAT64 well-known prefix (RFC 6052) — embeds 127.0.0.1
            "[64:ff9b:1::127.0.0.1]", // NAT64 local-use prefix (RFC 8215) — embeds 127.0.0.1
            "[::127.0.0.1]",          // IPv4-compatible (deprecated, RFC 4291 §2.5.5.1)
        ] {
            let err = validate_proxy_endpoint(&format!("http://{host}"), false)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), 503, "expected {host} to be rejected");
        }
    }

    // A domain-name host passes the URL-shape checks without being resolved here — its address is
    // validated at connect time by `SsrfResolver` (exercised directly below). Even a domain that
    // would resolve to loopback is accepted at this stage regardless of `allow_loopback`, since no
    // address check happens on the domain branch.
    #[tokio::test]
    async fn domain_host_passes_shape_checks_without_resolving() {
        assert!(validate_proxy_endpoint("https://example.com", false)
            .await
            .is_ok());
        assert!(validate_proxy_endpoint("http://localhost:80", false)
            .await
            .is_ok());
    }

    // ── ip_allowed: the one allowlist both branches share ────────────────────

    #[test]
    fn ip_allowed_permits_public_and_gates_loopback_on_the_relaxation() {
        use std::net::IpAddr;
        let public: IpAddr = "1.2.3.4".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let private: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(ip_allowed(public, false));
        assert!(ip_allowed(public, true));
        assert!(!ip_allowed(loopback, false));
        assert!(ip_allowed(loopback, true)); // relaxation on
        assert!(!ip_allowed(private, false));
        assert!(!ip_allowed(private, true)); // relaxation never widens past loopback
    }

    // ── SsrfResolver: the connect-time domain guard ──────────────────────────
    //
    // `localhost` resolves to loopback on every host, so these stay hermetic (no external DNS) yet
    // exercise both the reject-non-public path and the loopback relaxation the domain branch of
    // `validate_proxy_endpoint` now defers to.

    #[tokio::test]
    async fn ssrf_resolver_rejects_non_public_resolution() {
        use reqwest::dns::Resolve;
        let resolver = SsrfResolver {
            allow_loopback: false,
        };
        let name = reqwest::dns::Name::from_str("localhost").unwrap();
        // `Addrs` (the Ok type) isn't `Debug`, so match rather than `expect_err`.
        let err = match resolver.resolve(name).await {
            Ok(_) => panic!("localhost resolves to loopback, which is not public"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("non-public"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn ssrf_resolver_allows_loopback_when_relaxed() {
        use reqwest::dns::Resolve;
        let resolver = SsrfResolver {
            allow_loopback: true,
        };
        let name = reqwest::dns::Name::from_str("localhost").unwrap();
        let addrs: Vec<_> = resolver
            .resolve(name)
            .await
            .expect("loopback is permitted under the relaxation")
            .collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}
