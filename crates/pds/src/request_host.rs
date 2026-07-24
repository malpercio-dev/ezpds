// pattern: Functional Core
//
// Shared host resolution for Host-keyed public routes (`.well-known/atproto-did`,
// `.well-known/did.json`). Lives outside `routes/` so both handlers can call it without a
// route-to-route import (the constraint that would otherwise force duplication).

use axum::http::{header, HeaderMap, Uri};

/// Resolve the host the client addressed: `X-Forwarded-Host` (stamped by the deploy proxy — trusted
/// here because the PDS is only reachable through it) → `Host` header (HTTP/1.1) → URI authority
/// (HTTP/2 carries `:authority` instead of a Host header).
///
/// This replaces axum's `Host` extractor, which 0.8 moved to axum-extra and is being removed
/// upstream (tokio-rs/axum#3442): honouring a client-supplied `X-Forwarded-Host` is only safe
/// behind a proxy that overwrites it, which is this deployment's topology (Railway) — a
/// direct-exposure deployment would need to drop the forwarded lookup.
pub fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| uri.authority().map(|a| a.to_string()))
        .map(|host| strip_default_port(&host).to_owned())
}

/// Drop an explicit default port from a host: `example.com:443` names the same origin as
/// `example.com`, but verbatim it would key a different did:web DID / handle and miss every
/// lookup. Non-default ports are preserved — `did:web:host%3A8080` is a legitimately distinct
/// DID. Both 443 and 80 are treated as default (TLS terminates at the deploy proxy, so the
/// original scheme is not observable here; these well-known routes are only reachable on
/// standard ports either way).
fn strip_default_port(host: &str) -> &str {
    host.strip_suffix(":443")
        .or_else(|| host.strip_suffix(":80"))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn forwarded_host_wins_over_host() {
        let h = headers(&[
            ("host", "internal.local"),
            ("x-forwarded-host", "example.com"),
        ]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(request_host(&h, &uri).as_deref(), Some("example.com"));
    }

    #[test]
    fn host_used_when_no_forwarded() {
        let h = headers(&[("host", "example.com")]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(request_host(&h, &uri).as_deref(), Some("example.com"));
    }

    #[test]
    fn authority_used_when_no_headers() {
        let h = HeaderMap::new();
        let uri: Uri = "https://example.com/path".parse().unwrap();
        assert_eq!(request_host(&h, &uri).as_deref(), Some("example.com"));
    }

    #[test]
    fn default_ports_are_stripped() {
        let uri: Uri = "/".parse().unwrap();
        for host in ["example.com:443", "example.com:80"] {
            let h = headers(&[("host", host)]);
            assert_eq!(request_host(&h, &uri).as_deref(), Some("example.com"));
        }
    }

    #[test]
    fn non_default_port_is_preserved() {
        let h = headers(&[("host", "example.com:8080")]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(request_host(&h, &uri).as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn ipv6_literal_default_port_is_stripped() {
        let h = headers(&[("host", "[::1]:443")]);
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(request_host(&h, &uri).as_deref(), Some("[::1]"));
    }

    #[test]
    fn none_when_nothing_present() {
        let h = HeaderMap::new();
        let uri: Uri = "/path".parse().unwrap();
        assert_eq!(request_host(&h, &uri), None);
    }
}
