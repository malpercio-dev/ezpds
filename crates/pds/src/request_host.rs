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
    fn none_when_nothing_present() {
        let h = HeaderMap::new();
        let uri: Uri = "/path".parse().unwrap();
        assert_eq!(request_host(&h, &uri), None);
    }
}
