// pattern: Functional Core

use common::{ApiError, ErrorCode};

/// The authorization scheme an access token arrived under.
///
/// RFC 9449 makes the scheme part of the security model: `DPoP` declares the
/// token is proof-of-possession-bound, `Bearer` declares it is not. The
/// `AuthenticatedUser` extractor cross-checks the declared scheme against the
/// token's actual `cnf.jkt` binding, so a mismatch in either direction is
/// rejected rather than silently downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    Bearer,
    Dpop,
}

/// Extract `Authorization: Bearer <token>` from headers.
///
/// Bearer-only by design: session, refresh, and device tokens are never
/// DPoP-bound, so their routes keep the strict single-scheme check. Access-token
/// paths that must also accept spec-correct OAuth clients (`Authorization: DPoP`)
/// use [`extract_access_token`] instead.
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    let auth_value = authorization_header_value(headers)?;
    strip_scheme(auth_value, "Bearer ").ok_or_else(|| {
        ApiError::new(
            ErrorCode::AuthenticationRequired,
            "Authorization header must use Bearer scheme",
        )
    })
}

/// Extract an access token from `Authorization`, accepting the `Bearer` and
/// `DPoP` schemes (RFC 9449 §7.1 — a DPoP-bound token is presented as
/// `Authorization: DPoP <token>`, matching the reference PDS).
pub fn extract_access_token(
    headers: &axum::http::HeaderMap,
) -> Result<(AuthScheme, &str), ApiError> {
    let auth_value = authorization_header_value(headers)?;
    if let Some(token) = strip_scheme(auth_value, "Bearer ") {
        return Ok((AuthScheme::Bearer, token));
    }
    if let Some(token) = strip_scheme(auth_value, "DPoP ") {
        return Ok((AuthScheme::Dpop, token));
    }
    Err(ApiError::new(
        ErrorCode::AuthenticationRequired,
        "Authorization header must use Bearer or DPoP scheme",
    ))
}

fn authorization_header_value(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::AuthenticationRequired,
                "missing Authorization header",
            )
        })
}

/// Strip a `"<Scheme> "` prefix (scheme name + single SP) case-insensitively
/// (RFC 7235 §2.1: auth scheme names are case-insensitive).
fn strip_scheme<'a>(auth_value: &'a str, scheme_prefix: &str) -> Option<&'a str> {
    let len = scheme_prefix.len();
    auth_value
        .get(..len)
        .is_some_and(|s| s.eq_ignore_ascii_case(scheme_prefix))
        .then(|| &auth_value[len..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn extract_access_token_accepts_both_schemes_case_insensitively() {
        for (value, scheme) in [
            ("Bearer tok123", AuthScheme::Bearer),
            ("bearer tok123", AuthScheme::Bearer),
            ("DPoP tok123", AuthScheme::Dpop),
            ("dpop tok123", AuthScheme::Dpop),
            ("DPOP tok123", AuthScheme::Dpop),
        ] {
            let headers = headers_with_auth(value);
            let (got_scheme, token) = extract_access_token(&headers).unwrap();
            assert_eq!(got_scheme, scheme, "scheme for {value:?}");
            assert_eq!(token, "tok123", "token for {value:?}");
        }
    }

    #[test]
    fn extract_access_token_rejects_unknown_scheme_and_missing_header() {
        let headers = headers_with_auth("Token tok123");
        assert!(extract_access_token(&headers).is_err());
        assert!(extract_access_token(&HeaderMap::new()).is_err());
    }

    #[test]
    fn extract_bearer_token_stays_bearer_only() {
        let headers = headers_with_auth("Bearer tok123");
        assert_eq!(extract_bearer_token(&headers).unwrap(), "tok123");
        // A DPoP-scheme header is rejected by the Bearer-only extraction used for
        // session/refresh/device tokens, which are never DPoP-bound.
        let headers = headers_with_auth("DPoP tok123");
        assert!(extract_bearer_token(&headers).is_err());
    }
}
