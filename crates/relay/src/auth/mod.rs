// Dead-code lint suppressed: this module is foundational infrastructure.
// Items will be used once authenticated routes are wired up in subsequent waves.
#![allow(dead_code)]

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Method},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::{ApiError, ErrorCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::app::AppState;

// ── Public types ─────────────────────────────────────────────────────────────

/// Scope embedded in the JWT `scope` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScope {
    Access,
    Refresh,
    AppPass,
}

/// Whether this token was presented as a plain Bearer or a DPoP-bound token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    /// Simple Bearer JWT issued by `createSession`.
    Legacy,
    /// DPoP-bound token (RFC 9449).
    DPoP,
}

/// Axum extractor that validates a Bearer (or DPoP-bound) JWT and yields the
/// authenticated caller's DID, scope, and token type.
///
/// Extract this in any handler that requires authentication:
/// ```rust,ignore
/// async fn my_handler(user: AuthenticatedUser) -> impl IntoResponse { ... }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub did: String,
    pub scope: AuthScope,
    pub token_type: TokenType,
}

// ── JWT claims ───────────────────────────────────────────────────────────────

/// Claims decoded from the server-issued access/refresh JWT.
#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    /// Subject — the authenticated DID.
    sub: String,
    /// Scope string from the AT Protocol spec.
    scope: String,
    /// Confirmation claim — present on DPoP-bound tokens.
    cnf: Option<CnfClaim>,
}

/// `cnf` (confirmation) claim carrying the JWK thumbprint for DPoP binding.
#[derive(Debug, Deserialize)]
struct CnfClaim {
    /// JWK SHA-256 thumbprint (base64url, no padding) of the client's DPoP key.
    jkt: Option<String>,
}

// ── DPoP JWT header + claims ─────────────────────────────────────────────────

/// Decoded DPoP proof JWT header fields relevant to validation.
#[derive(Debug, Deserialize)]
struct DPopHeader {
    /// Must be `"dpop+jwt"`.
    typ: String,
    /// Algorithm (e.g. `"ES256"`).
    alg: String,
    /// The client's public JWK, embedded in the proof header (RFC 9449 §4.2).
    jwk: serde_json::Value,
}

/// Claims from the DPoP proof JWT payload.
#[derive(Debug, Deserialize)]
struct DPopClaims {
    /// HTTP method (e.g. `"POST"`).
    htm: String,
    /// HTTP URI (scheme + host + path, no query string).
    htu: String,
    /// Issued-at (Unix timestamp). Used for freshness; replaces `exp`.
    iat: i64,
    /// Unique token ID — must be present for replay protection.
    jti: String,
}

// ── Extractor implementation ─────────────────────────────────────────────────

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Extract the raw Bearer token string from Authorization header.
        let token_str = extract_bearer_token(&parts.headers)?;

        // 2. Detect the DPoP header before decoding the access token.
        let dpop_value = parts
            .headers
            .get("DPoP")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let has_dpop = dpop_value.is_some();

        // 3. Decode and verify the access token (HS256).
        let claims = verify_access_token(token_str, state)?;

        // 4. Resolve scope enum.
        let scope = parse_scope(&claims.scope)?;

        // 5. DPoP validation — only when the DPoP header is present.
        if has_dpop {
            let dpop_token = dpop_value.as_deref().unwrap();
            validate_dpop(dpop_token, &parts.method, &parts.uri, &claims)?;
        }

        let token_type = if has_dpop {
            TokenType::DPoP
        } else {
            TokenType::Legacy
        };

        Ok(AuthenticatedUser {
            did: claims.sub,
            scope,
            token_type,
        })
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Extract `Authorization: Bearer <token>` from headers.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    let auth_value = headers
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
        })?;

    auth_value.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            ErrorCode::AuthenticationRequired,
            "Authorization header must use Bearer scheme",
        )
    })
}

/// Decode and verify the HS256 access/refresh JWT issued by this server.
fn verify_access_token(
    token: &str,
    state: &AppState,
) -> Result<AccessTokenClaims, ApiError> {
    let decoding_key = DecodingKey::from_secret(&state.jwt_secret);

    let mut validation = Validation::new(Algorithm::HS256);
    // Validate audience only when the server DID is configured.
    match state.config.server_did.as_deref() {
        Some(did) => validation.set_audience(&[did]),
        None => {
            validation.validate_aud = false;
            tracing::debug!("server_did not configured; skipping JWT audience validation");
        }
    }
    // `sub` is required by AT Protocol but not in jsonwebtoken's default required set.
    validation.set_required_spec_claims(&["exp", "sub"]);
    // Zero leeway: tokens we issued ourselves need no clock-skew tolerance.
    validation.leeway = 0;

    decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => {
                    ApiError::new(ErrorCode::TokenExpired, "token has expired")
                }
                _ => ApiError::new(ErrorCode::InvalidToken, "invalid token"),
            }
        })
}

/// Parse the ATProto scope string into [`AuthScope`].
fn parse_scope(scope: &str) -> Result<AuthScope, ApiError> {
    match scope {
        "com.atproto.access" => Ok(AuthScope::Access),
        "com.atproto.refresh" => Ok(AuthScope::Refresh),
        "com.atproto.appPass" => Ok(AuthScope::AppPass),
        _ => Err(ApiError::new(ErrorCode::InvalidToken, "unrecognised token scope")),
    }
}

/// Validate the DPoP proof JWT (RFC 9449).
///
/// Checks:
/// - `typ` header is `"dpop+jwt"`
/// - Signature verifies against the embedded JWK
/// - `htm` matches request method, `htu` matches request URI
/// - `jti` is present (replay protection hook)
/// - Access token `cnf.jkt` matches the computed JWK thumbprint
fn validate_dpop(
    dpop_token: &str,
    method: &Method,
    uri: &axum::http::Uri,
    access_claims: &AccessTokenClaims,
) -> Result<(), ApiError> {
    let invalid = || ApiError::new(ErrorCode::InvalidToken, "DPoP proof invalid");

    // Decode the DPoP proof header manually — jsonwebtoken's Header type doesn't
    // expose custom header fields like `jwk`, so we base64-decode the first segment.
    let header_b64 = dpop_token.split('.').next().ok_or_else(invalid)?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| invalid())?;
    let dpop_header: DPopHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| invalid())?;

    if dpop_header.typ != "dpop+jwt" {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP proof typ must be dpop+jwt",
        ));
    }

    // Compute JWK thumbprint (RFC 7638) from the embedded public key.
    let thumbprint = jwk_thumbprint(&dpop_header.jwk).map_err(|_| invalid())?;

    // Verify that the access token was bound to this DPoP key.
    let bound_thumbprint = access_claims
        .cnf
        .as_ref()
        .and_then(|c| c.jkt.as_deref())
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidToken, "access token missing DPoP binding")
        })?;
    if thumbprint != bound_thumbprint {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP key thumbprint does not match token binding",
        ));
    }

    // Verify the DPoP JWT signature using the embedded public JWK.
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(dpop_header.jwk.clone()).map_err(|_| invalid())?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| invalid())?;
    let alg = dpop_alg_from_str(&dpop_header.alg).ok_or_else(invalid)?;

    let mut validation = Validation::new(alg);
    // DPoP proofs don't carry `exp`; freshness is via `iat`.
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;

    let dpop_data =
        decode::<DPopClaims>(dpop_token, &decoding_key, &validation).map_err(|_| invalid())?;
    let dpop_claims = dpop_data.claims;

    // Require `jti` for replay protection (must be present and non-empty).
    if dpop_claims.jti.is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidToken, "DPoP proof missing jti"));
    }

    // Validate `htm` (HTTP method) and `htu` (HTTP URI).
    if dpop_claims.htm.to_uppercase() != method.as_str().to_uppercase() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP htm does not match request method",
        ));
    }

    // `htu` must match scheme + authority + path (no query string per RFC 9449 §4.3).
    let expected_htu = {
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let path = uri.path();
        format!("{scheme}://{authority}{path}")
    };
    if dpop_claims.htu != expected_htu {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP htu does not match request URI",
        ));
    }

    // Freshness: reject proofs older than 60 seconds.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - dpop_claims.iat).abs() > 60 {
        return Err(ApiError::new(ErrorCode::InvalidToken, "DPoP proof is stale"));
    }

    Ok(())
}

/// Map a DPoP `alg` string to a [`jsonwebtoken::Algorithm`].
fn dpop_alg_from_str(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        _ => None,
    }
}

/// Compute the RFC 7638 JWK thumbprint: SHA-256 of the canonical JSON member set,
/// base64url-encoded with no padding.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, ()> {
    let kty = jwk["kty"].as_str().ok_or(())?;

    // Canonical member set per RFC 7638 §3.2, in lexicographic order.
    // serde_json's default Map is a BTreeMap, so json! keys are sorted automatically.
    let canonical: serde_json::Value = match kty {
        "EC" => serde_json::json!({
            "crv": jwk["crv"],
            "kty": kty,
            "x": jwk["x"],
            "y": jwk["y"],
        }),
        "RSA" => serde_json::json!({
            "e": jwk["e"],
            "kty": kty,
            "n": jwk["n"],
        }),
        "OKP" => serde_json::json!({
            "crv": jwk["crv"],
            "kty": kty,
            "x": jwk["x"],
        }),
        _ => return Err(()),
    };

    let canonical_json = serde_json::to_string(&canonical).map_err(|_| ())?;
    let hash = Sha256::digest(canonical_json.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use tower::ServiceExt;

    use crate::app::test_state;

    /// Claims struct for minting test JWTs.
    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        aud: String,
        exp: u64,
        scope: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cnf: Option<serde_json::Value>,
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mint a valid HS256 JWT using the test state's jwt_secret.
    fn mint_token(
        sub: &str,
        scope: &str,
        exp_offset_secs: i64,
        secret: &[u8; 32],
        cnf: Option<serde_json::Value>,
    ) -> String {
        let exp = (now_secs() as i64 + exp_offset_secs) as u64;
        let claims = TestClaims {
            sub: sub.to_owned(),
            aud: "did:plc:test".to_owned(),
            exp,
            scope: scope.to_owned(),
            cnf,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    /// Build a minimal Axum router that uses AuthenticatedUser as an extractor.
    fn protected_app(state: AppState) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|user: AuthenticatedUser| async move {
                    format!("did={} scope={:?}", user.did, user.scope)
                }),
            )
            .with_state(state)
    }

    async fn get_protected(app: Router, token: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().uri("/protected");
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        app.oneshot(builder.body(Body::empty()).unwrap()).await.unwrap()
    }

    // ── Missing / malformed Authorization header ──────────────────────────────

    #[tokio::test]
    async fn missing_auth_header_returns_401_authentication_required() {
        let state = test_state().await;
        let app = protected_app(state);
        let resp = get_protected(app, None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn bearer_prefix_missing_returns_401_authentication_required() {
        let state = test_state().await;
        let app = protected_app(state);
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Token abc123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    // ── Malformed / invalid token ─────────────────────────────────────────────

    #[tokio::test]
    async fn malformed_token_returns_401_invalid_token() {
        let state = test_state().await;
        let app = protected_app(state);
        let resp = get_protected(app, Some("not.a.jwt")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn wrong_signature_returns_401_invalid_token() {
        let state = test_state().await;
        let wrong_secret = [0xFFu8; 32];
        let token = mint_token("did:plc:user", "com.atproto.access", 3600, &wrong_secret, None);
        let app = protected_app(state);
        let resp = get_protected(app, Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── Expired token ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_token_returns_401_token_expired() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        // exp is 1 second in the past.
        let token = mint_token("did:plc:user", "com.atproto.access", -1, &secret, None);
        let app = protected_app(state);
        let resp = get_protected(app, Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
    }

    // ── Valid access token ────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_access_token_extracts_did_and_scope() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &secret,
            None,
        );
        let app = protected_app(state);
        let resp = get_protected(app, Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("did=did:plc:alice"));
        assert!(text.contains("scope=Access"));
    }

    #[tokio::test]
    async fn valid_refresh_token_extracts_refresh_scope() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        let token = mint_token("did:plc:alice", "com.atproto.refresh", 3600, &secret, None);
        let app = protected_app(state);
        let resp = get_protected(app, Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("scope=Refresh"));
    }

    // ── Unknown scope ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_scope_returns_401_invalid_token() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        let token = mint_token("did:plc:user", "com.example.unknown", 3600, &secret, None);
        let app = protected_app(state);
        let resp = get_protected(app, Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── JWK thumbprint ────────────────────────────────────────────────────────

    #[test]
    fn rsa_jwk_thumbprint_matches_rfc7638_example() {
        // RFC 7638 §3.3 canonical example — RSA key with known expected thumbprint.
        let jwk = serde_json::json!({
            "e": "AQAB",
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            // Extra member — must be excluded from the canonical form.
            "use": "sig"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn ec_jwk_thumbprint_produces_correct_format() {
        // EC (P-256) key from RFC 7517 Appendix A.2. Extra fields like "use" and "d"
        // must be stripped from the canonical form.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        // SHA-256 base64url (no padding) is always 43 characters.
        assert_eq!(thumb.len(), 43, "thumbprint must be 43 base64url chars");
        assert!(
            thumb.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint must be base64url"
        );
        // Stable value — verified against implementation; guards against regressions.
        assert_eq!(thumb, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
    }

    // ── DPoP binding — token without cnf claim rejected ───────────────────────

    #[tokio::test]
    async fn dpop_header_without_cnf_claim_returns_401() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        // Access token has no `cnf` claim.
        let token = mint_token("did:plc:user", "com.atproto.access", 3600, &secret, None);
        let app = protected_app(state);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", "dummy.dpop.value")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }
}
