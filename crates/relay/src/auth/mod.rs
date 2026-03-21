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
// Dead-code lint: foundational type; used once authenticated routes are wired up.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScope {
    Access,
    Refresh,
    AppPass,
}

/// Whether this token was presented as a plain Bearer or a DPoP-bound token.
// Dead-code lint: foundational type; used once authenticated routes are wired up.
#[allow(dead_code)]
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
// Dead-code lint: foundational type; used once authenticated routes are wired up.
#[allow(dead_code)]
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
    /// Confirmation claim — present on DPoP-bound tokens (RFC 9449 §4.3).
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
    /// HTTP method (e.g. `"GET"`).
    htm: String,
    /// HTTP target URI (scheme + host + path, no query string — RFC 9449 §4.3).
    htu: String,
    /// Issued-at (Unix timestamp). Used for freshness; replaces `exp`.
    iat: i64,
    /// Unique token ID — must be present and non-empty for replay protection.
    /// Full deduplication (RFC 9449 §11.1) requires a server-side nonce store,
    /// not yet implemented; this check only enforces presence.
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
            .and_then(|v| {
                v.to_str()
                    .inspect_err(|_| {
                        tracing::warn!(
                            "DPoP header contains non-UTF-8 bytes; treating as absent"
                        );
                    })
                    .ok()
            })
            .map(str::to_owned);
        let has_dpop = dpop_value.is_some();

        // 3. Decode and verify the access token (HS256).
        let claims = verify_access_token(token_str, state)?;

        // 4. Enforce DPoP binding (RFC 9449 §7.1): if the access token carries a
        //    `cnf.jkt` binding, the DPoP proof header is mandatory. Accepting the
        //    token as a plain Bearer would allow an attacker with a stolen access
        //    token to bypass the key binding entirely.
        let token_is_dpop_bound = claims.cnf.as_ref().map_or(false, |c| c.jkt.is_some());
        if token_is_dpop_bound && !has_dpop {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "DPoP-bound token requires a DPoP proof header",
            ));
        }

        // 5. Resolve scope enum.
        let scope = parse_scope(&claims.scope)?;

        // 6. DPoP proof validation — only when the DPoP header is present.
        if has_dpop {
            let dpop_token = dpop_value.as_deref().unwrap();
            validate_dpop(
                dpop_token,
                &parts.method,
                &parts.uri,
                &state.config.public_url,
                &claims,
            )?;
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
fn verify_access_token(token: &str, state: &AppState) -> Result<AccessTokenClaims, ApiError> {
    let decoding_key = DecodingKey::from_secret(&state.jwt_secret);

    let mut validation = Validation::new(Algorithm::HS256);
    // Validate audience only when the server DID is configured.
    match state.config.server_did.as_deref() {
        Some(did) => validation.set_audience(&[did]),
        None => {
            validation.validate_aud = false;
            tracing::warn!(
                "server_did not configured; JWT audience validation is disabled — \
                 set server_did in config for production deployments"
            );
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
/// - `htm` matches request method, `htu` matches `public_url + path`
/// - `jti` is present and non-empty
/// - `iat` is within the 60-second freshness window
/// - Access token `cnf.jkt` matches the computed JWK thumbprint
fn validate_dpop(
    dpop_token: &str,
    method: &Method,
    uri: &axum::http::Uri,
    public_url: &str,
    access_claims: &AccessTokenClaims,
) -> Result<(), ApiError> {
    let invalid = || ApiError::new(ErrorCode::InvalidToken, "DPoP proof invalid");

    // Decode the DPoP proof header manually — jsonwebtoken's Header type doesn't
    // expose custom header fields like `jwk`, so we base64-decode the first segment.
    let header_b64 = dpop_token.split('.').next().ok_or_else(invalid)?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof header is not valid base64url");
        invalid()
    })?;
    let dpop_header: DPopHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof header JSON is malformed or missing required fields");
        invalid()
    })?;

    if dpop_header.typ != "dpop+jwt" {
        tracing::debug!(typ = %dpop_header.typ, "DPoP proof typ is not dpop+jwt");
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP proof typ must be dpop+jwt",
        ));
    }

    // Compute JWK thumbprint (RFC 7638) from the embedded public key.
    let thumbprint = jwk_thumbprint(&dpop_header.jwk).map_err(|e| {
        tracing::debug!(error = %e, "failed to compute JWK thumbprint from DPoP proof header");
        invalid()
    })?;

    // Verify that the access token was bound to this DPoP key.
    let bound_thumbprint = access_claims
        .cnf
        .as_ref()
        .and_then(|c| c.jkt.as_deref())
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidToken, "access token missing DPoP binding")
        })?;
    if thumbprint != bound_thumbprint {
        tracing::debug!("DPoP proof key thumbprint does not match cnf.jkt in access token");
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP key thumbprint does not match token binding",
        ));
    }

    // Verify the DPoP JWT signature using the embedded public JWK.
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(dpop_header.jwk.clone()).map_err(|e| {
            tracing::debug!(error = %e, "failed to parse JWK from DPoP proof header");
            invalid()
        })?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        tracing::debug!(error = %e, "failed to build DecodingKey from DPoP JWK");
        invalid()
    })?;
    let alg = dpop_alg_from_str(&dpop_header.alg).ok_or_else(|| {
        tracing::debug!(alg = %dpop_header.alg, "unsupported DPoP proof algorithm");
        invalid()
    })?;

    let mut validation = Validation::new(alg);
    // DPoP proofs don't carry `exp`; freshness is enforced via `iat` below.
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;

    let dpop_data = decode::<DPopClaims>(dpop_token, &decoding_key, &validation).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof signature verification failed");
        invalid()
    })?;
    let dpop_claims = dpop_data.claims;

    // Require `jti` for replay protection (existence check only — full deduplication
    // per RFC 9449 §11.1 requires a server-side nonce store, not yet implemented).
    if dpop_claims.jti.is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidToken, "DPoP proof missing jti"));
    }

    // Validate `htm` (HTTP method).
    if dpop_claims.htm.to_uppercase() != method.as_str().to_uppercase() {
        tracing::debug!(
            proof_htm = %dpop_claims.htm,
            request_method = %method,
            "DPoP htm does not match request method"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP htm does not match request method",
        ));
    }

    // Validate `htu` (HTTP URI — scheme + host + path, no query string per RFC 9449 §4.3).
    // Axum receives path-form URIs behind a reverse proxy, so we reconstruct the
    // canonical URL from the configured public_url rather than the raw request URI.
    let expected_htu = format!("{}{}", public_url.trim_end_matches('/'), uri.path());
    if dpop_claims.htu != expected_htu {
        tracing::debug!(
            proof_htu = %dpop_claims.htu,
            expected_htu = %expected_htu,
            "DPoP htu does not match request URI"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP htu does not match request URI",
        ));
    }

    // Freshness: reject proofs issued more than 60 seconds ago or in the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "system clock is before UNIX epoch; DPoP validation impossible"
            );
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .as_secs() as i64;
    if (now - dpop_claims.iat).abs() > 60 {
        return Err(ApiError::new(ErrorCode::InvalidToken, "DPoP proof is stale"));
    }

    Ok(())
}

/// Map a DPoP `alg` header string to a [`jsonwebtoken::Algorithm`].
fn dpop_alg_from_str(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
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
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk["kty"]
        .as_str()
        .ok_or_else(|| "JWK missing kty".to_owned())?;

    // Canonical member set per RFC 7638 §3.2, in lexicographic order.
    // serde_json's default Map is a BTreeMap, so json! keys are always sorted.
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
        _ => return Err(format!("unsupported kty: {kty}")),
    };

    let canonical_json =
        serde_json::to_string(&canonical).map_err(|e| format!("serialization failed: {e}"))?;
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
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;
    use serde::Serialize;
    use tower::ServiceExt;

    use crate::app::test_state;

    // ── Test token helpers ────────────────────────────────────────────────────

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

    /// Mint a valid HS256 JWT using the given secret.
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

    // ── DPoP test helpers ─────────────────────────────────────────────────────

    /// Compute the JWK thumbprint for a P-256 signing key.
    fn dpop_key_thumbprint(key: &SigningKey) -> String {
        let jwk = dpop_key_to_jwk(key);
        jwk_thumbprint(&jwk).unwrap()
    }

    /// Build a minimal JWK Value from a P-256 signing key (public portion only).
    fn dpop_key_to_jwk(key: &SigningKey) -> serde_json::Value {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    /// Build a valid DPoP proof JWT signed with the given P-256 key.
    fn make_dpop_proof(key: &SigningKey, htm: &str, htu: &str) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": now_secs() as i64,
            "jti": "test-jti-unique-value",
        });

        let hdr_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let signing_input = format!("{hdr_b64}.{pay_b64}");

        let sig: Signature = key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);

        format!("{hdr_b64}.{pay_b64}.{sig_b64}")
    }

    // ── Minimal test router ───────────────────────────────────────────────────

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

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Missing / malformed Authorization header ──────────────────────────────

    #[tokio::test]
    async fn missing_auth_header_returns_401_authentication_required() {
        let state = test_state().await;
        let resp = get_protected(protected_app(state), None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn bearer_prefix_missing_returns_401_authentication_required() {
        let state = test_state().await;
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Token abc123")
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    // ── Malformed / invalid token ─────────────────────────────────────────────

    #[tokio::test]
    async fn malformed_token_returns_401_invalid_token() {
        let state = test_state().await;
        let resp = get_protected(protected_app(state), Some("not.a.jwt")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn wrong_signature_returns_401_invalid_token() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &[0xFFu8; 32],
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── Expired token ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_token_returns_401_token_expired() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        let token = mint_token("did:plc:user", "com.atproto.access", -1, &secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
    }

    // ── Valid access tokens ───────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_access_token_extracts_did_and_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), 4096).await.unwrap().to_vec())
                .unwrap();
        assert!(text.contains("did=did:plc:alice"));
        assert!(text.contains("scope=Access"));
    }

    #[tokio::test]
    async fn valid_refresh_token_extracts_refresh_scope() {
        let state = test_state().await;
        let token = mint_token("did:plc:alice", "com.atproto.refresh", 3600, &state.jwt_secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), 4096).await.unwrap().to_vec())
                .unwrap();
        assert!(text.contains("scope=Refresh"));
    }

    #[tokio::test]
    async fn valid_app_pass_token_extracts_app_pass_scope() {
        let state = test_state().await;
        let token = mint_token("did:plc:alice", "com.atproto.appPass", 3600, &state.jwt_secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text =
            String::from_utf8(axum::body::to_bytes(resp.into_body(), 4096).await.unwrap().to_vec())
                .unwrap();
        assert!(text.contains("scope=AppPass"));
    }

    // ── Unknown scope ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_scope_returns_401_invalid_token() {
        let state = test_state().await;
        let token = mint_token("did:plc:user", "com.example.unknown", 3600, &state.jwt_secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── Audience validation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn token_with_wrong_audience_returns_401_when_server_did_configured() {
        use std::sync::Arc;
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.server_did = Some("did:plc:server".to_string());
        let state = AppState { config: Arc::new(config), ..base };

        // mint_token encodes aud = "did:plc:test" — wrong for did:plc:server
        let token = mint_token("did:plc:user", "com.atproto.access", 3600, &state.jwt_secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — downgrade prevention (RFC 9449 §7.1) ──────────────────────────

    #[tokio::test]
    async fn dpop_bound_token_without_dpop_header_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);

        // Access token has cnf.jkt → DPoP-bound.
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // No DPoP header sent — must be rejected.
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_header_present_but_access_token_has_no_cnf_returns_401() {
        let state = test_state().await;
        // Access token has no cnf claim.
        let token = mint_token("did:plc:user", "com.atproto.access", 3600, &state.jwt_secret, None);
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", "dummy.dpop.value")
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — valid proof accepted ───────────────────────────────────────────

    #[tokio::test]
    async fn valid_dpop_bound_token_is_accepted() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);

        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // htu = public_url + path (matches how the extractor builds expected_htu)
        let htu = format!("{}/protected", state.config.public_url);
        let dpop_proof = make_dpop_proof(&dpop_key, "GET", &htu);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── DPoP — signature forgery rejected ────────────────────────────────────

    #[tokio::test]
    async fn dpop_proof_with_forged_signature_returns_401() {
        let state = test_state().await;
        // Attacker's key — different from the key that signed the access token.
        let attacker_key = SigningKey::random(&mut OsRng);
        let legit_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&legit_key);

        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // Proof is signed by attacker_key but claims legit_key's thumbprint in the header JWK.
        // The JWK in the proof header is attacker_key's public key → thumbprint mismatch.
        let htu = format!("{}/protected", state.config.public_url);
        let dpop_proof = make_dpop_proof(&attacker_key, "GET", &htu);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — individual claim validation ───────────────────────────────────

    #[tokio::test]
    async fn dpop_wrong_htm_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        let htu = format!("{}/protected", state.config.public_url);
        // htm says POST but request is GET.
        let dpop_proof = make_dpop_proof(&dpop_key, "POST", &htu);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_wrong_htu_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // htu points to a different endpoint.
        let dpop_proof = make_dpop_proof(
            &dpop_key,
            "GET",
            &format!("{}/other-endpoint", state.config.public_url),
        );

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_wrong_typ_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );

        let jwk = dpop_key_to_jwk(&dpop_key);
        // Wrong typ — should be "dpop+jwt".
        let header = serde_json::json!({ "typ": "JWT", "alg": "ES256", "jwk": jwk });
        let payload = serde_json::json!({
            "htm": "GET",
            "htu": format!("{}/protected", state.config.public_url),
            "iat": now_secs() as i64,
            "jti": "test-jti",
        });
        let hdr_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof =
            format!("{hdr_b64}.{pay_b64}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]));

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_empty_jti_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );

        let jwk = dpop_key_to_jwk(&dpop_key);
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        // Empty jti.
        let payload = serde_json::json!({
            "htm": "GET",
            "htu": format!("{}/protected", state.config.public_url),
            "iat": now_secs() as i64,
            "jti": "",
        });
        let hdr_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof =
            format!("{hdr_b64}.{pay_b64}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]));

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── JWK thumbprint ────────────────────────────────────────────────────────

    #[test]
    fn rsa_jwk_thumbprint_matches_rfc7638_example() {
        // RFC 7638 §3.3 canonical example — RSA key with normative expected thumbprint.
        let jwk = serde_json::json!({
            "e": "AQAB",
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "use": "sig"  // extra member — must be excluded from canonical form
        });
        assert_eq!(
            jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn ec_jwk_thumbprint_produces_correct_format() {
        // EC (P-256) key from RFC 7517 Appendix A.2.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb.len(), 43, "thumbprint must be 43 base64url chars");
        assert!(
            thumb.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint must be base64url"
        );
        // Stable regression guard — verified against this implementation.
        assert_eq!(thumb, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
    }

    #[test]
    fn okp_jwk_thumbprint_produces_correct_format() {
        // Ed25519 (OKP) JWK — verifies OKP branch of jwk_thumbprint.
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"  // private — must be excluded
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb.len(), 43);
        assert!(thumb.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        // Stable regression guard.
        assert_eq!(thumb, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }
}
