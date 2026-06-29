// pattern: Functional Core

use common::{ApiError, ErrorCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

/// Scope embedded in the JWT `scope` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScope {
    Access,
    Refresh,
    AppPass,
}

/// Claims decoded from the server-issued access/refresh JWT.
#[derive(Debug, Deserialize)]
pub(crate) struct AccessTokenClaims {
    /// Subject — the authenticated DID.
    pub sub: String,
    /// Scope string from the AT Protocol spec.
    pub scope: String,
    /// Confirmation claim — present on DPoP-bound tokens (RFC 9449 §4.3).
    pub cnf: Option<CnfClaim>,
}

/// `cnf` (confirmation) claim carrying the JWK thumbprint for DPoP binding.
#[derive(Debug, Deserialize)]
pub(crate) struct CnfClaim {
    /// JWK SHA-256 thumbprint (base64url, no padding) of the client's DPoP key.
    pub jkt: Option<String>,
}

/// Peek at the JWT header's `typ` field without verifying the signature.
/// Returns the `typ` value in lowercase, or `None` if parsing fails.
pub fn peek_jwt_typ(token: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header_b64 = token.split('.').next()?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    header["typ"].as_str().map(|s| s.to_ascii_lowercase())
}

/// Dispatch to the correct verification function based on token type.
/// Uses `typ` header as algorithm discriminator to prevent algorithm confusion attacks.
pub fn verify_access_token(token: &str, state: &AppState) -> Result<AccessTokenClaims, ApiError> {
    if peek_jwt_typ(token).as_deref() == Some("at+jwt") {
        verify_es256_access_token(token, state)
    } else {
        verify_hs256_access_token(token, state)
    }
}

/// Verify ES256 AT+JWT tokens issued by the OAuth token endpoint.
pub fn verify_es256_access_token(
    token: &str,
    state: &AppState,
) -> Result<AccessTokenClaims, ApiError> {
    let invalid = || ApiError::new(ErrorCode::InvalidToken, "invalid token");
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(
        state.oauth_signing_keypair.public_key_jwk.clone(),
    )
    .map_err(|_| {
        tracing::error!("failed to parse OAuth signing key JWK for ES256 token verification");
        invalid()
    })?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        tracing::error!(error = %e, "failed to build ES256 DecodingKey from OAuth signing key JWK");
        invalid()
    })?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_required_spec_claims(&["exp", "sub"]);
    validation.leeway = 0;
    validation.set_audience(&[state.config.public_url.as_str()]);
    decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => ApiError::new(ErrorCode::TokenExpired, "token has expired"),
                _ => {
                    tracing::debug!(error = %e, error_kind = ?e.kind(), "ES256 access token verification failed");
                    invalid()
                }
            }
        })
}

/// Verify HS256 access/refresh JWT issued by this server (legacy tokens).
pub fn verify_hs256_access_token(
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
                _ => {
                    tracing::debug!(error = %e, error_kind = ?e.kind(), "access token verification failed");
                    ApiError::new(ErrorCode::InvalidToken, "invalid token")
                }
            }
        })
}

/// Parse the ATProto scope string into [`AuthScope`].
pub fn parse_scope(scope: &str) -> Result<AuthScope, ApiError> {
    match scope {
        "com.atproto.access" => Ok(AuthScope::Access),
        "com.atproto.refresh" => Ok(AuthScope::Refresh),
        "com.atproto.appPass" => Ok(AuthScope::AppPass),
        _ => Err(ApiError::new(
            ErrorCode::InvalidToken,
            "unrecognised token scope",
        )),
    }
}

// ── Refresh token verification ────────────────────────────────────────────────

/// Claims decoded from a refresh JWT (scope: com.atproto.refresh).
///
/// `sub` is present in the JWT payload but intentionally not decoded here:
/// the library enforces its presence via `set_required_spec_claims`, and the
/// authoritative DID is read from the DB row after the token is confirmed to
/// exist — never trusted directly from the JWT claim.
#[derive(Debug, Deserialize)]
pub(crate) struct RefreshTokenClaims {
    pub scope: String,
    /// Token ID embedded in the JWT and stored in `refresh_tokens.jti`.
    /// `None` when an access token (which has no `jti`) is mistakenly presented.
    pub jti: Option<String>,
}

/// Verify an HS256 refresh JWT issued by this server.
///
/// Validates signature, expiry, and audience (when `server_did` is configured).
/// Does NOT check that `scope == "com.atproto.refresh"` — callers are responsible
/// for that check so that the error message can be precise.
pub fn verify_refresh_token(token: &str, state: &AppState) -> Result<RefreshTokenClaims, ApiError> {
    let decoding_key = DecodingKey::from_secret(&state.jwt_secret);
    let mut validation = Validation::new(Algorithm::HS256);
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
    validation.set_required_spec_claims(&["exp", "sub"]);
    validation.leeway = 0;

    decode::<RefreshTokenClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => {
                    ApiError::new(ErrorCode::TokenExpired, "token has expired")
                }
                _ => {
                    tracing::warn!(error = %e, error_kind = ?e.kind(), "refresh token verification failed");
                    ApiError::new(ErrorCode::InvalidToken, "invalid token")
                }
            }
        })
}

/// Verify an HS256 refresh JWT issued by this server, accepting expired tokens.
///
/// Validates HS256 signature and audience (when `server_did` is configured), but
/// intentionally skips the expiry check. Used by `deleteSession` so that users
/// can always revoke their session even after the refresh token has expired —
/// matching the ATProto spec's `allowExpired: true` behavior.
///
/// Security: HS256 signature is still fully verified. An expired-but-forged
/// token is rejected. Only tokens we signed (but whose exp has passed) are accepted.
///
/// Does NOT check `scope` — callers must verify `scope == "com.atproto.refresh"`.
pub fn verify_refresh_token_allow_expired(
    token: &str,
    state: &AppState,
) -> Result<RefreshTokenClaims, ApiError> {
    let decoding_key = DecodingKey::from_secret(&state.jwt_secret);
    let mut validation = Validation::new(Algorithm::HS256);
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
    validation.validate_exp = false;
    validation.set_required_spec_claims(&["sub"]);
    validation.leeway = 0;

    // Note: no ExpiredSignature arm — `validate_exp = false` means jsonwebtoken
    // never emits that error kind here. All failures are signature/structural.
    decode::<RefreshTokenClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::warn!(error = %e, error_kind = ?e.kind(), "refresh token verification failed");
            ApiError::new(ErrorCode::InvalidToken, "invalid token")
        })
}

// ── Service-auth JWT minting (inter-service auth for AppView/chat proxying) ───

/// Mint an inter-service auth JWT (ATProto `getServiceAuth` / proxy auth): a
/// `base64url(header).base64url(payload).base64url(signature)` triple where `signature` is the
/// 64-byte r‖s P-256 ECDSA signature of the `header.payload` bytes produced by `sign`.
///
/// The signature MUST be low-S normalized — the AppView verifies it as **ES256** against the
/// issuer's `#atproto` did:key and rejects high-S. `repo_engine::CommitSigner::sign` already
/// low-S normalizes, so pass `|bytes| signer.sign(bytes)`.
///
/// Claims: `iss` = account DID, `aud` = receiving service DID (no `#fragment`), `iat`, the
/// absolute `exp`, and — when `lxm` is `Some` — the lexicon method the token authorizes. A
/// `None` `lxm` mints a method-unrestricted token (callers should keep its `exp` short), matching
/// `com.atproto.server.getServiceAuth`, which omits the `lxm` claim entirely when not requested.
pub fn mint_service_auth_jwt<F>(
    sign: F,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    iat: u64,
    exp: u64,
) -> String
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let header = serde_json::json!({ "typ": "JWT", "alg": "ES256" });
    let mut payload = serde_json::json!({
        "iss": iss,
        "aud": aud,
        "iat": iat,
        "exp": exp,
    });
    if let Some(lxm) = lxm {
        payload["lxm"] = serde_json::Value::String(lxm.to_string());
    }

    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("JWT header serializes"));
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("JWT payload serializes"));
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig_b64 = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
    format!("{signing_input}.{sig_b64}")
}

// ── Legacy HS256 token issuance ───────────────────────────────────────────────

const ACCESS_TOKEN_TTL_SECS: u64 = 2 * 60 * 60; // 2 hours
const REFRESH_TOKEN_TTL_SECS: u64 = 90 * 24 * 60 * 60; // 90 days

#[derive(Serialize)]
struct LegacyAccessClaims {
    scope: &'static str,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Serialize)]
struct LegacyRefreshClaims {
    scope: &'static str,
    sub: String,
    aud: String,
    jti: String,
    iat: u64,
    exp: u64,
}

/// Sign an HS256 access JWT (scope: com.atproto.access) with a 2-hour lifetime.
pub(crate) fn issue_access_jwt(
    secret: &[u8; 32],
    did: &str,
    aud: &str,
    now: u64,
) -> Result<String, ApiError> {
    encode(
        &Header::new(Algorithm::HS256),
        &LegacyAccessClaims {
            scope: "com.atproto.access",
            sub: did.to_string(),
            aud: aud.to_string(),
            iat: now,
            exp: now + ACCESS_TOKEN_TTL_SECS,
        },
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to sign access JWT");
        ApiError::new(ErrorCode::InternalError, "failed to issue token")
    })
}

/// Sign an HS256 refresh JWT (scope: com.atproto.refresh) with a 90-day lifetime.
pub(crate) fn issue_refresh_jwt(
    secret: &[u8; 32],
    did: &str,
    aud: &str,
    jti: &str,
    now: u64,
) -> Result<String, ApiError> {
    encode(
        &Header::new(Algorithm::HS256),
        &LegacyRefreshClaims {
            scope: "com.atproto.refresh",
            sub: did.to_string(),
            aud: aud.to_string(),
            jti: jti.to_string(),
            iat: now,
            exp: now + REFRESH_TOKEN_TTL_SECS,
        },
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to sign refresh JWT");
        ApiError::new(ErrorCode::InternalError, "failed to issue token")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};

    /// The minted service-auth JWT is a well-formed ES256 token with the required claims, and
    /// — the load-bearing check — its signature verifies against the signing key, so Bluesky's
    /// AppView (which resolves the `#atproto` key from the DID doc) would accept it. Also
    /// asserts low-S, which atproto verifiers require.
    #[test]
    fn service_auth_jwt_is_es256_with_required_claims_and_verifies() {
        let key_bytes = [0x11u8; 32];
        let signer = repo_engine::CommitSigner::from_bytes(&key_bytes).unwrap();
        let signing_key = SigningKey::from_bytes(p256::FieldBytes::from_slice(&key_bytes)).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let jwt = mint_service_auth_jwt(
            |b| signer.sign(b),
            "did:plc:abc123",
            "did:web:api.bsky.app",
            Some("app.bsky.feed.getTimeline"),
            1_000,
            1_060,
        );

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must be header.payload.signature");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "did:plc:abc123");
        assert_eq!(claims["aud"], "did:web:api.bsky.app");
        assert_eq!(claims["lxm"], "app.bsky.feed.getTimeline");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_060);

        // Independent proof: the ES256 signature verifies against the key.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        assert!(
            verifying_key.verify(signing_input.as_bytes(), &sig).is_ok(),
            "ES256 signature must verify against the signing key"
        );
        assert!(
            sig.normalize_s().is_none(),
            "signature must be canonical low-S (atproto verifiers reject high-S)"
        );
    }

    /// A `None` `lxm` mints a method-unrestricted token: the `lxm` claim is omitted entirely
    /// (not `null`, not empty), matching `com.atproto.server.getServiceAuth` semantics.
    #[test]
    fn service_auth_jwt_omits_lxm_when_method_unrestricted() {
        let signer = repo_engine::CommitSigner::from_bytes(&[0x11u8; 32]).unwrap();
        let jwt = mint_service_auth_jwt(
            |b| signer.sign(b),
            "did:plc:abc123",
            "did:web:api.bsky.app",
            None,
            1_000,
            1_060,
        );
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(
            claims.get("lxm").is_none(),
            "a method-unrestricted token must omit the lxm claim, got {claims}"
        );
        assert_eq!(claims["iss"], "did:plc:abc123");
        assert_eq!(claims["exp"], 1_060);
    }
}
