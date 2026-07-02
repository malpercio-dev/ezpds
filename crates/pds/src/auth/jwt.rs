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
    AppPassPrivileged,
}

impl AuthScope {
    /// Whether this is an access-level scope — a full-access token *or* an app-password
    /// token (privileged or not). Only [`AuthScope::Refresh`] is not access-level.
    ///
    /// Endpoints that merely read/act on behalf of the session (e.g. `getSession`) accept any
    /// access-level scope; account-management endpoints (create/revoke app passwords, change
    /// handle, deactivate) require full [`AuthScope::Access`] and reject app-password scopes.
    pub fn is_access(&self) -> bool {
        matches!(
            self,
            AuthScope::Access | AuthScope::AppPass | AuthScope::AppPassPrivileged
        )
    }
}

/// The `scope` claim string for a full-access session token.
pub(crate) const SCOPE_ACCESS: &str = "com.atproto.access";

/// The `scope` claim string for an app-password session, selected by privilege.
pub(crate) fn app_pass_scope(privileged: bool) -> &'static str {
    if privileged {
        "com.atproto.appPassPrivileged"
    } else {
        "com.atproto.appPass"
    }
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
        "com.atproto.appPassPrivileged" => Ok(AuthScope::AppPassPrivileged),
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

// ── Service-auth JWT verification (inbound: authenticating a foreign account) ─

/// Claims decoded from an inbound service-auth JWT. All optional so a missing claim is a
/// validation failure we control, not a deserialization error.
#[derive(Debug, Deserialize)]
struct ServiceAuthClaims {
    iss: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    lxm: Option<String>,
}

/// Verify an inbound ES256 service-auth JWT — the counterpart to [`mint_service_auth_jwt`].
///
/// Used by migration-mode `createAccount` to authenticate a foreign account: the client
/// presents a token the **old** PDS minted (signed with the account's `#atproto` repo key),
/// and this server verifies it against that key resolved from the incoming DID's document.
///
/// Validates, independently of the signature: 3-part structure; header `alg == ES256`;
/// `iss == expected_iss` (the migrating DID); `aud == expected_aud` (this server's DID);
/// `exp` strictly in the future relative to `now`; and, when the token carries an `lxm`, that
/// it equals `expected_lxm`. A method-unrestricted token (no `lxm`) is accepted — matching the
/// reference PDS, whose `getServiceAuth` omits `lxm` when unrequested and caps such tokens'
/// lifetime tightly. Signature verification is delegated to [`crypto::verify_p256_signature`]
/// (ES256 = ECDSA-SHA256 over the exact `header.payload` bytes).
pub fn verify_service_auth_jwt(
    token: &str,
    expected_iss: &str,
    expected_aud: &str,
    expected_lxm: &str,
    atproto_key: &crypto::DidKeyUri,
    now: u64,
) -> Result<(), ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let invalid = || ApiError::new(ErrorCode::InvalidToken, "invalid service auth token");

    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(invalid)?;
    let payload_b64 = parts.next().ok_or_else(invalid)?;
    let sig_b64 = parts.next().ok_or_else(invalid)?;
    if parts.next().is_some() || sig_b64.is_empty() {
        return Err(invalid());
    }

    // Header: require ES256 so a token can't downgrade the algorithm.
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| invalid())?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| invalid())?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "service auth token must be ES256",
        ));
    }

    // Signature over the exact `header.payload` bytes, against the issuer's #atproto key.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| invalid())?;
    let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| invalid())?;
    crypto::verify_p256_signature(atproto_key, signing_input.as_bytes(), &sig).map_err(|e| {
        tracing::debug!(error = %e, "service auth signature verification failed");
        ApiError::new(
            ErrorCode::InvalidToken,
            "service auth signature verification failed",
        )
    })?;

    // Claims — validated independently of the signature.
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| invalid())?;
    let claims: ServiceAuthClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid())?;
    if claims.iss.as_deref() != Some(expected_iss) {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "service auth token issuer does not match the account DID",
        ));
    }
    if claims.aud.as_deref() != Some(expected_aud) {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "service auth token audience does not match this server",
        ));
    }
    match claims.exp {
        Some(exp) if exp > now => {}
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::TokenExpired,
                "service auth token has expired",
            ))
        }
        None => return Err(invalid()),
    }
    if let Some(lxm) = claims.lxm.as_deref() {
        if lxm != expected_lxm {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "service auth token is not authorized for this method",
            ));
        }
    }
    Ok(())
}

// ── Legacy HS256 token issuance ───────────────────────────────────────────────

const ACCESS_TOKEN_TTL_SECS: u64 = 2 * 60 * 60; // 2 hours
const REFRESH_TOKEN_TTL_SECS: u64 = 90 * 24 * 60 * 60; // 90 days

#[derive(Serialize)]
struct LegacyAccessClaims {
    scope: String,
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

/// Sign an HS256 access JWT with a 2-hour lifetime.
///
/// `scope` is the access-level scope claim to embed — [`SCOPE_ACCESS`] for a full session, or
/// the app-pass scope from [`app_pass_scope`] for an app-password session. Any other scope
/// (e.g. a refresh scope) is rejected here rather than trusted to every call site, so the
/// "an access token only ever carries an access-level scope" invariant stays centralized.
pub(crate) fn issue_access_jwt(
    secret: &[u8; 32],
    did: &str,
    aud: &str,
    now: u64,
    scope: &str,
) -> Result<String, ApiError> {
    if scope != SCOPE_ACCESS && scope != app_pass_scope(false) && scope != app_pass_scope(true) {
        tracing::error!(
            scope,
            "attempted to issue an access JWT with a non-access scope"
        );
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "failed to issue token",
        ));
    }

    encode(
        &Header::new(Algorithm::HS256),
        &LegacyAccessClaims {
            scope: scope.to_string(),
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

    /// `issue_access_jwt` accepts only access-level scopes; a refresh (or any other) scope is
    /// refused centrally so no call site can accidentally mint a 2-hour token with the wrong scope.
    #[test]
    fn issue_access_jwt_rejects_non_access_scope() {
        let secret = [0u8; 32];
        for scope in [SCOPE_ACCESS, app_pass_scope(false), app_pass_scope(true)] {
            assert!(
                issue_access_jwt(&secret, "did:plc:x", "aud", 1_000, scope).is_ok(),
                "access-level scope {scope} must be accepted"
            );
        }
        for scope in ["com.atproto.refresh", "com.atproto.access.bogus", ""] {
            assert!(
                issue_access_jwt(&secret, "did:plc:x", "aud", 1_000, scope).is_err(),
                "non-access scope {scope:?} must be rejected"
            );
        }
    }
}
