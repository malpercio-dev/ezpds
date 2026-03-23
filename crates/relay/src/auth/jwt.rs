// pattern: Functional Core

use common::{ApiError, ErrorCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::app::AppState;

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
pub fn verify_es256_access_token(token: &str, state: &AppState) -> Result<AccessTokenClaims, ApiError> {
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
pub fn verify_hs256_access_token(token: &str, state: &AppState) -> Result<AccessTokenClaims, ApiError> {
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
