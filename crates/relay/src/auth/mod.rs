use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Method},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::{ApiError, ErrorCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::app::AppState;
use p256::pkcs8::EncodePrivateKey;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

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

/// The server's persistent ES256 signing keypair, held in `AppState`.
///
/// `encoding_key` is derived from the P-256 private key in PKCS#8 DER format, as required by
/// `jsonwebtoken`. `key_id` is a UUID that appears as the `kid` header in issued access tokens.
///
/// # Dead Code Lint
///
/// Axum's `State<AppState>` extractor is opaque to Rust's dead code analyzer — fields read
/// through `State<AppState>` appear unused even though they are accessed by every handler.
#[derive(Clone)]
#[allow(dead_code)]
pub struct OAuthSigningKey {
    /// UUID identifier embedded in JWT `kid` header.
    pub key_id: String,
    /// PKCS#8 DER ES256 encoding key for JWT signing.
    pub encoding_key: jsonwebtoken::EncodingKey,
}

/// In-memory store for server-issued DPoP nonces.
///
/// Maps nonce string → expiry `Instant`. Protected by a `Mutex` so handlers can issue,
/// validate, and prune concurrently. Held in `AppState`.
pub type DpopNonceStore = Arc<Mutex<HashMap<String, Instant>>>;

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
    /// Full deduplication is enforced by the server-issued nonce validated
    /// in `validate_dpop_for_token_endpoint` (RFC 9449 §11.1).
    jti: String,
    /// Server-issued DPoP nonce (RFC 9449 §8). Required when the server has issued one.
    #[serde(default)]
    nonce: Option<String>,
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
        //    RFC 9449 §11.1: reject if multiple DPoP headers are present — a
        //    header-prepending proxy could inject a forged proof as the first value.
        if parts.headers.get_all("DPoP").iter().count() > 1 {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "multiple DPoP headers are not permitted",
            ));
        }
        let dpop_value = parts
            .headers
            .get("DPoP")
            .and_then(|v| {
                v.to_str()
                    .inspect_err(|_| {
                        tracing::warn!("DPoP header contains non-UTF-8 bytes; treating as absent");
                    })
                    .ok()
            })
            .map(str::to_owned);
        let has_dpop = dpop_value.is_some();

        // 3. Decode and verify the access token (HS256).
        let claims = verify_access_token(token_str, state)?;

        // 4. Enforce DPoP binding (RFC 9449 §7.1).
        //    When `cnf` is present the token carries a proof-of-possession claim; we
        //    must require a DPoP proof to honour that binding.
        //    * `cnf` present but no `jkt` → explicit rejection: a future cnf variant
        //      (e.g. `x5t#S256` for cert binding) could be silently downgraded to plain
        //      Bearer if we only check `jkt.is_some()`.
        //    * `cnf.jkt` present but no DPoP header → downgrade attack; reject.
        if let Some(cnf) = &claims.cnf {
            if cnf.jkt.is_none() {
                return Err(ApiError::new(
                    ErrorCode::InvalidToken,
                    "access token cnf present without jkt binding",
                ));
            }
            if !has_dpop {
                return Err(ApiError::new(
                    ErrorCode::InvalidToken,
                    "DPoP-bound token requires a DPoP proof header",
                ));
            }
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

// ── OAuth signing key management ─────────────────────────────────────────────

/// Create an empty `DpopNonceStore`.
pub fn new_nonce_store() -> DpopNonceStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Issue a fresh DPoP nonce with a 5-minute TTL.
///
/// Returns a 22-character base64url string (16 random bytes). The nonce is
/// inserted into the store with an expiry of `Instant::now() + 5 minutes`.
pub(crate) async fn issue_nonce(store: &DpopNonceStore) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    let expiry = std::time::Instant::now() + std::time::Duration::from_secs(300);
    store.lock().await.insert(nonce.clone(), expiry);
    nonce
}

/// Validate and consume a DPoP nonce.
///
/// Returns `true` if the nonce is present in the store and has not expired.
/// Removes the nonce unconditionally (whether valid or expired) to prevent reuse.
/// Returns `false` for unknown nonces.
///
/// Logs rejection reasons so operators can distinguish replay attempts from expiry from server restarts.
pub(crate) async fn validate_and_consume_nonce(store: &DpopNonceStore, nonce: &str) -> bool {
    let mut map = store.lock().await;
    match map.remove(nonce) {
        Some(expiry) => {
            if expiry > std::time::Instant::now() {
                true
            } else {
                tracing::debug!(nonce = %nonce, "DPoP nonce rejected: expired");
                false
            }
        }
        None => {
            tracing::debug!(nonce = %nonce, "DPoP nonce rejected: unknown (possible replay or server restart)");
            false
        }
    }
}

/// Remove all expired nonces from the store.
///
/// Call this on every token request to prevent unbounded memory growth.
/// Under normal relay load (low request volume) this is sufficient without a background task.
pub(crate) async fn cleanup_expired_nonces(store: &DpopNonceStore) {
    let now = std::time::Instant::now();
    store.lock().await.retain(|_, expiry| *expiry > now);
}

/// Load the OAuth signing key from the database, or generate a new one on first boot.
///
/// If `master_key` is `None`, generates an ephemeral (non-persistent) key and logs a warning.
/// Ephemeral keys are not stored in the DB and invalidate all issued tokens on restart.
pub(crate) async fn load_or_create_oauth_signing_key(
    pool: &SqlitePool,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    use crate::db::oauth::{get_oauth_signing_key, store_oauth_signing_key};

    // Attempt to load an existing key.
    if let Some(row) = get_oauth_signing_key(pool).await? {
        let key = decode_oauth_signing_key(&row.id, &row.private_key_encrypted, master_key)?;
        tracing::info!(key_id = %row.id, "OAuth signing key loaded from database");
        return Ok(key);
    }

    // No key stored yet. Generate one.
    let keypair = crypto::generate_p256_keypair()
        .map_err(|e| anyhow::anyhow!("failed to generate P-256 keypair: {e}"))?;

    let key_id = Uuid::new_v4().to_string();

    // Build JWK for the public key (uncompressed EC point → x, y coordinates).
    let signing_key = p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(
        keypair.private_key_bytes.as_ref(),
    ))
    .map_err(|e| anyhow::anyhow!("invalid P-256 private key bytes: {e}"))?;

    let vk = signing_key.verifying_key();
    let point = vk.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"));
    let public_key_jwk = serde_json::to_string(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key_id,
    }))
    .map_err(|e| anyhow::anyhow!("JWK serialization failed: {e}"))?;

    match master_key {
        Some(key) => {
            let encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, key)
                .map_err(|e| anyhow::anyhow!("key encryption failed: {e}"))?;
            store_oauth_signing_key(pool, &key_id, &public_key_jwk, &encrypted).await?;
            tracing::info!(key_id = %key_id, "OAuth signing key generated and persisted");
        }
        None => {
            tracing::warn!(
                "signing_key_master_key not configured; \
                 OAuth signing key is ephemeral — tokens will be invalidated on restart"
            );
        }
    }

    let encoding_key = build_encoding_key(&signing_key)?;
    Ok(OAuthSigningKey {
        key_id,
        encoding_key,
    })
}

/// Decode a stored OAuth signing key row into an `OAuthSigningKey`.
fn decode_oauth_signing_key(
    key_id: &str,
    private_key_encrypted: &str,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    let master_key = master_key.ok_or_else(|| {
        anyhow::anyhow!(
            "signing_key_master_key not configured but an OAuth signing key exists in the DB; \
             cannot decrypt it — set signing_key_master_key in config"
        )
    })?;

    let raw_bytes = crypto::decrypt_private_key(private_key_encrypted, master_key)
        .map_err(|e| anyhow::anyhow!("failed to decrypt OAuth signing key: {e}"))?;

    let signing_key =
        p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(raw_bytes.as_ref()))
            .map_err(|e| anyhow::anyhow!("invalid stored P-256 private key: {e}"))?;

    let encoding_key = build_encoding_key(&signing_key)?;
    Ok(OAuthSigningKey {
        key_id: key_id.to_string(),
        encoding_key,
    })
}

/// Convert a `p256::ecdsa::SigningKey` to a `jsonwebtoken::EncodingKey` via PKCS#8 DER.
fn build_encoding_key(
    signing_key: &p256::ecdsa::SigningKey,
) -> anyhow::Result<jsonwebtoken::EncodingKey> {
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("PKCS#8 DER encoding failed: {e}"))?;
    Ok(jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes()))
}

/// Error from DPoP validation at the token endpoint.
///
/// Converted to `OAuthTokenError` by the handler in `routes/oauth_token.rs`.
pub(crate) enum DpopTokenEndpointError {
    /// `DPoP:` header is absent.
    ///
    /// Never constructed in practice — the handler in `routes/oauth_token.rs` pre-checks for a
    /// missing `DPoP:` header and returns an error directly, so this function is only called when
    /// the header is present. Retained for API completeness so callers can match exhaustively.
    #[allow(dead_code)]
    MissingHeader,
    /// DPoP proof is syntactically or semantically invalid.
    InvalidProof(&'static str),
    /// Nonce is missing, unknown, or expired — fresh nonce included for the response header.
    UseNonce(String),
}

/// Validate the DPoP proof at the token endpoint and return the JWK thumbprint.
///
/// This is a token-endpoint-specific variant of `validate_dpop`:
/// - Does NOT check `cnf.jkt` against an existing access token (no token yet).
/// - DOES validate the `nonce` claim against the nonce store.
/// - Returns the JWK thumbprint (jkt) so the handler can embed it in `cnf.jkt`.
///
/// `htm` must be `"POST"`. `htu` must be the token endpoint URL (e.g.
/// `"https://relay.example.com/oauth/token"`).
pub(crate) async fn validate_dpop_for_token_endpoint(
    dpop_token: &str,
    htm: &str,
    htu: &str,
    nonce_store: &DpopNonceStore,
) -> Result<String, DpopTokenEndpointError> {
    // Decode the DPoP proof header manually (same pattern as validate_dpop).
    let header_b64 = dpop_token
        .split('.')
        .next()
        .ok_or(DpopTokenEndpointError::InvalidProof("malformed DPoP JWT"))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP header base64 invalid"))?;
    let dpop_header: DPopHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP header JSON malformed"))?;

    if dpop_header.typ != "dpop+jwt" {
        return Err(DpopTokenEndpointError::InvalidProof(
            "DPoP typ must be dpop+jwt",
        ));
    }

    // Verify the signature against the embedded JWK.
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(dpop_header.jwk.clone())
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP JWK parse failed"))?;
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP DecodingKey build failed"))?;
    let alg = dpop_alg_from_str(&dpop_header.alg)
        .ok_or(DpopTokenEndpointError::InvalidProof("DPoP unsupported alg"))?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;

    let dpop_data = decode::<DPopClaims>(dpop_token, &decoding_key, &validation)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP signature verification failed"))?;
    let claims = dpop_data.claims;

    // Validate htm (HTTP method).
    if claims.htm.to_uppercase() != htm.to_uppercase() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htm mismatch"));
    }

    // Validate htu (target URI).
    if claims.htu != htu {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htu mismatch"));
    }

    // Validate jti (presence only — server nonce provides replay protection).
    if claims.jti.is_empty() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP jti missing"));
    }

    // Freshness: reject proofs older than 60 seconds or from the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("system clock error"))?
        .as_secs() as i64;
    let diff = (now as i128) - (claims.iat as i128);
    if diff.unsigned_abs() > 60 {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP proof stale"));
    }

    // Validate nonce claim.
    match claims.nonce.as_deref() {
        None | Some("") => {
            // No nonce — issue a fresh one for the client to retry with.
            let fresh = issue_nonce(nonce_store).await;
            return Err(DpopTokenEndpointError::UseNonce(fresh));
        }
        Some(nonce) => {
            if !validate_and_consume_nonce(nonce_store, nonce).await {
                // Unknown or expired nonce — issue a fresh one.
                let fresh = issue_nonce(nonce_store).await;
                return Err(DpopTokenEndpointError::UseNonce(fresh));
            }
        }
    }

    // Compute and return the JWK thumbprint.
    jwk_thumbprint(&dpop_header.jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("JWK thumbprint computation failed"))
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

    // RFC 7235 §2.1: auth scheme names are case-insensitive ("bearer", "BEARER", etc.).
    const BEARER_LEN: usize = 7; // "Bearer ".len() — scheme name + single SP
    if !auth_value
        .get(..BEARER_LEN)
        .is_some_and(|s| s.eq_ignore_ascii_case("Bearer "))
    {
        return Err(ApiError::new(
            ErrorCode::AuthenticationRequired,
            "Authorization header must use Bearer scheme",
        ));
    }
    Ok(&auth_value[BEARER_LEN..])
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
                _ => {
                    tracing::debug!(error = %e, error_kind = ?e.kind(), "access token verification failed");
                    ApiError::new(ErrorCode::InvalidToken, "invalid token")
                }
            }
        })
}

/// Parse the ATProto scope string into [`AuthScope`].
fn parse_scope(scope: &str) -> Result<AuthScope, ApiError> {
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

    // Verify the DPoP JWT signature first (before making any binding decisions based
    // on the embedded JWK — defence-in-depth: prove key control before trusting claims).
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
        tracing::debug!(error = %e, "DPoP proof decoding or signature verification failed");
        invalid()
    })?;
    let dpop_claims = dpop_data.claims;

    // Compute JWK thumbprint (RFC 7638) and verify the access token was bound to this key.
    // Signature has already been verified above, so the JWK is authentic.
    let thumbprint = jwk_thumbprint(&dpop_header.jwk).map_err(|e| {
        tracing::debug!(error = %e, "failed to compute JWK thumbprint from DPoP proof header");
        invalid()
    })?;
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

    // Require `jti` for replay protection. Full deduplication per RFC 9449 §11.1
    // is enforced by the server-issued nonce mechanism in the token endpoint.
    if dpop_claims.jti.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP proof missing jti",
        ));
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
    // Widen to i128 before subtracting to prevent i64 overflow when a malicious
    // client sends iat = i64::MIN (debug panic; release wraparound bypass).
    let diff = (now as i128) - (dpop_claims.iat as i128);
    if diff.unsigned_abs() > 60 {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP proof is stale",
        ));
    }

    Ok(())
}

/// Map a DPoP `alg` header string to a [`jsonwebtoken::Algorithm`].
///
/// Only elliptic curve algorithms are accepted to match the server metadata
/// (which advertises ES256 as the sole supported algorithm for DPoP proofs).
/// RSA and EdDSA are excluded despite being valid JWT algorithms.
fn dpop_alg_from_str(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
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

    /// Build a valid DPoP proof JWT signed with the given P-256 key using current time as `iat`.
    fn make_dpop_proof(key: &SigningKey, htm: &str, htu: &str) -> String {
        make_dpop_proof_with_iat(key, htm, htu, now_secs() as i64)
    }

    /// Build a DPoP proof JWT with an explicit `iat` — used to test freshness rejection.
    fn make_dpop_proof_with_iat(key: &SigningKey, htm: &str, htu: &str, iat: i64) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": uuid::Uuid::new_v4().to_string(),
        });

        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
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
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
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
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("did=did:plc:alice"));
        assert!(text.contains("scope=Access"));
    }

    #[tokio::test]
    async fn valid_refresh_token_extracts_refresh_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.refresh",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("scope=Refresh"));
    }

    #[tokio::test]
    async fn valid_app_pass_token_extracts_app_pass_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.appPass",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("scope=AppPass"));
    }

    // ── Unknown scope ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_scope_returns_401_invalid_token() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.example.unknown",
            3600,
            &state.jwt_secret,
            None,
        );
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
        let state = AppState {
            config: Arc::new(config),
            ..base
        };

        // mint_token encodes aud = "did:plc:test" — wrong for did:plc:server
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
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
        // Access token has no cnf claim at all. DPoP header is present with a valid
        // proof — must be rejected at the "access token missing DPoP binding" guard,
        // not earlier (the old test used "dummy.dpop.value" which failed at base64
        // decode and never reached the binding check).
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
        let dpop_proof = make_dpop_proof(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
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
    async fn dpop_cnf_present_without_jkt_returns_401() {
        // Token with cnf:{} — cnf present but no jkt field. Must be rejected before
        // any DPoP proof is considered (guard added in round 2).
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({})), // cnf present but empty — no jkt
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
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
        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof = format!(
            "{hdr_b64}.{pay_b64}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
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
        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof = format!(
            "{hdr_b64}.{pay_b64}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
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
    async fn dpop_stale_proof_returns_401() {
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
        // iat = now - 120: 120 s in the past — outside the ±60 s freshness window.
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            now_secs() as i64 - 120,
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
    async fn dpop_future_dated_proof_returns_401() {
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
        // iat = now + 120: 120 s in the future — also outside the ±60 s window.
        // This exercises the abs() branch (unsigned_abs() after widening).
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            now_secs() as i64 + 120,
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
    async fn dpop_iat_at_i64_min_returns_401() {
        // i64::MIN is the specific iat value that motivated the i128 widening fix:
        // `now - i64::MIN` overflows in debug (panic → DoS) and wraps in release
        // (magnitude check bypass). The widened arithmetic must reject it as stale.
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
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            i64::MIN,
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
    async fn multiple_dpop_headers_returns_401() {
        // RFC 9449 §11.1: multiple DPoP headers must be rejected.
        // A header-prepending proxy could inject a forged proof as the first value.
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
        let proof1 = make_dpop_proof(&dpop_key, "GET", &htu);
        let proof2 = make_dpop_proof(&dpop_key, "GET", &htu);
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", proof1)
            .header("DPoP", proof2)
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
            thumb
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint must be base64url"
        );
        // Stable regression guard — verified against this implementation.
        assert_eq!(thumb, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
    }

    // ── DPoP nonce store tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn issued_nonce_validates_once() {
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;

        // First use: valid.
        assert!(
            validate_and_consume_nonce(&store, &nonce).await,
            "freshly issued nonce must validate"
        );

        // Second use: consumed — must fail (even though not expired).
        assert!(
            !validate_and_consume_nonce(&store, &nonce).await,
            "already-consumed nonce must not validate again"
        );
    }

    #[tokio::test]
    async fn unknown_nonce_is_rejected() {
        let store = new_nonce_store();
        assert!(
            !validate_and_consume_nonce(&store, "this-nonce-was-never-issued").await,
            "unknown nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        let store = new_nonce_store();
        // Manually insert a nonce that expired 1 second in the past.
        let nonce = "expired-nonce-test";
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert(nonce.to_string(), past);
        }

        assert!(
            !validate_and_consume_nonce(&store, nonce).await,
            "expired nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_nonces() {
        let store = new_nonce_store();

        // Insert one fresh nonce (not yet expired).
        let fresh_nonce = issue_nonce(&store).await;

        // Insert one already-expired nonce directly.
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert("stale-nonce".to_string(), past);
        }

        cleanup_expired_nonces(&store).await;

        let map = store.lock().await;
        assert!(
            map.contains_key(&fresh_nonce),
            "fresh nonce must survive cleanup"
        );
        assert!(
            !map.contains_key("stale-nonce"),
            "stale nonce must be pruned by cleanup"
        );
    }

    #[tokio::test]
    async fn issued_nonce_is_22_chars_base64url() {
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;
        assert_eq!(
            nonce.len(),
            22,
            "nonce must be 22 chars (16 bytes base64url no-pad)"
        );
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "nonce must be base64url charset"
        );
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
        assert!(thumb
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        // Stable regression guard.
        assert_eq!(thumb, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }
}
