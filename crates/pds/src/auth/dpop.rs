// pattern: Mixed (unavoidable)

use axum::http::Method;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::{ApiError, ErrorCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use super::jwt::AccessTokenClaims;

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
    /// Unique token ID (RFC 9449 §4.2). Validated for **presence** only — the server keeps no
    /// `jti` store, so proofs are never deduplicated by `jti` (RFC 9449 §11.1 makes such tracking
    /// a SHOULD, not a MUST). Replay is bounded instead by the ±60s `iat` freshness window, plus
    /// the single-use server nonce at the token endpoint and the `ath` access-token binding at
    /// resource endpoints. See the posture notes on `validate_dpop` /
    /// `validate_dpop_for_token_endpoint`.
    jti: String,
    /// Server-issued DPoP nonce (RFC 9449 §8). Required at the token endpoint.
    #[serde(default)]
    nonce: Option<String>,
    /// Access token hash (RFC 9449 §4.3). Required at resource endpoints.
    /// `ath = base64url(SHA-256(ASCII(access_token)))`.
    #[serde(default)]
    ath: Option<String>,
}

/// In-memory store for server-issued DPoP nonces.
///
/// Maps nonce string → expiry `Instant`. Protected by a `Mutex` so handlers can issue,
/// validate, and prune concurrently. Held in `AppState`.
pub type DpopNonceStore = Arc<Mutex<HashMap<String, Instant>>>;

/// Error from DPoP validation at the token endpoint.
///
/// Converted to `OAuthTokenError` by the handler in `routes/oauth_token.rs`.
pub enum DpopTokenEndpointError {
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

/// Create an empty `DpopNonceStore`.
pub fn new_nonce_store() -> DpopNonceStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Issue a fresh DPoP nonce with a 5-minute TTL.
///
/// Returns a 22-character base64url string (16 random bytes). The nonce is
/// inserted into the store with an expiry of `Instant::now() + 5 minutes`.
pub async fn issue_nonce(store: &DpopNonceStore) -> String {
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
pub async fn validate_and_consume_nonce(store: &DpopNonceStore, nonce: &str) -> bool {
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
/// Under normal PDS load (low request volume) this is sufficient without a background task.
pub async fn cleanup_expired_nonces(store: &DpopNonceStore) {
    let now = std::time::Instant::now();
    store.lock().await.retain(|_, expiry| *expiry > now);
}

/// A DPoP proof whose header and signature have passed the shared prologue.
///
/// Returned by [`verify_dpop_proof_prologue`]; the endpoint-specific tail reads
/// `header.jwk` (for the thumbprint) and the `claims`.
struct VerifiedProof {
    header: DPopHeader,
    claims: DPopClaims,
}

/// Which check in the shared DPoP proof prologue rejected the proof.
///
/// Each endpoint validator maps this to its own error vocabulary. The token /
/// revocation endpoints surface a distinct `error_description` per variant
/// (RFC 6749 `{error, error_description}`); the resource-endpoint path collapses
/// every variant except `typ`/`crv` into one opaque `"DPoP proof invalid"`.
/// Both mappings reproduce the pre-refactor strings exactly.
enum DPopProofError {
    /// The proof has no header segment before the first `.`.
    MalformedSplit,
    /// The header segment is not valid base64url.
    MalformedBase64,
    /// The header segment is not valid JSON / is missing required fields.
    MalformedJson,
    /// `typ` header is not `"dpop+jwt"`.
    WrongTyp,
    /// `alg` is `ES256` but the embedded JWK `crv` is not `P-256`.
    WrongCrv,
    /// The embedded JWK failed to parse.
    JwkParse,
    /// A `DecodingKey` could not be built from the embedded JWK.
    DecodingKey,
    /// `alg` is not an accepted DPoP algorithm.
    UnsupportedAlg,
    /// Signature verification (or claims decode) failed.
    Signature,
}

impl DPopProofError {
    /// `error_description` for the token / revocation endpoints (each variant
    /// distinct, as before the prologue was factored out).
    fn token_endpoint_message(self) -> &'static str {
        match self {
            DPopProofError::MalformedSplit => "malformed DPoP JWT",
            DPopProofError::MalformedBase64 => "DPoP header base64 invalid",
            DPopProofError::MalformedJson => "DPoP header JSON malformed",
            DPopProofError::WrongTyp => "DPoP typ must be dpop+jwt",
            DPopProofError::WrongCrv => "DPoP JWK crv must be P-256 for ES256",
            DPopProofError::JwkParse => "DPoP JWK parse failed",
            DPopProofError::DecodingKey => "DPoP DecodingKey build failed",
            DPopProofError::UnsupportedAlg => "DPoP unsupported alg",
            DPopProofError::Signature => "DPoP signature verification failed",
        }
    }

    /// `ApiError` for the resource-endpoint path. Only `typ`/`crv` carry a
    /// specific message; every other failure is deliberately opaque.
    fn resource_error(self) -> ApiError {
        match self {
            DPopProofError::WrongTyp => {
                ApiError::new(ErrorCode::InvalidToken, "DPoP proof typ must be dpop+jwt")
            }
            DPopProofError::WrongCrv => ApiError::new(
                ErrorCode::InvalidToken,
                "DPoP JWK crv must be P-256 for ES256",
            ),
            _ => ApiError::new(ErrorCode::InvalidToken, "DPoP proof invalid"),
        }
    }
}

/// The proof-validation prologue shared by both DPoP validators: base64-decode
/// the header → `typ == "dpop+jwt"` → `ES256 ⇒ crv=P-256` → build the decoding
/// key → verify the signature and decode the claims.
///
/// This is the security-critical common core; the endpoint-specific checks
/// (nonce vs `ath` + `cnf.jkt`) live in each validator's tail. Diagnostic
/// `tracing::debug!` logging happens here so both call sites benefit from it;
/// the returned [`DPopProofError`] carries only which check failed, letting each
/// caller render its own client-facing message.
fn verify_dpop_proof_prologue(dpop_token: &str) -> Result<VerifiedProof, DPopProofError> {
    // Decode the DPoP proof header manually — jsonwebtoken's Header type doesn't
    // expose custom header fields like `jwk`, so we base64-decode the first segment.
    let header_b64 = dpop_token
        .split('.')
        .next()
        .ok_or(DPopProofError::MalformedSplit)?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof header is not valid base64url");
        DPopProofError::MalformedBase64
    })?;
    let dpop_header: DPopHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof header JSON is malformed or missing required fields");
        DPopProofError::MalformedJson
    })?;

    if dpop_header.typ != "dpop+jwt" {
        tracing::debug!(typ = %dpop_header.typ, "DPoP proof typ is not dpop+jwt");
        return Err(DPopProofError::WrongTyp);
    }

    // Validate that the embedded JWK curve matches the declared algorithm.
    if dpop_header.alg == "ES256"
        && dpop_header.jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err(DPopProofError::WrongCrv);
    }

    // Verify the DPoP JWT signature (before making any binding decisions based
    // on the embedded JWK — defence-in-depth: prove key control before trusting claims).
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(dpop_header.jwk.clone()).map_err(|e| {
            tracing::debug!(error = %e, "failed to parse JWK from DPoP proof header");
            DPopProofError::JwkParse
        })?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        tracing::debug!(error = %e, "failed to build DecodingKey from DPoP JWK");
        DPopProofError::DecodingKey
    })?;
    let alg = dpop_alg_from_str(&dpop_header.alg).ok_or_else(|| {
        tracing::debug!(alg = %dpop_header.alg, "unsupported DPoP proof algorithm");
        DPopProofError::UnsupportedAlg
    })?;

    let mut validation = Validation::new(alg);
    // DPoP proofs don't carry `exp`; freshness is enforced via `iat` in the tail.
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;

    let dpop_data = decode::<DPopClaims>(dpop_token, &decoding_key, &validation).map_err(|e| {
        tracing::debug!(error = %e, "DPoP proof decoding or signature verification failed");
        DPopProofError::Signature
    })?;

    Ok(VerifiedProof {
        header: dpop_header,
        claims: dpop_data.claims,
    })
}

/// Maximum age — and future-dating tolerance — of a DPoP proof's `iat`, in
/// seconds. RFC 9449 §11.1 leaves the window to the server; a tight ±60s bounds
/// replay without tripping on ordinary clock skew.
const DPOP_MAX_AGE_SECS: u64 = 60;

/// Why the shared freshness check rejected a proof.
enum FreshnessError {
    /// The system clock is before the UNIX epoch — validation is impossible.
    ClockError,
    /// `iat` is more than [`DPOP_MAX_AGE_SECS`] from now (past or future).
    Stale,
}

/// Reject a DPoP proof whose `iat` falls outside the ±[`DPOP_MAX_AGE_SECS`]
/// freshness window.
///
/// Widen to i128 before subtracting so a malicious `iat = i64::MIN` can't
/// overflow the i64 subtraction (debug panic; release wraparound bypass).
fn check_dpop_freshness(iat: i64) -> Result<(), FreshnessError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FreshnessError::ClockError)?
        .as_secs() as i64;
    let diff = (now as i128) - (iat as i128);
    if diff.unsigned_abs() > DPOP_MAX_AGE_SECS as u128 {
        return Err(FreshnessError::Stale);
    }
    Ok(())
}

/// Validate the DPoP proof at the token endpoint and return the JWK thumbprint.
///
/// This is a token-endpoint-specific variant of `validate_dpop`:
/// - Does NOT check `cnf.jkt` against an existing access token (no token yet).
/// - DOES validate the `nonce` claim against the nonce store.
/// - Returns the JWK thumbprint (jkt) so the handler can embed it in `cnf.jkt`.
///
/// `htm` must be `"POST"`. `htu` must be the token endpoint URL (e.g.
/// `"https://pds.example.com/oauth/token"`).
pub async fn validate_dpop_for_token_endpoint(
    dpop_token: &str,
    htm: &str,
    htu: &str,
    nonce_store: &DpopNonceStore,
) -> Result<String, DpopTokenEndpointError> {
    // Shared prologue: header decode + typ/crv/alg/signature checks.
    let proof = verify_dpop_proof_prologue(dpop_token)
        .map_err(|e| DpopTokenEndpointError::InvalidProof(e.token_endpoint_message()))?;
    let claims = proof.claims;

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
    check_dpop_freshness(claims.iat).map_err(|e| match e {
        FreshnessError::ClockError => DpopTokenEndpointError::InvalidProof("system clock error"),
        FreshnessError::Stale => DpopTokenEndpointError::InvalidProof("DPoP proof stale"),
    })?;

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
    jwk_thumbprint(&proof.header.jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("JWK thumbprint computation failed"))
}

/// Validate the DPoP proof JWT (RFC 9449).
///
/// Checks:
/// - `typ` header is `"dpop+jwt"`
/// - Signature verifies against the embedded JWK
/// - `htm` matches request method, `htu` matches `public_url + path`
/// - `jti` is present and non-empty (presence only — **not** deduplicated; see Replay below)
/// - `iat` is within the 60-second freshness window
/// - Access token `cnf.jkt` matches the computed JWK thumbprint
/// - `ath` claim is present and matches the access token
///
/// # Replay
///
/// There is no `jti` store anywhere in the codebase (the only store here is the token-endpoint
/// nonce map), so resource-endpoint proofs are **not** deduplicated — RFC 9449 §11.1 makes `jti`
/// tracking a SHOULD, not a MUST, and the reference PDS's posture is similar. Replay is bounded
/// only by the ±60s `iat` freshness window plus the `ath` access-token binding: a captured
/// (access token + proof) pair is replayable against the same method+URI until the proof goes
/// stale (~60s). This is safe only while every endpoint behind `AuthenticatedUser` stays
/// idempotent / content-addressed; if one ever authorizes a non-idempotent side effect, add `jti`
/// (or nonce) tracking here first. Same posture as `service_auth::require_service_auth`.
pub fn validate_dpop(
    dpop_token: &str,
    method: &Method,
    uri: &axum::http::Uri,
    public_url: &str,
    access_claims: &AccessTokenClaims,
    access_token_str: &str,
) -> Result<(), ApiError> {
    let invalid = || ApiError::new(ErrorCode::InvalidToken, "DPoP proof invalid");

    // Shared prologue: header decode + typ/crv/alg/signature checks.
    let proof = verify_dpop_proof_prologue(dpop_token).map_err(DPopProofError::resource_error)?;
    let dpop_header = proof.header;
    let dpop_claims = proof.claims;

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

    // Validate ath (RFC 9449 §4.3): binds the proof to a specific access token.
    let expected_ath = {
        let hash = Sha256::digest(access_token_str.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    };
    match dpop_claims.ath.as_deref() {
        None | Some("") => {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "DPoP proof missing ath claim",
            ));
        }
        Some(ath) => {
            use subtle::ConstantTimeEq;
            if !bool::from(ath.as_bytes().ct_eq(expected_ath.as_bytes())) {
                tracing::debug!("DPoP proof ath does not match access token hash");
                return Err(ApiError::new(
                    ErrorCode::InvalidToken,
                    "DPoP proof ath does not match access token",
                ));
            }
        }
    }

    // Require `jti` to be present for RFC 9449 §4.2 conformance. It is NOT deduplicated: there is
    // no `jti` store, so this check alone provides no replay protection at resource endpoints (see
    // the Replay note on this function). Replay is bounded by the freshness window and the `ath`
    // binding verified above.
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
    check_dpop_freshness(dpop_claims.iat).map_err(|e| match e {
        FreshnessError::ClockError => {
            tracing::error!("system clock is before UNIX epoch; DPoP validation impossible");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        }
        FreshnessError::Stale => ApiError::new(ErrorCode::InvalidToken, "DPoP proof is stale"),
    })?;

    Ok(())
}

/// Map a DPoP `alg` header string to a [`jsonwebtoken::Algorithm`].
///
/// Only elliptic curve algorithms are accepted to match the server metadata
/// (which advertises ES256 as the sole supported algorithm for DPoP proofs).
/// RSA and EdDSA are excluded despite being valid JWT algorithms.
pub fn dpop_alg_from_str(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        _ => None,
    }
}

/// Compute the RFC 7638 JWK thumbprint: SHA-256 of the canonical JSON member set,
/// base64url-encoded with no padding.
pub fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
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
