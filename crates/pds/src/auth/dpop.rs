// pattern: Mixed (unavoidable)

use axum::http::Method;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::{ApiError, ErrorCode};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

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
    /// the server nonce at the token endpoint and the `ath` access-token binding at resource
    /// endpoints. See the posture notes on `validate_dpop` /
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

/// Rotation interval for the server-issued DPoP nonce, in seconds.
///
/// Matches the reference `@atproto/oauth-provider` (`DPOP_NONCE_MAX_AGE` = 3 minutes,
/// secret rotating every third of it): with the previous, current, and next windows all
/// accepted, a nonce stays valid for one to three minutes.
const NONCE_ROTATION_INTERVAL_SECS: u64 = 60;

/// Stateless, rotating server-issued DPoP nonce (RFC 9449 §8).
///
/// The nonce for a moment in time is `base64url(HMAC-SHA256(secret, rotation_counter))`,
/// where the counter is `unix_seconds / NONCE_ROTATION_INTERVAL_SECS`; validation accepts
/// the previous, current, and next windows, so a nonce is **deliberately reusable** for its
/// validity span. Derived rather than stored: no map, no lock, no cleanup, and every
/// instance sharing the secret agrees on the valid set. Why this replaced the single-use
/// store, and the replay-bound trade-off it accepts: ADR-0032.
pub struct DpopNonceRotator {
    secret: [u8; 32],
}

/// Shared handle to the rotator, held in `AppState`.
pub type DpopNonces = Arc<DpopNonceRotator>;

impl DpopNonceRotator {
    /// Derive the nonce secret from the server's persistent JWT signing secret.
    ///
    /// Domain-separated (HMAC over a fixed label) so the nonce values could never double as
    /// a MAC forgery oracle against anything else keyed on `jwt_secret`. Inherits that
    /// secret's persistence posture: stable across restarts and instances when
    /// `signing_key_master_key` is configured, per-boot otherwise.
    pub fn from_jwt_secret(jwt_secret: &[u8; 32]) -> Self {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(jwt_secret).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"custos-dpop-nonce-v1");
        let derived = mac.finalize().into_bytes();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&derived);
        Self { secret }
    }

    /// The nonce value for one rotation window.
    fn compute(&self, counter: u64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(&counter.to_be_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Rotation counter for a Unix timestamp.
    fn counter_at(now_secs: u64) -> u64 {
        now_secs / NONCE_ROTATION_INTERVAL_SECS
    }

    /// The nonce to hand out at `now_secs` (Unix seconds).
    fn issue_at(&self, now_secs: u64) -> String {
        self.compute(Self::counter_at(now_secs))
    }

    /// Whether `nonce` is acceptable at `now_secs`: the previous, current, or next window.
    fn validate_at(&self, nonce: &str, now_secs: u64) -> bool {
        use subtle::ConstantTimeEq;
        let counter = Self::counter_at(now_secs);
        // `counter.checked_sub(1)` only matters within the first minute after the epoch;
        // skipping the previous window there is harmless.
        let candidates = [
            counter.checked_sub(1).map(|c| self.compute(c)),
            Some(self.compute(counter)),
            Some(self.compute(counter + 1)),
        ];
        candidates
            .into_iter()
            .flatten()
            .fold(false, |ok, expected| {
                ok | bool::from(nonce.as_bytes().ct_eq(expected.as_bytes()))
            })
    }

    /// The nonce to hand out right now (the `DPoP-Nonce` response header value).
    pub fn issue(&self) -> String {
        self.issue_at(unix_now_secs())
    }

    /// Validate a client-presented nonce against the currently acceptable windows.
    ///
    /// Never consumes anything — reuse within the validity span is the intended semantics.
    pub fn validate(&self, nonce: &str) -> bool {
        let ok = self.validate_at(nonce, unix_now_secs());
        if !ok {
            tracing::debug!(nonce = %nonce, "DPoP nonce rejected: outside the acceptance window");
        }
        ok
    }
}

/// Current Unix time in seconds.
///
/// A pre-epoch system clock degrades to counter 0, which stays self-consistent between
/// issuance and validation; the token endpoint's freshness check rejects such requests
/// on its own `ClockError` path anyway.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Error from DPoP validation at the token endpoint.
///
/// Converted to `OAuthTokenError` by the handler in `routes/oauth_token/`.
pub enum DpopTokenEndpointError {
    /// `DPoP:` header is absent.
    ///
    /// Never constructed in practice — the handler in `routes/oauth_token/` pre-checks for a
    /// missing `DPoP:` header and returns an error directly, so this function is only called when
    /// the header is present. Retained for API completeness so callers can match exhaustively.
    #[allow(dead_code)]
    MissingHeader,
    /// DPoP proof is syntactically or semantically invalid.
    InvalidProof(&'static str),
    /// Nonce is missing or outside the acceptance window — fresh nonce included for the
    /// response header.
    UseNonce(String),
}

impl DpopTokenEndpointError {
    /// Render as the resource-endpoint error vocabulary. For the one proof validator that is
    /// reused outside the OAuth token/PAR endpoints — `getSpaceCredential`'s mint-time proof,
    /// which shares [`validate_dpop_for_par`]'s no-nonce, no-`ath` rules — where the RFC 6749
    /// `{error, error_description}` shape does not apply.
    pub fn into_api_error(self) -> ApiError {
        match self {
            DpopTokenEndpointError::MissingHeader => {
                ApiError::new(ErrorCode::InvalidToken, "DPoP proof header required")
            }
            DpopTokenEndpointError::InvalidProof(msg) => {
                ApiError::new(ErrorCode::InvalidToken, msg)
            }
            // Unreachable for the nonce-free validator; keep the mapping total.
            DpopTokenEndpointError::UseNonce(_) => {
                ApiError::new(ErrorCode::InvalidToken, "DPoP nonce required")
            }
        }
    }
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
pub const DPOP_MAX_AGE_SECS: u64 = 60;

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

/// Validate a DPoP proof presented at the PAR endpoint and return the JWK thumbprint.
///
/// Like [`validate_dpop_for_token_endpoint`] (same prologue: typ/crv/alg/signature,
/// `htm`/`htu`, `jti` presence, freshness) but with **no server-nonce requirement**: a PAR
/// is usually a flow's first contact, so the client cannot yet hold a nonce, and the proof
/// here only *asserts the client's own key* for `dpop_jkt` binding (RFC 9449 §10) — there
/// is nothing an attacker gains by replaying it, unlike at the token endpoint where the
/// nonce gates actual token issuance.
pub fn validate_dpop_for_par(
    dpop_token: &str,
    htm: &str,
    htu: &str,
) -> Result<String, DpopTokenEndpointError> {
    let proof = verify_dpop_proof_prologue(dpop_token)
        .map_err(|e| DpopTokenEndpointError::InvalidProof(e.token_endpoint_message()))?;
    let claims = proof.claims;

    if claims.htm.to_uppercase() != htm.to_uppercase() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htm mismatch"));
    }
    if claims.htu != htu {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htu mismatch"));
    }
    if claims.jti.is_empty() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP jti missing"));
    }
    check_dpop_freshness(claims.iat).map_err(|e| match e {
        FreshnessError::ClockError => DpopTokenEndpointError::InvalidProof("system clock error"),
        FreshnessError::Stale => DpopTokenEndpointError::InvalidProof("DPoP proof stale"),
    })?;

    jwk_thumbprint(&proof.header.jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("JWK thumbprint computation failed"))
}

/// Validate the DPoP proof at the token endpoint and return the JWK thumbprint.
///
/// This is a token-endpoint-specific variant of `validate_dpop`:
/// - Does NOT check `cnf.jkt` against an existing access token (no token yet).
/// - DOES validate the `nonce` claim against the rotating server nonce.
/// - Returns the JWK thumbprint (jkt) so the handler can embed it in `cnf.jkt`.
///
/// `htm` must be `"POST"`. `htu` must be the token endpoint URL (e.g.
/// `"https://pds.example.com/oauth/token"`).
pub fn validate_dpop_for_token_endpoint(
    dpop_token: &str,
    htm: &str,
    htu: &str,
    nonces: &DpopNonceRotator,
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
            // No nonce — tell the client the current one to retry with.
            return Err(DpopTokenEndpointError::UseNonce(nonces.issue()));
        }
        Some(nonce) => {
            if !nonces.validate(nonce) {
                // Outside the acceptance window — tell the client the current one.
                return Err(DpopTokenEndpointError::UseNonce(nonces.issue()));
            }
        }
    }

    // Compute and return the JWK thumbprint.
    jwk_thumbprint(&proof.header.jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("JWK thumbprint computation failed"))
}

/// Validate the DPoP proof JWT (RFC 9449) presented with a DPoP-bound token at a resource
/// endpoint, and return the proof's `jti`.
///
/// The bound token is an OAuth access token (`auth/extractors.rs`) or an Atproto Spaces space
/// credential (`auth/space.rs`); `bound_jkt` is its `cnf.jkt` and `bound_token_str` its exact
/// wire form (the `ath` input).
///
/// Checks:
/// - `typ` header is `"dpop+jwt"`
/// - Signature verifies against the embedded JWK
/// - `htm` matches request method, `htu` matches `public_url + path`
/// - `jti` is present and non-empty (presence only here — see Replay below)
/// - `iat` is within the 60-second freshness window
/// - the token's `cnf.jkt` matches the computed JWK thumbprint
/// - `ath` claim is present and matches the token
///
/// # Replay
///
/// This function keeps no `jti` store (and the token-endpoint nonce is derived, not stored), so
/// OAuth resource-endpoint proofs are **not** deduplicated — RFC 9449 §11.1 makes `jti` tracking
/// a SHOULD, not a MUST, and the reference PDS's posture is similar. Replay is bounded only by the
/// ±60s `iat` freshness window plus the `ath` token binding: a captured (token + proof) pair is
/// replayable against the same method+URI until the proof goes stale (~60s). This is safe only
/// while every endpoint behind `AuthenticatedUser` stays idempotent / content-addressed; if one
/// ever authorizes a non-idempotent side effect, add `jti` (or nonce) tracking there first. Same
/// posture as `service_auth::require_service_auth`. The space-credential seam, whose spec makes
/// per-host `jti` tracking a MUST, spends the returned `jti` in `space_jti_replay` itself.
pub fn validate_dpop(
    dpop_token: &str,
    method: &Method,
    uri: &axum::http::Uri,
    public_url: &str,
    bound_jkt: Option<&str>,
    bound_token_str: &str,
) -> Result<String, ApiError> {
    let invalid = || ApiError::new(ErrorCode::InvalidToken, "DPoP proof invalid");

    // Shared prologue: header decode + typ/crv/alg/signature checks.
    let proof = verify_dpop_proof_prologue(dpop_token).map_err(DPopProofError::resource_error)?;
    let dpop_header = proof.header;
    let dpop_claims = proof.claims;

    // Compute JWK thumbprint (RFC 7638) and verify the token was bound to this key.
    // Signature has already been verified above, so the JWK is authentic.
    let thumbprint = jwk_thumbprint(&dpop_header.jwk).map_err(|e| {
        tracing::debug!(error = %e, "failed to compute JWK thumbprint from DPoP proof header");
        invalid()
    })?;
    let bound_thumbprint = bound_jkt.ok_or_else(|| {
        ApiError::new(ErrorCode::InvalidToken, "access token missing DPoP binding")
    })?;
    if thumbprint != bound_thumbprint {
        tracing::debug!("DPoP proof key thumbprint does not match cnf.jkt in access token");
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP key thumbprint does not match token binding",
        ));
    }

    // Validate ath (RFC 9449 §4.3): binds the proof to a specific token.
    let expected_ath = access_token_hash(bound_token_str);
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

    Ok(dpop_claims.jti)
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

/// RFC 9449 §4.3 `ath`: `base64url(SHA-256(ASCII(access_token)))`.
fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A timestamp comfortably past the epoch guard in `validate_at`, on a window boundary
    /// so per-test offsets stay easy to reason about.
    const T0: u64 = 1_000_000 * NONCE_ROTATION_INTERVAL_SECS;

    #[test]
    fn issued_nonce_is_reusable_within_its_window() {
        let rotator = DpopNonceRotator { secret: [7u8; 32] };
        let nonce = rotator.issue_at(T0);
        assert!(
            rotator.validate_at(&nonce, T0),
            "freshly issued nonce must validate"
        );
        assert!(
            rotator.validate_at(&nonce, T0 + 1),
            "nonce must stay valid on reuse — it is derived, not consumed"
        );
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let rotator = DpopNonceRotator { secret: [7u8; 32] };
        assert!(!rotator.validate_at("this-nonce-was-never-issued", T0));
        assert!(!rotator.validate_at("", T0));
    }

    #[test]
    fn adjacent_windows_accepted_older_rejected() {
        let rotator = DpopNonceRotator { secret: [7u8; 32] };
        let nonce = rotator.issue_at(T0);

        // Still valid through the whole next window (issued in "prev").
        assert!(rotator.validate_at(&nonce, T0 + NONCE_ROTATION_INTERVAL_SECS));
        // Two windows on, it has aged out.
        assert!(!rotator.validate_at(&nonce, T0 + 2 * NONCE_ROTATION_INTERVAL_SECS));

        // Clock skew the other way: a nonce from the next window is already acceptable.
        let upcoming = rotator.issue_at(T0 + NONCE_ROTATION_INTERVAL_SECS);
        assert!(rotator.validate_at(&upcoming, T0));
        // But not from two windows ahead.
        let far = rotator.issue_at(T0 + 2 * NONCE_ROTATION_INTERVAL_SECS);
        assert!(!rotator.validate_at(&far, T0));
    }

    #[test]
    fn same_secret_agrees_across_instances() {
        // The multi-instance / restart property: two rotators over the same secret accept
        // each other's nonces with no shared state.
        let a = DpopNonceRotator { secret: [9u8; 32] };
        let b = DpopNonceRotator { secret: [9u8; 32] };
        assert_eq!(a.issue_at(T0), b.issue_at(T0));
        assert!(b.validate_at(&a.issue_at(T0), T0));
    }

    #[test]
    fn different_secret_rejects() {
        let a = DpopNonceRotator { secret: [1u8; 32] };
        let b = DpopNonceRotator { secret: [2u8; 32] };
        assert!(!b.validate_at(&a.issue_at(T0), T0));
    }

    #[test]
    fn jwt_secret_derivation_is_domain_separated() {
        // Using the JWT secret directly as the nonce secret must not produce the same
        // nonces as the derived rotator.
        let jwt_secret = [5u8; 32];
        let derived = DpopNonceRotator::from_jwt_secret(&jwt_secret);
        let raw = DpopNonceRotator { secret: jwt_secret };
        assert_ne!(derived.issue_at(T0), raw.issue_at(T0));
        // And the derivation itself is deterministic.
        let derived2 = DpopNonceRotator::from_jwt_secret(&jwt_secret);
        assert_eq!(derived.issue_at(T0), derived2.issue_at(T0));
    }

    #[test]
    fn nonce_is_43_chars_base64url() {
        let rotator = DpopNonceRotator { secret: [7u8; 32] };
        let nonce = rotator.issue_at(T0);
        assert_eq!(
            nonce.len(),
            43,
            "nonce must be 43 chars (32-byte HMAC, base64url no-pad)"
        );
        assert!(nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    // ── RFC 9449 normative vectors ────────────────────────────────────────────
    //
    // The RFC's example client key (Figures 2, 8, 11, 13) and its RFC 7638 thumbprint. The
    // proofs are dated 2019, so only the signature-verifying prologue can run them; the
    // ±60s `iat` freshness check lives in each validator's tail.

    const RFC9449_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    #[test]
    fn ec_jwk_thumbprint_matches_rfc9449_figure8() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
        });
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), RFC9449_JKT);
    }

    #[test]
    fn rfc9449_figure2_token_request_proof_passes_prologue() {
        let proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
        let verified = verify_dpop_proof_prologue(proof)
            .map_err(DPopProofError::token_endpoint_message)
            .expect("RFC 9449 Figure 2 proof must verify");
        assert_eq!(verified.claims.jti, "-BwC3ESc6acc2lTc");
        assert_eq!(verified.claims.htm, "POST");
        assert_eq!(verified.claims.htu, "https://server.example.com/token");
        assert_eq!(verified.claims.iat, 1562262616);
        assert_eq!(verified.claims.nonce, None);
        assert_eq!(verified.claims.ath, None);
        assert_eq!(jwk_thumbprint(&verified.header.jwk).unwrap(), RFC9449_JKT);
    }

    #[test]
    fn rfc9449_figure13_resource_proof_ath_matches_access_token() {
        let proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";
        let verified = verify_dpop_proof_prologue(proof)
            .map_err(DPopProofError::token_endpoint_message)
            .expect("RFC 9449 Figure 13 proof must verify");
        let ath = access_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU");
        assert_eq!(ath, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
        assert_eq!(verified.claims.ath.as_deref(), Some(ath.as_str()));
        assert_eq!(verified.claims.htm, "GET");
        assert_eq!(
            verified.claims.htu,
            "https://resource.example.org/protectedresource"
        );
        assert_eq!(jwk_thumbprint(&verified.header.jwk).unwrap(), RFC9449_JKT);
    }
}
