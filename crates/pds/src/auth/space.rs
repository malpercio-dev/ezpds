// pattern: Mixed (unavoidable)

//! Atproto Spaces token auth (proposal 0016, "Access control"): the three-token flow and the
//! one read-side seam.
//!
//! * **Delegation token** — the user's PDS mints it (`getDelegationToken`): an account-key JWT,
//!   `typ atproto-space-delegation+jwt`, `kid #atproto`, `sub` = space URI, `aud` = the
//!   authority's `#atproto_space_host`, single-use, ~60 s. [`mint_delegation_token`] /
//!   [`verify_delegation_token`] (the latter spends the `jti` in `space_jti_replay`).
//! * **Space credential** — the space authority mints it (`getSpaceCredential`) in exchange for
//!   a delegation token plus a mint-time DPoP proof (no `ath`): `typ
//!   atproto-space-credential+jwt`, `kid #atproto_space`, no `aud`, `cnf.jkt` = the proof key's
//!   RFC 7638 thumbprint, ~2 h. [`mint_space_credential`] / [`verify_space_credential`] (the
//!   latter resolves the authority's key with the `#atproto_space` → `#atproto` fallback).
//! * **The seam** — [`authenticate_space_read`] is the single path every space read/sync route
//!   authenticates through. It accepts a covering OAuth grant *or* a DPoP-bound space
//!   credential, never a bearer credential, and on the credential arm runs the full RFC 9449
//!   per-request proof validation (`auth/dpop.rs`'s `validate_dpop`: signature vs header `jwk`,
//!   thumbprint vs `cnf.jkt`, `ath` = hash of the credential, `htm`/`htu`, `iat` recency) plus
//!   the per-host `jti` replay check the proposal makes a MUST. `just space-auth-seam-check`
//!   (`scripts/space-auth-seam-check.sh`) confines `verify_space_credential` and
//!   `validate_dpop` to this seam and `extractors.rs`, so no route grows its own credential
//!   parsing.
//!
//! Both account-key-signed token shapes share `jwt.rs`'s [`sign_jwt`] / [`verify_did_key_jwt`]
//! core with service auth; the scheme ↔ `cnf.jkt` binding on the credential arm mirrors the one
//! `extractors::authenticate_access` enforces for OAuth.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, Method, Uri};
use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;
use crate::db::space_jti::{insert_jti_if_absent, SpaceJtiScope};
use crate::db::spaces::{self, SpaceRow};
use crate::identity::resolution::{
    atproto_verification_key, resolve_did_document, resolve_did_document_force_refresh,
    space_verification_key,
};

use super::bearer::{extract_access_token, AuthScheme};
use super::dpop::{validate_dpop, validate_dpop_for_par, DPOP_MAX_AGE_SECS};
use super::extractors::{authenticate_access, AuthenticatedUser};
use super::jwt::{
    peek_jwt_iss, peek_jwt_typ, random_jti, sign_jwt, verify_did_key_jwt, AuthScope, DidKeyJwt,
    ServiceAuthError,
};
use super::oauth_scopes::{require_space, SpaceOp, SpaceRequest};

/// JWT `typ` of a delegation token.
pub const DELEGATION_TOKEN_TYP: &str = "atproto-space-delegation+jwt";
/// JWT `typ` of a space credential.
pub const SPACE_CREDENTIAL_TYP: &str = "atproto-space-credential+jwt";
/// Lifetime of a delegation token this server mints (the proposal's default).
pub const DELEGATION_TOKEN_TTL_SECS: u64 = 60;
/// Longest remaining lifetime accepted on an inbound delegation token — also the horizon its
/// spent `jti` is retained for, so a token can never outlive its replay row.
const DELEGATION_TOKEN_MAX_TTL_SECS: u64 = 5 * 60;
/// Lifetime of a space credential this server mints (the proposal's default).
pub const SPACE_CREDENTIAL_TTL_SECS: u64 = 2 * 60 * 60;
/// Request path the mint-time DPoP proof's `htu` must name.
pub const GET_SPACE_CREDENTIAL_PATH: &str = "/xrpc/com.atproto.space.getSpaceCredential";

// ── Space references ─────────────────────────────────────────────────────────

/// A parsed space reference: `at://{authority}/space/{spaceType}/{skey}` (the lexicon
/// `space-ref` string format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRef {
    /// The canonical URI, exactly as parsed.
    pub uri: String,
    pub authority: String,
    pub space_type: String,
    pub skey: String,
}

impl SpaceRef {
    /// Parse a `space-ref`. The authority must be a valid DID, the type a valid NSID, and the
    /// key a non-empty URI path segment; anything longer than the three segments (a record
    /// URI) or with a different marker than the literal `space` is rejected.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let rest = value
            .strip_prefix("at://")
            .ok_or("space reference must start with at://")?;
        let segments: Vec<&str> = rest.split('/').collect();
        let [authority, marker, space_type, skey] = segments.as_slice() else {
            return Err("space reference must be at://{did}/space/{spaceType}/{skey}");
        };
        if !crate::identity::did::is_valid_did(authority) {
            return Err("space reference authority must be a valid DID");
        }
        if *marker != "space" {
            return Err("space reference must carry the literal `space` segment");
        }
        if repo_engine::validate_collection(space_type).is_err() {
            return Err("space reference type must be a valid NSID");
        }
        if skey.is_empty()
            || !skey
                .chars()
                .all(|c| c.is_ascii_graphic() && !matches!(c, '/' | '?' | '#'))
        {
            return Err("space reference key must be a non-empty URI path segment");
        }
        Ok(Self {
            uri: value.to_string(),
            authority: (*authority).to_string(),
            space_type: (*space_type).to_string(),
            skey: (*skey).to_string(),
        })
    }

    /// Whether `value` is a well-formed `space-ref` (the lexicon string-format check).
    pub fn is_valid(value: &str) -> bool {
        Self::parse(value).is_ok()
    }

    /// The delegation-token audience: the authority's space-host service reference.
    pub fn space_host_aud(&self) -> String {
        format!("{}#atproto_space_host", self.authority)
    }
}

// ── Delegation tokens ────────────────────────────────────────────────────────

/// Mint a delegation token for `space` on behalf of `user_did`, signed by the account's
/// `#atproto` key via `sign` (a low-S 64-byte ES256 signature — `CommitSigner::sign`).
pub fn mint_delegation_token<F>(sign: F, user_did: &str, space: &SpaceRef, now: u64) -> String
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    let header = serde_json::json!({
        "typ": DELEGATION_TOKEN_TYP,
        "alg": "ES256",
        "kid": "#atproto",
    });
    let payload = serde_json::json!({
        "iss": user_did,
        "sub": space.uri,
        "aud": space.space_host_aud(),
        "iat": now,
        "exp": now + DELEGATION_TOKEN_TTL_SECS,
        "jti": random_jti(),
    });
    sign_jwt(sign, &header, &payload)
}

/// A delegation token that verified and whose `jti` was spent.
#[derive(Debug)]
pub struct VerifiedDelegation {
    /// The delegating user (`iss`).
    pub user_did: String,
}

/// Verify an inbound delegation token for `space`, as the space authority, and spend its `jti`.
///
/// Checks: `typ`; header `kid` is `#atproto`; the signature against the issuer's `#atproto` key
/// (cache-first, force-refreshed and retried once on a signature mismatch); `sub` = `space`;
/// `aud` = `space`'s `#atproto_space_host`; no `lxm` (a service-auth token is not a delegation
/// token); `exp` in the future and within [`DELEGATION_TOKEN_MAX_TTL_SECS`]; and a non-empty
/// `jti` not yet seen on this surface. Every failure is the lexicon's `InvalidDelegationToken`.
pub async fn verify_delegation_token(
    state: &AppState,
    token: &str,
    space: &SpaceRef,
    now: u64,
) -> Result<VerifiedDelegation, ApiError> {
    let invalid = |msg: &str| ApiError::new(ErrorCode::InvalidDelegationToken, msg);

    if peek_jwt_typ(token).as_deref() != Some(DELEGATION_TOKEN_TYP) {
        return Err(invalid(
            "delegation token typ must be atproto-space-delegation+jwt",
        ));
    }
    let iss = peek_jwt_iss(token)
        .filter(|i| i.starts_with("did:"))
        .ok_or_else(|| invalid("delegation token issuer is missing or not a DID"))?;

    let jwt = verify_did_jwt_resolving_key(state, token, &iss, atproto_verification_key)
        .await
        .map_err(|e| e.with_code(ErrorCode::InvalidDelegationToken))?;

    if jwt.header.get("kid").and_then(Value::as_str) != Some("#atproto") {
        return Err(invalid("delegation token kid must be #atproto"));
    }
    let claims = &jwt.payload;
    if claims.get("sub").and_then(Value::as_str) != Some(space.uri.as_str()) {
        return Err(invalid("delegation token is for a different space"));
    }
    if claims.get("aud").and_then(Value::as_str) != Some(space.space_host_aud().as_str()) {
        return Err(invalid(
            "delegation token audience is not this space's host",
        ));
    }
    if claims.get("lxm").is_some() {
        return Err(invalid("delegation token must not carry lxm"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("delegation token has no exp"))?;
    if exp <= now {
        return Err(invalid("delegation token has expired"));
    }
    let remaining = exp - now;
    if remaining > DELEGATION_TOKEN_MAX_TTL_SECS {
        return Err(invalid("delegation token lifetime is too long"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| invalid("delegation token has no jti"))?;

    let fresh = insert_jti_if_absent(&state.db, SpaceJtiScope::Delegation, jti, remaining as i64)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to record delegation token jti");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?;
    if !fresh {
        return Err(invalid("delegation token has already been used"));
    }

    Ok(VerifiedDelegation { user_did: iss })
}

// ── Space credentials ────────────────────────────────────────────────────────

/// Mint a space credential for `space`, as its authority `authority_did`, bound to the DPoP
/// key with thumbprint `jkt`. `sign` is the authority's space signing key — this server signs
/// with the account's repo key, which is also what it publishes as `#atproto_space`, hence that
/// `kid` (verifiers fall back to `#atproto` when the dedicated entry is absent).
pub fn mint_space_credential<F>(
    sign: F,
    authority_did: &str,
    space: &SpaceRef,
    jkt: &str,
    now: u64,
) -> String
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    let header = serde_json::json!({
        "typ": SPACE_CREDENTIAL_TYP,
        "alg": "ES256",
        "kid": "#atproto_space",
    });
    let payload = serde_json::json!({
        "iss": authority_did,
        "sub": space.uri,
        "cnf": { "jkt": jkt },
        "iat": now,
        "exp": now + SPACE_CREDENTIAL_TTL_SECS,
        "jti": random_jti(),
    });
    sign_jwt(sign, &header, &payload)
}

/// A space credential whose signature and claims verified. Its DPoP binding is enforced by
/// [`authenticate_space_read`], not here.
// Its fields are read by the space read/sync routes, which land after this seam.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    /// The space the credential reads (`sub`).
    pub space: SpaceRef,
    /// The issuing authority (`iss`, equal to `space.authority`).
    pub authority: String,
    /// The bound DPoP key's thumbprint (`cnf.jkt`).
    pub jkt: String,
}

/// Verify a space credential as a repo host: `typ`; `kid` of `#atproto_space` (resolved with the
/// `#atproto` fallback) or `#atproto`; the signature against the authority's key (cache-first,
/// force-refreshed and retried once on a mismatch — a foreign authority may be ES256K, which the
/// shared core accepts); `sub` a space anchored on `iss`; `exp` in the future; and a `cnf.jkt`.
///
/// Only [`authenticate_space_read`] may call this — the proof-of-possession check that makes a
/// verified credential usable lives there, and `just space-auth-seam-check` enforces it.
pub async fn verify_space_credential(
    state: &AppState,
    token: &str,
    now: u64,
) -> Result<VerifiedCredential, ApiError> {
    let invalid = |msg: &str| ApiError::new(ErrorCode::InvalidToken, msg);

    if peek_jwt_typ(token).as_deref() != Some(SPACE_CREDENTIAL_TYP) {
        return Err(invalid(
            "space credential typ must be atproto-space-credential+jwt",
        ));
    }
    let iss = peek_jwt_iss(token)
        .filter(|i| i.starts_with("did:"))
        .ok_or_else(|| invalid("space credential issuer is missing or not a DID"))?;

    // The header `kid` names which published key signed the credential. Read it before the
    // signature check so the right key is resolved; it is plain data until the signature verifies.
    let pick_key = match peek_jwt_header(token)
        .and_then(|h| h.get("kid").and_then(Value::as_str).map(str::to_string))
        .as_deref()
    {
        Some("#atproto_space") => space_verification_key,
        Some("#atproto") => atproto_verification_key,
        _ => {
            return Err(invalid(
                "space credential kid must be #atproto_space or #atproto",
            ))
        }
    };

    let jwt = verify_did_jwt_resolving_key(state, token, &iss, pick_key).await?;
    let claims = &jwt.payload;

    let space = claims
        .get("sub")
        .and_then(Value::as_str)
        .and_then(|s| SpaceRef::parse(s).ok())
        .ok_or_else(|| invalid("space credential sub is not a space reference"))?;
    if space.authority != iss {
        return Err(invalid(
            "space credential issuer is not the space's authority",
        ));
    }
    match claims.get("exp").and_then(Value::as_u64) {
        Some(exp) if exp > now => {}
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::TokenExpired,
                "space credential has expired",
            ))
        }
        None => return Err(invalid("space credential has no exp")),
    }
    let jkt = claims
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| invalid("space credential has no cnf.jkt binding"))?
        .to_string();

    Ok(VerifiedCredential {
        space,
        authority: iss,
        jkt,
    })
}

// ── Credential issuance policy ───────────────────────────────────────────────

/// Decide, as the space authority, whether `user_did` may be issued a credential for `space`
/// — the simplespace `policy` axis. The authority itself is always authorized; `public` admits
/// anyone; `member-list` consults `space_members`. The `managing-app` policy and the
/// `allowList` app-access mode need the outbound `checkUserAccess` call and client-attestation
/// verification, which land with the client-attestation work; until then they fail closed.
pub async fn authorize_credential_request(
    db: &sqlx::SqlitePool,
    space: &SpaceRow,
    user_did: &str,
) -> Result<(), ApiError> {
    if space.app_access.as_deref() == Some("allowList") {
        return Err(ApiError::new(
            ErrorCode::AppNotAuthorized,
            "this host does not yet verify client attestations, so an allow-listed space cannot mint credentials",
        ));
    }
    if user_did == space.authority_did {
        return Ok(());
    }
    match space.policy.as_deref() {
        Some("public") => Ok(()),
        Some("member-list") => {
            let member = spaces::is_member(db, &space.uri, user_did)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space.uri, "failed to read space members");
                    ApiError::new(ErrorCode::InternalError, "internal server error")
                })?;
            if member {
                Ok(())
            } else {
                Err(ApiError::new(
                    ErrorCode::UserNotAuthorized,
                    "the requesting user is not a member of this space",
                ))
            }
        }
        Some("managing-app") => Err(ApiError::new(
            ErrorCode::UserNotAuthorized,
            "this host does not yet evaluate the managing-app policy",
        )),
        _ => Err(ApiError::new(
            ErrorCode::UserNotAuthorized,
            "this space's policy is not one this host evaluates",
        )),
    }
}

/// Validate the mint-time DPoP proof on a `getSpaceCredential` request and return the proof
/// key's thumbprint — the value that becomes the credential's `cnf.jkt`. Same rules as the PAR
/// proof: signature vs header `jwk`, `htm` POST, `htu` = this server's `getSpaceCredential`
/// URL, `jti` present, `iat` fresh; no server nonce and no `ath` (the delegation token is a
/// grant, not an access token).
pub fn mint_time_dpop_thumbprint(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<String, ApiError> {
    let proof = single_dpop_header(headers)?.ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidToken,
            "getSpaceCredential requires a DPoP proof header",
        )
    })?;
    let htu = format!(
        "{}{}",
        state.config.public_url.trim_end_matches('/'),
        GET_SPACE_CREDENTIAL_PATH
    );
    validate_dpop_for_par(proof, "POST", &htu).map_err(|e| e.into_api_error())
}

// ── The read seam ────────────────────────────────────────────────────────────

/// Who a space read/sync request is authenticated as.
// Consumed by the space read/sync routes, which land after this seam.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SpaceReader {
    /// An OAuth (or legacy full-access) session whose grant covers the space; routes that
    /// distinguish the holder's own repo from others' already had that folded into the
    /// `read`/`read_self` check by the seam.
    User(AuthenticatedUser),
    /// A DPoP-bound space credential for the space, with proof of possession verified for this
    /// request.
    Credential(VerifiedCredential),
}

/// Authenticate a space read/sync request for `space`: a covering OAuth grant *or* a DPoP-bound
/// space credential, never a bearer credential. `repo_did` is the target repo when the method is
/// repo-scoped (`None` for space-wide reads): an OAuth holder reading their own repo needs only
/// `read_self`, any other target needs `read`.
///
/// On the credential arm the scheme must be `DPoP` with exactly one `DPoP` header (the
/// scheme ↔ binding rule `extractors::authenticate_access` enforces for OAuth), the credential's
/// `sub` must be `space`, and the per-request proof is validated in full (`validate_dpop`, with
/// the credential as the bound token) and its `jti` spent per host in `space_jti_replay` for the
/// proof acceptance window.
// Published ahead of the space read/sync routes that call it (the record, sync, and
// simplespace read surfaces), like `oauth_scopes::require_space` before it.
#[allow(dead_code)]
pub async fn authenticate_space_read(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    state: &AppState,
    space: &SpaceRef,
    repo_did: Option<&str>,
) -> Result<SpaceReader, ApiError> {
    let (scheme, token) = extract_access_token(headers)?;

    if peek_jwt_typ(token).as_deref() != Some(SPACE_CREDENTIAL_TYP) {
        // OAuth arm: the shared access-token seam (binding rules + proof), then the grant.
        let user = authenticate_access(headers, method, uri, state)?;
        if user.scope != AuthScope::Access {
            return Err(ApiError::new(
                ErrorCode::InsufficientScope,
                "space reads require an OAuth session with a covering space: grant",
            ));
        }
        let op = if repo_did == Some(user.did.as_str()) {
            SpaceOp::ReadSelf
        } else {
            SpaceOp::Read
        };
        require_space(
            &user.scope_claim,
            &SpaceRequest {
                space_type: &space.space_type,
                authority: &space.authority,
                skey: &space.skey,
                op,
                account_did: &user.did,
                declared_collections: &[],
            },
        )?;
        return Ok(SpaceReader::User(user));
    }

    // Credential arm — proof of possession or nothing.
    if scheme != AuthScheme::Dpop {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "space credential must use the DPoP authorization scheme",
        ));
    }
    let proof = single_dpop_header(headers)?.ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidToken,
            "space credential requires a DPoP proof header",
        )
    })?;

    let credential = verify_space_credential(state, token, unix_now()?).await?;
    if credential.space.uri != space.uri {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "space credential is for a different space",
        ));
    }

    let jti = validate_dpop(
        proof,
        method,
        uri,
        &state.config.public_url,
        Some(&credential.jkt),
        token,
    )?;
    // Per-host replay protection (a MUST for credential-authed requests): a proof is acceptable
    // for ±DPOP_MAX_AGE_SECS around its iat, so its jti is retained for the full window.
    let fresh = insert_jti_if_absent(
        &state.db,
        SpaceJtiScope::Dpop,
        &jti,
        (2 * DPOP_MAX_AGE_SECS) as i64,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to record DPoP proof jti");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    })?;
    if !fresh {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP proof jti has already been used",
        ));
    }

    Ok(SpaceReader::Credential(credential))
}

// ── Shared plumbing ──────────────────────────────────────────────────────────

/// Resolve `iss`'s DID document, pick the verification key with `pick_key`, and verify `token`
/// against it — force-refreshing the cached document and retrying once on a signature
/// mismatch, the same fossil-key healing `service_auth::verify_service_auth_resolving_key`
/// does (the `did_documents` cache has no TTL). Errors are `InvalidToken`; callers re-code.
async fn verify_did_jwt_resolving_key(
    state: &AppState,
    token: &str,
    iss: &str,
    pick_key: fn(&Value) -> Option<crypto::DidKeyUri>,
) -> Result<DidKeyJwt, ApiError> {
    let verify = |doc: &Value| -> Result<DidKeyJwt, ServiceAuthError> {
        let key = pick_key(doc).ok_or_else(|| {
            ServiceAuthError::Invalid(ApiError::new(
                ErrorCode::InvalidToken,
                "the issuer's DID document has no matching verification key",
            ))
        })?;
        verify_did_key_jwt(token, &key)
    };
    let cached = resolve_did_document(state, iss)
        .await
        .map_err(|e| e.with_code(ErrorCode::InvalidToken))?;
    match verify(&cached) {
        Ok(jwt) => Ok(jwt),
        Err(ServiceAuthError::SignatureMismatch) => {
            tracing::info!(
                iss = %iss,
                "space token signature failed against the cached DID document; \
                 force-refreshing the key and retrying once"
            );
            let fresh = resolve_did_document_force_refresh(state, iss)
                .await
                .map_err(|e| e.with_code(ErrorCode::InvalidToken))?;
            Ok(verify(&fresh)?)
        }
        Err(other) => Err(other.into()),
    }
}

/// The decoded JWT header, unverified — for reading `kid` ahead of key resolution.
fn peek_jwt_header(token: &str) -> Option<Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_b64 = token.split('.').next()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).ok()?).ok()
}

/// The single `DPoP` header value, or `None` when absent. More than one is rejected (RFC 9449
/// §11.1: a header-prepending proxy could inject a forged proof as the first value).
fn single_dpop_header(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    if headers.get_all("DPoP").iter().count() > 1 {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "multiple DPoP headers are not permitted",
        ));
    }
    Ok(headers.get("DPoP").and_then(|v| v.to_str().ok()))
}

/// Current Unix time in seconds.
pub fn unix_now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "system clock error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::db::dids::seed_did_document;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::routes::test_utils::{
        access_jwt, app_pass_jwt, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
        DpopProofKey,
    };
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
    const SPACE: &str = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self";
    const PUBLIC_URL: &str = "https://test.example.com";

    /// A DID document whose `#atproto` (and, when `with_space_key`, `#atproto_space`) Multikey
    /// holds `kp`'s public key — what this server publishes for its own accounts.
    fn did_doc(did: &str, kp: &crypto::P256Keypair, with_space_key: bool) -> Value {
        let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        let mut methods = vec![serde_json::json!({
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase,
        })];
        if with_space_key {
            methods.push(serde_json::json!({
                "id": format!("{did}#atproto_space"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }));
        }
        serde_json::json!({ "id": did, "verificationMethod": methods })
    }

    /// Seed a local account with a repo key and a cached DID document carrying that key.
    async fn seed_identity(
        state: &AppState,
        did: &str,
        with_space_key: bool,
    ) -> repo_engine::CommitSigner {
        let kp = seed_account_with_repo(&state.db, did).await;
        seed_did_document(&state.db, did, did_doc(did, &kp, with_space_key)).await;
        repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap()
    }

    fn space() -> SpaceRef {
        SpaceRef::parse(SPACE).unwrap()
    }

    fn payload(token: &str) -> Value {
        let b64 = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    fn header(token: &str) -> Value {
        let b64 = token.split('.').next().unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    fn headers(scheme: &str, token: &str, dpop: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("{scheme} {token}")).unwrap(),
        );
        if let Some(p) = dpop {
            h.insert("DPoP", HeaderValue::from_str(p).unwrap());
        }
        h
    }

    fn get_uri(path: &str) -> Uri {
        path.parse().unwrap()
    }

    #[test]
    fn space_ref_parses_the_three_segment_form_only() {
        let r = SpaceRef::parse(SPACE).unwrap();
        assert_eq!(r.authority, AUTHORITY);
        assert_eq!(r.space_type, "org.example.bucket");
        assert_eq!(r.skey, "self");
        assert_eq!(r.uri, SPACE);
        assert_eq!(
            r.space_host_aud(),
            "did:plc:abc234567abc234567abc234#atproto_space_host"
        );

        for bad in [
            "https://example.com/space/org.example.bucket/self",
            "at://did:plc:abc234567abc234567abc234/org.example.bucket/self",
            "at://did:plc:abc234567abc234567abc234/space/org.example.bucket",
            // A record URI, not a space reference.
            "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self/did:plc:alice/org.example.post/3k",
            "at://not-a-did/space/org.example.bucket/self",
            "at://did:plc:abc234567abc234567abc234/space/notannsid/self",
            "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/",
            "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/a?b",
        ] {
            assert!(SpaceRef::parse(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[tokio::test]
    async fn delegation_token_mints_verifies_and_is_single_use() {
        let state = state_with_master_key().await;
        let alice = seed_identity(&state, ALICE, false).await;
        let now = unix_now().unwrap();

        let token = mint_delegation_token(|b| alice.sign(b), ALICE, &space(), now);
        let hdr = header(&token);
        assert_eq!(hdr["typ"], DELEGATION_TOKEN_TYP);
        assert_eq!(hdr["kid"], "#atproto");
        let claims = payload(&token);
        assert_eq!(claims["iss"], ALICE);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(
            claims["aud"],
            "did:plc:abc234567abc234567abc234#atproto_space_host"
        );
        assert_eq!(claims["exp"], now + DELEGATION_TOKEN_TTL_SECS);
        assert!(claims.get("lxm").is_none());

        let verified = verify_delegation_token(&state, &token, &space(), now)
            .await
            .unwrap();
        assert_eq!(verified.user_did, ALICE);

        // Single-use: the same token is a replay.
        let err = verify_delegation_token(&state, &token, &space(), now)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
        assert_eq!(*err.code(), ErrorCode::InvalidDelegationToken);

        // A token for another space, an expired token, and a service-auth token (wrong typ)
        // are all InvalidDelegationToken.
        let other =
            SpaceRef::parse("at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other")
                .unwrap();
        let wrong_space = mint_delegation_token(|b| alice.sign(b), ALICE, &other, now);
        assert_eq!(
            verify_delegation_token(&state, &wrong_space, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
        let expired = mint_delegation_token(|b| alice.sign(b), ALICE, &space(), now - 120);
        assert_eq!(
            verify_delegation_token(&state, &expired, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
        let service_auth = super::super::jwt::mint_service_auth_jwt(
            |b| alice.sign(b),
            ALICE,
            &space().space_host_aud(),
            None,
            now,
            now + 60,
        );
        assert_eq!(
            verify_delegation_token(&state, &service_auth, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
    }

    #[tokio::test]
    async fn delegation_token_signed_by_the_wrong_key_is_rejected() {
        let state = state_with_master_key().await;
        seed_identity(&state, ALICE, false).await;
        // A key that is not the one in alice's DID document.
        let imposter = crypto::generate_p256_keypair().unwrap();
        let imposter = repo_engine::CommitSigner::from_bytes(&imposter.private_key_bytes).unwrap();
        let now = unix_now().unwrap();
        let forged = mint_delegation_token(|b| imposter.sign(b), ALICE, &space(), now);
        let err = verify_delegation_token(&state, &forged, &space(), now)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::InvalidDelegationToken);
    }

    #[tokio::test]
    async fn space_credential_mints_and_the_seam_accepts_it_with_proof_of_possession() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();

        let credential = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            &key.thumbprint(),
            now,
        );
        let hdr = header(&credential);
        assert_eq!(hdr["typ"], SPACE_CREDENTIAL_TYP);
        assert_eq!(hdr["kid"], "#atproto_space");
        let claims = payload(&credential);
        assert_eq!(claims["iss"], AUTHORITY);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(claims["cnf"]["jkt"], key.thumbprint());
        assert!(claims.get("aud").is_none());
        assert_eq!(claims["exp"], now + SPACE_CREDENTIAL_TTL_SECS);

        let path = "/xrpc/com.atproto.space.getRecord";
        let htu = format!("{PUBLIC_URL}{path}");
        let proof = key.proof("GET", &htu, &credential);
        let reader = authenticate_space_read(
            &headers("DPoP", &credential, Some(&proof)),
            &Method::GET,
            &get_uri(path),
            &state,
            &space(),
            Some(ALICE),
        )
        .await
        .unwrap();
        match reader {
            SpaceReader::Credential(c) => {
                assert_eq!(c.authority, AUTHORITY);
                assert_eq!(c.space.uri, SPACE);
                assert_eq!(c.jkt, key.thumbprint());
            }
            other => panic!("expected the credential arm, got {other:?}"),
        }

        // The same proof again is a per-host replay.
        let err = authenticate_space_read(
            &headers("DPoP", &credential, Some(&proof)),
            &Method::GET,
            &get_uri(path),
            &state,
            &space(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.status_code(),
            401,
            "replayed proof jti must be rejected"
        );

        // A fresh proof works again; one from a different key (thumbprint ≠ cnf.jkt) does not.
        let fresh = key.proof("GET", &htu, &credential);
        assert!(authenticate_space_read(
            &headers("DPoP", &credential, Some(&fresh)),
            &Method::GET,
            &get_uri(path),
            &state,
            &space(),
            None
        )
        .await
        .is_ok());
        let other_key = DpopProofKey::generate();
        let wrong_key = other_key.proof("GET", &htu, &credential);
        assert_eq!(
            authenticate_space_read(
                &headers("DPoP", &credential, Some(&wrong_key)),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );
        // A proof for another method/URI does not transfer.
        let wrong_htu = key.proof("POST", &htu, &credential);
        assert_eq!(
            authenticate_space_read(
                &headers("DPoP", &credential, Some(&wrong_htu)),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn space_credential_is_never_bearer() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();
        let credential = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            &key.thumbprint(),
            now,
        );
        let path = "/xrpc/com.atproto.space.getRecord";
        let proof = key.proof("GET", &format!("{PUBLIC_URL}{path}"), &credential);

        // Bearer scheme (even with a valid proof attached) and DPoP scheme without a proof are
        // both refused — the scheme ↔ binding rule in both directions.
        for (scheme, dpop) in [
            ("Bearer", Some(proof.as_str())),
            ("Bearer", None),
            ("DPoP", None),
        ] {
            let err = authenticate_space_read(
                &headers(scheme, &credential, dpop),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(
                err.status_code(),
                401,
                "{scheme} with dpop={} must be rejected",
                dpop.is_some()
            );
        }
    }

    #[tokio::test]
    async fn space_credential_for_another_space_or_wrong_issuer_is_rejected() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let alice = seed_identity(&state, ALICE, false).await;
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();
        let path = "/xrpc/com.atproto.space.getRecord";
        let htu = format!("{PUBLIC_URL}{path}");

        // Credential for a different space than the request targets.
        let other =
            SpaceRef::parse("at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other")
                .unwrap();
        let cred = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &other,
            &key.thumbprint(),
            now,
        );
        let proof = key.proof("GET", &htu, &cred);
        assert_eq!(
            authenticate_space_read(
                &headers("DPoP", &cred, Some(&proof)),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );

        // Signed by alice (a valid key, but not the space's authority): iss ≠ space authority.
        let cred =
            mint_space_credential(|b| alice.sign(b), ALICE, &space(), &key.thumbprint(), now);
        let proof = key.proof("GET", &htu, &cred);
        assert_eq!(
            authenticate_space_read(
                &headers("DPoP", &cred, Some(&proof)),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );

        // Forged: claims iss = authority but signed by alice's key.
        let cred = mint_space_credential(
            |b| alice.sign(b),
            AUTHORITY,
            &space(),
            &key.thumbprint(),
            now,
        );
        let proof = key.proof("GET", &htu, &cred);
        assert_eq!(
            authenticate_space_read(
                &headers("DPoP", &cred, Some(&proof)),
                &Method::GET,
                &get_uri(path),
                &state,
                &space(),
                None
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn credential_kid_atproto_verifies_without_a_dedicated_space_key() {
        // An authority whose DID document has no `#atproto_space`: `kid #atproto_space` falls
        // back to `#atproto`, and `kid #atproto` resolves directly.
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, false).await;
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();
        let cred = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            &key.thumbprint(),
            now,
        );
        assert_eq!(
            verify_space_credential(&state, &cred, now)
                .await
                .unwrap()
                .jkt,
            key.thumbprint()
        );

        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto" });
        let cred = sign_jwt(|b| authority.sign(b), &header, &payload(&cred));
        assert!(verify_space_credential(&state, &cred, now).await.is_ok());

        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#other" });
        let cred = sign_jwt(|b| authority.sign(b), &header, &payload(&cred));
        assert!(verify_space_credential(&state, &cred, now).await.is_err());
    }

    #[tokio::test]
    async fn seam_oauth_arm_requires_a_covering_space_grant() {
        let state = state_with_master_key().await;
        let path = "/xrpc/com.atproto.space.getRecord";
        // Alice's own space (authority = self).
        let own = SpaceRef::parse("at://did:plc:alice/space/org.example.bucket/self").unwrap();

        let call = |token: String, space: SpaceRef, repo: Option<&'static str>| {
            let state = state.clone();
            async move {
                authenticate_space_read(
                    &headers("Bearer", &token, None),
                    &Method::GET,
                    &get_uri(path),
                    &state,
                    &space,
                    repo,
                )
                .await
            }
        };

        // Legacy full-access session: always covers.
        assert!(matches!(
            call(access_jwt(&state.jwt_secret, ALICE), own.clone(), None).await.unwrap(),
            SpaceReader::User(u) if u.did == ALICE
        ));
        // A bare `space:<type>` grant defaults to authority=self, action incl. read.
        let bare = scoped_access_jwt(&state.jwt_secret, ALICE, "atproto space:org.example.bucket");
        assert!(call(bare.clone(), own.clone(), None).await.is_ok());
        // ...but does not cover a space of another authority.
        assert_eq!(
            call(bare, space(), None).await.unwrap_err().status_code(),
            403
        );
        // A named-authority grant covers that authority's space.
        let named = scoped_access_jwt(
            &state.jwt_secret,
            ALICE,
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234",
        );
        assert!(call(named, space(), Some(AUTHORITY)).await.is_ok());
        // `read_self` covers only the holder's own repo.
        let read_self = scoped_access_jwt(
            &state.jwt_secret,
            ALICE,
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234&action=read_self",
        );
        assert!(call(read_self.clone(), space(), Some(ALICE)).await.is_ok());
        assert_eq!(
            call(read_self.clone(), space(), Some(AUTHORITY))
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        assert_eq!(
            call(read_self, space(), None)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        // An unrelated grant, and an app password, are refused.
        let repo_only = scoped_access_jwt(&state.jwt_secret, ALICE, "atproto repo:*");
        assert_eq!(
            call(repo_only, own.clone(), None)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        let app_pass = app_pass_jwt(&state.jwt_secret, ALICE, true);
        assert_eq!(
            call(app_pass, own, None).await.unwrap_err().status_code(),
            403
        );
    }

    #[tokio::test]
    async fn issuance_policy_public_member_list_and_fail_closed_modes() {
        let state = state_with_master_key().await;
        let mut row = crate::db::spaces::SpaceRow {
            uri: SPACE.to_string(),
            authority_did: AUTHORITY.to_string(),
            space_type: "org.example.bucket".to_string(),
            skey: "self".to_string(),
            policy: Some("member-list".to_string()),
            app_access: Some("open".to_string()),
            managing_app: None,
            created_at: "now".to_string(),
            deleted_at: None,
        };
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some("member-list"),
                app_access: Some("open"),
                managing_app: None,
            },
        )
        .await
        .unwrap();

        // The authority always may; a non-member may not; a member may.
        assert!(authorize_credential_request(&state.db, &row, AUTHORITY)
            .await
            .is_ok());
        let err = authorize_credential_request(&state.db, &row, ALICE)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::UserNotAuthorized);
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) VALUES (?, ?, 'now')",
        )
        .bind(SPACE)
        .bind(ALICE)
        .execute(&state.db)
        .await
        .unwrap();
        assert!(authorize_credential_request(&state.db, &row, ALICE)
            .await
            .is_ok());

        row.policy = Some("public".to_string());
        assert!(
            authorize_credential_request(&state.db, &row, "did:plc:stranger")
                .await
                .is_ok()
        );

        row.policy = Some("managing-app".to_string());
        assert_eq!(
            authorize_credential_request(&state.db, &row, "did:plc:stranger")
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::UserNotAuthorized
        );
        row.policy = Some("public".to_string());
        row.app_access = Some("allowList".to_string());
        assert_eq!(
            authorize_credential_request(&state.db, &row, AUTHORITY)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::AppNotAuthorized
        );
    }
}
