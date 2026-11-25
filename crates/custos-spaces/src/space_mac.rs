// pattern: Imperative Shell

//! MACs on space reads: the repo-host side of the Spaces KEM/MAC exchange, over RFC 9421 HTTP
//! message signatures.
//!
//! A syncer asks for a MAC with `Accept-Signature`, naming a fresh ephemeral P-256 key of its
//! own as `keyid`. This host agrees a secret from that key and the account's `#atproto_kem` key
//! (`crypto::space_mac_secret`) and answers with the covered header (`Atproto-Space-Commit` on
//! `getRepo`, `listRepoOps` and `getLatestCommit`; `Atproto-Space-Record` on `getRecord`) plus a
//! `Signature-Input` / `Signature` pair over it. Only the syncer and this host can compute the
//! MAC, so a leaked response proves nothing to anyone else.
//!
//! Following the reference's `getSpaceMacRequest`:
//!
//! * A malformed request, or one whose key share is not a usable P-256 key, is `InvalidSpaceMac`.
//! * A space-credential read must ask for a MAC (`InvalidSpaceMac` otherwise); an account reading
//!   its own repo may, and is otherwise served without one.
//! * Every response of the four reads varies on `Accept-Signature` ([`vary_accept_signature`]).
//!   The reference also lists the MAC headers in `Access-Control-Expose-Headers`; here the
//!   public surface's permissive CORS layer already answers `*` there, overwriting any list.
//!
//! One Custos rule on top: an account whose DID document does not publish its active KEM key is
//! served without the MAC headers, since no syncer could verify them (ADR-0043). Its writes are
//! refused until then (`kem_gate`).

use axum::http::{header, HeaderMap, HeaderName, HeaderValue};
use axum::response::Response;
use common::{ApiError, ErrorCode};
use crypto::http_signature::{MacHeaders, MacProfile, MacRequest};
use custos_core::CoreState;

use crate::auth::space::SpaceReader;

/// The `Accept-Signature` request header (RFC 9421 §5.1).
pub const ACCEPT_SIGNATURE: &str = "accept-signature";

/// A MAC request this read answers: what the syncer asked for, and the secret to answer it with.
pub struct MacGrant {
    request: MacRequest,
    secret: zeroize::Zeroizing<[u8; 32]>,
}

/// Read and check the MAC request on a read of `repo`'s data under `profile`. `None` when no
/// MAC is to be attached: an account's own read that asked for none, or an account whose KEM
/// key is not published.
pub async fn mac_grant(
    state: &CoreState,
    headers: &HeaderMap,
    reader: &SpaceReader,
    repo: &common::Did,
    profile: MacProfile,
) -> Result<Option<MacGrant>, ApiError> {
    let value = headers
        .get(ACCEPT_SIGNATURE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| invalid_mac("malformed Accept-Signature header"))?;
    let request = crypto::http_signature::parse_mac_request(value, profile).map_err(crypto_err)?;
    let Some(request) = request else {
        if matches!(reader, SpaceReader::Credential(_)) {
            return Err(invalid_mac(format!(
                "a MAC must be requested with tag \"{}\"",
                profile.tag()
            )));
        }
        return Ok(None);
    };

    let enc = crypto::p256_public_key_from_did_key(&request.key_share)
        .map_err(|_| invalid_mac("MAC keyid is not a P-256 did:key"))?;
    let Some(kem_key) = crate::kem_gate::published_kem_private_key(state, repo).await? else {
        tracing::debug!(did = %repo, "space read served without a MAC: KEM key not published");
        return Ok(None);
    };
    let secret = crypto::space_mac_secret(&enc, &kem_key)
        .map_err(|_| invalid_mac("MAC keyid is not a usable key share"))?;
    Ok(Some(MacGrant {
        request,
        secret: zeroize::Zeroizing::new(secret),
    }))
}

/// Attach the MAC over `commit` to `response`, if one was granted.
pub fn with_commit_mac(
    response: Response,
    commit: &crate::views::SpaceCommit,
    grant: Option<&MacGrant>,
) -> Result<Response, ApiError> {
    attach(response, grant, |g| {
        crypto::http_signature::commit_mac_headers(&commit.mac_fields(), &g.request, &g.secret)
    })
}

/// Attach the MAC over the record at `uri` with `cid` to `response`, if one was granted.
pub fn with_record_mac(
    response: Response,
    uri: &str,
    cid: &str,
    grant: Option<&MacGrant>,
) -> Result<Response, ApiError> {
    attach(response, grant, |g| {
        crypto::http_signature::record_mac_headers(uri, cid, &g.request, &g.secret)
    })
}

fn attach(
    mut response: Response,
    grant: Option<&MacGrant>,
    mac: impl FnOnce(&MacGrant) -> Result<MacHeaders, crypto::CryptoError>,
) -> Result<Response, ApiError> {
    let Some(grant) = grant else {
        return Ok(response);
    };
    let mac = mac(grant).map_err(|e| ApiError::internal(e, "failed to compute space MAC"))?;
    let value = |v: &str| {
        HeaderValue::from_str(v).map_err(|e| ApiError::internal(e, "space MAC header is invalid"))
    };
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static(mac.covered_name),
        value(&mac.covered)?,
    );
    headers.insert("signature-input", value(&mac.signature_input)?);
    headers.insert("signature", value(&mac.signature)?);
    Ok(response)
}

/// Response middleware for the four MAC'd reads: what they answer depends on
/// `Accept-Signature`, so a cache must key on it.
pub async fn vary_accept_signature(mut response: Response) -> Response {
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Accept-Signature"));
    response
}

fn invalid_mac(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::InvalidSpaceMac, message)
}

fn crypto_err(e: crypto::CryptoError) -> ApiError {
    match e {
        crypto::CryptoError::Space(message) => invalid_mac(message),
        other => invalid_mac(other.to_string()),
    }
}
