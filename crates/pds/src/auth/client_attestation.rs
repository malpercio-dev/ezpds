// pattern: Imperative Shell

//! Client attestation verification — how a space authority learns *which application* is asking
//! for a space credential (Atproto Spaces, proposal 0016, "Client attestation").
//!
//! An attestation is structurally the `private_key_jwt` the token endpoint already verifies: a
//! JWT the client signs with its own authentication key, `iss` = `sub` = its `client_id`. It
//! differs in what it is addressed to and how strictly it is spent — `typ`
//! `atproto-client-attestation+jwt`, `aud` the space host it is presented to, and a single-use
//! `jti`, so one minted for one authority cannot be replayed at another (or twice at the same
//! one).
//!
//! Verifying it means resolving `client_id` — a URL the *caller* chose — to its
//! `client-metadata.json` and then to the keys that document publishes. Both fetches go through
//! the SSRF-hardened client, and the attested `client_id` is only as trustworthy as that
//! resolution: skip it and `appAccess: #allowList` degrades from an enforceable perimeter to an
//! unverified claim. The key resolution itself is shared verbatim with the token endpoint
//! ([`crate::auth::jwks::client_verification_key`]).
//!
//! Reached only from `auth::space`'s credential-issuance policy, and only after the request's
//! delegation token has verified — so no unauthenticated caller can drive the outbound fetches.

use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

use common::{ApiError, ApiResultExt, ErrorCode};

use crate::app::AppState;
use crate::db::oauth::ClientMetadata;
use crate::db::space_jti::{insert_jti_if_absent, SpaceJtiScope};

use super::jwt::peek_jwt_typ;

/// JWT `typ` of a client attestation.
pub const CLIENT_ATTESTATION_TYP: &str = "atproto-client-attestation+jwt";

/// Clock skew tolerated on an attestation's `exp`, matching the token endpoint's client-assertion
/// tolerance — the reference's zero-tolerance check is a known interop trap.
const CLOCK_TOLERANCE_SECS: u64 = 30;

/// Longest remaining lifetime accepted on an attestation. The proposal's attestations live
/// ~60 s; this is the generous ceiling, not the expected value.
///
/// A *rejection* bound, not a clamp on the replay row's retention — those are not
/// interchangeable. Clamping retention while still accepting the token would retire the `jti`
/// row while the attestation it belongs to is still verifiable, and the next presentation of
/// that same attestation would insert cleanly and be accepted: single-use in name only. The
/// bound has to fall on what is admitted, exactly as `space::verify_delegation_token` does it.
const MAX_TTL_SECS: u64 = 5 * 60;

#[derive(Deserialize)]
struct AttestationClaims {
    iss: String,
    sub: String,
    exp: u64,
    jti: Option<String>,
}

/// Verify a client attestation addressed to `expected_aud` and return the attested `client_id`.
///
/// `now` is the request's clock reading, used only to bound the `jti` retention window;
/// expiry itself is checked with [`CLOCK_TOLERANCE_SECS`] of leeway.
pub async fn verify_client_attestation(
    state: &AppState,
    attestation: &str,
    expected_aud: &str,
    now: u64,
) -> Result<String, ApiError> {
    let invalid = |msg: String| ApiError::new(ErrorCode::InvalidClientAttestation, msg);

    if peek_jwt_typ(attestation).as_deref() != Some(CLIENT_ATTESTATION_TYP) {
        return Err(invalid(format!(
            "client attestation typ must be {CLIENT_ATTESTATION_TYP}"
        )));
    }
    let header = jsonwebtoken::decode_header(attestation)
        .map_err(|_| invalid("client attestation is not a well-formed JWT".into()))?;
    if header.alg != Algorithm::ES256 {
        return Err(invalid(
            "client attestation must be signed with ES256".into(),
        ));
    }
    // The issuer is read *unverified* here only to know whose keys to fetch; every claim below is
    // re-checked against the signature.
    let client_id = super::jwt::peek_jwt_iss(attestation)
        .filter(|iss| !iss.is_empty())
        .ok_or_else(|| invalid("client attestation has no iss".into()))?;

    // A caller-chosen URL: the resolver applies the client_id URL policy before any I/O and the
    // hardened client controls which address the fetch reaches.
    // ponytail: resolved per mint (a credential lasts 2 h, so this is not a hot path) — add a
    // metadata cache alongside the JWKS cache if attestation volume ever says otherwise.
    let metadata_json = crate::auth::oauth_client_resolution::resolve_client_metadata(
        &state.hardened_http_client,
        &client_id,
    )
    .await
    .map_err(|e| invalid(format!("could not resolve client metadata: {e}")))?;
    let metadata: ClientMetadata = serde_json::from_str(&metadata_json)
        .map_err(|_| invalid("client metadata document is not valid client metadata".into()))?;

    let key = crate::auth::jwks::client_verification_key(
        &state.oauth_client_jwks_cache,
        metadata.jwks.as_ref(),
        metadata.jwks_uri.as_deref(),
        header.kid.as_deref(),
    )
    .await
    .map_err(|e| {
        invalid(format!(
            "no key to verify the attestation of \"{client_id}\": {e}"
        ))
    })?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = CLOCK_TOLERANCE_SECS;
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);
    let claims = jsonwebtoken::decode::<AttestationClaims>(attestation, &key, &validation)
        .map_err(|e| invalid(format!("client attestation rejected: {e}")))?
        .claims;

    if claims.sub != claims.iss {
        return Err(invalid(
            "client attestation iss and sub must both be the client_id".into(),
        ));
    }
    let jti = claims
        .jti
        .as_deref()
        .filter(|jti| !jti.is_empty())
        .ok_or_else(|| invalid("client attestation has no jti".into()))?;
    let remaining = claims.exp.saturating_sub(now);
    if remaining > MAX_TTL_SECS {
        return Err(invalid(
            "client attestation lifetime is too long".to_string(),
        ));
    }
    // Retained past the token's own `exp` by the leeway that admitted it: `decode` accepts an
    // attestation up to `CLOCK_TOLERANCE_SECS` past expiry, so a row retired at `exp` would
    // leave that trailing window replayable. The row must outlive every instant the token is
    // still accepted — the horizon `space_jti_replay` is specified to hold.
    let retain = remaining + CLOCK_TOLERANCE_SECS;

    // Spent only now: the signature decides whether this jti was ever the client's to spend, so
    // burning it earlier would let an unsigned forgery lock out the real attestation.
    let fresh = insert_jti_if_absent(&state.db, SpaceJtiScope::Attestation, jti, retain as i64)
        .await
        .or_internal_as(
            "failed to record client attestation jti",
            "internal server error",
        )?;
    if !fresh {
        return Err(invalid("client attestation has already been used".into()));
    }

    Ok(client_id)
}
