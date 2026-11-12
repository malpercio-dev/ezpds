// pattern: Imperative Shell

//! Shared token-endpoint DPoP preamble for `oauth_token/`'s grant handlers and
//! `oauth_revoke.rs` (routes may not import one another): reject multiple `DPoP` headers
//! (RFC 9449 §11.1), extract the single proof, and run it through
//! `validate_dpop_for_token_endpoint` against the caller's own URL — so a proof minted for one
//! endpoint can't be replayed against the other.

use axum::http::HeaderMap;

use custos_core::auth::{validate_dpop_for_token_endpoint, DpopTokenEndpointError};
use custos_core::CoreState;

use super::oauth_errors::OAuthTokenError;

/// Validate the DPoP proof on a token-endpoint-shaped request. `url` is the caller's own
/// endpoint (`/oauth/token` or `/oauth/revoke`), bound into the proof's `htu` check. Returns the
/// proof key's JWK thumbprint (`jkt`) on success.
/// [`token_endpoint_dpop`] for the two grants a connector may use without a proof (ADR-0042).
/// `Ok(None)` means no proof was sent and one may turn out not to be needed: the caller decides
/// once it has loaded the grant, and answers [`dpop_required`] if the grant is not a connector's.
/// With no connector resource configured a missing proof is refused here, as it always was.
pub(super) fn optional_token_endpoint_dpop(
    state: &CoreState,
    headers: &HeaderMap,
    url: &str,
) -> Result<Option<String>, OAuthTokenError> {
    if !headers.contains_key("DPoP") && !state.config.oauth.connector_resources.is_empty() {
        return Ok(None);
    }
    token_endpoint_dpop(state, headers, url).map(Some)
}

/// The refusal for a token request that needed a DPoP proof and carried none.
pub(super) fn dpop_required() -> OAuthTokenError {
    OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
}

pub(super) fn token_endpoint_dpop(
    state: &CoreState,
    headers: &HeaderMap,
    url: &str,
) -> Result<String, OAuthTokenError> {
    // Reject multiple DPoP headers (RFC 9449 §11.1).
    if headers.get_all("DPoP").iter().count() > 1 {
        return Err(OAuthTokenError::new(
            "invalid_dpop_proof",
            "multiple DPoP headers are not permitted",
        ));
    }

    let dpop_token = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => return Err(dpop_required()),
    };

    match validate_dpop_for_token_endpoint(&dpop_token, "POST", url, &state.dpop_nonces) {
        Ok(jkt) => Ok(jkt),
        Err(DpopTokenEndpointError::MissingHeader) => Err(dpop_required()),
        Err(DpopTokenEndpointError::InvalidProof(msg)) => {
            Err(OAuthTokenError::new("invalid_dpop_proof", msg))
        }
        Err(DpopTokenEndpointError::UseNonce(fresh_nonce)) => Err(OAuthTokenError::with_nonce(
            "use_dpop_nonce",
            "DPoP nonce required",
            fresh_nonce,
        )),
    }
}
