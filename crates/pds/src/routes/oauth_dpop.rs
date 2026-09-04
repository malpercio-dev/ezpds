// pattern: Imperative Shell

//! Shared token-endpoint DPoP preamble for `oauth_token/`'s grant handlers and
//! `oauth_revoke.rs` (routes may not import one another): reject multiple `DPoP` headers
//! (RFC 9449 §11.1), extract the single proof, and run it through
//! `validate_dpop_for_token_endpoint` against the caller's own URL — so a proof minted for one
//! endpoint can't be replayed against the other.

use axum::http::HeaderMap;

use crate::app::AppState;
use crate::auth::{validate_dpop_for_token_endpoint, DpopTokenEndpointError};

use super::oauth_errors::OAuthTokenError;

/// Validate the DPoP proof on a token-endpoint-shaped request. `url` is the caller's own
/// endpoint (`/oauth/token` or `/oauth/revoke`), bound into the proof's `htu` check. Returns the
/// proof key's JWK thumbprint (`jkt`) on success.
pub(super) fn token_endpoint_dpop(
    state: &AppState,
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
        None => {
            return Err(OAuthTokenError::new(
                "invalid_dpop_proof",
                "DPoP header required",
            ));
        }
    };

    match validate_dpop_for_token_endpoint(&dpop_token, "POST", url, &state.dpop_nonces) {
        Ok(jkt) => Ok(jkt),
        Err(DpopTokenEndpointError::MissingHeader) => Err(OAuthTokenError::new(
            "invalid_dpop_proof",
            "DPoP header required",
        )),
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
