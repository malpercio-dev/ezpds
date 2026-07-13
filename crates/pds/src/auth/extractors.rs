// pattern: Imperative Shell

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, Method, Uri},
};
use common::ApiError;

use crate::app::AppState;

use common::ErrorCode;

use super::bearer::{extract_access_token, AuthScheme};
use super::dpop::validate_dpop;
use super::jwt::{parse_scope, verify_access_token, AuthScope};

/// Axum extractor that validates a Bearer (or DPoP-bound) JWT and yields the
/// authenticated caller's DID and scope.
///
/// Extract this in any handler that requires authentication:
/// ```rust,ignore
/// async fn my_handler(user: AuthenticatedUser) -> impl IntoResponse { ... }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub did: String,
    pub scope: AuthScope,
    /// Raw `scope` claim. OAuth tokens carry the granular grant here; legacy
    /// session/app-password tokens carry their `com.atproto.*` scope string.
    pub scope_claim: String,
    /// Agent registration id, present only when this token was derived from an auth.md agent
    /// `identity_assertion`. `Some(_)` marks the caller as an agent; ordinary session/OAuth tokens
    /// carry `None`.
    pub registration_id: Option<String>,
}

impl AuthenticatedUser {
    /// Whether this caller is an auth.md agent (its token carries a `registration_id`).
    pub fn is_agent(&self) -> bool {
        self.registration_id.is_some()
    }

    /// Reject an agent-derived caller from a route reserved for the account holder's own full
    /// session. Agent tokens map to [`AuthScope::Access`] for coarse admission, so a route that
    /// gates on `AuthScope::Access` alone (with no granular `require_*` mapping — e.g. app-password
    /// management) would otherwise admit an agent; this closes that gap. Ordinary session/OAuth
    /// callers are unaffected.
    pub fn require_not_agent(&self) -> Result<(), ApiError> {
        if self.is_agent() {
            return Err(ApiError::new(
                ErrorCode::InsufficientScope,
                "this operation is not available to agent-derived credentials",
            ));
        }
        Ok(())
    }
}

/// Authenticate an access-token request end to end and yield the same [`AuthenticatedUser`]
/// the extractor produces.
///
/// This is the single authoritative access-auth path: extract the token under either the
/// `Bearer` or `DPoP` scheme (RFC 9449 §7.1), verify it, enforce the scheme ↔ `cnf.jkt`
/// binding rules in both directions, and — when a DPoP proof is present — validate that proof
/// against the request `method` and `uri` (its `htm`/`htu`).
///
/// The [`AuthenticatedUser`] extractor is a thin wrapper over this function. The repo-write
/// handlers (`createRecord`/`putRecord`/`deleteRecord`/`applyWrites`) authenticate by calling it
/// directly rather than via the extractor — they must resolve the target repo's DID and open it
/// around the auth check — so their scheme/binding enforcement can never drift from the
/// extractor's. In particular, a DPoP-bound token (`cnf.jkt` present) presented as plain `Bearer`
/// with no proof is rejected here, closing the binding-downgrade surface on repo writes.
pub fn authenticate_access(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    state: &AppState,
) -> Result<AuthenticatedUser, ApiError> {
    // 1. Extract the access token from the Authorization header. Both schemes are accepted here
    //    (RFC 9449 §7.1): a DPoP-bound OAuth token arrives as `Authorization: DPoP <token>`, a
    //    plain session/agent token as `Authorization: Bearer <token>`. Scheme ↔ binding
    //    consistency is enforced below, after the token's claims are decoded.
    let (scheme, token_str) = extract_access_token(headers)?;

    // 2. Detect the DPoP header before decoding the access token.
    //    RFC 9449 §11.1: reject if multiple DPoP headers are present — a
    //    header-prepending proxy could inject a forged proof as the first value.
    if headers.get_all("DPoP").iter().count() > 1 {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "multiple DPoP headers are not permitted",
        ));
    }
    let dpop_value = headers
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

    // 3. Decode and verify the access token (HS256 or ES256).
    let claims = verify_access_token(token_str, state)?;

    // 4. Enforce DPoP binding and scheme ↔ binding consistency (RFC 9449 §7.1).
    //    The authorization scheme *declares* the token's binding regime, so a
    //    mismatch in either direction is rejected rather than downgraded:
    //    * `cnf` present but no `jkt` → explicit rejection: a future cnf variant
    //      (e.g. `x5t#S256` for cert binding) could be silently downgraded to plain
    //      Bearer if we only check `jkt.is_some()`.
    //    * `cnf.jkt` present but no DPoP header → downgrade attack; reject.
    //    * `cnf.jkt` present but presented as `Bearer` → a bound token used
    //      without declaring its binding (matches the reference PDS rejection).
    //    * `DPoP` scheme but an unbound token → the client claims
    //      proof-of-possession the token doesn't carry; reject.
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
        if scheme != AuthScheme::Dpop {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "DPoP-bound token must use the DPoP authorization scheme",
            ));
        }
    } else if scheme == AuthScheme::Dpop {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "DPoP authorization scheme requires a DPoP-bound access token",
        ));
    }

    // 5. Resolve scope enum.
    let scope = parse_scope(&claims.scope)?;

    // 6. DPoP proof validation — only when the DPoP header is present.
    if has_dpop {
        let dpop_token = dpop_value.as_deref().unwrap();
        validate_dpop(
            dpop_token,
            method,
            uri,
            &state.config.public_url,
            &claims,
            token_str,
        )?;
    }

    Ok(AuthenticatedUser {
        did: claims.sub,
        scope,
        scope_claim: claims.scope,
        registration_id: claims.registration_id,
    })
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate_access(&parts.headers, &parts.method, &parts.uri, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(registration_id: Option<&str>) -> AuthenticatedUser {
        AuthenticatedUser {
            did: "did:plc:test000000000000000".to_string(),
            scope: AuthScope::Access,
            scope_claim: "atproto repo:*?action=create&action=update".to_string(),
            registration_id: registration_id.map(str::to_string),
        }
    }

    #[test]
    fn require_not_agent_rejects_agent_and_allows_others() {
        // An agent-derived caller (registration_id present) is refused with InsufficientScope (403).
        let err = user(Some("reg_1")).require_not_agent().unwrap_err();
        assert_eq!(err.status_code(), 403);
        // An ordinary session/OAuth caller passes.
        assert!(user(None).require_not_agent().is_ok());
    }

    #[test]
    fn is_agent_reflects_registration_id_presence() {
        assert!(user(Some("reg_1")).is_agent());
        assert!(!user(None).is_agent());
    }
}
