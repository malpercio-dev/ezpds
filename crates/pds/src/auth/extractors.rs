// pattern: Imperative Shell

use axum::{extract::FromRequestParts, http::request::Parts};
use common::ApiError;

use crate::app::AppState;

use super::bearer::extract_bearer_token;
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
}

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
                common::ErrorCode::InvalidToken,
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

        // 3. Decode and verify the access token (HS256 or ES256).
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
                    common::ErrorCode::InvalidToken,
                    "access token cnf present without jkt binding",
                ));
            }
            if !has_dpop {
                return Err(ApiError::new(
                    common::ErrorCode::InvalidToken,
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
                token_str,
            )?;
        }

        Ok(AuthenticatedUser {
            did: claims.sub,
            scope,
        })
    }
}
