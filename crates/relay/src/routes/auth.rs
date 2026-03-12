use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Validate the admin Bearer token from request headers.
///
/// Returns `Ok(())` when the token is present, has the `"Bearer "` prefix, and matches
/// `Config.admin_token` in constant time. Returns `ApiError::Unauthorized` in all other
/// cases, including when the server has no token configured.
///
/// Call this at the top of any handler that requires admin access.
pub fn require_admin_token(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let expected_token = state
        .config
        .admin_token
        .as_deref()
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "admin token not configured"))?;

    let auth_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::debug!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .unwrap_or("");

    let provided_token = auth_value.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            ErrorCode::Unauthorized,
            "missing or invalid Authorization header",
        )
    })?;

    if provided_token
        .as_bytes()
        .ct_eq(expected_token.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(ApiError::new(ErrorCode::Unauthorized, "invalid admin token"));
    }

    Ok(())
}
