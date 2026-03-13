use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Validate the admin Bearer token from request headers.
///
/// Returns `Ok(())` when the token is present, has the `"Bearer "` prefix, and the
/// final byte comparison passes. The presence check and `"Bearer "` prefix strip are
/// conventional short-circuits that do not expose the token value; only the final byte
/// comparison uses `subtle::ct_eq` to avoid timing side-channels on the token itself.
/// Returns `ApiError::Unauthorized` in all other cases, including when the server has
/// no token configured.
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
                    tracing::warn!(
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

    if !bool::from(provided_token.as_bytes().ct_eq(expected_token.as_bytes())) {
        return Err(ApiError::new(
            ErrorCode::Unauthorized,
            "invalid admin token",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::sync::Arc;

    use crate::app::test_state;

    async fn state_with_token(token: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.admin_token = Some(token.to_string());
        AppState {
            config: Arc::new(config),
            db: base.db,
            http_client: base.http_client,
        }
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn no_token_configured_returns_401() {
        let state = test_state().await; // admin_token = None
        let headers = headers_with_bearer("anything");
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let state = state_with_token("secret").await;
        let err = require_admin_token(&HeaderMap::new(), &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn bare_token_without_bearer_prefix_returns_401() {
        let state = state_with_token("secret").await;
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "secret".parse().unwrap());
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let state = state_with_token("correct").await;
        let err = require_admin_token(&headers_with_bearer("wrong"), &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn correct_token_returns_ok() {
        let state = state_with_token("secret").await;
        assert!(require_admin_token(&headers_with_bearer("secret"), &state).is_ok());
    }

    #[tokio::test]
    async fn non_utf8_authorization_header_returns_401() {
        // Exercises the inspect_err / treat-as-absent path.
        // HeaderValue::from_bytes accepts arbitrary bytes; to_str() will fail on \xff.
        let state = state_with_token("secret").await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        );
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }
}
