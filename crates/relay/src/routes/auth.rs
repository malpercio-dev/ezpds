use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Information about an authenticated pending session.
pub struct PendingSessionInfo {
    pub account_id: String,
    #[allow(dead_code)]
    pub device_id: String,
}

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

/// Authenticate a `pending_session` Bearer token.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes the raw
/// decoded bytes (matching the storage format from `POST /v1/accounts/mobile`), and
/// queries `pending_sessions` for a matching, unexpired row.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing
/// - The token is not valid base64url
/// - No unexpired session matches the token hash
pub async fn require_pending_session(
    headers: &HeaderMap,
    db: &sqlx::SqlitePool,
) -> Result<PendingSessionInfo, ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    // Extract Bearer token from Authorization header.
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    // Decode base64url → raw bytes, then SHA-256 hash → hex string.
    // Matches the storage format written by POST /v1/accounts/mobile.
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ApiError::new(ErrorCode::Unauthorized, "invalid session token"))?;
    let token_hash: String = Sha256::digest(&token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Look up the session by hash, rejecting expired sessions.
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT account_id, device_id FROM pending_sessions \
         WHERE token_hash = ? AND expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pending session");
        ApiError::new(ErrorCode::InternalError, "session lookup failed")
    })?;

    let (account_id, device_id) = row.ok_or_else(|| {
        ApiError::new(ErrorCode::Unauthorized, "invalid or expired session token")
    })?;

    Ok(PendingSessionInfo {
        account_id,
        device_id,
    })
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
