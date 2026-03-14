use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Information about an authenticated pending session.
#[derive(Debug)]
pub struct PendingSessionInfo {
    pub account_id: String,
    #[allow(dead_code)]
    pub device_id: String,
}

/// Information about an authenticated promoted-account session.
#[derive(Debug)]
pub struct SessionInfo {
    pub did: String,
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
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
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

/// Authenticate a promoted-account Bearer token.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes the raw
/// decoded bytes (matching the storage format written by `POST /v1/dids`), and
/// queries `sessions` for a matching, unexpired row.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing
/// - The token is not valid base64url
/// - No unexpired session matches the token hash
pub async fn require_session(
    headers: &HeaderMap,
    db: &sqlx::SqlitePool,
) -> Result<SessionInfo, ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let token = headers
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
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    let token_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ApiError::new(ErrorCode::Unauthorized, "invalid session token"))?;
    let token_hash: String = Sha256::digest(&token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT did FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query session");
        ApiError::new(ErrorCode::InternalError, "session lookup failed")
    })?;

    let (did,) = row.ok_or_else(|| {
        ApiError::new(ErrorCode::Unauthorized, "invalid or expired session token")
    })?;

    Ok(SessionInfo { did })
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
            dns_provider: base.dns_provider,
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

    // ── require_pending_session tests ────────────────────────────────────────

    #[tokio::test]
    async fn pending_session_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let err = require_pending_session(&HeaderMap::new(), &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_non_base64url_token_returns_401() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer not-valid-base64url!!!".parse().unwrap(),
        );
        let state = test_state().await;
        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_valid_unexpired_session_returns_ok() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use rand_core::{OsRng, RngCore};
        use sha2::{Digest, Sha256};
        use uuid::Uuid;

        let state = test_state().await;

        // Set up a claim code, pending account, device, and pending session.
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert claim_code");

        let account_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("test{}@example.com", &account_id[..8]))
        .bind(format!("test{}.example.com", &account_id[..8]))
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert pending_account");

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(&state.db)
        .await
        .expect("insert device");

        // Generate a valid session token.
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let session_token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash: String = Sha256::digest(token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token_hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with valid token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {session_token}").parse().unwrap(),
        );

        let result = require_pending_session(&headers, &state.db)
            .await
            .expect("valid session should succeed");
        assert_eq!(result.account_id, account_id);
        assert_eq!(result.device_id, device_id);
    }

    #[tokio::test]
    async fn pending_session_expired_session_returns_401() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use rand_core::{OsRng, RngCore};
        use sha2::{Digest, Sha256};
        use uuid::Uuid;

        let state = test_state().await;

        // Set up claim code, pending account, device, and expired pending session.
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert claim_code");

        let account_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("test{}@example.com", &account_id[..8]))
        .bind(format!("test{}.example.com", &account_id[..8]))
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert pending_account");

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(&state.db)
        .await
        .expect("insert device");

        // Generate a token but set it as expired.
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let session_token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash: String = Sha256::digest(token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '-1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token_hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with expired token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {session_token}").parse().unwrap(),
        );

        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_non_utf8_authorization_header_returns_401() {
        // Exercises the inspect_err / treat-as-absent path.
        // HeaderValue::from_bytes accepts arbitrary bytes; to_str() will fail on \xff.
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        );
        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }
}
