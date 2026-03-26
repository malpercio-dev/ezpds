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
    use crate::routes::token::hash_bearer_token;

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
    let token_hash = hash_bearer_token(token)?;

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

/// Authenticate a device Bearer token for a specific device ID.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes it, and
/// queries `devices WHERE id = ? AND device_token_hash = ?`. The `device_id` scope
/// ensures that a token belonging to device A cannot authenticate requests for device B.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing or malformed
/// - The token is not valid base64url
/// - No device matches both the `device_id` and the token hash
pub async fn require_device_token(
    headers: &HeaderMap,
    device_id: &str,
    db: &sqlx::SqlitePool,
) -> Result<(), ApiError> {
    use crate::routes::token::hash_bearer_token;

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

    let token_hash = hash_bearer_token(token)?;

    let found: Option<(String,)> =
        sqlx::query_as("SELECT id FROM devices WHERE id = ? AND device_token_hash = ?")
            .bind(device_id)
            .bind(&token_hash)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query device token");
                ApiError::new(ErrorCode::InternalError, "device lookup failed")
            })?;

    found
        .map(|_| ())
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "invalid device token"))
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
    use crate::routes::token::hash_bearer_token;

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

    let token_hash = hash_bearer_token(token)?;

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
        tracing::debug!("no unexpired session row found for token hash");
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
            txt_resolver: base.txt_resolver,
            well_known_resolver: base.well_known_resolver,
            jwt_secret: base.jwt_secret,
            oauth_signing_keypair: base.oauth_signing_keypair,
            dpop_nonces: base.dpop_nonces,
            failed_login_attempts: base.failed_login_attempts,
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
        use crate::routes::token::generate_token;
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
        let token = generate_token();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with valid token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let result = require_pending_session(&headers, &state.db)
            .await
            .expect("valid session should succeed");
        assert_eq!(result.account_id, account_id);
        assert_eq!(result.device_id, device_id);
    }

    #[tokio::test]
    async fn pending_session_expired_session_returns_401() {
        use crate::routes::token::generate_token;
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
        let token = generate_token();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '-1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with expired token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
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

    // ── require_session tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn session_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let err = require_session(&HeaderMap::new(), &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn session_non_base64url_token_returns_401() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer not-valid-base64url!!!".parse().unwrap(),
        );
        let state = test_state().await;
        let err = require_session(&headers, &state.db).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn session_valid_unexpired_session_returns_ok() {
        use crate::routes::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Insert an account (required by sessions FK constraint).
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("test{}@example.com", &did[8..16]))
        .execute(&state.db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert session");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let result = require_session(&headers, &state.db)
            .await
            .expect("valid session should succeed");
        assert_eq!(result.did, did);
    }

    #[tokio::test]
    async fn session_expired_session_returns_401() {
        use crate::routes::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Insert an account (required by sessions FK constraint).
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("test{}@example.com", &did[8..16]))
        .execute(&state.db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '-1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert expired session");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let err = require_session(&headers, &state.db).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // ── require_device_token tests ────────────────────────────────────────────

    /// Seed a device row and return (device_id, plaintext_token).
    async fn seed_device(db: &sqlx::SqlitePool) -> (String, String) {
        use crate::routes::token::generate_token;
        use uuid::Uuid;

        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(db)
        .await
        .unwrap();

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
        .execute(db)
        .await
        .unwrap();

        let device_id = Uuid::new_v4().to_string();
        let token = generate_token();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', ?, datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .bind(&token.hash)
        .execute(db)
        .await
        .unwrap();

        (device_id, token.plaintext)
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn device_token_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        let err = require_device_token(&HeaderMap::new(), &device_id, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_wrong_token_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        // Generate a fresh token that was never stored in DB
        let wrong_token = crate::routes::token::generate_token().plaintext;
        let err = require_device_token(&bearer(&wrong_token), &device_id, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_valid_token_wrong_device_id_returns_401() {
        let state = test_state().await;
        let (_, token) = seed_device(&state.db).await;
        let err = require_device_token(&bearer(&token), "non-existent-device-id", &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_valid_token_and_device_id_returns_ok() {
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;
        require_device_token(&bearer(&token), &device_id, &state.db)
            .await
            .expect("valid device token must succeed");
    }
}
