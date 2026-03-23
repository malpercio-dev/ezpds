// pattern: Imperative Shell
//
// Gathers: JSON body {identifier, password}, DB pool, jwt_secret, config, rate-limit state
// Processes: rate limit gate → identifier resolution → password verification →
//            JWT issuance → session + refresh_token DB insert
// Returns: JSON {accessJwt, refreshJwt, handle, did, email} on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.createSession

use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH, Duration};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{extract::State, http::StatusCode, response::Json};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

const ACCESS_TOKEN_TTL_SECS: u64 = 2 * 60 * 60;        // 2 hours
const REFRESH_TOKEN_TTL_SECS: u64 = 90 * 24 * 60 * 60; // 90 days
pub(crate) const RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(crate) const RATE_LIMIT_MAX_FAILURES: usize = 5;

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    identifier: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
    handle: String,
    did: String,
    email: String,
}

// ── JWT claim structs ────────────────────────────────────────────────────────

/// Claims for a legacy HS256 access token (scope: com.atproto.access).
#[derive(Serialize)]
struct LegacyAccessClaims {
    scope: &'static str,
    sub: String,
    /// Audience — server_did when configured, public_url otherwise.
    aud: String,
    iat: u64,
    exp: u64,
}

/// Claims for a legacy HS256 refresh token (scope: com.atproto.refresh).
#[derive(Serialize)]
struct LegacyRefreshClaims {
    scope: &'static str,
    sub: String,
    aud: String,
    /// Unique token ID stored in `refresh_tokens.jti` for refresh-token rotation.
    jti: String,
    iat: u64,
    exp: u64,
}

// ── Internal account record ──────────────────────────────────────────────────

struct AccountRow {
    did: String,
    email: String,
    /// Argon2id PHC string. `None` for mobile accounts (password auth not allowed).
    password_hash: Option<String>,
    /// One associated handle (if any). Empty string returned in the response when absent.
    handle: Option<String>,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// POST /xrpc/com.atproto.server.createSession
///
/// Password-based authentication (ATProto legacy session flow).
/// Issues a short-lived HS256 access JWT and a 90-day refresh JWT.
pub async fn create_session(
    State(state): State<AppState>,
    Json(payload): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), ApiError> {
    // --- Rate limit gate ---
    // Check before any DB work to shed load on targeted accounts.
    {
        let mut attempts = state
            .failed_login_attempts
            .lock()
            .map_err(|_| {
                tracing::error!("failed_login_attempts mutex is poisoned");
                ApiError::new(ErrorCode::InternalError, "internal error")
            })?;
        if is_rate_limited(&mut attempts, &payload.identifier) {
            return Err(ApiError::new(
                ErrorCode::RateLimited,
                "too many failed login attempts, please try again later",
            ));
        }
    }

    // --- Resolve identifier and verify password ---
    // Both "account not found" and "wrong password" surface as the same error to prevent
    // user enumeration via distinguishable error messages.
    let account_opt = resolve_identifier(&state.db, &payload.identifier).await?;

    let account = match account_opt {
        Some(row) => {
            let auth_ok = row
                .password_hash
                .as_deref()
                .map(|h| !h.is_empty() && verify_password(h, &payload.password))
                .unwrap_or(false); // mobile accounts (NULL password_hash) cannot use createSession
            if !auth_ok {
                let mut attempts = state
                    .failed_login_attempts
                    .lock()
                    .map_err(|_| {
                        tracing::error!("failed_login_attempts mutex is poisoned");
                        ApiError::new(ErrorCode::InternalError, "internal error")
                    })?;
                record_failure(&mut attempts, &payload.identifier);
                return Err(ApiError::new(
                    ErrorCode::AuthenticationRequired,
                    "invalid identifier or password",
                ));
            }
            row
        }
        None => {
            let mut attempts = state
                .failed_login_attempts
                .lock()
                .map_err(|_| {
                    tracing::error!("failed_login_attempts mutex is poisoned");
                    ApiError::new(ErrorCode::InternalError, "internal error")
                })?;
            record_failure(&mut attempts, &payload.identifier);
            return Err(ApiError::new(
                ErrorCode::AuthenticationRequired,
                "invalid identifier or password",
            ));
        }
    };

    // --- Issue legacy HS256 JWTs ---
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            tracing::error!(error = %e, "system clock is before Unix epoch");
            ApiError::new(ErrorCode::InternalError, "failed to issue token")
        })?
        .as_secs();

    // Prefer server_did as audience (what verify_hs256_access_token validates against
    // when configured); fall back to public_url.
    let aud = state
        .config
        .server_did
        .as_deref()
        .unwrap_or(&state.config.public_url)
        .to_string();

    let access_jwt = issue_access_jwt(&state.jwt_secret, &account.did, &aud, now)?;

    let refresh_jti = Uuid::new_v4().to_string();
    let refresh_jwt =
        issue_refresh_jwt(&state.jwt_secret, &account.did, &aud, &refresh_jti, now)?;

    // --- Persist session and refresh token atomically ---
    let session_id = Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, NULL, datetime('now'), datetime('now', '+90 days'))",
    )
    .bind(&session_id)
    .bind(&account.did)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert session");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    sqlx::query(
        "INSERT INTO refresh_tokens (jti, did, session_id, expires_at, created_at) \
         VALUES (?, ?, ?, datetime('now', '+90 days'), datetime('now'))",
    )
    .bind(&refresh_jti)
    .bind(&account.did)
    .bind(&session_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert refresh token");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit session transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    // Clear failure history only after the session is fully committed.
    // Doing this earlier would reset the counter even if JWT issuance or the
    // DB transaction subsequently fails.
    {
        let mut attempts = state
            .failed_login_attempts
            .lock()
            .map_err(|_| {
                tracing::error!("failed_login_attempts mutex is poisoned");
                ApiError::new(ErrorCode::InternalError, "internal error")
            })?;
        clear_failures(&mut attempts, &payload.identifier);
    }

    Ok((
        StatusCode::OK,
        Json(CreateSessionResponse {
            access_jwt,
            refresh_jwt,
            handle: account.handle.unwrap_or_default(),
            did: account.did,
            email: account.email,
        }),
    ))
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Resolve a handle or DID to an active (non-deactivated) account.
///
/// Returns `None` when not found; `Err` only on DB errors.
async fn resolve_identifier(
    db: &sqlx::SqlitePool,
    identifier: &str,
) -> Result<Option<AccountRow>, ApiError> {
    if identifier.starts_with("did:") {
        let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT a.email, a.password_hash, h.handle \
             FROM accounts a \
             LEFT JOIN handles h ON h.did = a.did \
             WHERE a.did = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DB error resolving DID");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(email, password_hash, handle)| AccountRow {
            did: identifier.to_string(),
            email,
            password_hash,
            handle,
        }))
    } else {
        let row: Option<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT a.did, a.email, a.password_hash, h.handle \
             FROM handles h \
             JOIN accounts a ON a.did = h.did \
             WHERE h.handle = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DB error resolving handle");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(did, email, password_hash, handle)| AccountRow {
            did,
            email,
            password_hash,
            handle: Some(handle),
        }))
    }
}

/// Verify `password` against a stored argon2id PHC-format hash string.
fn verify_password(stored_hash: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(stored_hash) else {
        tracing::error!("stored password_hash is not a valid PHC string; possible DB corruption");
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

/// Sign an HS256 access JWT with a 2-hour lifetime.
fn issue_access_jwt(
    secret: &[u8; 32],
    did: &str,
    aud: &str,
    now: u64,
) -> Result<String, ApiError> {
    encode(
        &Header::new(Algorithm::HS256),
        &LegacyAccessClaims {
            scope: "com.atproto.access",
            sub: did.to_string(),
            aud: aud.to_string(),
            iat: now,
            exp: now + ACCESS_TOKEN_TTL_SECS,
        },
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to sign access JWT");
        ApiError::new(ErrorCode::InternalError, "failed to issue token")
    })
}

/// Sign an HS256 refresh JWT with a 90-day lifetime.
fn issue_refresh_jwt(
    secret: &[u8; 32],
    did: &str,
    aud: &str,
    jti: &str,
    now: u64,
) -> Result<String, ApiError> {
    encode(
        &Header::new(Algorithm::HS256),
        &LegacyRefreshClaims {
            scope: "com.atproto.refresh",
            sub: did.to_string(),
            aud: aud.to_string(),
            jti: jti.to_string(),
            iat: now,
            exp: now + REFRESH_TOKEN_TTL_SECS,
        },
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to sign refresh JWT");
        ApiError::new(ErrorCode::InternalError, "failed to issue token")
    })
}

// ── Rate limiting ────────────────────────────────────────────────────────────

/// Returns `true` if `identifier` has had ≥ `RATE_LIMIT_MAX_FAILURES` failed login
/// attempts within the last `RATE_LIMIT_WINDOW_SECS` seconds (sliding window).
///
/// Prunes expired entries from the front of the deque during the check, keeping
/// memory bounded without a separate background task.
fn is_rate_limited(
    attempts: &mut HashMap<String, VecDeque<Instant>>,
    identifier: &str,
) -> bool {
    let deque = attempts.get_mut(identifier);
    if let Some(deque) = deque {
        let now = Instant::now();
        while let Some(&oldest) = deque.front() {
            if now - oldest > Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
                deque.pop_front();
            } else {
                break;
            }
        }
        return deque.len() >= RATE_LIMIT_MAX_FAILURES;
    }
    false
}

/// Record a new failed attempt timestamp for `identifier`.
fn record_failure(attempts: &mut HashMap<String, VecDeque<Instant>>, identifier: &str) {
    attempts
        .entry(identifier.to_string())
        .or_default()
        .push_back(Instant::now());
}

/// Clear the failure history for `identifier` on successful authentication.
fn clear_failures(attempts: &mut HashMap<String, VecDeque<Instant>>, identifier: &str) {
    attempts.remove(identifier);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn post_create_session(identifier: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{identifier}","password":"{password}"}}"#
            )))
            .unwrap()
    }

    async fn insert_account_with_password(
        db: &sqlx::SqlitePool,
        did: &str,
        handle: &str,
        email: &str,
        password: &str,
    ) {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
        .bind(&hash)
        .execute(db)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))",
        )
        .bind(handle)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_did_returns_200_with_jwts() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "hunter2",
        )
        .await;

        let response = app(state)
            .oneshot(post_create_session("did:plc:alice", "hunter2"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["accessJwt"].as_str().is_some(), "accessJwt required");
        assert!(json["refreshJwt"].as_str().is_some(), "refreshJwt required");
        assert_eq!(json["did"], "did:plc:alice");
        assert_eq!(json["email"], "alice@example.com");
    }

    #[tokio::test]
    async fn valid_handle_returns_handle_in_response() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:bob",
            "bob.test.example.com",
            "bob@example.com",
            "p@ssw0rd",
        )
        .await;

        let response = app(state)
            .oneshot(post_create_session("bob.test.example.com", "p@ssw0rd"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["handle"], "bob.test.example.com");
        assert_eq!(json["did"], "did:plc:bob");
    }

    #[tokio::test]
    async fn session_and_refresh_token_persisted_in_db() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:persist",
            "persist.test.example.com",
            "persist@example.com",
            "testpass",
        )
        .await;

        let db = state.db.clone();
        let response = app(state)
            .oneshot(post_create_session("did:plc:persist", "testpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = 'did:plc:persist'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(session_count, 1, "one session row expected");

        let refresh_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE did = 'did:plc:persist'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(refresh_count, 1, "one refresh token row expected");
    }

    #[tokio::test]
    async fn access_jwt_has_correct_scope() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:jwtcheck",
            "jwt.test.example.com",
            "jwt@example.com",
            "jwtpass",
        )
        .await;

        let secret = state.jwt_secret;
        let response = app(state)
            .oneshot(post_create_session("did:plc:jwtcheck", "jwtpass"))
            .await
            .unwrap();

        let json = body_json(response).await;
        let access_jwt = json["accessJwt"].as_str().unwrap();

        // Decode without audience validation (test state has no server_did).
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "sub"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            access_jwt,
            &jsonwebtoken::DecodingKey::from_secret(&secret),
            &validation,
        )
        .expect("access JWT must be valid");

        assert_eq!(data.claims["scope"], "com.atproto.access");
        assert_eq!(data.claims["sub"], "did:plc:jwtcheck");
    }

    #[tokio::test]
    async fn refresh_jwt_has_jti_stored_in_db() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:jticheck",
            "jti.test.example.com",
            "jti@example.com",
            "jtipass",
        )
        .await;

        let secret = state.jwt_secret;
        let db = state.db.clone();
        let response = app(state)
            .oneshot(post_create_session("did:plc:jticheck", "jtipass"))
            .await
            .unwrap();

        let json = body_json(response).await;
        let refresh_jwt = json["refreshJwt"].as_str().unwrap();

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "sub"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            refresh_jwt,
            &jsonwebtoken::DecodingKey::from_secret(&secret),
            &validation,
        )
        .expect("refresh JWT must be valid");

        assert_eq!(data.claims["scope"], "com.atproto.refresh");
        let jti = data.claims["jti"].as_str().expect("jti must be present");

        let stored: Option<String> =
            sqlx::query_scalar("SELECT jti FROM refresh_tokens WHERE jti = ?")
                .bind(jti)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(stored.is_some(), "refresh jti must be persisted in DB");
    }

    // ── Auth failure ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn wrong_password_returns_401() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:charlie",
            "charlie.test.example.com",
            "charlie@example.com",
            "correcthorsebatterystaple",
        )
        .await;

        let response = app(state)
            .oneshot(post_create_session("did:plc:charlie", "wrongpassword"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn unknown_identifier_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_create_session("did:plc:nobody", "password"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn mobile_account_without_password_returns_401() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:mobile', 'mobile@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_session("did:plc:mobile", "anypassword"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rate_limit_triggers_after_five_failures() {
        let state = test_state().await;

        // Five wrong-password attempts against a non-existent account.
        // Each should return 401, and each records a failure in the shared store.
        for i in 0..RATE_LIMIT_MAX_FAILURES {
            let response = app(state.clone())
                .oneshot(post_create_session("did:plc:ratelimited", "wrongpassword"))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {i} should be 401"
            );
        }

        // The sixth attempt should now be rate-limited.
        let response = app(state)
            .oneshot(post_create_session("did:plc:ratelimited", "wrongpassword"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn deactivated_account_returns_401() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:deactivated",
            "deact.test.example.com",
            "deact@example.com",
            "password",
        )
        .await;

        sqlx::query(
            "UPDATE accounts SET deactivated_at = datetime('now') WHERE did = 'did:plc:deactivated'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_session("did:plc:deactivated", "password"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_identifier_return_identical_errors() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:enumtest",
            "enumtest.test.example.com",
            "enumtest@example.com",
            "correctpassword",
        )
        .await;

        let wrong_pw = app(state.clone())
            .oneshot(post_create_session("did:plc:enumtest", "wrongpassword"))
            .await
            .unwrap();
        let unknown = app(state)
            .oneshot(post_create_session("did:plc:nobody", "anything"))
            .await
            .unwrap();

        assert_eq!(wrong_pw.status(), unknown.status());
        let wrong_pw_json = body_json(wrong_pw).await;
        let unknown_json = body_json(unknown).await;
        assert_eq!(wrong_pw_json["error"]["code"], unknown_json["error"]["code"]);
        assert_eq!(
            wrong_pw_json["error"]["message"],
            unknown_json["error"]["message"]
        );
    }

    #[tokio::test]
    async fn successful_login_clears_rate_limit_counter() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:cleartest",
            "cleartest.test.example.com",
            "cleartest@example.com",
            "correctpassword",
        )
        .await;

        // N-1 failed attempts (one below the threshold)
        for _ in 0..(RATE_LIMIT_MAX_FAILURES - 1) {
            app(state.clone())
                .oneshot(post_create_session("did:plc:cleartest", "wrongpassword"))
                .await
                .unwrap();
        }

        // Successful login clears the counter
        let ok = app(state.clone())
            .oneshot(post_create_session("did:plc:cleartest", "correctpassword"))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // One more failure should be 401, not 429 — counter was reset
        let after = app(state)
            .oneshot(post_create_session("did:plc:cleartest", "wrongpassword"))
            .await
            .unwrap();
        assert_eq!(
            after.status(),
            StatusCode::UNAUTHORIZED,
            "counter must have been cleared by the successful login"
        );
    }
}
