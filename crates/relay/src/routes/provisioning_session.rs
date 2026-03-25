// pattern: Imperative Shell
//
// Gathers: JSON body {email, password}, DB pool, rate-limit state
// Processes: rate limit gate → email resolution → password verification →
//            session token generation → sessions DB insert
// Returns: JSON {session_token, did} on success; ApiError on failure
//
// Implements: POST /v1/accounts/sessions

use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::password::{verify_password, VerifyResult};
use crate::auth::rate_limit::{clear_failures, is_rate_limited, record_failure};
use crate::db::accounts::resolve_by_email;
use crate::routes::token::generate_token;

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProvisioningSessionRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProvisioningSessionResponse {
    session_token: String,
    did: String,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// POST /v1/accounts/sessions
///
/// Email + password login for the provisioning API. Issues a 1-year opaque bearer
/// token stored in the `sessions` table. Used when the session token has expired or
/// been lost (e.g., app reinstall). The returned `session_token` works with
/// `require_session`-protected provisioning endpoints.
pub async fn create_provisioning_session(
    State(state): State<AppState>,
    Json(payload): Json<CreateProvisioningSessionRequest>,
) -> Result<(StatusCode, Json<CreateProvisioningSessionResponse>), ApiError> {
    // --- Rate limit gate ---
    // Check before any DB work to shed load on targeted accounts.
    {
        let mut attempts = state.failed_login_attempts.lock().map_err(|_| {
            tracing::error!("failed_login_attempts mutex is poisoned");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;
        if is_rate_limited(&mut attempts, &payload.email) {
            return Err(ApiError::new(
                ErrorCode::RateLimited,
                "too many failed login attempts, please try again later",
            ));
        }
    }

    // --- Resolve email and verify password ---
    // Both "account not found" and "wrong password" surface as the same error to prevent
    // user enumeration via distinguishable error messages.
    let account_opt = resolve_by_email(&state.db, &payload.email).await?;

    let account = match account_opt {
        Some(row) => {
            let result = match row.password_hash.as_deref() {
                // Accounts without a password_hash cannot use provisioning session login.
                None | Some("") => VerifyResult::WrongPassword,
                Some(h) => verify_password(h, &payload.password),
            };
            match result {
                VerifyResult::Ok => {}
                VerifyResult::WrongPassword => {
                    let mut attempts = state.failed_login_attempts.lock().map_err(|_| {
                        tracing::error!("failed_login_attempts mutex is poisoned");
                        ApiError::new(ErrorCode::InternalError, "internal error")
                    })?;
                    record_failure(&mut attempts, &payload.email);
                    return Err(ApiError::new(
                        ErrorCode::AuthenticationRequired,
                        "invalid email or password",
                    ));
                }
                VerifyResult::CorruptHash => {
                    tracing::error!(
                        "stored password_hash is not a valid PHC string; possible DB corruption"
                    );
                    return Err(ApiError::new(ErrorCode::InternalError, "internal error"));
                }
            }
            row
        }
        None => {
            let mut attempts = state.failed_login_attempts.lock().map_err(|_| {
                tracing::error!("failed_login_attempts mutex is poisoned");
                ApiError::new(ErrorCode::InternalError, "internal error")
            })?;
            record_failure(&mut attempts, &payload.email);
            return Err(ApiError::new(
                ErrorCode::AuthenticationRequired,
                "invalid email or password",
            ));
        }
    };

    // --- Issue opaque bearer session token ---
    let session_token = generate_token();
    let session_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
    )
    .bind(&session_id)
    .bind(&account.did)
    .bind(&session_token.hash)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert provisioning session");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    // Clear failure history only after the session is fully committed.
    {
        let mut attempts = state.failed_login_attempts.lock().map_err(|_| {
            tracing::error!("failed_login_attempts mutex is poisoned");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;
        clear_failures(&mut attempts, &payload.email);
    }

    Ok((
        StatusCode::OK,
        Json(CreateProvisioningSessionResponse {
            session_token: session_token.plaintext,
            did: account.did,
        }),
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
    use crate::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn post_provisioning_session(email: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/accounts/sessions")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"email":"{email}","password":"{password}"}}"#
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

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
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
    async fn valid_email_and_password_returns_200_with_session_token() {
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
            .oneshot(post_provisioning_session("alice@example.com", "hunter2"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            json["sessionToken"].as_str().is_some(),
            "sessionToken required"
        );
        assert_eq!(json["did"], "did:plc:alice");
    }

    #[tokio::test]
    async fn session_token_is_persisted_in_db() {
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
            .oneshot(post_provisioning_session("persist@example.com", "testpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = 'did:plc:persist'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(session_count, 1, "one session row expected");
    }

    #[tokio::test]
    async fn session_token_hash_is_found_by_require_session_query() {
        // Verify that the issued token can be looked up by the same query
        // `require_session` uses: SELECT did FROM sessions WHERE token_hash = ?
        // AND expires_at > datetime('now').
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:authcheck",
            "authcheck.test.example.com",
            "authcheck@example.com",
            "authpass",
        )
        .await;

        let response = app(state.clone())
            .oneshot(post_provisioning_session(
                "authcheck@example.com",
                "authpass",
            ))
            .await
            .unwrap();

        let json = body_json(response).await;
        let token = json["sessionToken"].as_str().unwrap();

        // Hash the token (same as require_session does internally).
        let hash = crate::routes::token::hash_bearer_token(token).unwrap();

        let did: Option<String> = sqlx::query_scalar(
            "SELECT did FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')",
        )
        .bind(&hash)
        .fetch_optional(&state.db)
        .await
        .unwrap();

        assert_eq!(did.as_deref(), Some("did:plc:authcheck"),
            "require_session query must find the issued token");
    }

    // ── Auth failures ─────────────────────────────────────────────────────────

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
            .oneshot(post_provisioning_session(
                "charlie@example.com",
                "wrongpassword",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn unknown_email_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_provisioning_session("nobody@example.com", "password"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn account_without_password_returns_401() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:nopass', 'nopass@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_provisioning_session("nopass@example.com", "anypassword"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
            .oneshot(post_provisioning_session("deact@example.com", "password"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_email_return_identical_errors() {
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
            .oneshot(post_provisioning_session("enumtest@example.com", "wrongpassword"))
            .await
            .unwrap();
        let unknown = app(state)
            .oneshot(post_provisioning_session("nobody@example.com", "anything"))
            .await
            .unwrap();

        assert_eq!(wrong_pw.status(), unknown.status());
        let wrong_pw_json = body_json(wrong_pw).await;
        let unknown_json = body_json(unknown).await;
        assert_eq!(
            wrong_pw_json["error"]["code"],
            unknown_json["error"]["code"]
        );
        assert_eq!(
            wrong_pw_json["error"]["message"],
            unknown_json["error"]["message"]
        );
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rate_limit_triggers_after_max_failures() {
        let state = test_state().await;

        for i in 0..RATE_LIMIT_MAX_FAILURES {
            let response = app(state.clone())
                .oneshot(post_provisioning_session(
                    "did:plc:ratelimited@example.com",
                    "wrongpassword",
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {i} should be 401"
            );
        }

        let response = app(state)
            .oneshot(post_provisioning_session(
                "did:plc:ratelimited@example.com",
                "wrongpassword",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
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
                .oneshot(post_provisioning_session(
                    "cleartest@example.com",
                    "wrongpassword",
                ))
                .await
                .unwrap();
        }

        // Successful login clears the counter
        let ok = app(state.clone())
            .oneshot(post_provisioning_session(
                "cleartest@example.com",
                "correctpassword",
            ))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // One more failure should be 401, not 429 — counter was reset
        let after = app(state)
            .oneshot(post_provisioning_session(
                "cleartest@example.com",
                "wrongpassword",
            ))
            .await
            .unwrap();
        assert_eq!(
            after.status(),
            StatusCode::UNAUTHORIZED,
            "counter must have been cleared by the successful login"
        );
    }
}
