// pattern: Imperative Shell
//
// Gathers: JSON body {identifier, password}, DB pool, jwt_secret, config, rate-limit state
// Processes: rate limit gate → identifier resolution → main-password then app-password
//            verification (selecting the session scope) → JWT issuance → session +
//            refresh_token DB insert (tagged with the app password name, if any)
// Returns: JSON {accessJwt, refreshJwt, handle, did, email?} on success; ApiError on failure.
//          email is omitted for app-password sessions.
//
// Implements: POST /xrpc/com.atproto.server.createSession

use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::password::{verify_password, VerifyResult};
use crate::auth::rate_limit::{clear_failures, is_rate_limited, record_failure};
use crate::db::accounts::resolve_identifier;
use crate::db::app_passwords::list_verify_candidates;
use crate::session_issuer::{issue_session, SessionKind};

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
    /// Omitted for app-password sessions: a limited credential does not see the account email
    /// (matching atproto, whose `createSession` returns email only for full account sessions).
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

/// An app password matched during `createSession`: its name and whether it is privileged.
struct MatchedAppPassword {
    name: String,
    privileged: bool,
}

/// Try `password` against each of the account's stored app passwords, returning the first
/// match. A revoked app password is absent from the candidate set, so it can no longer
/// authenticate — satisfying "revoked passwords stop authenticating".
async fn match_app_password(
    db: &sqlx::SqlitePool,
    did: &str,
    password: &str,
) -> Result<Option<MatchedAppPassword>, ApiError> {
    for candidate in list_verify_candidates(db, did).await? {
        if matches!(
            verify_password(&candidate.password_hash, password),
            VerifyResult::Ok
        ) {
            return Ok(Some(MatchedAppPassword {
                name: candidate.name,
                privileged: candidate.privileged,
            }));
        }
    }
    Ok(None)
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
        let mut attempts = crate::auth::validation::lock_failed_login_attempts(
            &state.failed_login_attempts,
            None,
        )?;
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
    //
    // Verification order: try the main account password first; a correct one yields a
    // full-access session. Otherwise fall back to the account's app passwords — a match yields
    // an app-password-scoped session (privileged or not) and tags the session with the app
    // password's name so refresh/revocation can track it. Only if neither matches is it a
    // failure. Mobile accounts (no main password) can still authenticate via an app password.
    let account_opt = resolve_identifier(&state.db, &payload.identifier).await?;

    let (account, session_kind) = match account_opt {
        Some(row) => {
            let main_result = match row.password_hash.as_deref() {
                None | Some("") => VerifyResult::WrongPassword,
                Some(h) => verify_password(h, &payload.password),
            };
            match main_result {
                VerifyResult::Ok => (row, SessionKind::FullAccess),
                VerifyResult::CorruptHash => {
                    tracing::error!(
                        identifier = %payload.identifier,
                        "stored password_hash is not a valid PHC string; possible DB corruption"
                    );
                    return Err(ApiError::new(ErrorCode::InternalError, "internal error"));
                }
                VerifyResult::WrongPassword => {
                    match match_app_password(&state.db, &row.did, &payload.password).await? {
                        Some(matched) => (
                            row,
                            SessionKind::AppPassword {
                                name: matched.name,
                                privileged: matched.privileged,
                            },
                        ),
                        None => {
                            let mut attempts = crate::auth::validation::lock_failed_login_attempts(
                                &state.failed_login_attempts,
                                None,
                            )?;
                            record_failure(&mut attempts, &payload.identifier);
                            return Err(ApiError::new(
                                ErrorCode::AuthenticationRequired,
                                "invalid identifier or password",
                            ));
                        }
                    }
                }
            }
        }
        None => {
            let mut attempts = crate::auth::validation::lock_failed_login_attempts(
                &state.failed_login_attempts,
                None,
            )?;
            record_failure(&mut attempts, &payload.identifier);
            return Err(ApiError::new(
                ErrorCode::AuthenticationRequired,
                "invalid identifier or password",
            ));
        }
    };

    let issued = issue_session(&state, &account.did, &session_kind).await?;

    // Clear failure history only after the session is fully committed.
    // Doing this earlier would reset the counter even if JWT issuance or the
    // DB transaction subsequently fails.
    // Mutex poison here must not override a committed session — log and continue.
    match state.failed_login_attempts.lock() {
        Ok(mut attempts) => clear_failures(&mut attempts, &payload.identifier),
        Err(_) => tracing::error!(
            identifier = %payload.identifier,
            phase = "clear_failures",
            "mutex poisoned; rate-limit counter not cleared after successful login"
        ),
    }

    Ok((
        StatusCode::OK,
        Json(CreateSessionResponse {
            access_jwt: issued.access_jwt,
            refresh_jwt: issued.refresh_jwt,
            handle: issued.handle,
            did: issued.did,
            email: issued.email,
        }),
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;
    use crate::routes::test_utils::{body_json, insert_account_with_password, seed_app_password};

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
        assert_eq!(
            wrong_pw_json["error"]["code"],
            unknown_json["error"]["code"]
        );
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

    // ── App-password login ────────────────────────────────────────────────────

    /// Decode an HS256 access JWT (no audience validation) and return its `scope` claim.
    fn decode_scope(token: &str, secret: &[u8; 32]) -> String {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.validate_aud = false;
        v.set_required_spec_claims(&["exp", "sub"]);
        jsonwebtoken::decode::<serde_json::Value>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &v,
        )
        .unwrap()
        .claims["scope"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn app_password_login_succeeds_with_app_pass_scope() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "cli",
            "abcd-efgh-ijkl-mnop",
            false,
        )
        .await;
        let secret = state.jwt_secret;

        let response = app(state)
            .oneshot(post_create_session("did:plc:alice", "abcd-efgh-ijkl-mnop"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(
            decode_scope(json["accessJwt"].as_str().unwrap(), &secret),
            "com.atproto.appPass"
        );
        // App-password sessions do not receive the account email.
        assert!(
            json.get("email").is_none(),
            "email must be omitted for app-pass sessions"
        );
        assert_eq!(json["did"], "did:plc:alice");
    }

    #[tokio::test]
    async fn privileged_app_password_login_has_privileged_scope() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:priv",
            "priv.test.example.com",
            "priv@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(&state.db, "did:plc:priv", "dm", "priv-priv-priv-priv", true).await;
        let secret = state.jwt_secret;

        let response = app(state)
            .oneshot(post_create_session("did:plc:priv", "priv-priv-priv-priv"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(
            decode_scope(json["accessJwt"].as_str().unwrap(), &secret),
            "com.atproto.appPassPrivileged"
        );
    }

    #[tokio::test]
    async fn main_password_login_keeps_full_access_scope_and_email() {
        // With an app password also present, the main password must still yield a full-access
        // session with the email — the app-pass fallback only fires when the main password fails.
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:full",
            "full.test.example.com",
            "full@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:full",
            "cli",
            "abcd-efgh-ijkl-mnop",
            false,
        )
        .await;
        let secret = state.jwt_secret;

        let response = app(state)
            .oneshot(post_create_session("did:plc:full", "mainpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(
            decode_scope(json["accessJwt"].as_str().unwrap(), &secret),
            "com.atproto.access"
        );
        assert_eq!(json["email"], "full@example.com");
    }

    #[tokio::test]
    async fn wrong_app_password_returns_401() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:w",
            "w.test.example.com",
            "w@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(&state.db, "did:plc:w", "cli", "abcd-efgh-ijkl-mnop", false).await;

        let response = app(state)
            .oneshot(post_create_session("did:plc:w", "not-the-right-secret"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mobile_account_can_login_with_app_password() {
        // A mobile account has a NULL password_hash (no main password) but can still
        // authenticate with an app password.
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:mobile', 'mobile@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        seed_app_password(
            &state.db,
            "did:plc:mobile",
            "cli",
            "abcd-efgh-ijkl-mnop",
            false,
        )
        .await;
        let secret = state.jwt_secret;

        let response = app(state)
            .oneshot(post_create_session("did:plc:mobile", "abcd-efgh-ijkl-mnop"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(
            decode_scope(json["accessJwt"].as_str().unwrap(), &secret),
            "com.atproto.appPass"
        );
    }

    #[tokio::test]
    async fn app_password_session_tags_refresh_token_with_name() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:nm",
            "nm.test.example.com",
            "nm@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(&state.db, "did:plc:nm", "cli", "abcd-efgh-ijkl-mnop", false).await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post_create_session("did:plc:nm", "abcd-efgh-ijkl-mnop"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let name: Option<String> = sqlx::query_scalar(
            "SELECT app_password_name FROM refresh_tokens WHERE did = 'did:plc:nm'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(name.as_deref(), Some("cli"));
    }
}
