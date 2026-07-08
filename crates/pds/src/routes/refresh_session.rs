// pattern: Imperative Shell
//
// Gathers: Authorization header (refresh JWT Bearer), DB pool, jwt_secret, config
// Processes: JWT verification → scope check → refresh_token DB lookup →
//            replay detection → new JWT issuance → token rotation DB update
// Returns: JSON {accessJwt, refreshJwt, handle, did} on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.refreshSession

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::Json};
use serde::Serialize;
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extract_bearer_token;
use crate::auth::jwt::{
    app_pass_scope, issue_access_jwt, issue_refresh_jwt, parse_scope, verify_refresh_token,
    AuthScope, SCOPE_ACCESS,
};

// ── Response type ────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
    handle: String,
    did: String,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// POST /xrpc/com.atproto.server.refreshSession
///
/// Exchanges a refresh JWT for a new access + refresh token pair.
/// Token rotation: the old refresh token is marked as used (via next_jti) on
/// first use and a new one is issued. Replay detection: if an already-rotated
/// refresh token is presented, the entire session is revoked as a security measure.
pub async fn refresh_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<RefreshSessionResponse>), ApiError> {
    // --- Extract and verify the refresh JWT ---
    let token = extract_bearer_token(&headers)?;
    let claims = verify_refresh_token(token, &state)?;

    if parse_scope(&claims.scope)? != AuthScope::Refresh {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "refresh token required",
        ));
    }

    let jti = claims
        .jti
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "invalid refresh token"))?;

    // --- Look up the refresh token in the DB ---
    // `next_jti IS NULL` is not checked here — we need the row regardless to detect replays.
    // `app_password_name` carries the app-pass identity forward so the rotated session keeps its
    // (limited) scope rather than silently escalating to full access.
    let crate::db::refresh_tokens::ActiveRefreshToken {
        did,
        session_id,
        next_jti,
        app_password_name,
    } = crate::db::refresh_tokens::get_active_refresh_token(&state.db, &jti)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidToken,
                "refresh token not found or expired",
            )
        })?;

    // --- Replay detection: next_jti being set means this token was already rotated ---
    if next_jti.is_some() {
        // Revoke the entire session atomically.
        let mut tx = state.db.begin().await.map_err(|e| {
            tracing::error!(error = %e, "failed to begin revocation transaction");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;

        sqlx::query("DELETE FROM refresh_tokens WHERE session_id = ?")
            .bind(&session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to delete refresh tokens during revocation");
                ApiError::new(ErrorCode::InternalError, "internal error")
            })?;

        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to delete session during revocation");
                ApiError::new(ErrorCode::InternalError, "internal error")
            })?;

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "failed to commit revocation transaction");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;

        tracing::warn!(
            did = %did,
            session_id = %session_id,
            jti = %jti,
            "refresh token replay detected; session revoked"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "refresh token already used",
        ));
    }

    // --- Issue new tokens ---
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            tracing::error!(error = %e, "system clock is before Unix epoch");
            ApiError::new(ErrorCode::InternalError, "failed to issue token")
        })?
        .as_secs();

    let aud = state
        .config
        .server_did
        .as_deref()
        .unwrap_or(&state.config.public_url)
        .to_string();

    // An app-pass session stays app-pass on refresh; re-derive the privilege from the stored
    // app password. A missing row means the app password was revoked out from under the session
    // (defence in depth — revoke also deletes the refresh tokens), so refuse to rotate rather
    // than keep a revoked credential alive.
    let session_scope = match &app_password_name {
        Some(name) => {
            let privileged =
                crate::db::app_passwords::app_password_privileged(&state.db, &did, name)
                    .await?
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::InvalidToken, "app password revoked")
                    })?;
            app_pass_scope(privileged)
        }
        None => SCOPE_ACCESS,
    };

    let new_access_jwt = issue_access_jwt(&state.jwt_secret, &did, &aud, now, session_scope)?;
    let new_refresh_jti = Uuid::new_v4().to_string();
    let new_refresh_jwt = issue_refresh_jwt(&state.jwt_secret, &did, &aud, &new_refresh_jti, now)?;

    // --- Atomically rotate: insert new token, mark old as used ---
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, session_id = %session_id, jti = %jti, "failed to begin token rotation transaction");
        ApiError::new(ErrorCode::InternalError, "failed to refresh session")
    })?;

    sqlx::query(
        "INSERT INTO refresh_tokens (jti, did, session_id, expires_at, app_password_name, created_at) \
         VALUES (?, ?, ?, datetime('now', '+90 days'), ?, datetime('now'))",
    )
    .bind(&new_refresh_jti)
    .bind(&did)
    .bind(&session_id)
    .bind(app_password_name.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, session_id = %session_id, jti = %jti, "failed to insert new refresh token");
        ApiError::new(ErrorCode::InternalError, "failed to refresh session")
    })?;

    // Guard the rotation on `next_jti IS NULL` so it is a no-op if the token was already
    // rotated. The replay check above reads `next_jti` outside this transaction, so two
    // requests presenting the same jti can both observe it NULL; without this guard both
    // would rotate and mint working token pairs, leaving two live refresh chains from one
    // token with the theft never detected. With it, only one UPDATE finds the row unrotated
    // — the loser gets 0 rows and fails closed (its freshly-inserted token is rolled back
    // with the transaction), so one refresh token yields at most one live chain.
    let updated =
        sqlx::query("UPDATE refresh_tokens SET next_jti = ? WHERE jti = ? AND next_jti IS NULL")
            .bind(&new_refresh_jti)
            .bind(&jti)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, session_id = %session_id, jti = %jti, "failed to mark old refresh token as used");
                ApiError::new(ErrorCode::InternalError, "failed to refresh session")
            })?;

    if updated.rows_affected() != 1 {
        // 0 rows: between our read and this write the token was rotated (or deleted)
        // concurrently. Fail closed and roll back — never commit a second rotation.
        tracing::warn!(
            did = %did,
            session_id = %session_id,
            jti = %jti,
            rows = updated.rows_affected(),
            "concurrent refresh lost the rotation race; refusing to issue a second token chain"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "refresh token already used",
        ));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, session_id = %session_id, jti = %jti, "failed to commit token rotation transaction");
        ApiError::new(ErrorCode::InternalError, "failed to refresh session")
    })?;

    // --- Look up handle for the response ---
    // Non-fatal: token rotation already committed. A handle lookup failure must not
    // force the client to retry with the old token (which would trigger replay detection).
    let handle = sqlx::query_scalar::<_, String>(
        "SELECT h.handle FROM handles h WHERE h.did = ? LIMIT 1",
    )
    .bind(&did)
    .fetch_optional(&state.db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, did = %did, "handle lookup failed after token rotation; using handle.invalid");
        None
    });

    // ATProto spec: "handle.invalid" is the sentinel for accounts without a resolvable handle.
    let handle = handle.unwrap_or_else(|| "handle.invalid".to_string());

    Ok((
        StatusCode::OK,
        Json(RefreshSessionResponse {
            access_jwt: new_access_jwt,
            refresh_jwt: new_refresh_jwt,
            handle,
            did,
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
    use crate::routes::test_utils::{body_json, insert_account_with_password};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn post_refresh_session(refresh_jwt: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.refreshSession")
            .header("Authorization", format!("Bearer {refresh_jwt}"))
            .body(Body::empty())
            .unwrap()
    }

    /// Call createSession and return the JSON response body.
    async fn create_session_tokens(
        state: &crate::app::AppState,
        did: &str,
        password: &str,
    ) -> serde_json::Value {
        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{did}","password":"{password}"}}"#
            )))
            .unwrap();
        let response = app(state.clone()).oneshot(request).await.unwrap();
        body_json(response).await
    }

    /// Decode an HS256 JWT without audience validation and return its claims as JSON.
    fn decode_jwt(token: &str, secret: &[u8; 32]) -> serde_json::Value {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "sub"]);
        jsonwebtoken::decode::<serde_json::Value>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )
        .expect("JWT must decode without error")
        .claims
    }

    /// Build a syntactically valid HS256 refresh JWT whose `exp` is in the past.
    fn expired_refresh_jwt(secret: &[u8; 32], did: &str) -> String {
        let past = 1_000_000_000u64;
        let claims = serde_json::json!({
            "scope": "com.atproto.refresh",
            "sub": did,
            "jti": uuid::Uuid::new_v4().to_string(),
            "iat": past,
            "exp": past + 1,
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_refresh_token_returns_new_token_pair() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:alice", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["accessJwt"].as_str().is_some(), "accessJwt required");
        assert!(json["refreshJwt"].as_str().is_some(), "refreshJwt required");
        assert_eq!(json["did"], "did:plc:alice");
        assert_eq!(json["handle"], "alice.test.example.com");
    }

    #[tokio::test]
    async fn new_access_jwt_has_access_scope() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:scope",
            "scope.test.example.com",
            "scope@example.com",
            "hunter2",
        )
        .await;

        let secret = state.jwt_secret;
        let tokens = create_session_tokens(&state, "did:plc:scope", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let access_claims = decode_jwt(json["accessJwt"].as_str().unwrap(), &secret);
        assert_eq!(access_claims["scope"], "com.atproto.access");
        assert_eq!(access_claims["sub"], "did:plc:scope");
    }

    #[tokio::test]
    async fn new_refresh_jwt_has_refresh_scope_and_different_jti() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:jtirot",
            "jtirot.test.example.com",
            "jtirot@example.com",
            "hunter2",
        )
        .await;

        let secret = state.jwt_secret;
        let tokens = create_session_tokens(&state, "did:plc:jtirot", "hunter2").await;
        let original_refresh_jwt = tokens["refreshJwt"].as_str().unwrap();
        let original_jti = decode_jwt(original_refresh_jwt, &secret)["jti"]
            .as_str()
            .unwrap()
            .to_string();

        let response = app(state)
            .oneshot(post_refresh_session(original_refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let new_claims = decode_jwt(json["refreshJwt"].as_str().unwrap(), &secret);
        assert_eq!(new_claims["scope"], "com.atproto.refresh");
        let new_jti = new_claims["jti"].as_str().unwrap();
        assert_ne!(new_jti, original_jti, "new jti must differ from original");
    }

    #[tokio::test]
    async fn token_rotation_stored_in_db() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:dbcheck",
            "dbcheck.test.example.com",
            "dbcheck@example.com",
            "hunter2",
        )
        .await;

        let secret = state.jwt_secret;
        let db = state.db.clone();
        let tokens = create_session_tokens(&state, "did:plc:dbcheck", "hunter2").await;
        let original_refresh_jwt = tokens["refreshJwt"].as_str().unwrap();
        let old_jti = decode_jwt(original_refresh_jwt, &secret)["jti"]
            .as_str()
            .unwrap()
            .to_string();

        let response = app(state)
            .oneshot(post_refresh_session(original_refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let new_jti = decode_jwt(json["refreshJwt"].as_str().unwrap(), &secret)["jti"]
            .as_str()
            .unwrap()
            .to_string();

        // Old token's next_jti must point to the new token.
        let next_jti_matches: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM refresh_tokens WHERE jti = ? AND next_jti = ?",
        )
        .bind(&old_jti)
        .bind(&new_jti)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            next_jti_matches, 1,
            "old token's next_jti must point to the new jti"
        );

        // New token must exist in the DB.
        let new_exists: Option<String> =
            sqlx::query_scalar("SELECT jti FROM refresh_tokens WHERE jti = ?")
                .bind(&new_jti)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(
            new_exists.is_some(),
            "new refresh token must be persisted in DB"
        );
    }

    #[tokio::test]
    async fn second_rotation_succeeds_with_new_token() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:chain",
            "chain.test.example.com",
            "chain@example.com",
            "hunter2",
        )
        .await;

        // First rotation.
        let tokens1 = create_session_tokens(&state, "did:plc:chain", "hunter2").await;
        let refresh_jwt1 = tokens1["refreshJwt"].as_str().unwrap().to_string();
        let resp1 = app(state.clone())
            .oneshot(post_refresh_session(&refresh_jwt1))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let json1 = body_json(resp1).await;
        let refresh_jwt2 = json1["refreshJwt"].as_str().unwrap().to_string();

        // Second rotation using the token issued by the first rotation.
        let resp2 = app(state)
            .oneshot(post_refresh_session(&refresh_jwt2))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let json2 = body_json(resp2).await;
        assert!(
            json2["accessJwt"].as_str().is_some(),
            "second rotation must issue new accessJwt"
        );
        assert!(
            json2["refreshJwt"].as_str().is_some(),
            "second rotation must issue new refreshJwt"
        );
    }

    #[tokio::test]
    async fn account_without_handle_returns_handle_invalid() {
        let state = test_state().await;
        // Insert account with a handle, then delete the handle to simulate no-handle account.
        insert_account_with_password(
            &state.db,
            "did:plc:nohandle",
            "nohandle.test.example.com",
            "nohandle@example.com",
            "hunter2",
        )
        .await;
        sqlx::query("DELETE FROM handles WHERE did = 'did:plc:nohandle'")
            .execute(&state.db)
            .await
            .unwrap();

        let tokens = create_session_tokens(&state, "did:plc:nohandle", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["handle"], "handle.invalid");
    }

    // ── Replay detection ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn old_refresh_token_rejected_after_rotation() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:replay",
            "replay.test.example.com",
            "replay@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:replay", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // First use succeeds — token is rotated.
        let first = app(state.clone())
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // Replaying the same (now rotated) token must be rejected.
        let replay = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(
            replay.status(),
            StatusCode::UNAUTHORIZED,
            "replay must be rejected"
        );
        let json = body_json(replay).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn replay_of_used_refresh_token_revokes_session() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:revoke",
            "revoke.test.example.com",
            "revoke@example.com",
            "hunter2",
        )
        .await;

        let db = state.db.clone();
        let tokens = create_session_tokens(&state, "did:plc:revoke", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // Capture the session ID before rotation.
        let session_id: String =
            sqlx::query_scalar("SELECT id FROM sessions WHERE did = 'did:plc:revoke'")
                .fetch_one(&db)
                .await
                .unwrap();

        // First use rotates the token.
        app(state.clone())
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();

        // Replay triggers full session revocation.
        let replay = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();

        assert_eq!(
            replay.status(),
            StatusCode::UNAUTHORIZED,
            "replay must return 401"
        );
        let json = body_json(replay).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");

        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = ?")
            .bind(&session_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(session_count, 0, "session must be deleted on replay");

        let token_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE session_id = ?")
                .bind(&session_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            token_count, 0,
            "all refresh tokens for the session must be deleted on replay"
        );
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_refresh_token_returns_401() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:expired",
            "expired.test.example.com",
            "expired@example.com",
            "hunter2",
        )
        .await;

        let expired_jwt = expired_refresh_jwt(&state.jwt_secret, "did:plc:expired");
        let response = app(state)
            .oneshot(post_refresh_session(&expired_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
    }

    #[tokio::test]
    async fn token_deleted_from_db_returns_401() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:deleted",
            "deleted.test.example.com",
            "deleted@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:deleted", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // Simulate out-of-band revocation by deleting the DB row directly.
        sqlx::query("DELETE FROM refresh_tokens WHERE did = 'did:plc:deleted'")
            .execute(&state.db)
            .await
            .unwrap();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn invalid_token_signature_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_refresh_session("not.a.valid.jwt"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn access_token_rejected_as_refresh_token() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:wrongscope",
            "wrongscope.test.example.com",
            "wrongscope@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:wrongscope", "hunter2").await;
        let access_jwt = tokens["accessJwt"].as_str().unwrap();

        let response = app(state)
            .oneshot(post_refresh_session(access_jwt))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "access token must be rejected at the refresh endpoint"
        );
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.refreshSession")
            .body(Body::empty())
            .unwrap();

        let response = app(test_state().await).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    // ── App-password scope preservation ───────────────────────────────────────

    #[tokio::test]
    async fn app_password_session_refresh_preserves_app_pass_scope_and_name() {
        use crate::routes::test_utils::seed_app_password;

        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:app",
            "app.test.example.com",
            "app@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:app",
            "cli",
            "abcd-efgh-ijkl-mnop",
            false,
        )
        .await;
        let secret = state.jwt_secret;
        let db = state.db.clone();

        // Log in with the app password, then refresh.
        let tokens = create_session_tokens(&state, "did:plc:app", "abcd-efgh-ijkl-mnop").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        // New access token keeps the app-pass scope (not silently upgraded to full access).
        let access_claims = decode_jwt(json["accessJwt"].as_str().unwrap(), &secret);
        assert_eq!(access_claims["scope"], "com.atproto.appPass");

        // Rotated refresh token still carries the app password name.
        let new_jti = decode_jwt(json["refreshJwt"].as_str().unwrap(), &secret)["jti"]
            .as_str()
            .unwrap()
            .to_string();
        let name: Option<String> =
            sqlx::query_scalar("SELECT app_password_name FROM refresh_tokens WHERE jti = ?")
                .bind(&new_jti)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(name.as_deref(), Some("cli"));
    }

    #[tokio::test]
    async fn privileged_app_password_session_refresh_stays_privileged() {
        use crate::routes::test_utils::seed_app_password;

        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:pv",
            "pv.test.example.com",
            "pv@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(&state.db, "did:plc:pv", "dm", "priv-priv-priv-priv", true).await;
        let secret = state.jwt_secret;

        let tokens = create_session_tokens(&state, "did:plc:pv", "priv-priv-priv-priv").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let access_claims = decode_jwt(json["accessJwt"].as_str().unwrap(), &secret);
        assert_eq!(access_claims["scope"], "com.atproto.appPassPrivileged");
    }

    #[tokio::test]
    async fn refresh_aborts_when_app_password_deleted() {
        use crate::routes::test_utils::seed_app_password;

        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:gone",
            "gone.test.example.com",
            "gone@example.com",
            "mainpass",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:gone",
            "cli",
            "abcd-efgh-ijkl-mnop",
            false,
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:gone", "abcd-efgh-ijkl-mnop").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // Delete only the app_passwords row (leave the refresh token) to exercise the
        // missing-app-password guard directly, independent of revoke's token cleanup.
        sqlx::query("DELETE FROM app_passwords WHERE did = 'did:plc:gone' AND name = 'cli'")
            .execute(&state.db)
            .await
            .unwrap();

        let response = app(state)
            .oneshot(post_refresh_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }
}
