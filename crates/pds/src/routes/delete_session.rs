// pattern: Imperative Shell
//
// Gathers: Authorization header (refresh JWT Bearer), DB pool
// Processes: JWT verification (exp allowed) → scope check → DB lookup →
//            atomic session revocation (refresh_tokens + sessions)
// Returns: 200 OK (empty) on success or idempotent already-revoked; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.deleteSession

use axum::{extract::State, http::HeaderMap, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extract_bearer_token;
use crate::auth::jwt::{parse_scope, verify_refresh_token_allow_expired, AuthScope};

// ── Handler ──────────────────────────────────────────────────────────────────

/// POST /xrpc/com.atproto.server.deleteSession
///
/// Revokes the session identified by the refresh JWT's `jti` claim, deleting
/// all associated refresh tokens and the session row atomically.
///
/// Accepts expired refresh tokens (`allowExpired: true`) so users can always
/// log out regardless of token age. Idempotent: if the token was already
/// revoked (row not found), returns 200 OK — logout already succeeded.
pub async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    // --- Extract and verify the refresh JWT (expiry allowed) ---
    let token = extract_bearer_token(&headers)?;
    let claims = verify_refresh_token_allow_expired(token, &state)?;

    if parse_scope(&claims.scope)? != AuthScope::Refresh {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "refresh token required",
        ));
    }

    let jti = claims
        .jti
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "invalid refresh token"))?;

    // --- Look up the token — no expiry filter, revocation must always work ---
    let session_id = crate::db::refresh_tokens::session_id_for_jti(&state.db, &jti).await?;

    // Idempotent: token not found means already revoked — logout already done.
    let Some(session_id) = session_id else {
        tracing::debug!(jti = %jti, "deleteSession called with unknown jti; treating as already revoked");
        return Ok(StatusCode::OK);
    };

    // --- Atomically revoke: delete all refresh tokens + the session row ---
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, session_id = %session_id, "failed to begin revocation transaction");
        ApiError::new(ErrorCode::InternalError, "internal error")
    })?;

    sqlx::query("DELETE FROM refresh_tokens WHERE session_id = ?")
        .bind(&session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, session_id = %session_id, "failed to delete refresh tokens");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;

    let deleted = sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(&session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, session_id = %session_id, "failed to delete session");
            ApiError::new(ErrorCode::InternalError, "internal error")
        })?;

    if deleted.rows_affected() != 1 {
        tracing::warn!(
            session_id = %session_id,
            jti = %jti,
            rows = deleted.rows_affected(),
            "session DELETE affected unexpected row count; session may have been removed concurrently"
        );
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, session_id = %session_id, "failed to commit revocation transaction");
        ApiError::new(ErrorCode::InternalError, "internal error")
    })?;

    tracing::info!(session_id = %session_id, jti = %jti, "session revoked via deleteSession");

    Ok(StatusCode::OK)
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

    fn post_delete_session(refresh_jwt: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.deleteSession")
            .header("Authorization", format!("Bearer {refresh_jwt}"))
            .body(Body::empty())
            .unwrap()
    }

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
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "createSession must succeed"
        );
        body_json(response).await
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
    async fn valid_refresh_token_returns_200() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del1",
            "del1.test.example.com",
            "del1@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:del1", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap();

        let response = app(state)
            .oneshot(post_delete_session(refresh_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revocation_deletes_session_and_refresh_tokens() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del2",
            "del2.test.example.com",
            "del2@example.com",
            "hunter2",
        )
        .await;

        let db = state.db.clone();
        let tokens = create_session_tokens(&state, "did:plc:del2", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap();

        let session_id: String =
            sqlx::query_scalar("SELECT id FROM sessions WHERE did = 'did:plc:del2'")
                .fetch_one(&db)
                .await
                .unwrap();

        let response = app(state)
            .oneshot(post_delete_session(refresh_jwt))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = ?")
            .bind(&session_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(session_count, 0, "session must be deleted");

        let token_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE session_id = ?")
                .bind(&session_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            token_count, 0,
            "all refresh tokens for the session must be deleted"
        );
    }

    #[tokio::test]
    async fn revoked_refresh_token_cannot_be_used_for_refresh() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del3",
            "del3.test.example.com",
            "del3@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:del3", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // Delete the session.
        let del = app(state.clone())
            .oneshot(post_delete_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);

        // The revoked refresh token must no longer work for rotation.
        let refresh = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {refresh_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            refresh.status(),
            StatusCode::UNAUTHORIZED,
            "revoked token must not be usable for refreshSession"
        );
    }

    // ── Expired token revocation ──────────────────────────────────────────────

    #[tokio::test]
    async fn expired_token_with_valid_db_row_is_revoked() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del4",
            "del4.test.example.com",
            "del4@example.com",
            "hunter2",
        )
        .await;

        let db = state.db.clone();

        // Create a real session so the session_id and refresh_tokens row exist.
        let tokens = create_session_tokens(&state, "did:plc:del4", "hunter2").await;
        let real_refresh_jwt = tokens["refreshJwt"].as_str().unwrap();

        // Decode the JTI from the real token so we can build a matching expired JWT.
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["sub"]);
        let real_claims: serde_json::Value = jsonwebtoken::decode(
            real_refresh_jwt,
            &jsonwebtoken::DecodingKey::from_secret(&state.jwt_secret),
            &validation,
        )
        .unwrap()
        .claims;
        let real_jti = real_claims["jti"].as_str().unwrap();

        // Construct an expired JWT with the same JTI and valid signature.
        let past = 1_000_000_000u64;
        let expired_jwt_with_real_jti = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.refresh",
                "sub": "did:plc:del4",
                "jti": real_jti,
                "iat": past,
                "exp": past + 1,
            }),
            &jsonwebtoken::EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap();

        let session_id: String =
            sqlx::query_scalar("SELECT id FROM sessions WHERE did = 'did:plc:del4'")
                .fetch_one(&db)
                .await
                .unwrap();

        // deleteSession with the expired JWT must succeed.
        let response = app(state)
            .oneshot(post_delete_session(&expired_jwt_with_real_jti))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "expired refresh token must still revoke the session"
        );

        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = ?")
            .bind(&session_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            session_count, 0,
            "session must be deleted even with expired token"
        );
    }

    // ── Idempotency ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn already_revoked_token_returns_200() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del5",
            "del5.test.example.com",
            "del5@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:del5", "hunter2").await;
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // First deletion.
        let first = app(state.clone())
            .oneshot(post_delete_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // Second call with the same (now-revoked) token — must be idempotent 200.
        let second = app(state)
            .oneshot(post_delete_session(&refresh_jwt))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "deleteSession on already-revoked token must be idempotent 200"
        );
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn access_token_rejected() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del6",
            "del6.test.example.com",
            "del6@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:del6", "hunter2").await;
        let access_jwt = tokens["accessJwt"].as_str().unwrap();

        let response = app(state)
            .oneshot(post_delete_session(access_jwt))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn invalid_token_signature_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_delete_session("not.a.valid.jwt"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.deleteSession")
            .body(Body::empty())
            .unwrap();

        let response = app(test_state().await).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn expired_token_not_in_db_returns_200() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del7",
            "del7.test.example.com",
            "del7@example.com",
            "hunter2",
        )
        .await;

        // A well-signed expired JWT whose JTI was never inserted into refresh_tokens.
        let expired_jwt = expired_refresh_jwt(&state.jwt_secret, "did:plc:del7");

        let response = app(state)
            .oneshot(post_delete_session(&expired_jwt))
            .await
            .unwrap();

        // Token not found in DB → already revoked (or never existed) → idempotent 200.
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "expired token not in DB must be idempotent 200"
        );
    }

    // ── Rotated token revocation ──────────────────────────────────────────────

    #[tokio::test]
    async fn rotated_token_revokes_entire_session() {
        // After refreshSession, the old refresh token has next_jti set but is still
        // in the DB with a valid session_id. deleteSession with the old token must
        // still revoke the session and all its refresh tokens.
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del8",
            "del8.test.example.com",
            "del8@example.com",
            "hunter2",
        )
        .await;

        let db = state.db.clone();
        let tokens = create_session_tokens(&state, "did:plc:del8", "hunter2").await;
        let original_refresh_jwt = tokens["refreshJwt"].as_str().unwrap().to_string();

        // Rotate the token via refreshSession — old token now has next_jti set.
        let rotated = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {original_refresh_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            rotated.status(),
            StatusCode::OK,
            "refreshSession must succeed"
        );

        let session_id: String =
            sqlx::query_scalar("SELECT id FROM sessions WHERE did = 'did:plc:del8'")
                .fetch_one(&db)
                .await
                .unwrap();

        // Call deleteSession with the old (now-rotated) token.
        let del = app(state)
            .oneshot(post_delete_session(&original_refresh_jwt))
            .await
            .unwrap();
        assert_eq!(
            del.status(),
            StatusCode::OK,
            "deleteSession with rotated token must return 200"
        );

        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = ?")
            .bind(&session_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(session_count, 0, "session must be deleted");

        let token_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE session_id = ?")
                .bind(&session_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            token_count, 0,
            "all refresh tokens (including rotated) must be deleted"
        );
    }

    // ── Access token boundary ─────────────────────────────────────────────────

    #[tokio::test]
    async fn access_token_from_deleted_session_is_still_valid_until_expiry() {
        // Access JWTs are stateless — deleteSession cannot invalidate them before
        // their natural expiry. This test documents that as an intentional contract:
        // getSession must still succeed with the access JWT after the session is deleted.
        // If a future change adds session-row validation to the access path, this test
        // will fail loudly.
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:del9",
            "del9.test.example.com",
            "del9@example.com",
            "hunter2",
        )
        .await;

        let tokens = create_session_tokens(&state, "did:plc:del9", "hunter2").await;
        let access_jwt = tokens["accessJwt"].as_str().unwrap().to_string();
        let refresh_jwt = tokens["refreshJwt"].as_str().unwrap();

        // Delete the session.
        let del = app(state.clone())
            .oneshot(post_delete_session(refresh_jwt))
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);

        // Access JWT is still valid — getSession must return 200.
        let get = app(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/xrpc/com.atproto.server.getSession")
                    .header("Authorization", format!("Bearer {access_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            get.status(),
            StatusCode::OK,
            "access JWT must remain valid until expiry after session deletion (stateless)"
        );
    }
}
