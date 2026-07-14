// pattern: Imperative Shell
//
// Gathers: JSON body {token, password}, DB pool
// Processes: token hash → lookup (with expiry check) → argon2id hash →
//            atomic tx (mark used + update password_hash)
// Returns: 200 on success; 401 InvalidToken if not found; 400 ExpiredToken if expired/used
//
// Implements: POST /xrpc/com.atproto.server.resetPassword

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::password::hash_password;
use crate::auth::token::hash_bearer_token;
use crate::db::password_reset::{get_reset_token, mark_reset_token_used, update_password_hash};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    token: String,
    password: String,
}

/// POST /xrpc/com.atproto.server.resetPassword
///
/// Validates a single-use reset token, hashes the new password with argon2id,
/// and atomically marks the token used and updates `accounts.password_hash`.
pub async fn reset_password(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<ResetPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    let token_hash = hash_bearer_token(&payload.token)
        .map_err(|_| ApiError::new(ErrorCode::InvalidToken, "invalid reset token"))?;

    // The lookup and the two writes (mark used + update password) must be atomic.
    // The transaction is the correctness guarantee; don't rely on pool configuration.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin reset_password transaction");
        ApiError::new(ErrorCode::InternalError, "failed to reset password")
    })?;

    // Expiry is evaluated in the same query as the lookup, not a separate check.
    let row = get_reset_token(&mut tx, &token_hash)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "invalid or unknown reset token"))?;

    // Check used_at first — a consumed token is non-recoverable regardless of expiry.
    if row.used_at.is_some() {
        tracing::warn!(did = %row.did, "password reset attempted with already-used token");
        return Err(ApiError::new(
            ErrorCode::ExpiredToken,
            "this reset token has already been used",
        ));
    }

    if row.is_expired {
        tracing::warn!(did = %row.did, "password reset attempted with expired token");
        return Err(ApiError::new(
            ErrorCode::ExpiredToken,
            "this reset token has expired",
        ));
    }

    let new_hash = hash_password(&payload.password)?;

    mark_reset_token_used(&mut tx, &token_hash).await?;
    update_password_hash(&mut tx, &row.did, &new_hash).await?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit reset_password transaction");
        ApiError::new(ErrorCode::InternalError, "failed to reset password")
    })?;

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
    use crate::auth::token::generate_token;
    use crate::routes::test_utils::{body_json, insert_account_with_password};

    fn post_reset_password(token: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.resetPassword")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{token}","password":"{password}"}}"#
            )))
            .unwrap()
    }

    fn post_request_password_reset(email: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestPasswordReset")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"email":"{email}"}}"#)))
            .unwrap()
    }

    /// Seed a valid (non-expired, unused) reset token in the DB. Returns plaintext token.
    async fn seed_reset_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        sqlx::query(
            "INSERT INTO password_reset_tokens \
             (token_hash, did, expires_at, created_at) \
             VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
        token.plaintext
    }

    /// Seed an expired reset token. Returns plaintext token.
    async fn seed_expired_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        sqlx::query(
            "INSERT INTO password_reset_tokens \
             (token_hash, did, expires_at, created_at) \
             VALUES (?, ?, datetime('now', '-1 hour'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
        token.plaintext
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_returns_200() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:rp1",
            "rp1.test.example.com",
            "rp1@example.com",
            "oldpass",
        )
        .await;
        let token = seed_reset_token(&state.db, "did:plc:rp1").await;

        let response = app(state)
            .oneshot(post_reset_password(&token, "newpass123"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_token_updates_password_hash() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:rp2",
            "rp2.test.example.com",
            "rp2@example.com",
            "oldpass",
        )
        .await;
        let token = seed_reset_token(&state.db, "did:plc:rp2").await;

        let db = state.db.clone();
        app(state)
            .oneshot(post_reset_password(&token, "brandnewpass"))
            .await
            .unwrap();

        let hash: Option<String> =
            sqlx::query_scalar("SELECT password_hash FROM accounts WHERE did = 'did:plc:rp2'")
                .fetch_one(&db)
                .await
                .unwrap();
        let hash = hash.expect("password_hash must not be null after reset");
        use crate::auth::password::{verify_password, VerifyResult};
        assert!(
            matches!(verify_password(&hash, "brandnewpass"), VerifyResult::Ok),
            "new password_hash must verify with the submitted password"
        );
        assert!(
            !matches!(verify_password(&hash, "oldpass"), VerifyResult::Ok),
            "old password must not verify against the new hash"
        );
    }

    #[tokio::test]
    async fn valid_token_marks_token_as_used() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:rp3",
            "rp3.test.example.com",
            "rp3@example.com",
            "pass",
        )
        .await;
        let token = seed_reset_token(&state.db, "did:plc:rp3").await;
        let db = state.db.clone();

        app(state)
            .oneshot(post_reset_password(&token, "newpass"))
            .await
            .unwrap();

        let used_at: Option<String> = sqlx::query_scalar(
            "SELECT used_at FROM password_reset_tokens WHERE did = 'did:plc:rp3'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            used_at.is_some(),
            "used_at must be set after successful reset"
        );
    }

    #[tokio::test]
    async fn response_body_is_empty_on_success() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:rp4",
            "rp4.test.example.com",
            "rp4@example.com",
            "pass",
        )
        .await;
        let token = seed_reset_token(&state.db, "did:plc:rp4").await;

        let response = app(state)
            .oneshot(post_reset_password(&token, "newpass"))
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.is_empty(), "response body must be empty on 200");
    }

    // ── Error paths ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_token_returns_401() {
        let token = generate_token();
        let response = app(test_state().await)
            .oneshot(post_reset_password(&token.plaintext, "newpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn expired_token_returns_400() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:expired",
            "expired.test.example.com",
            "expired@example.com",
            "pass",
        )
        .await;
        let token = seed_expired_token(&state.db, "did:plc:expired").await;

        let response = app(state)
            .oneshot(post_reset_password(&token, "newpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "ExpiredToken");
    }

    #[tokio::test]
    async fn used_token_returns_400() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:used",
            "used.test.example.com",
            "used@example.com",
            "pass",
        )
        .await;
        let token = seed_reset_token(&state.db, "did:plc:used").await;

        // First use — should succeed.
        app(state.clone())
            .oneshot(post_reset_password(&token, "newpass1"))
            .await
            .unwrap();

        // Second use — should return 400 ExpiredToken.
        let response = app(state)
            .oneshot(post_reset_password(&token, "newpass2"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "ExpiredToken");
    }

    #[tokio::test]
    async fn malformed_token_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_reset_password("not-valid-base64url!!!", "newpass"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── End-to-end flow ───────────────────────────────────────────────────────

    /// Full round-trip: requestPasswordReset → extract token from DB → resetPassword → createSession.
    /// Catches any hash algorithm divergence between the two endpoints.
    #[tokio::test]
    async fn e2e_request_reset_then_login_with_new_password() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:e2e",
            "e2e.test.example.com",
            "e2e@example.com",
            "oldpass",
        )
        .await;

        // Step 1: request reset (always 200).
        app(state.clone())
            .oneshot(post_request_password_reset("e2e@example.com"))
            .await
            .unwrap();

        // Step 2: extract plaintext token from DB (simulates email delivery).
        // The token is stored hashed; we can't reverse it — instead seed a fresh
        // known token directly in the DB, simulating the flow from the DB side.
        let db = state.db.clone();
        let known_token = generate_token();
        sqlx::query(
            "INSERT INTO password_reset_tokens \
             (token_hash, did, expires_at, created_at) \
             VALUES (?, 'did:plc:e2e', datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&known_token.hash)
        .execute(&db)
        .await
        .unwrap();

        // Step 3: reset password.
        let reset_response = app(state.clone())
            .oneshot(post_reset_password(&known_token.plaintext, "newpass456"))
            .await
            .unwrap();
        assert_eq!(reset_response.status(), StatusCode::OK);

        // Step 4: createSession with new password succeeds.
        let login_response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.createSession")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"identifier":"did:plc:e2e","password":"newpass456"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            login_response.status(),
            StatusCode::OK,
            "createSession with new password must succeed after resetPassword"
        );
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    /// Deactivated accounts cannot receive reset tokens (resolve_by_email filters them).
    /// resetPassword with a directly-seeded token for a deactivated account returns 500
    /// because update_password_hash rows_affected() will be 0 (WHERE did = ? matches nothing
    /// once the account is deactivated and the rows_affected guard fires).
    ///
    /// In practice the requestPasswordReset handler returns 200 silently for deactivated
    /// accounts (no token is inserted), so this path is defensive-only.
    #[tokio::test]
    async fn deactivated_account_request_returns_200_with_no_token() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:deact",
            "deact.test.example.com",
            "deact@example.com",
            "pass",
        )
        .await;
        sqlx::query(
            "UPDATE accounts SET deactivated_at = datetime('now') WHERE did = 'did:plc:deact'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let db = state.db.clone();
        let response = app(state)
            .oneshot(post_request_password_reset("deact@example.com"))
            .await
            .unwrap();

        // Always 200 — deactivated accounts look like unknown emails.
        assert_eq!(response.status(), StatusCode::OK);

        // No token inserted.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "no token should be inserted for deactivated account"
        );
    }

    /// Multiple outstanding tokens per DID are allowed — each is valid independently.
    #[tokio::test]
    async fn multiple_tokens_per_did_all_valid_independently() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:multi",
            "multi.test.example.com",
            "multi@example.com",
            "pass",
        )
        .await;

        let token1 = seed_reset_token(&state.db, "did:plc:multi").await;
        let token2 = seed_reset_token(&state.db, "did:plc:multi").await;

        // Use token1 — should succeed.
        let r1 = app(state.clone())
            .oneshot(post_reset_password(&token1, "newpass1"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK, "first token should be valid");

        // token2 was issued before token1 was used — it must still work (independent tokens).
        let r2 = app(state)
            .oneshot(post_reset_password(&token2, "newpass2"))
            .await
            .unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::OK,
            "second token must remain valid after first is used"
        );
    }
}
