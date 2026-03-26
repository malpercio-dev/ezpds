// pattern: Imperative Shell
//
// Gathers: JSON body {email}, DB pool
// Processes: email lookup → token generation → DB insert → log token (email stub)
// Returns: 200 always (prevents email enumeration)
//
// Implements: POST /xrpc/com.atproto.server.requestPasswordReset

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::accounts::resolve_by_email;
use crate::db::password_reset::insert_reset_token;
use crate::routes::token::generate_token;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetRequest {
    email: String,
}

/// POST /xrpc/com.atproto.server.requestPasswordReset
///
/// Generates a short-lived (1-hour) single-use reset token for the given email address.
/// Always returns 200 regardless of whether the email exists, to prevent account enumeration.
/// Email delivery is stubbed — the plaintext token is logged via `tracing::info!`.
pub async fn request_password_reset(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<RequestPasswordResetRequest>,
) -> StatusCode {
    // --- Look up account by email ---
    // Silently return 200 on any failure to prevent enumeration.
    let account = match resolve_by_email(&state.db, &payload.email).await {
        Ok(Some(account)) => account,
        Ok(None) => return StatusCode::OK,
        Err(_) => return StatusCode::OK,
    };

    // --- Generate reset token ---
    let token = generate_token();

    // --- Persist token in DB ---
    if let Err(e) = insert_reset_token(&state.db, &account.did, &token.hash).await {
        tracing::error!(error = %e, "failed to store password reset token; returning 200 to prevent enumeration");
        return StatusCode::OK;
    }

    // --- Stub: log token (replace with email delivery in a future wave) ---
    tracing::info!(
        did = %account.did,
        reset_token = %token.plaintext,
        "password reset token generated (email delivery not yet implemented)"
    );

    StatusCode::OK
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
    use crate::routes::test_utils::insert_account_with_password;

    fn post_request_password_reset(email: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestPasswordReset")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"email":"{email}"}}"#)))
            .unwrap()
    }

    #[tokio::test]
    async fn returns_200_for_known_email() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:reset1",
            "reset1.test.example.com",
            "reset1@example.com",
            "hunter2",
        )
        .await;

        let response = app(state)
            .oneshot(post_request_password_reset("reset1@example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_200_for_unknown_email() {
        let response = app(test_state().await)
            .oneshot(post_request_password_reset("nobody@example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn known_email_inserts_token_in_db() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:tokencheck",
            "tokencheck.test.example.com",
            "tokencheck@example.com",
            "pass",
        )
        .await;

        let db = state.db.clone();
        app(state)
            .oneshot(post_request_password_reset("tokencheck@example.com"))
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE did = 'did:plc:tokencheck'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 1, "one reset token should be inserted");
    }

    #[tokio::test]
    async fn unknown_email_does_not_insert_token() {
        let state = test_state().await;
        let db = state.db.clone();

        app(state)
            .oneshot(post_request_password_reset("ghost@example.com"))
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 0, "no token should be inserted for unknown email");
    }

    #[tokio::test]
    async fn response_body_is_empty() {
        let response = app(test_state().await)
            .oneshot(post_request_password_reset("any@example.com"))
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.is_empty(), "response body must be empty");
    }

    #[tokio::test]
    async fn token_has_1_hour_expiry() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:expiry",
            "expiry.test.example.com",
            "expiry@example.com",
            "pass",
        )
        .await;

        let db = state.db.clone();
        app(state)
            .oneshot(post_request_password_reset("expiry@example.com"))
            .await
            .unwrap();

        // expires_at should be approximately 1 hour in the future (within 5 seconds of drift).
        let diff: i64 = sqlx::query_scalar(
            "SELECT ABS(strftime('%s', expires_at) - strftime('%s', datetime('now', '+1 hour'))) \
             FROM password_reset_tokens WHERE did = 'did:plc:expiry'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(diff < 5, "expiry should be ~1 hour from now, got {diff}s drift");
    }
}
