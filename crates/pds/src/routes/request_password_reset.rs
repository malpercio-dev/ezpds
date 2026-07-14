// pattern: Imperative Shell
//
// Gathers: JSON body {email}, DB pool
// Processes: email lookup → token generation → DB insert → send reset email
// Returns: 200 always (prevents email enumeration)
//
// Implements: POST /xrpc/com.atproto.server.requestPasswordReset

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::accounts::resolve_by_email;
use crate::db::password_reset::insert_reset_token;
use crate::token::generate_token;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetRequest {
    email: String,
}

/// POST /xrpc/com.atproto.server.requestPasswordReset
///
/// Generates a short-lived (1-hour) single-use reset token for the given email address.
/// Always returns 200 regardless of whether the email exists, to prevent account enumeration.
/// The token is delivered via the configured [`crate::email::EmailSender`] (the default log
/// sender writes it to the logs; SMTP delivers a real email). Delivery failures are logged but
/// still return 200 so the response never reveals whether the address exists.
pub async fn request_password_reset(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<RequestPasswordResetRequest>,
) -> StatusCode {
    // --- Look up account by email ---
    // Generate and discard a token on all non-found paths to equalize work with the
    // happy path and make timing-based email enumeration impractical.
    let account = match resolve_by_email(&state.db, &payload.email).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            let _ = generate_token();
            return StatusCode::OK;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                endpoint = "requestPasswordReset",
                "DB error looking up account by email; returning 200 to prevent enumeration"
            );
            let _ = generate_token();
            return StatusCode::OK;
        }
    };

    // --- Generate reset token ---
    let token = generate_token();

    // --- Persist token in DB ---
    if let Err(e) = insert_reset_token(&state.db, &account.did, &token.hash).await {
        tracing::error!(
            did = %account.did,
            error = %e,
            "failed to store password reset token; returning 200 to prevent enumeration"
        );
        return StatusCode::OK;
    }

    // --- Deliver the reset token by email ---
    // Send to the requested address (which `resolve_by_email` matched to this account). A delivery
    // failure is logged but still returns 200: this endpoint must never reveal whether an email
    // exists, and a best-effort notification must not surface a 500 to an anonymous caller.
    let host = state.config.public_host();
    let message = crate::email::EmailMessage {
        to: payload.email.clone(),
        subject: format!("Reset your {host} password"),
        body: format!(
            "A password reset was requested for your {host} account.\n\n\
             Reset code: {token}\n\n\
             Enter this code in your app to choose a new password. It expires in 1 hour.\n\n\
             If you didn't request this, you can safely ignore this email.",
            token = token.plaintext,
        ),
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %account.did, error = %e, "failed to send password reset email");
    }

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

    /// Accounts are now stored with a normalized (lowercase) email. This confirms a reset
    /// request submitted in a *different* case than what the user originally typed at signup
    /// still resolves — this is the fix for a `requestPasswordReset` that used to silently
    /// no-op whenever the submitted email's case didn't byte-exact-match the stored one.
    #[tokio::test]
    async fn differently_cased_reset_request_resolves_normalized_stored_email() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:mixedcasereset",
            "mixedcasereset.test.example.com",
            "mixedcase@example.com",
            "hunter2",
        )
        .await;

        let db = state.db.clone();
        let response = app(state)
            .oneshot(post_request_password_reset("MixedCase@Example.com"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE did = 'did:plc:mixedcasereset'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            count, 1,
            "a differently-cased reset request must resolve the normalized stored email"
        );
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

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens")
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
        assert!(
            diff < 5,
            "expiry should be ~1 hour from now, got {diff}s drift"
        );
    }
}
