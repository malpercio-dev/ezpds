// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.requestEmailConfirmation
//
// Mints a single-use, 1-hour email token authorizing a later `confirmEmail` call and delivers it
// to the account's current email address. Proving control of that address is what lets the PDS set
// `emailConfirmed = true`, which standard clients surface as "verify your email".
//
// Gather:  AuthenticatedUser (full access token) → DID
// Process: load account email → mint confirm token (1h TTL) → send email
// Respond: 200, empty body

use axum::{extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::auth::token::generate_token;
use crate::db::accounts::get_session_account;
use crate::db::email_tokens::{insert_email_token, EmailTokenPurpose};
use crate::no_input::NoInputBody;

pub async fn request_email_confirmation(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    // No lexicon input; reject a spurious body with 400 like the reference PDS (MM-291).
    _: NoInputBody,
) -> Result<StatusCode, ApiError> {
    // Managing the account email is a full-account action; app-password/refresh scopes are refused.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_account(&user.scope_claim, "email", "manage")?;

    let account = get_session_account(&state.db, &user.did)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "account not found"))?;

    let token = generate_token();
    insert_email_token(
        &state.db,
        &user.did,
        &token.hash,
        EmailTokenPurpose::Confirm,
    )
    .await?;

    let host = state.config.public_host();
    let message = crate::email::EmailMessage {
        to: account.email.clone(),
        subject: format!("Confirm your {host} email"),
        body: format!(
            "Confirm the email address on your {host} account.\n\n\
             Confirmation code: {token}\n\n\
             Enter this code in your app to confirm your email. It expires in 1 hour.\n\n\
             If you didn't request this, you can safely ignore this email.",
            token = token.plaintext,
        ),
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %user.did, error = %e, "failed to send email confirmation");
        return Err(ApiError::new(
            ErrorCode::ServiceUnavailable,
            "failed to send confirmation email",
        ));
    }

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{
        access_jwt, app_pass_jwt, seed_account_with_signing_key, state_with_failing_email,
    };

    fn post_req(jwt: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestEmailConfirmation")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn stores_confirm_token_for_authenticated_account() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqconfirm1111111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_tokens WHERE did = ? AND purpose = 'confirm'",
        )
        .bind(did)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 1, "one confirm token should be stored");
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state).oneshot(post_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// No lexicon input: a spurious body is rejected with 400 (reference-PDS parity, MM-291) and
    /// no token is minted.
    #[tokio::test]
    async fn non_empty_body_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqconfirm4444444444444444";
        seed_account_with_signing_key(&db, did, "dave.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestEmailConfirmation")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_tokens WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0, "a rejected request must not mint a token");
    }

    #[tokio::test]
    async fn app_password_scope_rejected() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqconfirm2222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        let jwt = app_pass_jwt(&state.jwt_secret, did, true);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn email_delivery_failure_returns_503() {
        let state = state_with_failing_email().await;
        let db = state.db.clone();
        let did = "did:plc:reqconfirm3333333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
