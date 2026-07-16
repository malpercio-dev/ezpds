// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.requestEmailUpdate
//
// Reports whether changing the account email requires an email token, and — when it does — mints
// and delivers one. A confirmed email may only be changed by someone who can still receive mail at
// the current address, so a token is required; an unconfirmed email carries no such proof and can
// be changed outright.
//
// Gather:  AuthenticatedUser (full access) → DID
// Process: load account → tokenRequired = emailConfirmed → if required, mint update token + send
// Respond: 200 {tokenRequired: bool}

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::auth::token::generate_token;
use crate::db::accounts::get_session_account;
use crate::db::email_tokens::{insert_email_token, EmailTokenPurpose};
use crate::no_input::NoInputBody;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestEmailUpdateResponse {
    token_required: bool,
}

pub async fn request_email_update(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    // No lexicon input; reject a spurious body with 400 like the reference PDS.
    _: NoInputBody,
) -> Result<Json<RequestEmailUpdateResponse>, ApiError> {
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

    // A confirmed email requires proof-of-control (a token) to change; an unconfirmed one does not.
    let token_required = account.email_confirmed;

    if token_required {
        let token = generate_token();
        insert_email_token(&state.db, &user.did, &token.hash, EmailTokenPurpose::Update).await?;

        let host = state.config.public_host();
        let message = crate::email::EmailMessage {
            to: account.email.clone(),
            subject: format!("Confirm your {host} email change"),
            body: format!(
                "A change to the email address on your {host} account was requested.\n\n\
                 Confirmation code: {token}\n\n\
                 Enter this code in your app to authorize the change. It expires in 1 hour.\n\n\
                 If you didn't request this, you can safely ignore this email — your address is \
                 unchanged.",
                token = token.plaintext,
            ),
        };
        if let Err(e) = state.email.send(message).await {
            tracing::error!(did = %user.did, error = %e, "failed to send email-update token");
            return Err(ApiError::new(
                ErrorCode::ServiceUnavailable,
                "failed to send confirmation email",
            ));
        }
    }

    Ok(Json(RequestEmailUpdateResponse { token_required }))
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
        access_jwt, body_json, seed_account_with_signing_key, state_with_failing_email,
    };

    fn post_req(jwt: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestEmailUpdate")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn confirm(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query("UPDATE accounts SET email_confirmed_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unconfirmed_email_needs_no_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:requpdate1111111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["tokenRequired"], false);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_tokens WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0, "no token minted when email is unconfirmed");
    }

    #[tokio::test]
    async fn confirmed_email_requires_and_mints_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:requpdate2222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        confirm(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["tokenRequired"], true);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_tokens WHERE did = ? AND purpose = 'update'",
        )
        .bind(did)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 1, "an update token should be minted");
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state).oneshot(post_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// No lexicon input: a spurious body is rejected with 400 (reference-PDS parity) and
    /// no token is minted.
    #[tokio::test]
    async fn non_empty_body_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:requpdate4444444444444444";
        seed_account_with_signing_key(&db, did, "dave.example.com").await;
        confirm(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestEmailUpdate")
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
    async fn email_delivery_failure_returns_503() {
        // Delivery only happens when a token is required (confirmed email), so confirm first.
        let state = state_with_failing_email().await;
        let db = state.db.clone();
        let did = "did:plc:requpdate3333333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        confirm(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
