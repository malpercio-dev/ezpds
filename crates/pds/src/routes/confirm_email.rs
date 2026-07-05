// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.confirmEmail
//
// Consumes a token minted by `requestEmailConfirmation` and marks the account's email confirmed
// (`email_confirmed_at`), which `getSession` then reports as `emailConfirmed = true`. Two factors:
// a full-access session AND the single-use email token (proving control of the address). The
// submitted `email` must match the account's current address so a token minted before an email
// change can't confirm the new address.
//
// Gather:  AuthenticatedUser (full access) + JSON {email, token}
// Process: load account → check email matches → consume confirm token → set email_confirmed_at
// Respond: 200 on success; 400 on email mismatch / bad token

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::db::accounts::{get_session_account, set_email_confirmed};
use crate::db::email_tokens::{consume_email_token, EmailTokenPurpose};
use crate::token::hash_bearer_token;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmEmailRequest {
    email: String,
    token: String,
}

pub async fn confirm_email(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<ConfirmEmailRequest>,
) -> Result<StatusCode, ApiError> {
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

    // The submitted email must be the account's current address (case-insensitive). Rejecting a
    // mismatch prevents confirming a stale address with a token minted before an email change.
    if !account.email.eq_ignore_ascii_case(&payload.email) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "email does not match the account email",
        ));
    }

    // Hash the wire token and atomically consume it (bound to this DID + the confirm purpose).
    // A malformed token hashes fine but simply won't match any stored row.
    let token_hash = hash_bearer_token(&payload.token)
        .map_err(|_| ApiError::new(ErrorCode::ExpiredToken, "invalid confirmation token"))?;
    let consumed = consume_email_token(
        &state.db,
        &user.did,
        &token_hash,
        EmailTokenPurpose::Confirm,
    )
    .await?;
    if !consumed {
        return Err(ApiError::new(
            ErrorCode::ExpiredToken,
            "invalid or expired confirmation token",
        ));
    }

    // Mark confirmed. The token was already consumed; if this update somehow matches no active
    // account (e.g. a concurrent deactivation), surface an error rather than silently succeeding.
    if !set_email_confirmed(&state.db, &user.did).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "account not found or not active",
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
    use crate::db::email_tokens::{insert_email_token, EmailTokenPurpose};
    use crate::routes::test_utils::{access_jwt, body_json, seed_account_with_signing_key};
    use crate::token::generate_token;

    fn post_req(jwt: Option<&str>, email: &str, token: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.confirmEmail")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder
            .body(Body::from(format!(
                r#"{{"email":"{email}","token":"{token}"}}"#
            )))
            .unwrap()
    }

    /// Seed a confirm token for `did`, returning the plaintext.
    async fn seed_confirm_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        insert_email_token(db, did, &token.hash, EmailTokenPurpose::Confirm)
            .await
            .unwrap();
        token.plaintext
    }

    #[tokio::test]
    async fn valid_token_confirms_email() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:confirmemail1111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        // seed_account_with_signing_key inserts email `<handle>@example.com`? verify below.
        let email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        let token = seed_confirm_token(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), &email, &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let confirmed_at: Option<String> =
            sqlx::query_scalar("SELECT email_confirmed_at FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            confirmed_at.is_some(),
            "email_confirmed_at must be set after confirmEmail"
        );
    }

    #[tokio::test]
    async fn wrong_email_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:confirmemail2222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        let token = seed_confirm_token(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), "wrong@example.com", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn unknown_token_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:confirmemail3333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        let email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        let bogus = generate_token();
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), &email, &bogus.plaintext))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "ExpiredToken");
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_req(None, "x@example.com", "tok"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_is_single_use() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:confirmemail4444444444444";
        seed_account_with_signing_key(&db, did, "dave.example.com").await;
        let email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        let token = seed_confirm_token(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let first = app(state.clone())
            .oneshot(post_req(Some(&jwt), &email, &token))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app(state)
            .oneshot(post_req(Some(&jwt), &email, &token))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::BAD_REQUEST,
            "a consumed confirm token must not work twice"
        );
    }
}
