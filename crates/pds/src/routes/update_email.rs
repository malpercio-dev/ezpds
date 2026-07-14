// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.updateEmail
//
// Changes the account email and resets its confirmation state (a changed address is unconfirmed
// until re-verified). If the *current* email is confirmed, a token minted by `requestEmailUpdate`
// is required — proving the requester still controls the old address before it is abandoned. An
// unconfirmed current email can be changed without a token.
//
// Gather:  AuthenticatedUser (full access) + JSON {email, token?}
// Process: load account → (if confirmed) consume update token → update email + reset confirmation
// Respond: 200 on success; 400 on missing/bad token, invalid email, or an address already in use

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::auth::token::hash_bearer_token;
use crate::db::accounts::{get_session_account, update_account_email, EmailUpdateOutcome};
use crate::db::email_tokens::{consume_email_token, EmailTokenPurpose};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEmailRequest {
    email: String,
    #[serde(default)]
    token: Option<String>,
}

pub async fn update_email(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<UpdateEmailRequest>,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_account(&user.scope_claim, "email", "manage")?;

    // Normalize (trim + lowercase) so storage/lookup match the reference PDS's case-insensitive
    // email handling.
    let new_email = crate::uniqueness::normalize_email(&payload.email);
    // Minimal shape check — a real address has an '@' with something on each side. The SMTP layer
    // rejects a truly malformed address later, but catching it here yields a clean 400.
    if !is_plausible_email(&new_email) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "invalid email address",
        ));
    }

    let account = get_session_account(&state.db, &user.did)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "account not found"))?;

    // A confirmed current email may only be changed with a valid update token.
    if account.email_confirmed {
        let Some(token) = payload.token.as_deref() else {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "a confirmation token is required to change a confirmed email; call requestEmailUpdate first",
            ));
        };
        let token_hash = hash_bearer_token(token)
            .map_err(|_| ApiError::new(ErrorCode::ExpiredToken, "invalid update token"))?;
        let consumed =
            consume_email_token(&state.db, &user.did, &token_hash, EmailTokenPurpose::Update)
                .await?;
        if !consumed {
            return Err(ApiError::new(
                ErrorCode::ExpiredToken,
                "invalid or expired update token",
            ));
        }
    }

    match update_account_email(&state.db, &user.did, &new_email).await? {
        EmailUpdateOutcome::Updated => Ok(StatusCode::OK),
        EmailUpdateOutcome::Taken => Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "this email address is already in use",
        )),
        EmailUpdateOutcome::NotFound => Err(ApiError::new(
            ErrorCode::InvalidToken,
            "account not found or not active",
        )),
    }
}

/// A minimal plausibility check: exactly one `@` with a non-empty local part and a dotted domain.
/// Not a full RFC 5322 validation — just enough to reject obvious garbage before the DB write.
fn is_plausible_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::auth::token::generate_token;
    use crate::db::email_tokens::{insert_email_token, EmailTokenPurpose};
    use crate::routes::test_utils::{access_jwt, body_json, seed_account_with_signing_key};

    fn post_req(jwt: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.updateEmail")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn confirm(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query("UPDATE accounts SET email_confirmed_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(db)
            .await
            .unwrap();
    }

    async fn email_of(db: &sqlx::SqlitePool, did: &str) -> String {
        sqlx::query_scalar("SELECT email FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn unconfirmed_email_changes_without_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:updemail1111111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), r#"{"email":"new@example.com"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(email_of(&db, did).await, "new@example.com");
    }

    #[tokio::test]
    async fn confirmed_email_requires_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:updemail2222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        confirm(&db, did).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        // No token → 400.
        let response = app(state)
            .oneshot(post_req(Some(&jwt), r#"{"email":"new@example.com"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn confirmed_email_changes_with_valid_token_and_resets_confirmation() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:updemail3333333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        confirm(&db, did).await;
        let token = generate_token();
        insert_email_token(&db, did, &token.hash, EmailTokenPurpose::Update)
            .await
            .unwrap();
        let jwt = access_jwt(&state.jwt_secret, did);

        let body = format!(
            r#"{{"email":"changed@example.com","token":"{}"}}"#,
            token.plaintext
        );
        let response = app(state)
            .oneshot(post_req(Some(&jwt), &body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(email_of(&db, did).await, "changed@example.com");

        // Confirmation must be reset by the change.
        let confirmed_at: Option<String> =
            sqlx::query_scalar("SELECT email_confirmed_at FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            confirmed_at.is_none(),
            "email_confirmed_at must be reset when the address changes"
        );
    }

    #[tokio::test]
    async fn new_email_is_stored_normalized_lowercase() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:updemailnorm11111111111";
        seed_account_with_signing_key(&db, did, "norm.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(
                Some(&jwt),
                r#"{"email":"  MixedCase@Example.COM  "}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(email_of(&db, did).await, "mixedcase@example.com");
    }

    #[tokio::test]
    async fn duplicate_email_differing_only_by_case_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let existing = "did:plc:updemailexistingcase4444";
        let did = "did:plc:updemailcase5555555555555";
        seed_account_with_signing_key(&db, existing, "existingcase.example.com").await;
        seed_account_with_signing_key(&db, did, "davecase.example.com").await;
        let taken = email_of(&db, existing).await.to_uppercase();
        let jwt = access_jwt(&state.jwt_secret, did);

        let body = format!(r#"{{"email":"{taken}"}}"#);
        let response = app(state)
            .oneshot(post_req(Some(&jwt), &body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn duplicate_email_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let existing = "did:plc:updemailexisting444444444";
        let did = "did:plc:updemail5555555555555555";
        seed_account_with_signing_key(&db, existing, "existing.example.com").await;
        seed_account_with_signing_key(&db, did, "dave.example.com").await;
        let taken = email_of(&db, existing).await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let body = format!(r#"{{"email":"{taken}"}}"#);
        let response = app(state)
            .oneshot(post_req(Some(&jwt), &body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn invalid_email_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:updemail6666666666666666";
        seed_account_with_signing_key(&db, did, "erin.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), r#"{"email":"not-an-email"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_req(None, r#"{"email":"x@example.com"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
