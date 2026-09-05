// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.requestAccountDelete
//
// Mints a single-use, 1-hour email token that authorizes a later `deleteAccount` call. Deleting
// an account is destructive and irreversible, so — like the reference PDS — we require the user to
// prove control of the account email before the deletion is honored (the token is the second
// factor alongside the account password that `deleteAccount` itself checks).
//
// The token is delivered to the account email via the configured [`crate::email::EmailSender`]
// (the default log sender writes it to the logs; SMTP delivers a real email).
//
// Gather:  AuthenticatedUser (full access token) → DID
// Process: generate token → store hash (1h TTL) → email it
// Respond: 200, empty body

use axum::{extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::auth::token::generate_token;
use crate::db::account_deletion_tokens::insert_account_deletion_token;
use crate::db::accounts::get_session_account;
use crate::no_input::NoInputBody;

pub async fn request_account_delete(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    // No lexicon input; reject a spurious body with 400 like the reference PDS.
    _: NoInputBody,
) -> Result<StatusCode, ApiError> {
    // Deleting an account is a full-account action; app-password/refresh scopes are refused.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_account(&user.scope_claim, "status", "manage")?;

    let account = get_session_account(&state.db, &user.did)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "account not found"))?;

    let token = generate_token();
    insert_account_deletion_token(&state.db, &user.did, &token.hash).await?;

    let host = state.config.public_host();
    let message = crate::email::EmailMessage {
        to: account.email.clone(),
        subject: format!("Confirm deletion of your {host} account"),
        body: format!(
            "Permanent deletion of your {host} account was requested. This cannot be undone.\n\n\
             Confirmation code: {token}\n\n\
             Enter this code in your app to confirm deletion. It expires in 1 hour.\n\n\
             If you didn't request this, ignore this email and consider changing your password.",
            token = token.plaintext,
        ),
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %user.did, error = %e, "failed to send account deletion token");
        return Err(ApiError::new(
            ErrorCode::ServiceUnavailable,
            "failed to send confirmation email",
        ));
    }

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{
        access_jwt, post_req as shared_post_req, seed_account_with_signing_key,
    };

    const URI: &str = "/xrpc/com.atproto.server.requestAccountDelete";

    fn post_req(jwt: Option<&str>) -> axum::http::Request<axum::body::Body> {
        shared_post_req(URI, jwt, None)
    }

    #[tokio::test]
    async fn stores_token_for_authenticated_account() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqdelete1111111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM account_deletion_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 1, "one account deletion token should be stored");
    }
}
