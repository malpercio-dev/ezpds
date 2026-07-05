// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.requestAccountDelete
//
// Mints a single-use, 1-hour email token that authorizes a later `deleteAccount` call. Deleting
// an account is destructive and irreversible, so — like the reference PDS — we require the user to
// prove control of the account email before the deletion is honored (the token is the second
// factor alongside the account password that `deleteAccount` itself checks).
//
// Email delivery is stubbed repo-wide (see `requestPasswordReset` / `requestPlcOperationSignature`)
// pending an outbound-email path: the plaintext token is logged via `tracing::info!` rather than
// emailed.
//
// Gather:  AuthenticatedUser (full access token) → DID
// Process: generate token → store hash (1h TTL) → "deliver" (log)
// Respond: 200, empty body

use axum::{extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::db::account_deletion_tokens::insert_account_deletion_token;
use crate::token::generate_token;

pub async fn request_account_delete(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    // Deleting an account is a full-account action; app-password/refresh scopes are refused.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_account(&user.scope_claim, "status", "manage")?;

    let token = generate_token();
    insert_account_deletion_token(&state.db, &user.did, &token.hash).await?;

    // Stub delivery: log the plaintext token until an outbound-email path is implemented.
    tracing::info!(
        did = %user.did,
        account_deletion_token = %token.plaintext,
        "account deletion token generated (email delivery not yet implemented)"
    );

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
    use crate::routes::test_utils::{access_jwt, app_pass_jwt, seed_account_with_signing_key};

    fn post_req(jwt: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.requestAccountDelete")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::empty()).unwrap()
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

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state).oneshot(post_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn app_password_scope_rejected() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqdelete2222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        let jwt = app_pass_jwt(&state.jwt_secret, did, true);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
