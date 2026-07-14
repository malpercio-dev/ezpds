// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.identity.requestPlcOperationSignature
//
// Mints a single-use, 1-hour email token that authorizes a later `signPlcOperation`
// call. This is the interop (PDS-signed) migration path (ADR-0002): proving control
// of the account email before the PDS will sign a DID-repointing operation on the
// account's behalf. The wallet-authorized path signs its identity leg locally and
// never calls this.
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
use crate::db::accounts::get_session_account;
use crate::db::plc_operation_tokens::insert_plc_operation_token;
use crate::identity::plc::ensure_did_plc;
use crate::no_input::NoInputBody;

pub async fn request_plc_operation_signature(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    // No lexicon input; reject a spurious body with 400 like the reference PDS (MM-291).
    _: NoInputBody,
) -> Result<StatusCode, ApiError> {
    // Signing a PLC operation is a full-account action; app-password/refresh scopes are refused.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_identity(&user.scope_claim, "*")?;

    // PLC operations only apply to a did:plc identity — reject a did:web account explicitly rather
    // than minting a token for a signPlcOperation that could never succeed.
    ensure_did_plc(&user.did)?;

    let account = get_session_account(&state.db, &user.did)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidToken, "account not found"))?;

    let token = generate_token();
    insert_plc_operation_token(&state.db, &user.did, &token.hash).await?;

    let host = state.config.public_host();
    let message = crate::email::EmailMessage {
        to: account.email.clone(),
        subject: format!("Authorize an identity operation on {host}"),
        body: format!(
            "An identity (PLC) operation was requested on your {host} account.\n\n\
             Authorization code: {token}\n\n\
             Enter this code in your app to authorize the operation. It expires in 1 hour.\n\n\
             If you didn't request this, you can safely ignore this email.",
            token = token.plaintext,
        ),
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %user.did, error = %e, "failed to send PLC operation token");
        return Err(ApiError::new(
            ErrorCode::ServiceUnavailable,
            "failed to send authorization email",
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
            .uri("/xrpc/com.atproto.identity.requestPlcOperationSignature")
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
        let did = "did:plc:reqplcsig1111111111111111";
        seed_account_with_signing_key(&db, did, "alice.example.com").await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM plc_operation_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 1, "one PLC operation token should be stored");
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state).oneshot(post_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The lexicon defines no input; a spurious body is rejected with 400, matching the reference
    /// PDS (the MM-291 divergence this route concealed).
    #[tokio::test]
    async fn non_empty_body_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqplcsig4444444444444444";
        seed_account_with_signing_key(&db, did, "dave.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.requestPlcOperationSignature")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"unexpected":"payload"}"#))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM plc_operation_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 0, "a rejected request must not mint a token");
    }

    #[tokio::test]
    async fn email_delivery_failure_returns_503() {
        let state = state_with_failing_email().await;
        let db = state.db.clone();
        let did = "did:plc:reqplcsig3333333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        let jwt = access_jwt(&state.jwt_secret, did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A did:web account gets an explicit "not a did:plc" 400 before any token is minted or emailed
    /// — a signPlcOperation for a did:web identity could never succeed, so no token is issued.
    #[tokio::test]
    async fn did_web_account_rejected_and_no_token_minted() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:web:malpercio.dev";
        // Seed an account row so the guard, not a missing-account lookup, is what rejects.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind("operator@malpercio.dev")
        .execute(&db)
        .await
        .unwrap();
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM plc_operation_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            count, 0,
            "no PLC operation token may be minted for a did:web account"
        );
    }

    #[tokio::test]
    async fn app_password_scope_rejected() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:reqplcsig2222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        let jwt = app_pass_jwt(&[0x42u8; 32], did, true);

        let response = app(state).oneshot(post_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
