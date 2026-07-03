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
// Email delivery is stubbed repo-wide (see `requestPasswordReset`) pending an outbound-email
// path: the plaintext token is logged via `tracing::info!` rather than emailed.
//
// Gather:  AuthenticatedUser (full access token) → DID
// Process: generate token → store hash (1h TTL) → "deliver" (log)
// Respond: 200, empty body

use axum::{extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::plc_operation_tokens::insert_plc_operation_token;
use crate::token::generate_token;

pub async fn request_plc_operation_signature(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    // Signing a PLC operation is a full-account action; app-password/refresh scopes are refused.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }

    let token = generate_token();
    insert_plc_operation_token(&state.db, &user.did, &token.hash).await?;

    // Stub delivery: log the plaintext token until an outbound-email path is implemented.
    tracing::info!(
        did = %user.did,
        plc_operation_token = %token.plaintext,
        "PLC operation signature token generated (email delivery not yet implemented)"
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
