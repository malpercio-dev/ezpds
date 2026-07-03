// pattern: Imperative Shell
//
// Gathers: DB pool + firehose via AppState, JSON body { did, password, token }
// Processes: validate body → verify account password → consume the single-use email token →
//            permanently delete the account (all local data) and emit an `#account` (deleted) frame
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.deleteAccount
//
// Unlike deactivate/activate, this endpoint is **not** session-authenticated: the credentials are
// the `did` + `password` + `token` in the body (a user must be able to delete an account they can
// no longer log a session into). The email `token` (minted by `requestAccountDelete`) is the
// second factor alongside the account password. The heavy lifting — the multi-table atomic delete,
// the firehose frame, and on-disk blob reclamation — lives in `account_delete::purge_account`,
// shared with the scheduled-deletion reaper.

use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::account_delete::purge_account;
use crate::app::AppState;
use crate::auth::password::{verify_password, VerifyResult};
use crate::db::account_deletion_tokens::consume_account_deletion_token;
use crate::db::accounts::account_password_hash;
use crate::token::hash_bearer_token;

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    did: String,
    password: String,
    token: String,
}

/// The uniform error for any credential failure (unknown DID, no password on file, wrong password).
/// Kept deliberately generic so the endpoint is not an account-existence or password oracle — the
/// email token is bound to the DID, so a legitimate deleter always has all three factors anyway.
fn invalid_credentials() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, "invalid credentials")
}

/// POST /xrpc/com.atproto.server.deleteAccount
///
/// Permanently deletes the account named by `did` after verifying its `password` and a single-use
/// email `token` (from `requestAccountDelete`). On success every local trace of the account is
/// removed — repo blocks/blobs (including on-disk blob files), sessions, tokens, handles, DID-doc
/// cache, preferences, app passwords, and the account row — and an `#account` frame
/// (`active=false`, `status="deleted"`) is broadcast so relays drop the repo. The did:plc identity
/// itself is untouched (the wallet owns the rotation key), matching ezpds's wallet-native model.
///
/// Credential failures return a uniform 401; a malformed body is 400. Deleting an
/// already-deleted account (a race with the reaper or a duplicate request) is a 200 no-op.
pub async fn delete_account_handler(
    State(state): State<AppState>,
    Json(payload): Json<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    if payload.did.trim().is_empty()
        || payload.password.is_empty()
        || payload.token.trim().is_empty()
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "did, password, and token are required",
        ));
    }

    // Verify the account password first, so a wrong password never burns the single-use token.
    // The lookup is deliberately lifecycle-unfiltered — a deactivated account must still be
    // deletable.
    match account_password_hash(&state.db, &payload.did).await? {
        // No such account, or a mobile account with no main password: nothing to verify against.
        None | Some(None) => return Err(invalid_credentials()),
        Some(Some(hash)) => match verify_password(&hash, &payload.password) {
            VerifyResult::Ok => {}
            VerifyResult::WrongPassword => return Err(invalid_credentials()),
            VerifyResult::CorruptHash => {
                tracing::error!(
                    did = %payload.did,
                    "stored password_hash is not a valid PHC string; possible DB corruption"
                );
                return Err(ApiError::new(ErrorCode::InternalError, "internal error"));
            }
        },
    }

    // Redeem the email token (atomic single-use, bound to the DID). Password is already verified,
    // so consuming here neither leaks account existence nor burns a token on a wrong password.
    let token_hash = hash_bearer_token(&payload.token)?;
    if !consume_account_deletion_token(&state.db, &payload.did, &token_hash).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "invalid or expired account deletion token",
        ));
    }

    // Both factors check out — permanently delete. A `NotFound` here means the account was deleted
    // out from under us between the password check and now (a race with the reaper or a duplicate
    // request); treat it as an idempotent success.
    purge_account(&state, &payload.did).await?;

    Ok(StatusCode::OK)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::db::account_deletion_tokens::insert_account_deletion_token;
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{body_json, insert_account_with_password};
    use crate::token::generate_token;

    fn post_req(json: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.deleteAccount")
            .header("Content-Type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap()
    }

    /// Seed a deletion token for `did`, returning its plaintext (as a client would receive it).
    async fn seed_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        insert_account_deletion_token(db, did, &token.hash)
            .await
            .unwrap();
        token.plaintext
    }

    async fn account_exists(db: &sqlx::SqlitePool, did: &str) -> bool {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap();
        count > 0
    }

    #[tokio::test]
    async fn valid_password_and_token_deletes_and_emits_frame() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del1";
        insert_account_with_password(&db, did, "del1.example.com", "del1@example.com", "hunter2")
            .await;
        let token = seed_token(&db, did).await;
        let mut rx = state.firehose.subscribe();

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "hunter2", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!account_exists(&db, did).await, "account must be gone");

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, did);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deleted"));
    }

    #[tokio::test]
    async fn wrong_password_returns_401_and_preserves_account_and_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del2";
        insert_account_with_password(&db, did, "del2.example.com", "del2@example.com", "hunter2")
            .await;
        let token = seed_token(&db, did).await;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "wrong", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(account_exists(&db, did).await, "account must survive");

        // The token must not have been consumed by a failed password attempt.
        let used_at: Option<String> =
            sqlx::query_scalar("SELECT used_at FROM account_deletion_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(used_at, None, "a wrong password must not burn the token");
    }

    #[tokio::test]
    async fn invalid_token_returns_401_and_preserves_account() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del3";
        insert_account_with_password(&db, did, "del3.example.com", "del3@example.com", "hunter2")
            .await;
        // A syntactically valid but never-issued token (base64url of 32 bytes hashes cleanly).
        let bogus = crate::token::generate_token().plaintext;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "hunter2", "token": bogus,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
        assert!(account_exists(&db, did).await, "account must survive");
    }

    #[tokio::test]
    async fn unknown_account_returns_401() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": "did:plc:ghostdelete", "password": "x", "token": "y",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mobile_account_without_password_cannot_be_deleted() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:delmobile";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'm@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&db)
        .await
        .unwrap();
        let token = seed_token(&db, did).await;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "anything", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(account_exists(&db, did).await, "account must survive");
    }

    #[tokio::test]
    async fn missing_fields_returns_400() {
        let state: AppState = test_state().await;
        let response = app(state)
            .oneshot(post_req(
                serde_json::json!({ "did": "", "password": "", "token": "" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
