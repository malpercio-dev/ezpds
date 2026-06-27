// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool + firehose via AppState
// Processes: scope validation → clear the account's deactivation →
//            emit an `#account` firehose event so relays resume serving the repo
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.activateAccount

use axum::{body::Bytes, extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::accounts::{activate_account, AccountStateChange};

/// POST /xrpc/com.atproto.server.activateAccount
///
/// Reactivates the authenticated account: clears `deactivated_at` (and any pending
/// `deleteAfter`), making the repo accessible again, and emits an active `#account` firehose
/// event so relays resume serving it — but only on a real transition; activating an already-active
/// account is a 200 no-op that emits nothing. The endpoint takes no body, so a non-empty payload
/// is rejected with 400. Only full access-scope tokens are accepted, like `deactivateAccount`.
pub async fn activate_account_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    // The lexicon defines no input for activateAccount. Accept an empty (or whitespace-only) body,
    // but reject any actual payload so a malformed request is not silently treated as valid.
    if !body.iter().all(u8::is_ascii_whitespace) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "activateAccount does not accept a request body",
        ));
    }

    match activate_account(&state.db, &user.did).await? {
        // `NotFound` means no account row matched the token's DID — the account was removed out
        // from under an otherwise-valid token, mirroring `getPreferences`/`deactivateAccount`.
        AccountStateChange::NotFound => {
            tracing::warn!(did = %user.did, "activateAccount: account not found");
            return Err(ApiError::new(ErrorCode::InvalidToken, "account not found"));
        }
        // Already active: idempotent no-op. Don't re-emit a status-quo `#account` event.
        AccountStateChange::Unchanged => {
            tracing::debug!(did = %user.did, "activateAccount: already active; no event emitted");
        }
        // Real transition: tell subscribers the repo is active again so they resume serving it.
        AccountStateChange::Changed => {
            state.firehose.emit_account(user.did.clone(), true, None);
            tracing::info!(did = %user.did, "account activated");
        }
    }

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

    use crate::app::{app, test_state};
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{access_jwt, body_json};

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str, deactivated: bool) {
        // Bind the deactivation timestamp as a value (a fixed instant suffices for tests) rather
        // than splicing a SQL fragment, so the query stays fully parameterized.
        let deactivated_at: Option<&str> = if deactivated {
            Some("2026-01-01T00:00:00Z")
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at, deactivated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'), ?)",
        )
        .bind(did)
        .bind(email)
        .bind(deactivated_at)
        .execute(db)
        .await
        .unwrap();
    }

    fn scoped_jwt(secret: &[u8; 32], sub: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({ "scope": scope, "sub": sub, "iat": now, "exp": now + 7200_u64 }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn activate_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.activateAccount")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn deactivated_at(db: &sqlx::SqlitePool, did: &str) -> Option<String> {
        sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn activates_deactivated_account_and_emits_firehose_event() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:act1", "act1@example.com", true).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:act1");
        let db = state.db.clone();
        let mut rx = state.firehose.subscribe();

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert!(
            deactivated_at(&db, "did:plc:act1").await.is_none(),
            "deactivated_at must be cleared"
        );

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, "did:plc:act1");
        assert!(event.active);
        assert_eq!(event.status, None);
    }

    #[tokio::test]
    async fn already_active_account_is_a_noop_200_without_event() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:act2", "act2@example.com", false).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:act2");
        let mut rx = state.firehose.subscribe();

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "activating an already-active account is a 200 no-op"
        );
        assert!(
            rx.try_recv().is_err(),
            "activating an already-active account must not emit a status-quo #account event"
        );
    }

    #[tokio::test]
    async fn clears_pending_delete_after() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:act3", "act3@example.com", true).await;
        sqlx::query("UPDATE accounts SET delete_after = '2030-01-01T00:00:00Z' WHERE did = ?")
            .bind("did:plc:act3")
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:act3");
        let db = state.db.clone();

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let delete_after: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:act3")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            delete_after, None,
            "delete_after must be cleared on activation"
        );
    }

    #[tokio::test]
    async fn app_pass_token_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:act4", "act4@example.com", true).await;
        let token = scoped_jwt(&state.jwt_secret, "did:plc:act4", "com.atproto.appPass");

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn nonexistent_account_returns_401() {
        let state = test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:ghost");

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_empty_body_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:act5", "act5@example.com", true).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:act5");

        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.activateAccount")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"unexpected":"payload"}"#))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "activateAccount must reject a non-empty body"
        );
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.activateAccount")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
