// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool + firehose via AppState, optional JSON body
// Processes: scope validation → flip the account to deactivated (storing optional deleteAfter) →
//            emit an `#account` firehose event so relays stop serving the repo
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.deactivateAccount

use axum::{body::Bytes, extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::{AuthScope, SCOPE_ACCESS};
use crate::auth::oauth_scopes;
use crate::db::accounts::{deactivate_account, AccountStateChange};

/// The non-active status reported on the firehose `#account` event for a deactivation.
const STATUS_DEACTIVATED: &str = "deactivated";

#[derive(Deserialize)]
struct DeactivateAccountBody {
    /// Optional RFC 3339 instant after which the account should be permanently deleted. Stored
    /// verbatim once validated; the reaper that acts on it is a separate concern (not yet built).
    #[serde(rename = "deleteAfter")]
    delete_after: Option<String>,
}

/// Parse the optional request body of `deactivateAccount`.
///
/// The body is optional: an empty (or whitespace-only) body means "no scheduled deletion" and
/// yields `None`. A present body must be valid JSON; a present `deleteAfter` must be an RFC 3339
/// datetime. Anything else is a 400 so a malformed `deleteAfter` is never silently dropped.
fn parse_optional_delete_after(body: &[u8]) -> Result<Option<String>, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }

    let parsed: DeactivateAccountBody = serde_json::from_slice(body).map_err(|e| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            format!("invalid request body: {e}"),
        )
    })?;

    if let Some(delete_after) = &parsed.delete_after {
        chrono::DateTime::parse_from_rfc3339(delete_after).map_err(|_| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "deleteAfter must be an RFC 3339 datetime",
            )
        })?;
    }

    Ok(parsed.delete_after)
}

/// POST /xrpc/com.atproto.server.deactivateAccount
///
/// Temporarily deactivates the authenticated account: repo reads report a deactivated status
/// (`getRepoStatus`), write operations are rejected, and an `#account` firehose event is emitted
/// so relays stop serving the repo — but only on a real transition. An optional `deleteAfter`
/// records a requested permanent-deletion time. Idempotent — re-deactivating an already-
/// deactivated account refreshes `deleteAfter` and returns 200 without emitting another event.
/// Only full access-scope tokens are accepted, like `getSession`; app passwords cannot deactivate
/// an account.
pub async fn deactivate_account_handler(
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
    if user.scope_claim != SCOPE_ACCESS
        && !oauth_scopes::allows_account(&user.scope_claim, "status", "manage")
    {
        return Err(oauth_scopes::insufficient_scope(
            "token scope does not permit account status changes",
        ));
    }

    let delete_after = parse_optional_delete_after(&body)?;

    // Open a transaction so the status transition and its firehose `#account` event (if any)
    // commit atomically — a durable status change must never end up without a corresponding
    // durable firehose row (see `Firehose::stage_account`). The sequencer lock is acquired
    // *before* the transaction, per `Firehose::lock_emit`'s lock/connection-ordering contract.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %user.did, "failed to open deactivate transaction");
        ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
    })?;

    match deactivate_account(&mut tx, &user.did, delete_after.as_deref()).await? {
        // A valid JWT is not enough: the account row must still exist. `NotFound` means it was
        // removed out from under an otherwise-valid token, mirroring `getPreferences`.
        AccountStateChange::NotFound => {
            tx.rollback().await.ok();
            tracing::warn!(did = %user.did, "deactivateAccount: account not found");
            return Err(ApiError::new(ErrorCode::InvalidToken, "account not found"));
        }
        // Already deactivated: idempotent no-op. Don't re-emit a status-quo `#account` event, but
        // still commit — a re-deactivation refreshes `delete_after`.
        AccountStateChange::Unchanged => {
            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, did = %user.did, "failed to commit deactivate (no-op) transaction");
                ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
            })?;
            tracing::debug!(did = %user.did, "deactivateAccount: already deactivated; no event emitted");
        }
        // Real transition: tell subscribers the repo is no longer active so they stop serving it.
        AccountStateChange::Changed => {
            let pending = emit_guard
                .stage_account(
                    &mut tx,
                    user.did.clone(),
                    false,
                    Some(STATUS_DEACTIVATED.to_string()),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %user.did, "failed to stage #account deactivation event");
                    ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
                })?;
            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, did = %user.did, "failed to commit deactivate transaction");
                ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
            })?;
            pending.finish();
            tracing::info!(
                did = %user.did,
                scheduled_deletion = delete_after.is_some(),
                "account deactivated"
            );
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

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
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

    fn deactivate_request(token: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.deactivateAccount")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body)
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
    async fn deactivates_account_and_emits_firehose_event() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact1", "deact1@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:deact1");
        let db = state.db.clone();
        let mut rx = state.firehose.subscribe();

        let response = app(state)
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert!(
            deactivated_at(&db, "did:plc:deact1").await.is_some(),
            "deactivated_at must be set"
        );

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, "did:plc:deact1");
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deactivated"));
    }

    #[tokio::test]
    async fn stores_valid_delete_after() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact2", "deact2@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:deact2");
        let db = state.db.clone();

        let response = app(state)
            .oneshot(deactivate_request(
                &token,
                Body::from(r#"{"deleteAfter":"2030-01-01T00:00:00Z"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let stored: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:deact2")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stored.as_deref(), Some("2030-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn malformed_delete_after_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact3", "deact3@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:deact3");

        let response = app(state)
            .oneshot(deactivate_request(
                &token,
                Body::from(r#"{"deleteAfter":"not-a-date"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn is_idempotent() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact4", "deact4@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:deact4");

        let first = app(state.clone())
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app(state)
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "re-deactivating an already-deactivated account is a 200 no-op"
        );
    }

    #[tokio::test]
    async fn re_deactivating_does_not_emit_a_second_event() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact6", "deact6@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:deact6");
        let mut rx = state.firehose.subscribe();

        // First call transitions active → deactivated and emits one event.
        let first = app(state.clone())
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert!(
            matches!(rx.try_recv(), Ok(FirehoseEvent::Account(_))),
            "the first deactivation must emit one #account event"
        );

        // Second call is a status-quo no-op and must not emit again.
        let second = app(state)
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert!(
            rx.try_recv().is_err(),
            "re-deactivating an already-deactivated account must not emit a second event"
        );
    }

    #[tokio::test]
    async fn app_pass_token_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact5", "deact5@example.com").await;
        let token = scoped_jwt(&state.jwt_secret, "did:plc:deact5", "com.atproto.appPass");

        let response = app(state)
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn nonexistent_account_returns_401() {
        let state = test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:ghost");

        let response = app(state)
            .oneshot(deactivate_request(&token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.deactivateAccount")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
