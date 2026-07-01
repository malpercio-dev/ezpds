// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool + firehose via AppState
// Processes: scope validation → clear the account's deactivation →
//            emit an `#account` firehose event (and a chained Sync v1.1 `#sync` head assertion
//            when the account has a repo) so relays resume serving and re-anchor to the repo
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.activateAccount

use axum::{body::Bytes, extract::State, http::StatusCode};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::accounts::{activate_account, AccountStateChange};
use crate::db::blocks::SqliteBlockStore;
use crate::firehose::SyncInput;
use repo_engine::Cid;

/// POST /xrpc/com.atproto.server.activateAccount
///
/// Reactivates the authenticated account: clears `deactivated_at` (and any pending
/// `deleteAfter`), making the repo accessible again, and emits an active `#account` firehose event
/// — followed by a Sync v1.1 `#sync` head assertion when the account has a repo — so relays resume
/// serving it and re-anchor to its current commit. Both fire only on a real transition; activating
/// an already-active account is a 200 no-op that emits nothing. The endpoint takes no body, so a
/// non-empty payload is rejected with 400. Only full access-scope tokens are accepted, like
/// `deactivateAccount`.
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

    // Build the Sync v1.1 `#sync` state assertion (a CAR carrying just the signed commit block)
    // *before* opening the transaction: this crate's single-connection pool can't serve the block
    // read while the transaction holds the connection. It is best-effort — an account with no repo,
    // no stored rev, or an unreadable commit block emits the `#account` frame alone. Activation
    // never moves the repo root, so reading the head here (outside the transaction) is stable.
    let sync = build_activation_sync(&state, &user.did).await;

    // Open a transaction so the status transition and its firehose `#account` (and chained `#sync`)
    // events commit atomically — a durable status change must never end up without a corresponding
    // durable firehose row (see `Firehose::stage_account`). The sequencer lock is acquired
    // *before* the transaction, per `Firehose::lock_emit`'s lock/connection-ordering contract.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %user.did, "failed to open activate transaction");
        ApiError::new(ErrorCode::InternalError, "failed to activate account")
    })?;

    match activate_account(&mut tx, &user.did).await? {
        // `NotFound` means no account row matched the token's DID — the account was removed out
        // from under an otherwise-valid token, mirroring `getPreferences`/`deactivateAccount`.
        AccountStateChange::NotFound => {
            tx.rollback().await.ok();
            tracing::warn!(did = %user.did, "activateAccount: account not found");
            return Err(ApiError::new(ErrorCode::InvalidToken, "account not found"));
        }
        // Already active: idempotent no-op. Don't re-emit a status-quo `#account` event.
        AccountStateChange::Unchanged => {
            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, did = %user.did, "failed to commit activate (no-op) transaction");
                ApiError::new(ErrorCode::InternalError, "failed to activate account")
            })?;
            tracing::debug!(did = %user.did, "activateAccount: already active; no event emitted");
        }
        // Real transition: tell subscribers the repo is active again so they resume serving it,
        // and (when we could build one) chain a `#sync` head assertion so a relay that drifted
        // while the account was deactivated re-anchors to its current commit.
        AccountStateChange::Changed => {
            let account = emit_guard
                .stage_account(&mut tx, user.did.clone(), true, None)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %user.did, "failed to stage #account activation event");
                    ApiError::new(ErrorCode::InternalError, "failed to activate account")
                })?;
            match sync {
                Some(sync_input) => {
                    let pending = account.stage_sync(&mut tx, sync_input).await.map_err(|e| {
                        tracing::error!(error = %e, did = %user.did, "failed to stage #sync activation event");
                        ApiError::new(ErrorCode::InternalError, "failed to activate account")
                    })?;
                    tx.commit().await.map_err(|e| {
                        tracing::error!(error = %e, did = %user.did, "failed to commit activate transaction");
                        ApiError::new(ErrorCode::InternalError, "failed to activate account")
                    })?;
                    pending.finish();
                }
                None => {
                    tx.commit().await.map_err(|e| {
                        tracing::error!(error = %e, did = %user.did, "failed to commit activate transaction");
                        ApiError::new(ErrorCode::InternalError, "failed to activate account")
                    })?;
                    account.finish();
                }
            }
            tracing::info!(did = %user.did, "account activated");
        }
    }

    Ok(StatusCode::OK)
}

/// Assemble the Sync v1.1 `#sync` input for an account being reactivated: a CARv1 (root = the
/// repo head) carrying just the signed commit block, plus the commit's `rev`. Best-effort — returns
/// `None` (so the caller emits `#account` alone) when the account has no repo, no stored `rev`, an
/// unparseable head CID, or a commit block that can't be read. Must be called *before* the caller
/// opens its transaction: it reads the block store, which needs the pool's sole connection.
async fn build_activation_sync(state: &AppState, did: &str) -> Option<SyncInput> {
    let status = crate::db::accounts::get_repo_status(&state.db, did)
        .await
        .ok()??;
    let head = status.head?;
    let rev = status.rev?;
    let root = Cid::try_from(head.as_str()).ok()?;
    let mut store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    // A single-root CAR containing only the commit block — everything a relay needs to anchor to
    // this head, and comfortably under the lexicon's 10 KB `#sync.blocks` cap.
    let blocks = repo_engine::build_car_from_cids(&mut store, root, vec![root])
        .await
        .ok()?;
    Some(SyncInput {
        did: did.to_string(),
        rev,
        blocks,
    })
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
    async fn activation_with_a_repo_emits_account_then_sync() {
        // A reactivated account that has a repo emits the `#account` (active) frame followed by a
        // Sync v1.1 `#sync` head assertion (a single-root CAR of the commit block), so a relay that
        // drifted while the account was deactivated can re-anchor to its current head.
        use crate::firehose::FirehoseEvent;
        use crate::routes::test_utils::seed_account_with_repo;

        let state = test_state().await;
        let did = "did:plc:actrepo";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET deactivated_at = '2026-01-01T00:00:00Z' WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let head: String = sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, did);
        let mut rx = state.firehose.subscribe();

        let response = app(state).oneshot(activate_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let FirehoseEvent::Account(acct) = rx.try_recv().unwrap() else {
            panic!("expected the #account event first");
        };
        assert!(acct.active);
        assert!(acct.status.is_none());

        let FirehoseEvent::Sync(sync) = rx.try_recv().unwrap() else {
            panic!("expected the #sync event second");
        };
        assert_eq!(sync.did, did);
        assert!(
            !sync.blocks.is_empty(),
            "#sync must carry the commit-block CAR"
        );
        // The CAR's sole declared root is the current repo head.
        let car = atrium_repo::blockstore::CarStore::open(std::io::Cursor::new(&sync.blocks))
            .await
            .expect("#sync blocks must be a valid CAR");
        let roots: Vec<_> = car.roots().collect();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].to_string(), head);
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
