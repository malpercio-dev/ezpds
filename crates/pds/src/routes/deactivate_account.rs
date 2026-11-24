// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool + firehose via AppState, optional JSON body
// Processes: scope validation → flip the account to deactivated (storing optional deleteAfter) →
//            emit an `#account` firehose event so relays stop serving the repo
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.deactivateAccount

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use custos_core::auth::extractors::AuthenticatedUser;
use custos_core::auth::jwt::AuthScope;
use custos_core::auth::oauth_scopes;
use custos_core::lexicon::LexiconInput;
use custos_db::accounts::{deactivate_account, AccountStateChange};

/// The non-active status reported on the firehose `#account` event for a deactivation.
const STATUS_DEACTIVATED: &str = "deactivated";

#[derive(Deserialize)]
pub struct DeactivateAccountBody {
    /// Optional instant after which the account should be permanently deleted, stored verbatim.
    /// The lexicon layer has already asserted it is a strict atproto datetime; the reaper that
    /// acts on it is a separate concern.
    #[serde(rename = "deleteAfter")]
    delete_after: Option<String>,
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
    LexiconInput(body): LexiconInput<DeactivateAccountBody>,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    oauth_scopes::require_account(&user.scope_claim, "status", "manage")?;

    let delete_after = body.delete_after;

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
                    user.did.to_string(),
                    false,
                    Some(STATUS_DEACTIVATED.to_string()),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %user.did, "failed to stage #account deactivation event");
                    ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
                })?;
            tx.commit().await.map_err(|e| {
                {
                    tracing::error!(error = %e, did = %user.did, "failed to commit deactivate transaction");
                    ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
                }
            })?;
            pending.finish();
            tracing::info!(
                did = %user.did,
                scheduled_deletion = delete_after.is_some(),
                "account deactivated"
            );
        }
    }

    retire_kem_key_if_migrated_out(&state, &user.did).await;

    Ok(StatusCode::OK)
}

/// After a deactivation, delete the account's KEM keys if its DID document now names another
/// host (ADR-0043). Deactivating is the last step of migrating away: the new host publishes its
/// own KEM key, and this host should not keep a private key for an identity it no longer serves.
/// A plain deactivation (the document still points here) keeps the key, because reactivating
/// needs it. Best-effort: the deactivation already succeeded, and a key left behind is deleted
/// with the account.
async fn retire_kem_key_if_migrated_out(state: &AppState, did: &common::Did) {
    match custos_db::kem_keys::get_active_kem_key(&state.db, did).await {
        Ok(Some(_)) => {}
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "failed to read KEM key after deactivation (non-fatal)");
            return;
        }
    }
    let document = match custos_core::identity::resolution::resolve_did_document_force_refresh(
        state, did,
    )
    .await
    {
        Ok(document) => document,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "could not resolve DID document after deactivation; KEM key kept (non-fatal)");
            return;
        }
    };
    let endpoint = custos_core::identity::resolution::service_endpoint(&document, "atproto_pds");
    if endpoint.map(|e| e.trim_end_matches('/'))
        == Some(state.config.public_url.trim_end_matches('/'))
    {
        return;
    }
    match custos_db::kem_keys::delete_kem_keys(&state.db, did).await {
        Ok(deleted) => {
            tracing::info!(did = %did, deleted, "deleted KEM key of an account that migrated away")
        }
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "failed to delete KEM key after migration (non-fatal)")
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, test_state_with_plc_url};
    use crate::routes::test_utils::{
        access_jwt, body_json, insert_account_with_email as insert_account,
        scoped_access_jwt as scoped_jwt,
    };
    use custos_core::firehose::FirehoseEvent;

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
        assert_eq!(json["error"], "InvalidToken");
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

    /// Deactivating after the DID document moved to another host deletes the KEM key; a plain
    /// deactivation keeps it.
    #[tokio::test]
    async fn deactivation_after_migrating_away_deletes_the_kem_key() {
        use crate::routes::test_utils::seed_kem_key;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let plc = MockServer::start().await;
        let state = test_state_with_plc_url(plc.uri()).await;
        let here = state.config.public_url.clone();
        for (did, endpoint, kept) in [
            ("did:plc:kemstays0000000000000000", here.as_str(), true),
            (
                "did:plc:kemleaves000000000000000",
                "https://elsewhere.example.com",
                false,
            ),
        ] {
            insert_account(&state.db, did, &format!("{}@example.com", &did[8..])).await;
            seed_kem_key(&state.db, did).await;
            Mock::given(method("GET"))
                .and(path(format!("/{did}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": did,
                    "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": endpoint}],
                })))
                .mount(&plc)
                .await;
            let token = access_jwt(&state.jwt_secret, did);
            let response = app(state.clone())
                .oneshot(deactivate_request(&token, Body::from("{}")))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let held = custos_db::kem_keys::get_active_kem_key(&state.db, did)
                .await
                .unwrap();
            assert_eq!(held.is_some(), kept, "{did}");
        }
    }
}
