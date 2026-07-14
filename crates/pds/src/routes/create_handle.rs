// pattern: Imperative Shell
//
// POST /v1/handles — Initial handle creation for a provisioned account
//
// Inputs:
//   - Authorization: Bearer <session_token>
//   - JSON body: {
//       "account_id": "did:plc:...",
//       "handle": "alice.example.com"
//     }
//
// Processing steps:
//   1. require_session → SessionInfo { did }
//   2. Validate account_id matches session did (prevents acting on other accounts)
//   3. validate_handle(handle, available_user_domains) → 400 INVALID_HANDLE on failure
//   4. INSERT INTO handles (handle, did, created_at) → 409 HANDLE_TAKEN on UNIQUE violation
//   4b. Update DID document alsoKnownAs (best-effort, logged not fatal)
//   5. If state.dns_provider is Some: call create_record(name, hostname); dns_status = "propagating"
//      If state.dns_provider is None: dns_status = "not_configured"
//   5b. Emit `#identity` firehose frame (best-effort, non-fatal). Placed AFTER the DNS step so
//      DNS failure (502, exits before reaching here) suppresses the frame rather than
//      announcing a handle the route reports as not-yet-provisioned.
//   6. Return { "handle": "...", "dns_status": "...", "did": "..." }
//
// Note: INSERT precedes the DNS call (step 4 before step 5) so that a DB row
// without a DNS record is a recoverable/operator-fixable state, whereas a DNS
// record without a DB row would be an invisible orphan.
//
// Outputs (success):  200 { "handle": "...", "dns_status": "not_configured"|"propagating", "did": "..." }
// Outputs (error):    400 INVALID_HANDLE, 401 UNAUTHORIZED, 409 HANDLE_TAKEN,
//                     502 DNS_ERROR, 500 INTERNAL_ERROR

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::guards::require_session;
use crate::db::dids::{fetch_also_known_as, update_also_known_as};
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateHandleRequest {
    pub account_id: String,
    pub handle: String,
}

#[derive(Serialize)]
pub struct CreateHandleResponse {
    pub handle: String,
    pub dns_status: &'static str,
    pub did: String,
}

pub async fn create_handle_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateHandleRequest>,
) -> Result<Json<CreateHandleResponse>, ApiError> {
    let session = require_session(&headers, &state.db).await?;

    if payload.account_id != session.did {
        return Err(ApiError::new(
            ErrorCode::Unauthorized,
            "account_id does not match authenticated session",
        ));
    }

    let name = crate::handle::validate_handle(
        &payload.handle,
        &state.config.available_user_domains,
        &state.config.reserved_handles,
    )
    .map_err(|msg| ApiError::new(ErrorCode::InvalidHandle, msg))?;

    match crate::db::handles::insert_handle(&state.db, &payload.handle, &session.did).await? {
        crate::db::handles::InsertHandleOutcome::Inserted => {}
        crate::db::handles::InsertHandleOutcome::HandleTaken => {
            return Err(ApiError::new(
                ErrorCode::HandleTaken,
                "handle is already taken",
            ));
        }
    }

    let also_known_as = fetch_also_known_as(&state.db, &session.did).await?;

    if let Err(e) = update_also_known_as(&state.db, &session.did, &also_known_as).await {
        // Log the error but don't fail the request — handle is already inserted.
        tracing::error!(
            error = %e,
            did = %session.did,
            handle = %payload.handle,
            "failed to update DID document alsoKnownAs after handle creation"
        );
    }

    // INSERT precedes this call: a row with no DNS record is recoverable; a DNS record
    // with no row would be an invisible orphan.
    let public_url = &state.config.public_url;
    let hostname = public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))
        .unwrap_or(public_url.as_str());

    let dns_status = if let Some(provider) = &state.dns_provider {
        provider.create_record(name, hostname).await.map_err(|e| {
            tracing::error!(
                error = %e,
                handle = %payload.handle,
                did = %session.did,
                "DNS record creation failed"
            );
            ApiError::new(ErrorCode::DnsError, "failed to create DNS record")
        })?;
        "propagating"
    } else {
        "not_configured"
    };

    // Emitted after the DNS step so DNS failure (which returns 502 and exits this handler
    // before reaching here) does not broadcast a handle the route has reported as
    // not-yet-provisioned; a later successful create/retry or a subsequent commit will emit it.
    // Best-effort, matching the rest of the firehose emit path: a sequencer write failure is
    // logged and dropped (a subscriber that misses the event backfills via the DID document).
    if let Err(e) = state
        .firehose
        .emit_identity(session.did.clone(), Some(payload.handle.clone()))
        .await
    {
        tracing::warn!(
            error = %e,
            did = %session.did,
            handle = %payload.handle,
            "failed to sequence #identity firehose event after handle creation (non-fatal)"
        );
    }

    Ok(Json(CreateHandleResponse {
        handle: payload.handle,
        dns_status,
        did: session.did,
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::app::test_state;
    use crate::routes::test_utils::{state_with_err_dns, state_with_ok_dns};
    use crate::token::generate_token;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    // ── Integration test helpers ───────────────────────────────────────────────

    struct TestSession {
        did: String,
        session_token: String,
    }

    /// Insert a promoted account and session directly into the DB.
    ///
    /// Skips the full DID ceremony — sets up only what the create_handle handler needs.
    async fn insert_account_and_session(db: &sqlx::SqlitePool) -> TestSession {
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{}@test.example.com", &did[8..16]))
        .execute(db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        TestSession {
            did,
            session_token: token.plaintext,
        }
    }

    fn create_handle_request(session_token: &str, account_id: &str, handle: &str) -> Request<Body> {
        let body = serde_json::json!({
            "accountId": account_id,
            "handle": handle,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/handles")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// Valid handle creates a handles row and returns dns_status: "not_configured".
    #[tokio::test]
    async fn happy_path_creates_handle_with_no_dns_provider() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["handle"].as_str(), Some(handle.as_str()));
        assert_eq!(body["dns_status"].as_str(), Some("not_configured"));
        assert_eq!(body["did"].as_str(), Some(ts.did.as_str()));

        // Verify handles row was inserted.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        let (stored_did,) = row.expect("handles row should exist");
        assert_eq!(stored_did, ts.did);
    }

    // ── DNS provider tests ─────────────────────────────────────────────────────

    /// DNS provider succeeds: row is inserted, response has dns_status: "propagating".
    #[tokio::test]
    async fn dns_provider_success_returns_propagating_status() {
        let state = state_with_ok_dns().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["dns_status"].as_str(), Some("propagating"));

        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_some(), "handles row must be inserted on DNS success");
    }

    /// DNS provider fails: returns 502 DNS_ERROR; the handles row is inserted before DNS
    /// is attempted and persists (recoverable/retryable by an operator).
    #[tokio::test]
    async fn dns_provider_failure_returns_502_and_row_persists() {
        let state = state_with_err_dns().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "DNS_ERROR");

        // INSERT precedes the DNS call: the row is durable even when DNS fails.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_some(),
            "handles row is inserted before DNS and persists even when DNS fails"
        );
    }

    /// When DNS creation fails, the route returns 502 and emits NO `#identity` frame: the
    /// firehose emit (Step 5b) sits after the DNS step, which exits the handler on failure, so
    /// a handle the route reports as not-yet-provisioned is never broadcast to relays.
    #[tokio::test]
    async fn dns_failure_emits_no_identity_frame() {
        let state = state_with_err_dns().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        // Hold a clone so the channel stays open after the oneshot router is dropped.
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // The emit is gated behind successful DNS; a 502 must not have broadcast anything.
        use tokio::sync::broadcast::error::TryRecvError;
        assert_eq!(
            rx.try_recv().unwrap_err(),
            TryRecvError::Empty,
            "DNS failure must suppress the #identity frame"
        );
        drop(firehose);
    }

    // ── Duplicate handle ───────────────────────────────────────────────────────

    /// Creating the same handle twice returns 409 HANDLE_TAKEN.
    #[tokio::test]
    async fn duplicate_handle_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("bob.{}", state.config.available_user_domains[0]);

        // Pre-insert the handle (simulate it already being taken).
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(&handle)
            .bind(&ts.did)
            .execute(&db)
            .await
            .expect("pre-insert handle");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_TAKEN");
    }

    // ── Invalid handle format ──────────────────────────────────────────────────

    /// Handle with no dot returns 400 INVALID_HANDLE.
    #[tokio::test]
    async fn invalid_handle_format_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                &ts.did,
                "nodothandle",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
    }

    /// Handle with a domain not in available_user_domains returns 400.
    #[tokio::test]
    async fn unavailable_domain_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                &ts.did,
                "alice.not-our-domain.com",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
    }

    // ── Auth failures ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/handles")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"accountId": ts.did, "handle": handle}).to_string(),
            ))
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Creating a handle emits exactly one `#identity` firehose frame carrying the new handle,
    /// ordered through the shared sequencer (its `seq` is one greater than the firehose frontier
    /// before the call).
    #[tokio::test]
    async fn creating_a_handle_emits_one_identity_frame() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        // Subscribe before the request so the broadcast frame is delivered to this receiver.
        // Hold a clone of the firehose so it is not dropped when the oneshot router is dropped
        // (otherwise the channel closes and `try_recv` below would report `Closed`).
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();
        let frontier = firehose.current_seq();

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Exactly one frame is emitted, and it is an `#identity` frame with the new handle.
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("identity frame was emitted")
            .expect("receiver not closed");
        let crate::firehose::FirehoseEvent::Identity(identity) = event else {
            panic!("expected an #identity frame, got {event:?}");
        };
        assert_eq!(identity.did, ts.did);
        assert_eq!(identity.handle.as_deref(), Some(handle.as_str()));
        assert_eq!(
            identity.seq,
            frontier + 1,
            "the identity frame must be sequenced immediately after the prior frontier"
        );
        // No further frame is emitted by this single-handle creation.
        use tokio::sync::broadcast::error::TryRecvError;
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
        drop(firehose);
    }

    /// account_id that doesn't match the session DID returns 401.
    #[tokio::test]
    async fn mismatched_account_id_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                "did:plc:somebodyelse",
                &handle,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
