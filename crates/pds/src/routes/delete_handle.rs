// pattern: Imperative Shell
//
// DELETE /v1/handles/:handle — Remove a handle from the account and clean up DNS.
//
// Inputs:
//   - Authorization: Bearer <session_token>
//   - Path: :handle (e.g., "alice.example.com")
//
// Processing steps:
//   1. require_session → SessionInfo { did }
//   2. SELECT did FROM handles WHERE handle = ? → 404 HANDLE_NOT_FOUND if absent
//   3. Verify session.did == handle_row.did → 403 FORBIDDEN if not owner
//   4. If state.dns_provider is Some: call delete_record(name) → 502 DNS_ERROR on failure
//      (DNS deletion precedes DB deletion: a DB row without a DNS record is operator-fixable;
//       a DNS record without a DB row is an invisible orphan that can corrupt future
//       registrations for the same subdomain)
//      If state.dns_provider is None: emit tracing::warn! (no DNS cleanup performed)
//   5. DELETE FROM handles WHERE handle = ?; check rows_affected() → 404 HANDLE_NOT_FOUND if zero
//   6. Return 204 No Content
//
// Outputs (success):  204 No Content
// Outputs (error):    401 UNAUTHORIZED, 403 FORBIDDEN, 404 HANDLE_NOT_FOUND,
//                     502 DNS_ERROR, 500 INTERNAL_ERROR

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::app::AppState;
use crate::auth::guards::require_session;
use crate::db::dids::{fetch_also_known_as, update_also_known_as};
use common::{ApiError, ErrorCode};

pub async fn delete_handle_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let session = require_session(&headers, &state.db).await?;

    let owner_did = crate::db::handles::resolve_handle(&state.db, &handle)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::HandleNotFound, "handle not found"))?;

    if session.did != owner_did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "you do not own this handle",
        ));
    }

    // Step 4: Delete DNS record before deleting the DB row.
    // DNS deletion precedes DB deletion: a DB row without a DNS record is operator-fixable
    // (admin can retry), whereas a DNS record without a DB row is an invisible orphan that
    // could corrupt a future handle registration for the same subdomain.
    let name = handle.split_once('.').map(|(n, _)| n).unwrap_or(&handle);
    if let Some(provider) = &state.dns_provider {
        provider.delete_record(name).await.map_err(|e| {
            tracing::error!(
                error = %e,
                handle = %handle,
                dns_record_name = %name,
                did = %session.did,
                "DNS record deletion failed"
            );
            ApiError::new(ErrorCode::DnsError, "failed to delete DNS record")
        })?;
    } else {
        tracing::warn!(
            handle = %handle,
            did = %session.did,
            "no DNS provider configured; DNS record for handle was not cleaned up"
        );
    }

    let result = sqlx::query("DELETE FROM handles WHERE handle = ?")
        .bind(&handle)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                handle = %handle,
                did = %session.did,
                "failed to delete handle row after DNS deletion; manual DB cleanup required"
            );
            ApiError::new(ErrorCode::InternalError, "failed to delete handle")
        })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::new(ErrorCode::HandleNotFound, "handle not found"));
    }

    let also_known_as = fetch_also_known_as(&state.db, &session.did).await?;

    if let Err(e) = update_also_known_as(&state.db, &session.did, &also_known_as).await {
        // Log the error but don't fail the request — handle is already deleted.
        tracing::error!(
            error = %e,
            did = %session.did,
            handle = %handle,
            "failed to update DID document alsoKnownAs after handle deletion"
        );
    }

    // The removed handle is no longer asserted here, so `handle` is `None`: a relay re-resolves
    // the DID document to discover the remaining `alsoKnownAs`. Best-effort, like the rest of the
    // firehose emit path — the handle row is already gone and the DID-doc update is durable, so a
    // sequencer write failure is logged and dropped.
    if let Err(e) = state
        .firehose
        .emit_identity(session.did.clone(), None)
        .await
    {
        tracing::warn!(
            error = %e,
            did = %session.did,
            handle = %handle,
            "failed to sequence #identity firehose event after handle deletion (non-fatal)"
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::app::test_state;
    use crate::routes::test_utils::{seed_handle, state_with_err_dns, state_with_ok_dns};
    use crate::token::generate_token;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    // ── Test session helpers ───────────────────────────────────────────────────

    /// Insert a session for an existing account row. Returns the plaintext token.
    async fn insert_session(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");
        token.plaintext
    }

    fn delete_handle_request(session_token: &str, handle: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/handles/{handle}"))
            .header("Authorization", format!("Bearer {session_token}"))
            .body(Body::empty())
            .unwrap()
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// Deleting an owned handle with no DNS provider removes the row and returns 204.
    #[tokio::test]
    async fn happy_path_deletes_handle_no_dns_provider() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify the row was removed.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_none(), "handle row must be removed after deletion");
    }

    /// DNS provider succeeds: row is deleted and DNS is cleaned up; returns 204.
    #[tokio::test]
    async fn dns_provider_success_deletes_handle_and_dns() {
        let state = state_with_ok_dns().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_none(),
            "handle row must be removed when DNS succeeds"
        );
    }

    /// DNS provider fails: returns 502 DNS_ERROR and the DB row is NOT deleted.
    #[tokio::test]
    async fn dns_provider_failure_returns_502_and_row_survives() {
        let state = state_with_err_dns().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
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

        // DNS precedes DB: the row must still exist when DNS deletion fails.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_some(),
            "handle row must survive when DNS deletion fails"
        );
    }

    // ── Auth failures ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        seed_handle(&db, &handle, &did).await;

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/handles/{handle}"))
            .body(Body::empty())
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Authorization (ownership) ─────────────────────────────────────────────

    /// Session DID that does not own the handle returns 403.
    #[tokio::test]
    async fn non_owner_session_returns_403() {
        let state = test_state().await;
        let db = state.db.clone();

        // Owner account + handle.
        let owner_did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        seed_handle(&db, &handle, &owner_did).await;

        // Different account that tries to delete the handle.
        let other_did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&other_did)
        .bind(format!("{other_did}@test.example.com"))
        .execute(&db)
        .await
        .unwrap();
        let other_token = insert_session(&db, &other_did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&other_token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "FORBIDDEN");
    }

    // ── Not found ─────────────────────────────────────────────────────────────

    /// Deleting a handle that doesn't exist returns 404.
    #[tokio::test]
    async fn nonexistent_handle_returns_404() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{did}@test.example.com"))
        .execute(&db)
        .await
        .unwrap();
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, "ghost.test.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_NOT_FOUND");
    }

    /// Deleting an owned handle emits exactly one `#identity` firehose frame (with `handle = None`,
    /// signalling relays to re-resolve the DID document for the remaining `alsoKnownAs`), ordered
    /// through the shared sequencer immediately after the prior frontier.
    #[tokio::test]
    async fn deleting_a_handle_emits_one_identity_frame() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;
        // Subscribe before the request so the broadcast frame is delivered to this receiver.
        // Hold a clone of the firehose so it is not dropped when the oneshot router is dropped
        // (otherwise the channel closes and `try_recv` below would report `Closed`).
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();
        let frontier = firehose.current_seq();

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Exactly one frame is emitted, and it is an `#identity` frame with no handle asserted.
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("identity frame was emitted")
            .expect("receiver not closed");
        let crate::firehose::FirehoseEvent::Identity(identity) = event else {
            panic!("expected an #identity frame, got {event:?}");
        };
        assert_eq!(identity.did, did);
        assert_eq!(identity.handle, None);
        assert_eq!(
            identity.seq,
            frontier + 1,
            "the identity frame must be sequenced immediately after the prior frontier"
        );
        // No further frame is emitted by this single-handle deletion.
        use tokio::sync::broadcast::error::TryRecvError;
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
        drop(firehose);
    }
}
