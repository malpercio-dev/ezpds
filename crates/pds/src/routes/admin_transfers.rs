// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), query/path, DB pool
// Processes: admin auth → in-flight transfer listing / operator cancel workflow
// Returns: JSON on success; ApiError on all failure paths

//! GET /v1/admin/transfers - Operator visibility into in-flight device transfers.
//! POST /v1/admin/transfers/:id/cancel - Operator interruption of one.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::admin_audit::{record_admin_audit_event, AdminAuditAction};
use crate::db::transfers::list_inflight_transfers;
use crate::transfer::{cancel_transfer, CancelOutcome};

const MAX_LIST_LIMIT: u32 = 200;

fn default_list_limit() -> u32 {
    50
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTransfersParams {
    #[serde(default = "default_list_limit")]
    limit: u32,
    /// Opaque cursor from the prior response (the last row's `created_at|id` keyset,
    /// exclusive); absent for the first page.
    cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    id: String,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    /// Stored state-machine status: `pending` | `accepted` | `completing`.
    status: String,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_device_platform: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTransfersResponse {
    transfers: Vec<TransferView>,
    /// Present when another page may exist; pass back as the `cursor` query param.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// `GET /v1/admin/transfers` — admin-only in-flight device-transfer listing.
///
/// An in-flight transfer is a security-relevant pending state: from initiate onward a
/// live code can hand the account's device credentials to whoever types it in, and once
/// `accepted` the target device already holds a working token. This lists every transfer
/// that can still advance — `accepted`/`completing` rows regardless of the clock
/// (completion has no expiry check) plus unexpired `pending` ones — newest first, paged
/// on the `(created_at, id)` keyset. The response never carries the transfer code (it is
/// a live account-takeover credential; the operator needs the state, not the secret).
/// Admin-authed: the master token **or** an active companion-app device's signed request
/// ([`require_admin`]); a GET signs the bare path with an empty body, so paging params
/// vary without re-signing.
pub async fn list_admin_transfers(
    State(state): State<AppState>,
    Query(params): Query<ListTransfersParams>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ListTransfersResponse>, ApiError> {
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    if params.limit == 0 || params.limit > MAX_LIST_LIMIT {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("limit must be between 1 and {MAX_LIST_LIMIT}"),
        ));
    }
    // The opaque cursor is the previous page's last `created_at|id`; created_at never
    // contains '|' and ids are UUIDs, so the first '|' is the seam.
    let cursor = params
        .cursor
        .as_deref()
        .map(|raw| {
            raw.split_once('|')
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))
        })
        .transpose()?;

    let rows = list_inflight_transfers(&state.db, cursor, params.limit)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list in-flight transfers");
            ApiError::new(ErrorCode::InternalError, "failed to list transfers")
        })?;

    // A short page means the in-flight set is exhausted; a full page may have more.
    let cursor = (rows.len() == params.limit as usize)
        .then(|| rows.last().map(|r| format!("{}|{}", r.created_at, r.id)))
        .flatten();
    let transfers = rows
        .into_iter()
        .map(|row| TransferView {
            id: row.id,
            did: row.did,
            handle: row.handle,
            status: row.status,
            created_at: row.created_at,
            expires_at: row.expires_at,
            accepted_at: row.accepted_at,
            accepted_device_platform: row.accepted_device_platform,
        })
        .collect();

    Ok(Json(ListTransfersResponse { transfers, cursor }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelTransferResponse {
    id: String,
    status: &'static str,
    /// Whether an accepted target device credential was tombstoned by this cancel.
    revoked_device_credential: bool,
}

/// `POST /v1/admin/transfers/:id/cancel` — admin-only transfer interruption.
///
/// Cancels an in-flight transfer: the code stops being acceptable immediately (the
/// active-code lookup filters terminal states) and, if a target device had already
/// accepted, its credential is tombstoned in the same transaction — otherwise the
/// "interrupted" device would stay authenticated. The account's existing sessions are
/// deliberately untouched: in the benign case (a user mid-phone-swap) those belong to
/// the legitimate source device, and an operator who suspects the account itself is
/// compromised composes this with `/v1/admin/accounts/{id}/revoke-credentials`.
/// Idempotent for an already-cancelled transfer (200); a terminal `complete`/`expired`
/// transfer is 409 — there is nothing in flight to interrupt, and pretending otherwise
/// would hide a swap that already happened (or already died of clock). Unknown ids are
/// 404, checked after auth. Admin-authed via [`require_admin`]; the id rides in the
/// signed path, binding the signature to its target.
pub async fn cancel_admin_transfer(
    State(state): State<AppState>,
    Path(transfer_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CancelTransferResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe which transfer ids exist.
    let actor = require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let outcome = cancel_transfer(&state.db, &transfer_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to cancel transfer");
            ApiError::new(ErrorCode::InternalError, "failed to cancel transfer")
        })?;

    match outcome {
        CancelOutcome::Cancelled {
            revoked_device_credential,
        } => {
            // Audit only the real interruption (an idempotent repeat changed nothing).
            // The transfer id is the subject; `transfer_audit_events` already ties it to
            // its DID for per-account forensics.
            let detail = serde_json::json!({
                "revokedDeviceCredential": revoked_device_credential,
            })
            .to_string();
            record_admin_audit_event(
                &state.db,
                actor.as_log_str().as_ref(),
                AdminAuditAction::TransferCancelled,
                Some(&transfer_id),
                "cancelled",
                Some(&detail),
            )
            .await?;
            Ok(Json(CancelTransferResponse {
                id: transfer_id,
                status: "cancelled",
                revoked_device_credential,
            }))
        }
        CancelOutcome::AlreadyCancelled => Ok(Json(CancelTransferResponse {
            id: transfer_id,
            status: "cancelled",
            revoked_device_credential: false,
        })),
        CancelOutcome::Terminal { status } => Err(ApiError::new(
            ErrorCode::Conflict,
            format!("transfer is already {status}"),
        )),
        CancelOutcome::NotFound => Err(ApiError::new(ErrorCode::NotFound, "unknown transfer")),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{body_json, seed_handle, test_state_with_admin_token};

    const ADMIN: &str = "test-admin-token";

    async fn seed_transfer(
        db: &sqlx::SqlitePool,
        id: &str,
        did: &str,
        code: &str,
        status: &str,
        expires_offset_minutes: i64,
    ) {
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES (?, ?, ?, ?, datetime('now', ?), datetime('now'))",
        )
        .bind(id)
        .bind(did)
        .bind(code)
        .bind(status)
        .bind(format!("{expires_offset_minutes:+} minutes"))
        .execute(db)
        .await
        .unwrap();
    }

    /// Seed an accepted transfer whose target device credential is live.
    async fn seed_accepted_transfer(db: &sqlx::SqlitePool, id: &str, did: &str, device_id: &str) {
        sqlx::query(
            "INSERT INTO transfer_devices (id, did, platform, public_key, device_token_hash, \
             created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'pk', ?, datetime('now'), datetime('now'))",
        )
        .bind(device_id)
        .bind(did)
        .bind(format!("hash-{device_id}"))
        .execute(db)
        .await
        .unwrap();
        seed_transfer(db, id, did, &format!("C{}", &id[2..]), "accepted", 10).await;
        sqlx::query(
            "UPDATE transfers SET accepted_device_id = ?, accepted_at = datetime('now') \
             WHERE id = ?",
        )
        .bind(device_id)
        .bind(id)
        .execute(db)
        .await
        .unwrap();
    }

    fn list_request(token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/admin/transfers");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    fn cancel_request(id: &str, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/v1/admin/transfers/{id}/cancel"));
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    async fn transfer_status(db: &sqlx::SqlitePool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM transfers WHERE id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn audit_event_count(db: &sqlx::SqlitePool, transfer_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM transfer_audit_events \
             WHERE transfer_id = ? AND event_type = 'transfer.cancelled'",
        )
        .bind(transfer_id)
        .fetch_one(db)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn both_routes_require_admin() {
        let state = test_state_with_admin_token().await;

        let list = app(state.clone())
            .oneshot(list_request(None))
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::UNAUTHORIZED);

        let cancel = app(state)
            .oneshot(cancel_request("t1", None))
            .await
            .unwrap();
        assert_eq!(cancel.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_reports_inflight_state_but_never_the_code() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "swap.test.example.com", "did:plc:atl1").await;
        seed_accepted_transfer(&state.db, "t-atl1", "did:plc:atl1", "dev-atl1").await;

        let response = app(state).oneshot(list_request(Some(ADMIN))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let transfers = json["transfers"].as_array().unwrap();
        assert_eq!(transfers.len(), 1);
        let t = &transfers[0];
        assert_eq!(t["id"], "t-atl1");
        assert_eq!(t["did"], "did:plc:atl1");
        assert_eq!(t["handle"], "swap.test.example.com");
        assert_eq!(t["status"], "accepted");
        assert_eq!(t["acceptedDevicePlatform"], "ios");
        assert!(t["acceptedAt"].is_string());
        assert!(t["expiresAt"].is_string());
        // The transfer code is a live account-takeover credential; the row's code
        // ("C" + the id tail, see the fixture) must not appear anywhere in the response.
        let body = serde_json::to_string(&json).unwrap();
        assert!(
            !body.contains("Catl1") && t.get("code").is_none(),
            "response leaked the transfer code: {body}"
        );
    }

    #[tokio::test]
    async fn list_rejects_bad_limit_and_malformed_cursor() {
        let state = test_state_with_admin_token().await;

        let bad_limit = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/admin/transfers?limit=0")
            .header("Authorization", format!("Bearer {ADMIN}"))
            .body(Body::empty())
            .unwrap();
        let response = app(state.clone()).oneshot(bad_limit).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bad_cursor = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/admin/transfers?cursor=no-seam")
            .header("Authorization", format!("Bearer {ADMIN}"))
            .body(Body::empty())
            .unwrap();
        let response = app(state).oneshot(bad_cursor).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cancel_pending_transfer_frees_the_active_slot() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "pend.test.example.com", "did:plc:atc1").await;
        seed_transfer(&state.db, "t-atc1", "did:plc:atc1", "ATC111", "pending", 10).await;

        let response = app(state.clone())
            .oneshot(cancel_request("t-atc1", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "cancelled");
        assert_eq!(json["revokedDeviceCredential"], false);

        assert_eq!(transfer_status(&state.db, "t-atc1").await, "cancelled");
        assert_eq!(audit_event_count(&state.db, "t-atc1").await, 1);

        // `cancelled` is terminal: the partial unique index slot is free, so the account
        // can open a fresh transfer.
        let outcome = crate::db::transfers::insert_transfer(
            &state.db,
            "t-atc1b",
            "did:plc:atc1",
            "ATC112",
            15,
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            crate::db::transfers::InitiateOutcome::Created { .. }
        ));
    }

    #[tokio::test]
    async fn cancel_accepted_transfer_tombstones_target_credential() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "acc.test.example.com", "did:plc:atc2").await;
        seed_accepted_transfer(&state.db, "t-atc2", "did:plc:atc2", "dev-atc2").await;

        let response = app(state.clone())
            .oneshot(cancel_request("t-atc2", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "cancelled");
        assert_eq!(json["revokedDeviceCredential"], true);

        // Without the tombstone the "interrupted" device would stay authenticated.
        let revoked_at: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM transfer_devices WHERE id = 'dev-atc2'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(revoked_at.is_some());
        assert!(
            !crate::db::transfers::transfer_device_token_exists(
                &state.db,
                "dev-atc2",
                "hash-dev-atc2"
            )
            .await
            .unwrap(),
            "the auth guard must stop honoring the cancelled target's token"
        );
    }

    #[tokio::test]
    async fn cancel_repeat_is_idempotent() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "idem.test.example.com", "did:plc:atc3").await;
        seed_transfer(&state.db, "t-atc3", "did:plc:atc3", "ATC333", "pending", 10).await;

        for expected_revoked in [false, false] {
            let response = app(state.clone())
                .oneshot(cancel_request("t-atc3", Some(ADMIN)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let json = body_json(response).await;
            assert_eq!(json["status"], "cancelled");
            assert_eq!(json["revokedDeviceCredential"], expected_revoked);
        }

        assert_eq!(
            audit_event_count(&state.db, "t-atc3").await,
            1,
            "a repeat cancel must not duplicate the audit event"
        );
    }

    #[tokio::test]
    async fn cancel_terminal_transfer_is_conflict() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "term.test.example.com", "did:plc:atc4").await;
        seed_transfer(
            &state.db,
            "t-done",
            "did:plc:atc4",
            "ATC441",
            "complete",
            10,
        )
        .await;

        let response = app(state.clone())
            .oneshot(cancel_request("t-done", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(transfer_status(&state.db, "t-done").await, "complete");
    }

    #[tokio::test]
    async fn cancel_lapsed_pending_transfer_sweeps_and_conflicts() {
        let state = test_state_with_admin_token().await;
        seed_handle(&state.db, "lapse.test.example.com", "did:plc:atc5").await;
        seed_transfer(
            &state.db,
            "t-lapsed",
            "did:plc:atc5",
            "ATC551",
            "pending",
            -10,
        )
        .await;

        let response = app(state.clone())
            .oneshot(cancel_request("t-lapsed", Some(ADMIN)))
            .await
            .unwrap();
        // The transfer already died of clock; the sweep materialises that instead of
        // recording an operator cancel that never interrupted anything.
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(transfer_status(&state.db, "t-lapsed").await, "expired");
        assert_eq!(audit_event_count(&state.db, "t-lapsed").await, 0);
    }

    #[tokio::test]
    async fn cancel_unknown_transfer_is_not_found() {
        let state = test_state_with_admin_token().await;

        let response = app(state)
            .oneshot(cancel_request("no-such-transfer", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
