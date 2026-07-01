// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), the subject DID and
//          requested `takedown` status from the request body
// Processes: admin auth → flip `taken_down_at` → emit an `#account` firehose event reflecting
//            the account's full resulting lifecycle (not just the takedown dimension) on a real
//            transition
// Returns: 200 OK with the resulting subject/takedown status; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.admin.updateSubjectStatus

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::validation::is_valid_did;
use crate::db::accounts::{set_account_takedown, TakedownStateChange};
use crate::routes::admin_subject_defs::{RepoRefView, StatusAttrView};
use crate::routes::auth::require_admin_json;

/// `subject` is a lexicon union (`com.atproto.admin.defs#repoRef` | `com.atproto.repo.strongRef`
/// | `com.atproto.repo.strongRef` blob variant); `$type` is the discriminant. ezpds only
/// implements the `repoRef` (account-level) arm, so `$type` is required and checked explicitly
/// rather than inferred from which fields happen to be present — a body that merely has a `did`
/// field is not necessarily a `repoRef`.
const REPO_REF_TYPE: &str = "com.atproto.admin.defs#repoRef";

/// `com.atproto.admin.defs#repoRef` — the only subject type this endpoint accepts. Record- and
/// blob-level takedown (the reference PDS's other subject kinds) are not modelled here; ezpds
/// only tracks lifecycle state per-account. Unlike [`StatusAttrInput`], `repoRef` has no optional
/// lexicon field ezpds chooses not to persist, so an unrecognised field is rejected outright
/// rather than silently ignored — it means the caller sent something other than a plain repoRef.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoRefSubject {
    #[serde(rename = "$type")]
    type_: String,
    did: String,
}

/// `com.atproto.admin.defs#statusAttr`. `ref` (an optional free-text reason) is accepted by the
/// lexicon but ezpds has no column to persist it in, so it is parsed-and-discarded rather than
/// rejected — omitting it entirely would make a spec-conformant client's request a 422.
#[derive(Deserialize)]
struct StatusAttrInput {
    applied: bool,
}

#[derive(Deserialize)]
struct UpdateSubjectStatusBody {
    subject: RepoRefSubject,
    /// The only status dimension this endpoint writes. `deactivated` (the lexicon's other
    /// `StatusAttr` field) is intentionally unsupported here — self-service deactivation already
    /// has its own endpoint (`deactivateAccount`), and an admin-driven deactivation is not part
    /// of this issue's scope.
    takedown: Option<StatusAttrInput>,
}

#[derive(Serialize)]
pub struct UpdateSubjectStatusResponse {
    subject: RepoRefView,
    takedown: StatusAttrView,
}

/// POST /xrpc/com.atproto.admin.updateSubjectStatus
///
/// Apply or clear an account takedown. Admin-authed: the master token **or** an active
/// companion-app device's signed request ([`require_admin_json`]). A taken-down account is
/// rejected by the repo-write gate and the public sync/login paths (`AccountLifecycle`), and a
/// real transition emits an `#account` firehose event so relays stop (or resume) serving the
/// repo — the event's `active`/`status` reflect the account's full derived lifecycle, since
/// clearing a takedown does not necessarily mean `active: true` if the account is also
/// suspended or deactivated. Idempotent: re-applying (or re-clearing) an already-applied (or
/// already-clear) takedown is a 200 no-op that emits nothing.
pub async fn update_subject_status(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UpdateSubjectStatusResponse>, Response> {
    let actor = require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let payload: UpdateSubjectStatusBody = serde_json::from_slice(&body).map_err(|e| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            format!("invalid request body: {e}"),
        )
        .into_response()
    })?;

    if payload.subject.type_ != REPO_REF_TYPE {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("subject.$type must be {REPO_REF_TYPE}"),
        )
        .into_response());
    }
    if !is_valid_did(&payload.subject.did) {
        return Err(
            ApiError::new(ErrorCode::InvalidRequest, "subject.did is not a valid DID")
                .into_response(),
        );
    }
    let Some(takedown) = payload.takedown else {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "takedown is required (deactivated and record/blob subjects are not supported)",
        )
        .into_response());
    };
    let did = payload.subject.did;

    // Open a transaction so the status transition and its firehose `#account` event (if any)
    // commit atomically — see `deactivate_account.rs`. The sequencer lock is acquired *before*
    // the transaction, per `Firehose::lock_emit`'s lock/connection-ordering contract.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open updateSubjectStatus transaction");
        ApiError::new(ErrorCode::InternalError, "failed to update account status").into_response()
    })?;

    let applied = takedown.applied;
    match set_account_takedown(&mut tx, &did, applied)
        .await
        .map_err(IntoResponse::into_response)?
    {
        TakedownStateChange::NotFound => {
            tx.rollback().await.ok();
            return Err(
                ApiError::new(ErrorCode::NotFound, "subject account not found").into_response(),
            );
        }
        TakedownStateChange::Unchanged(lifecycle) => {
            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to commit updateSubjectStatus (no-op) transaction");
                ApiError::new(ErrorCode::InternalError, "failed to update account status").into_response()
            })?;
            tracing::debug!(
                did = %did,
                applied,
                status = ?lifecycle.as_status_str(),
                actor = %actor.as_log_str(),
                "updateSubjectStatus: takedown already at requested value; no event emitted"
            );
        }
        TakedownStateChange::Changed(lifecycle) => {
            let active = lifecycle.is_active();
            let status = lifecycle.as_status_str().map(str::to_string);
            let pending = emit_guard
                .stage_account(&mut tx, did.clone(), active, status)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %did, "failed to stage #account takedown event");
                    ApiError::new(ErrorCode::InternalError, "failed to update account status").into_response()
                })?;
            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to commit updateSubjectStatus transaction");
                ApiError::new(ErrorCode::InternalError, "failed to update account status").into_response()
            })?;
            pending.finish();
            tracing::info!(
                did = %did,
                applied,
                actor = %actor.as_log_str(),
                "account takedown status updated"
            );
        }
    }

    Ok(Json(UpdateSubjectStatusResponse {
        subject: RepoRefView {
            type_: "com.atproto.admin.defs#repoRef",
            did: did.clone(),
        },
        takedown: StatusAttrView { applied },
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::app;
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

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

    fn request(body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.admin.updateSubjectStatus")
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn applies_takedown_and_emits_firehose_event() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd1", "usstd1@example.com").await;
        let db = state.db.clone();
        let mut rx = state.firehose.subscribe();

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:usstd1"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["takedown"]["applied"], true);
        assert_eq!(json["subject"]["did"], "did:plc:usstd1");

        let taken_down_at: Option<String> =
            sqlx::query_scalar("SELECT taken_down_at FROM accounts WHERE did = ?")
                .bind("did:plc:usstd1")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(taken_down_at.is_some());

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, "did:plc:usstd1");
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("takendown"));
    }

    #[tokio::test]
    async fn clears_takedown_and_emits_active_event() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd2", "usstd2@example.com").await;
        sqlx::query("UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?")
            .bind("did:plc:usstd2")
            .execute(&state.db)
            .await
            .unwrap();
        let mut rx = state.firehose.subscribe();

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:usstd2"},
            "takedown": {"applied": false},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["takedown"]["applied"], false);

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert!(event.active);
        assert_eq!(event.status, None);
    }

    #[tokio::test]
    async fn reapplying_takedown_is_a_noop_without_a_second_event() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd3", "usstd3@example.com").await;
        let mut rx = state.firehose.subscribe();

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:usstd3"},
            "takedown": {"applied": true},
        })
        .to_string();
        let first = app(state.clone())
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert!(matches!(rx.try_recv(), Ok(FirehoseEvent::Account(_))));

        let second = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert!(
            rx.try_recv().is_err(),
            "re-applying an already-applied takedown must not emit a second event"
        );
    }

    #[tokio::test]
    async fn missing_takedown_field_returns_400() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd4", "usstd4@example.com").await;

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:usstd4"},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = test_state_with_admin_token().await;

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "not-a-did"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wrong_subject_type_returns_400() {
        // subject.$type is a required discriminant — a strongRef-shaped (or merely
        // mistyped) subject must be rejected, not silently treated as a repoRef because it
        // happens to also carry a `did` field.
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd7", "usstd7@example.com").await;

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.repo.strongRef", "did": "did:plc:usstd7"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn subject_with_unknown_field_returns_400() {
        // deny_unknown_fields on RepoRefSubject: an extra field (e.g. a strongRef's `uri`/`cid`
        // smuggled alongside `did`) is rejected rather than silently ignored.
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd9", "usstd9@example.com").await;

        let body = serde_json::json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:usstd9",
                "uri": "at://did:plc:usstd9/app.bsky.feed.post/abc",
            },
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_subject_type_returns_400() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd8", "usstd8@example.com").await;

        let body = serde_json::json!({
            "subject": {"did": "did:plc:usstd8"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_did_returns_404() {
        let state = test_state_with_admin_token().await;

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:usstdghost"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state)
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn without_admin_auth_returns_401() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:usstd5", "usstd5@example.com").await;

        let body = serde_json::json!({
            "subject": {"did": "did:plc:usstd5"},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state).oneshot(request(&body, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn takendown_account_is_rejected_from_repo_writes() {
        // End-to-end: after a takedown, the account's own repo-write gate now rejects it —
        // proving updateSubjectStatus wires into the same enforcement deactivateAccount uses.
        use crate::routes::test_utils::{
            access_jwt, delete_record_request, seed_account_with_repo, state_with_master_key,
        };

        let state = state_with_master_key().await;
        let did = "did:plc:usstd6".to_string();
        seed_account_with_repo(&state.db, &did).await;

        let mut config = (*state.config).clone();
        config.admin_token = Some("test-admin-token".to_string());
        let state = crate::app::AppState {
            config: std::sync::Arc::new(config),
            ..state
        };

        let body = serde_json::json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
            "takedown": {"applied": true},
        })
        .to_string();
        let response = app(state.clone())
            .oneshot(request(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let token = access_jwt(&state.jwt_secret, &did);
        let write = delete_record_request(
            &did,
            "app.bsky.feed.post",
            "doesnotexist",
            serde_json::json!({}),
            Some(&token),
        );
        let write_response = app(state).oneshot(write).await.unwrap();
        assert_eq!(write_response.status(), StatusCode::FORBIDDEN);
    }
}
