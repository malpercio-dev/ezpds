// pattern: Imperative Shell
//
// Parent-owned provisioning for sovereign child agents. Recovery authority enters only as a
// wallet-signed PLC genesis operation; the server stores the public DID document and its separate
// repo-signing key, then issues a revocable, scope-clamped agent assertion.

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::agent_child_core::{mint_child_account, ChildRegistration};
use crate::app::AppState;
use crate::auth::agent_assertion::{mint_identity_assertion, parse_sqlite_datetime};
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::db::accounts::{deactivate_account, AccountStateChange};
use crate::db::agent_audit::{insert_agent_audit_event, AgentAuditEventType};
use crate::db::agent_auth::{
    get_child_of_parent, list_children_of_parent, revoke_agent_identity,
    set_agent_identity_assertion, AgentIdentityStatus, RegistrationType,
};
use crate::db::agent_child_deletions::{list_child_deletions_of_parent, upsert_child_deletion};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintChildRequest {
    handle: String,
    plc_op: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintChildResponse {
    registration_id: String,
    did: String,
    handle: String,
    did_document: serde_json::Value,
    identity_assertion: String,
    assertion_expires: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildView {
    registration_id: String,
    did: String,
    handle: String,
    status: &'static str,
    created_at: String,
    /// The child's granted scopes — what the parent consented to when it minted the account.
    scopes: Vec<String>,
    /// Present only for a child whose deletion is scheduled: the instant after which the reaper
    /// purges it permanently. Deletion revokes as a side effect, so without this a retired child
    /// and a merely revoked one would be indistinguishable in the list.
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_after: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChildListResponse {
    children: Vec<ChildView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeChildRequest {
    did: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeChildResponse {
    did: String,
    status: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildAssertionRequest {
    did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildAssertionResponse {
    did: String,
    registration_id: String,
    identity_assertion: String,
    assertion_expires: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteChildRequest {
    did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteChildResponse {
    did: String,
    status: &'static str,
    /// The instant after which the scheduled-deletion reaper permanently purges the child.
    delete_after: String,
}

/// The non-active status reported on the firehose `#account` event when a child's deletion is
/// scheduled: the child is deactivated (so relays stop serving its repo) ahead of the purge.
const STATUS_DEACTIVATED: &str = "deactivated";

fn owner_error(error: OwnerAuthError) -> ApiError {
    match error {
        OwnerAuthError::Unauthenticated(error) => error,
        OwnerAuthError::AgentDerived | OwnerAuthError::NotFullAccess => ApiError::new(
            ErrorCode::Forbidden,
            "full account-owner authority is required",
        ),
    }
}

/// POST /agent/child
///
/// Provision a sovereign child agent under the authenticated account owner. The wallet holds the
/// child's rotation key and signs its genesis operation; this server only verifies that operation,
/// hosts the resulting account, and issues the revocable, scope-clamped capability.
pub async fn mint_child(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<MintChildRequest>,
) -> Result<Json<MintChildResponse>, ApiError> {
    let parent_did = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(owner_error)?;
    if !crate::db::accounts::account_exists(&state.db, &parent_did).await? {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "parent account is not local",
        ));
    }
    let minted = mint_child_account(
        &state,
        &parent_did,
        &request.handle,
        &request.plc_op,
        ChildRegistration::New,
    )
    .await?;
    Ok(Json(MintChildResponse {
        registration_id: minted.registration_id,
        did: minted.did,
        handle: request.handle,
        did_document: minted.did_document,
        identity_assertion: minted.identity_assertion,
        assertion_expires: rfc3339_expiry(&minted.assertion_expires),
        scopes: minted.scopes,
    }))
}

/// The wire form of an assertion expiry, from the SQLite datetime stored on the identity row.
fn rfc3339_expiry(sqlite_datetime: &str) -> String {
    parse_sqlite_datetime(sqlite_datetime).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub async fn list_children(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<ChildListResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(owner_error)?;
    let rows = list_children_of_parent(&state.db, &parent).await?;
    // One tombstone sweep for the whole list rather than a lookup per child.
    let scheduled: std::collections::HashMap<String, String> =
        list_child_deletions_of_parent(&state.db, &parent)
            .await?
            .into_iter()
            .map(|row| (row.child_did, row.delete_after))
            .collect();
    let mut children = Vec::with_capacity(rows.len());
    for row in rows {
        let did = row.did.unwrap_or_default();
        let handle = crate::db::handles::get_handle_by_did(&state.db, &did)
            .await?
            .unwrap_or_default();
        children.push(ChildView {
            registration_id: row.id,
            delete_after: scheduled.get(&did).cloned(),
            did,
            handle,
            status: row.status.as_str(),
            created_at: row.created_at,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
        });
    }
    Ok(Json(ChildListResponse { children }))
}

pub async fn revoke_child(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<RevokeChildRequest>,
) -> Result<Json<RevokeChildResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(owner_error)?;
    let child = get_child_of_parent(&state.db, &request.did, &parent)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "child agent not found"))?;
    revoke_agent_identity(&state.db, &child.id).await?;
    Ok(Json(RevokeChildResponse {
        did: request.did,
        status: "revoked",
    }))
}

/// POST /agent/child/assertion
///
/// Renew a live child's `identity_assertion` — the short-lived credential it exchanges at the token
/// endpoint. Assertions expire (`[agent_auth] claimed_assertion_ttl_secs`) while the child
/// identity does not, so without this a child dormant past a full assertion lifetime would be
/// stranded (an *active* child renews automatically at every jwt-bearer exchange); nothing about
/// the child's DID, repo, or rotation key changes here.
///
/// Only the parent can renew: the owner guard refuses agent-derived credentials, so a child can
/// never extend its own capability or a sibling's, and an unknown or foreign child DID is the same
/// uniform 404 as `revoke_child`. A revoked child is refused — renewal must never be a way back up
/// the custody ladder that `revoke_child` walked down.
///
/// The renewed grant is re-clamped to the operator's *current* `granted_scopes`, matching the
/// `identity_assertion` re-mint path, so narrowing the config narrows every subsequent renewal
/// without re-minting the child.
pub async fn remint_child_assertion(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<ChildAssertionRequest>,
) -> Result<Json<ChildAssertionResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(owner_error)?;
    let child = get_child_of_parent(&state.db, &request.did, &parent)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "child agent not found"))?;
    if child.status != AgentIdentityStatus::Claimed {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "child agent is not active",
        ));
    }

    let scopes = crate::auth::oauth_scopes::intersect_scope_tokens(
        &serde_json::from_str::<Vec<String>>(&child.scopes).unwrap_or_default(),
        &state.config.agent_auth.granted_scopes,
    );
    let minted = mint_identity_assertion(
        &state.oauth_signing_keypair,
        &state.config.public_url,
        state.config.agent_auth.claimed_assertion_ttl_secs,
        &request.did,
        &child.id,
        RegistrationType::Child.as_str(),
        &scopes,
    )
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to renew child capability"))?;

    // The stored assertion and its audit row commit together, so a renewal can never be issued
    // without landing on the trail the parent reads.
    let mut tx =
        state.db.begin().await.map_err(|_| {
            ApiError::new(ErrorCode::InternalError, "failed to renew child capability")
        })?;
    set_agent_identity_assertion(&mut *tx, &child.id, &minted.jwt, &minted.expires_sqlite).await?;
    insert_agent_audit_event(
        &mut *tx,
        &Uuid::new_v4().to_string(),
        &child.id,
        Some(&parent),
        AgentAuditEventType::AssertionReminted,
        None,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to renew child capability"))?;

    Ok(Json(ChildAssertionResponse {
        did: request.did,
        registration_id: child.id,
        identity_assertion: minted.jwt,
        assertion_expires: minted.expires_rfc3339,
        scopes,
    }))
}

/// POST /agent/child/delete
///
/// Permanently retires a sovereign child's *hosting*. Revocation (`/agent/child/revoke`) kills only
/// the delegated capability and keeps the identity (ADR-0023 custody ladder); this goes further and
/// schedules the account/repo/handle/blobs for permanent deletion. It reuses the deactivate +
/// `delete_after` + reaper pipeline: the child is revoked and deactivated *now* (so relays stop
/// serving its repo at once via an `#account` deactivated frame), a durable deletion tombstone is
/// recorded, and the scheduled-deletion reaper permanently purges the child once the grace window
/// (`accounts.child_deletion_grace_secs`) elapses — emitting `#account status="deleted"` and
/// removing all local data through the same `purge_account` transaction as `deleteAccount`.
///
/// Delete *implies* revoke, so a parent can retire a child in one call whether or not it was
/// already revoked, and a repeat call is idempotent (the tombstone upserts and the deactivation
/// refreshes `delete_after`). Ownership is enforced exactly like `revoke_child`: an unknown or
/// foreign child DID is a uniform 404, and agent-derived credentials never pass the owner guard.
///
/// The did:plc identity is untouched — ezpds holds no rotation key, so a full identity retirement is
/// delete-on-PDS (here) plus a wallet-driven PLC tombstone (see `account_delete.rs`'s doctrine).
pub async fn delete_child(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<DeleteChildRequest>,
) -> Result<Json<DeleteChildResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(owner_error)?;
    let child = get_child_of_parent(&state.db, &request.did, &parent)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "child agent not found"))?;

    // The tombstone carries the handle because the `handles` row is purged with the child.
    let handle = crate::db::handles::get_handle_by_did(&state.db, &request.did)
        .await?
        .unwrap_or_default();
    let grace = i64::try_from(state.config.accounts.child_deletion_grace_secs).unwrap_or(i64::MAX);
    let delete_after = (chrono::Utc::now() + chrono::Duration::seconds(grace))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // One transaction under the sequencer lock (acquired before the transaction per
    // `Firehose::lock_emit`): revoke the capability, deactivate + schedule the account, and record
    // the durable tombstone together, staging the `#account` frame only on a real transition so the
    // status change can never land without its firehose row.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to schedule child deletion",
        )
    })?;

    revoke_agent_identity(&mut *tx, &child.id).await?;
    let change = deactivate_account(&mut tx, &request.did, Some(&delete_after)).await?;
    upsert_child_deletion(
        &mut *tx,
        &request.did,
        &parent,
        &handle,
        &child.id,
        &delete_after,
    )
    .await?;

    let pending = match change {
        // A child freshly transitioned active → deactivated: announce it so relays stop serving.
        AccountStateChange::Changed => Some(
            emit_guard
                .stage_account(
                    &mut tx,
                    request.did.clone(),
                    false,
                    Some(STATUS_DEACTIVATED.to_string()),
                )
                .await
                .map_err(|_| {
                    ApiError::new(
                        ErrorCode::InternalError,
                        "failed to schedule child deletion",
                    )
                })?,
        ),
        // Already deactivated (e.g. a re-delete, or a child mid-provisioning): the reschedule
        // refreshed `delete_after` without a status change, so no new frame is emitted.
        AccountStateChange::Unchanged => None,
        // The owner guard + `get_child_of_parent` already proved the child account exists.
        AccountStateChange::NotFound => {
            tx.rollback().await.ok();
            return Err(ApiError::new(ErrorCode::NotFound, "child agent not found"));
        }
    };

    tx.commit().await.map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to schedule child deletion",
        )
    })?;
    if let Some(pending) = pending {
        pending.finish();
    }

    tracing::info!(child = %request.did, parent = %parent, %delete_after, "child deletion scheduled");
    Ok(Json(DeleteChildResponse {
        did: request.did,
        status: "deletion_scheduled",
        delete_after,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::app::app;
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{
        access_jwt, agent_jwt, child_genesis_op as genesis, cnf_bound_access_jwt,
        reserve_repo_key as reserve, seed_account_with_repo, test_master_key, DpopProofKey,
    };

    /// Callers must keep the returned `MockServer` alive for the whole test. `MockServer::start`
    /// hands out servers from wiremock's shared process-wide pool; dropping the guard returns the
    /// server to the pool while its listener stays up, and the next test to check it out *resets*
    /// it — silently unmounting the plc mock under a state that still points at its URL, so a
    /// mid-test mint's plc POST 404s and surfaces as a 502 (observed as a parallel-load CI flake).
    async fn state_with_plc() -> (AppState, MockServer) {
        let plc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&plc)
            .await;
        let base = crate::app::test_state_with_plc_url(plc.uri()).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        config.available_user_domains = vec!["example.com".to_string()];
        (
            AppState {
                config: Arc::new(config),
                ..base
            },
            plc,
        )
    }

    fn request(uri: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn get_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    /// A `state_with_plc()` whose child-deletion grace window is overridden — `0` makes the next
    /// reaper run purge, a large value keeps a scheduled child parked in its window.
    async fn state_with_grace(grace_secs: u64) -> (AppState, MockServer) {
        let (base, plc) = state_with_plc().await;
        let mut config = (*base.config).clone();
        config.accounts.child_deletion_grace_secs = grace_secs;
        (
            AppState {
                config: Arc::new(config),
                ..base
            },
            plc,
        )
    }

    /// Mint a sovereign child of `parent` and return its DID. Reserves a fresh repo key and drives
    /// the real `POST /agent/child` path so the child has an account, repo, handle, provisioning
    /// row, and a claimed capability — exactly what a delete must later unwind.
    async fn mint_child_for(state: &AppState, handle: &str, token: &str) -> String {
        let repo_key = reserve(&state.db).await;
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "child mint should succeed"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        minted["did"].as_str().unwrap().to_string()
    }

    /// Minting a child emits an `#identity` firehose frame carrying the child's handle, so relays
    /// and AppViews learn the new DID's handle binding immediately — without it, every app shows
    /// the child as an invalid handle until an unrelated event forces a resolution.
    #[tokio::test]
    async fn minting_a_child_emits_an_identity_frame_with_the_handle() {
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:parentchildowner111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "identity-frame.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let token = access_jwt(&[0x42; 32], parent);

        // Subscribe before the request so the broadcast frame is delivered to this receiver.
        // Hold a clone of the firehose so it is not dropped when the oneshot router is dropped
        // (otherwise the channel closes and `try_recv` below would report `Closed`).
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();
        let frontier = firehose.current_seq();

        let app = crate::app::app(state);
        let response = app
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let child = minted["did"].as_str().unwrap();

        // The #account frame is emitted first, then the #identity frame with the handle. Drain
        // until the identity frame rather than assuming broadcast order, but require both to
        // have arrived — a mint that skips the identity emission fails this drain.
        let mut saw_account = false;
        let identity = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let event = rx.recv().await.expect("receiver not closed");
                match event {
                    crate::firehose::FirehoseEvent::Account(_) => saw_account = true,
                    crate::firehose::FirehoseEvent::Identity(identity) => break identity,
                    _ => {}
                }
            }
        })
        .await
        .expect("identity frame was emitted");
        assert!(saw_account, "the account frame precedes the identity frame");
        assert_eq!(identity.did, child);
        assert_eq!(identity.handle.as_deref(), Some(handle));
        assert!(
            identity.seq > frontier,
            "identity is sequenced after the pre-mint frontier"
        );
        drop(firehose);
    }

    #[tokio::test]
    async fn local_parent_mints_lists_and_revokes_sovereign_child() {
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:parentchildowner111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "alice-writer.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let child = minted["did"].as_str().unwrap();
        assert_ne!(child, parent);
        assert!(crate::db::accounts::account_exists(&state.db, child)
            .await
            .unwrap());
        assert_eq!(
            crate::db::handles::resolve_handle(&state.db, handle)
                .await
                .unwrap()
                .as_deref(),
            Some(child)
        );
        let row = get_child_of_parent(&state.db, child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, AgentIdentityStatus::Claimed);

        let response = app(state.clone())
            .oneshot(get_request("/agent/child", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["children"][0]["did"], child);
        assert_eq!(listed["children"][0]["handle"], handle);
        assert_eq!(listed["children"][0]["status"], "claimed");
        assert_eq!(
            listed["children"][0]["registrationId"],
            minted["registrationId"]
        );
        // The wallet's child detail renders the grant, so the list has to carry it.
        assert_eq!(listed["children"][0]["scopes"], minted["scopes"]);
        assert!(
            listed["children"][0]["deleteAfter"].is_null(),
            "a live child carries no purge date"
        );

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/revoke",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let row = get_child_of_parent(&state.db, child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, AgentIdentityStatus::Revoked);
        assert!(
            crate::db::accounts::account_exists(&state.db, child)
                .await
                .unwrap(),
            "revocation preserves the sovereign identity and recovery path"
        );
    }

    #[tokio::test]
    async fn parent_reads_child_audit_trail_foreign_account_cannot() {
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:parentchildaudit111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "audited-writer.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registration_id = minted["registrationId"].as_str().unwrap().to_string();

        // The child's own tokens are agent-derived and never pass the owner guard, so the
        // parent is the only party that can read the child's audit trail.
        let response = app(state.clone())
            .oneshot(get_request(
                &format!("/v1/agents/{registration_id}/audit"),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A foreign account still sees the uniform 404 (no existence oracle).
        let foreign = access_jwt(&[0x42; 32], "did:plc:someoneelse1111111");
        let response = app(state.clone())
            .oneshot(get_request(
                &format!("/v1/agents/{registration_id}/audit"),
                &foreign,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mint_child_dpop_bound_token_as_bearer_returns_401() {
        // A DPoP-bound access token (cnf.jkt present) presented as plain `Bearer` with no proof is
        // the RFC 9449 binding downgrade — a captured token replayed without its key. The owner
        // guard behind child minting must reject it exactly as the AuthenticatedUser extractor and
        // the repo-write handlers do; nothing may be provisioned under the victim's DID.
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:downgradeparent111111";
        seed_account_with_repo(&state.db, parent).await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, parent, &dpop_key.thumbprint());

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": "stolen-bot.example.com", "plcOp": {}}),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a cnf.jkt-bound token presented as plain Bearer must be rejected on mintChild"
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_identities WHERE registration_type = 'child'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn caller_without_local_parent_cannot_mint() {
        let (state, _plc) = state_with_plc().await;
        let repo_key = reserve(&state.db).await;
        let op = genesis(
            "outsider-bot.example.com",
            &state.config.public_url,
            &repo_key.key_id.0,
        );
        let token = access_jwt(&[0x42; 32], "did:plc:not-local-parent1111");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": "outsider-bot.example.com", "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_identities WHERE registration_type = 'child'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn plc_failure_leaves_a_deactivated_provisioning_that_retry_finishes() {
        let (state, plc) = state_with_plc().await;
        plc.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&plc)
            .await;
        let parent = "did:plc:parentchildretry111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "alice-retry.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let rotation_key = op["rotationKeys"][0].as_str().unwrap();
        let child = crate::identity::genesis::verify_and_validate_genesis_op(
            rotation_key,
            &op,
            handle,
            &state.config.public_url,
        )
        .unwrap()
        .0
        .did;
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op.clone()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let deactivated: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(deactivated.is_some());
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_child_provisionings WHERE child_did = ? AND plc_published_at IS NULL",
        )
        .bind(&child)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(pending, 1);

        plc.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&plc)
            .await;
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let deactivated: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(deactivated.is_none());
        assert!(get_child_of_parent(&state.db, &child, parent)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn parent_remints_an_active_childs_assertion() {
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:parentchildremint11";
        seed_account_with_repo(&state.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&state, "renewable-writer.example.com", &token).await;
        let issued: Option<String> =
            sqlx::query_scalar("SELECT identity_assertion FROM agent_identities WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/assertion",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let renewed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(renewed["did"], child);
        assert!(renewed["assertionExpires"].as_str().is_some());
        // Same grant as the mint, re-derived through the scope clamp (which orders by its own
        // canonicalization, so compare as the set it is).
        let mut renewed_scopes: Vec<&str> = renewed["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        renewed_scopes.sort_unstable();
        let mut granted: Vec<&str> = state
            .config
            .agent_auth
            .granted_scopes
            .iter()
            .map(String::as_str)
            .collect();
        granted.sort_unstable();
        assert_eq!(renewed_scopes, granted);

        let fresh = renewed["identityAssertion"].as_str().unwrap();
        assert_ne!(
            Some(fresh),
            issued.as_deref(),
            "the renewal must be a distinct credential, not the assertion minted at provisioning"
        );
        let row = get_child_of_parent(&state.db, &child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.identity_assertion.as_deref(),
            Some(fresh),
            "the renewal must be the assertion the token endpoint will accept"
        );
        assert_eq!(renewed["registrationId"], row.id);

        // The renewal lands on the trail the parent reads for its child.
        let reminted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_events \
             WHERE registration_id = ? AND event_type = 'assertion_reminted' AND did = ?",
        )
        .bind(&row.id)
        .bind(parent)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(reminted, 1);
    }

    #[tokio::test]
    async fn assertion_remint_refuses_revoked_children_and_non_parent_callers() {
        let (state, _plc) = state_with_plc().await;
        let parent = "did:plc:parentremintrefuse1";
        seed_account_with_repo(&state.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&state, "refused-writer.example.com", &token).await;
        let stored = |db: sqlx::SqlitePool, did: String| async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT identity_assertion FROM agent_identities WHERE did = ?",
            )
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap()
        };
        let before = stored(state.db.clone(), child.clone()).await;

        // A foreign account gets the same uniform 404 as an unknown child — no existence oracle.
        let foreign = access_jwt(&[0x42; 32], "did:plc:someoneelse3333333");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/assertion",
                Some(&foreign),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // The child's own agent-derived token is exactly the credential it would renew itself
        // with; the owner guard refuses it, so a child can never extend its own capability.
        let agent = agent_jwt(&[0x42; 32], &child, "com.atproto.access", "reg_impostor");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/assertion",
                Some(&agent),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        assert_eq!(
            stored(state.db.clone(), child.clone()).await,
            before,
            "a refused renewal must not touch the stored credential"
        );

        // Revocation walked the custody ladder down; renewal must not walk it back up.
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/revoke",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/assertion",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            get_child_of_parent(&state.db, &child, parent)
                .await
                .unwrap()
                .unwrap()
                .status,
            AgentIdentityStatus::Revoked
        );
        let reminted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_events WHERE event_type = 'assertion_reminted'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(reminted, 0, "no refused renewal may leave an audit row");
    }

    #[tokio::test]
    async fn parent_deletes_child_then_reaper_purges_and_tombstone_survives() {
        // grace = 0 → the child is due the moment it is scheduled, so one reaper pass purges it.
        let (state, _plc) = state_with_grace(0).await;
        let parent = "did:plc:parentchilddelete1111";
        seed_account_with_repo(&state.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let handle = "deletable-writer.example.com";
        let child = mint_child_for(&state, handle, &token).await;

        // Subscribe *after* the mint so only the delete/purge frames are observed.
        let mut rx = state.firehose.subscribe();
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/delete",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let scheduled: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(scheduled["status"], "deletion_scheduled");
        assert!(scheduled["deleteAfter"].as_str().is_some());

        // The capability is revoked, the account is deactivated + scheduled, and the durable
        // tombstone is recorded — all in the one scheduling call.
        let row = get_child_of_parent(&state.db, &child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, AgentIdentityStatus::Revoked);
        let (deactivated, delete_after): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT deactivated_at, delete_after FROM accounts WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(deactivated.is_some(), "child must be deactivated");
        assert!(
            delete_after.is_some(),
            "child must be scheduled for deletion"
        );
        let tombstones =
            crate::db::agent_child_deletions::list_child_deletions_of_parent(&state.db, parent)
                .await
                .unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].child_did, child);
        assert_eq!(tombstones[0].handle, handle);

        // Deletion revokes as a side effect, so `status` alone cannot tell a retired child from a
        // merely revoked one — the list has to carry the purge date for the wallet to say which.
        let response = app(state.clone())
            .oneshot(get_request("/agent/child", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["children"][0]["status"], "revoked");
        assert_eq!(
            listed["children"][0]["deleteAfter"],
            scheduled["deleteAfter"]
        );

        // Deactivation announces the repo is no longer served, ahead of the physical purge.
        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event for the deactivation");
        };
        assert_eq!(event.did, child);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deactivated"));

        // The reaper permanently purges the child (account/repo/handle gone) and emits #account
        // deleted — the FK-ordered purge also drops the provisioning row without a constraint error.
        let stats = crate::account_reaper::run_account_reaper(&state).await;
        assert_eq!(stats.deleted, 1);
        assert!(!crate::db::accounts::account_exists(&state.db, &child)
            .await
            .unwrap());
        let provisioning: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_child_provisionings WHERE child_did = ?",
        )
        .bind(&child)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(
            provisioning, 0,
            "the child's provisioning row must be purged"
        );

        // The deletion stays auditable after the fact: the tombstone outlives the purged child.
        let after =
            crate::db::agent_child_deletions::list_child_deletions_of_parent(&state.db, parent)
                .await
                .unwrap();
        assert_eq!(
            after.len(),
            1,
            "the deletion tombstone must survive the child's purge"
        );

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event for the deletion");
        };
        assert_eq!(event.did, child);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deleted"));
    }

    #[tokio::test]
    async fn foreign_account_cannot_delete_child_uniform_404() {
        let (state, _plc) = state_with_grace(0).await;
        let parent = "did:plc:parentchilddelforeign";
        seed_account_with_repo(&state.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&state, "foreign-target.example.com", &token).await;

        let foreign = access_jwt(&[0x42; 32], "did:plc:someoneelse2222222");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/delete",
                Some(&foreign),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // The child is untouched: still active, capability intact, nothing scheduled.
        assert!(crate::db::accounts::account_exists(&state.db, &child)
            .await
            .unwrap());
        assert_eq!(
            get_child_of_parent(&state.db, &child, parent)
                .await
                .unwrap()
                .unwrap()
                .status,
            AgentIdentityStatus::Claimed
        );
    }

    #[tokio::test]
    async fn agent_derived_token_cannot_delete_child() {
        let (state, _plc) = state_with_grace(0).await;
        let parent = "did:plc:parentagentrefuse111";
        seed_account_with_repo(&state.db, parent).await;
        let owner = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&state, "agent-refuse.example.com", &owner).await;

        // A child's own agent-derived token (a `registration_id` claim) is exactly the credential a
        // revoked child would try to act with; the owner guard must refuse it so a child can never
        // delete itself or a sibling.
        let agent = agent_jwt(&[0x42; 32], &child, "com.atproto.access", "reg_impostor");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/delete",
                Some(&agent),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(crate::db::accounts::account_exists(&state.db, &child)
            .await
            .unwrap());
        assert_eq!(
            get_child_of_parent(&state.db, &child, parent)
                .await
                .unwrap()
                .unwrap()
                .status,
            AgentIdentityStatus::Claimed
        );
    }

    #[tokio::test]
    async fn deleting_a_child_twice_is_idempotent() {
        // A non-zero grace keeps the child parked so both calls exercise the schedule path.
        let (state, _plc) = state_with_grace(3600).await;
        let parent = "did:plc:parentdelidempotent1";
        seed_account_with_repo(&state.db, parent).await;
        let token = access_jwt(&[0x42; 32], parent);
        let child = mint_child_for(&state, "idem-target.example.com", &token).await;

        let first = app(state.clone())
            .oneshot(request(
                "/agent/child/delete",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // Subscribe after the first schedule: the second call is an already-deactivated no-op and
        // must not emit a second #account frame.
        let mut rx = state.firehose.subscribe();
        let second = app(state.clone())
            .oneshot(request(
                "/agent/child/delete",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert!(
            rx.try_recv().is_err(),
            "re-deleting an already-scheduled child must not emit a second #account event"
        );

        // Still exactly one tombstone (the upsert collapses on child_did).
        let tombstones =
            crate::db::agent_child_deletions::list_child_deletions_of_parent(&state.db, parent)
                .await
                .unwrap();
        assert_eq!(tombstones.len(), 1);
    }
}
