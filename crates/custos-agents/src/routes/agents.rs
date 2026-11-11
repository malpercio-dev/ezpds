// pattern: Imperative Shell

//! Per-account agent management for the wallet's "My agents" surface:
//!
//! - `GET /v1/agents` — list the agent identities bound to the caller's DID: each one's
//!   type/issuer/subject/scopes/status plus `lastUsedAt` (the newest activity audit event) and
//!   `effectiveScopes` (the grant clamped to the current scope profile), with the profile itself
//!   once as `scopeProfile`
//! - `POST /v1/agents/claim-preview` — "what would confirming this `user_code` grant?":
//!   registration type + the operator's current canonicalized `granted_scopes`, so the wallet
//!   shows the grant *before* the biometric approval gate. Authorization mirrors claim confirm,
//!   every failure shape is the same 404, and it shares the confirm endpoint's rate-limit
//!   budget (same code-guessing surface)
//! - `POST /v1/agents/{registration_id}/revoke` — turn an agent off: flips
//!   `status = 'revoked'` and writes the `revoked` audit event atomically; idempotent (a repeat
//!   is 200 with no duplicate event)
//! - `GET /v1/agents/{registration_id}/audit` — page the V040 audit trail newest-first with a
//!   rowid cursor
//! - `POST /v1/agents/{registration_id}/scopes` — the owner approves more of the current scope
//!   profile for a live agent or child (ADR-0041): the grant becomes
//!   `grant ∪ (shown ∩ profile)`, with a `scopes_widened` audit row in the same transaction
//!
//! These are account-holder routes, not operator/admin ones. Auth is the shared owner guard
//! `auth::guards::authenticate_account_owner` (also the claim-confirm gate's guard), accepting
//! either a wallet session token (`sessions` table) or a full-access OAuth/XRPC access token —
//! the same dual-credential posture as `transfer/complete`. Agent-derived and app-password
//! credentials are refused: an agent must never list, preview, audit, revoke, or widen agents
//! (including itself), and a scoped app password is below this trust bar.
//!
//! A registration is operable by the account it acts as **or** by the parent of a sovereign
//! `child` registration — the parent provisions, revokes, and audits its children; a child's
//! own tokens never pass the owner guard, so without the parent arm its audit trail would be
//! readable by no one. An unknown registration id and one bound to a different account are both
//! a uniform 404, so the endpoint is not an existence oracle for other accounts' registration
//! ids.

use std::collections::BTreeSet;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use common::{ApiError, ApiResultExt, ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use custos_core::auth::agent_assertion::{
    effective_agent_scopes, parse_sqlite_datetime, scopes_to_json,
};
use custos_core::auth::guards::authenticate_owner;
use custos_core::auth::oauth_scopes::intersect_scope_tokens;
use custos_core::CoreState;
use custos_db::agent_audit::{
    insert_agent_audit_event, list_agent_audit_events, AgentAuditEventType,
};
use custos_db::agent_auth::{
    get_agent_claim_attempt_by_user_code, get_agent_identity, list_agent_identities_for_did,
    revoke_agent_identity, widen_agent_identity_scopes, AgentIdentityRow, AgentIdentityStatus,
};

/// Default and maximum page sizes for the audit listing.
const AUDIT_PAGE_DEFAULT: i64 = 50;
const AUDIT_PAGE_MAX: i64 = 100;

// ── Response types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentView {
    registration_id: String,
    registration_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    /// The OAuth client a `connector` / `oauth_app` grant record was approved for.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    scopes: Vec<String>,
    /// The grant clamped to the current scope profile: what the agent holds now. `scopes` minus
    /// this is suspended. An OAuth grant record isn't governed by the profile, so it is `scopes`.
    effective_scopes: Vec<String>,
    status: &'static str,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAgentsResponse {
    agents: Vec<AgentView>,
    /// The operator's current scope profile, canonical order: the ceiling a widening can reach.
    scope_profile: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeAgentResponse {
    registration_id: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    id: String,
    event_type: String,
    /// The account the action was attributed to; absent for pre-claim events on an anonymous
    /// registration (nothing was bound yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
    created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResponse {
    events: Vec<AuditEventView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

// ── Shared auth + ownership ─────────────────────────────────────────────────────

/// Load a registration and require `did` to own it — as the account it acts as, or as the
/// parent of a sovereign child (the parent provisions, revokes, and audits its children; the
/// child's own tokens are agent-derived and never pass the owner guard, so without the parent
/// arm a child's audit trail would be readable by no one). Unknown and foreign registrations
/// are the same uniform 404 (no cross-account existence oracle).
async fn owned_identity(
    state: &CoreState,
    registration_id: &str,
    did: &str,
) -> Result<AgentIdentityRow, ApiError> {
    let not_found = || ApiError::new(ErrorCode::NotFound, "unknown agent registration");
    let identity = get_agent_identity(&state.db, registration_id)
        .await?
        .ok_or_else(not_found)?;
    let owner = identity.did.as_deref() == Some(did) || identity.parent_did.as_deref() == Some(did);
    if !owner {
        return Err(not_found());
    }
    Ok(identity)
}

/// Render a stored sqlite datetime as RFC 3339 for the API surface.
fn rfc3339(sqlite: &str) -> String {
    parse_sqlite_datetime(sqlite).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ── GET /v1/agents ──────────────────────────────────────────────────────────────

pub async fn list_agents(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<ListAgentsResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    let rows = list_agent_identities_for_did(&state.db, &did).await?;
    let profile = &state.config.agent_auth.granted_scopes;
    let agents = rows
        .into_iter()
        .map(|row| {
            let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
            let effective_scopes = if row.registration_type.is_oauth_grant() {
                scopes.clone()
            } else {
                effective_agent_scopes(&row.scopes, profile)
            };
            AgentView {
                registration_id: row.id,
                registration_type: row.registration_type.as_str(),
                issuer: row.issuer,
                subject: row.subject,
                client_id: row.client_id,
                scopes,
                effective_scopes,
                status: row.status.as_str(),
                created_at: rfc3339(&row.created_at),
                updated_at: rfc3339(&row.updated_at),
                last_used_at: row.last_used_at.as_deref().map(rfc3339),
            }
        })
        .collect();
    Ok(Json(ListAgentsResponse {
        agents,
        scope_profile: intersect_scope_tokens(profile, profile),
    }))
}

// ── POST /v1/agents/{registration_id}/revoke ────────────────────────────────────

pub async fn revoke_agent(
    State(state): State<CoreState>,
    Path(registration_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<RevokeAgentResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    owned_identity(&state, &registration_id, &did).await?;

    // The status flip and its audit row commit atomically; the `status != 'revoked'` guard in
    // `revoke_agent_identity` makes a repeat revoke an idempotent 200 with no duplicate event.
    let mut tx = state.db.begin().await.or_internal_as(
        "failed to open transaction for agent revocation",
        "failed to revoke agent",
    )?;
    let transitioned = revoke_agent_identity(&mut *tx, &registration_id).await?;
    if transitioned {
        insert_agent_audit_event(
            &mut *tx,
            &Uuid::new_v4().to_string(),
            &registration_id,
            Some(&did),
            AgentAuditEventType::Revoked,
            None,
        )
        .await?;
    }
    tx.commit().await.or_internal_as(
        "failed to commit agent revocation",
        "failed to revoke agent",
    )?;

    Ok(Json(RevokeAgentResponse {
        registration_id,
        status: "revoked",
    }))
}

// ── POST /v1/agents/{registration_id}/scopes ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WidenScopesRequest {
    /// The exact set the wallet's consent screen showed.
    scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WidenScopesResponse {
    /// The stored grant.
    scopes: Vec<String>,
    /// The grant clamped to the current scope profile: what the next renewal carries.
    effective_scopes: Vec<String>,
}

impl WidenScopesResponse {
    fn new(scopes: Vec<String>, profile: &[String]) -> Self {
        Self {
            effective_scopes: intersect_scope_tokens(&scopes, profile),
            scopes,
        }
    }
}

/// Widen a live agent's grant to `before ∪ (shown ∩ current profile)` (ADR-0041). The UPDATE and
/// its `scopes_widened` audit row commit together; a request that adds nothing writes neither.
/// OAuth grant records are refused: OAuth re-consent rewrites their grant.
pub async fn widen_agent_scopes(
    State(state): State<CoreState>,
    Path(registration_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<WidenScopesRequest>,
) -> Result<Json<WidenScopesResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    let identity = owned_identity(&state, &registration_id, &did).await?;
    if identity.registration_type.is_oauth_grant() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "this agent is an OAuth grant; widen it by approving the app again through OAuth consent",
        ));
    }
    if identity.status != AgentIdentityStatus::Claimed {
        return Err(ApiError::new(ErrorCode::Forbidden, "agent is not active"));
    }
    let shown: Vec<String> = request
        .scopes
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "missing required field: scopes"))?
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let profile = &state.config.agent_auth.granted_scopes;
    let before: Vec<String> = serde_json::from_str(&identity.scopes).or_internal_as(
        "stored agent scopes are not a JSON array",
        "failed to widen agent scopes",
    )?;
    let after: Vec<String> = before
        .iter()
        .cloned()
        .chain(intersect_scope_tokens(&shown, profile))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if after.len() == before.iter().collect::<BTreeSet<_>>().len() {
        return Ok(Json(WidenScopesResponse::new(before, profile)));
    }
    let detail = serde_json::json!({ "before": before, "shown": shown, "after": after });

    let mut tx = state.db.begin().await.or_internal_as(
        "failed to open transaction for agent scope widening",
        "failed to widen agent scopes",
    )?;
    if !widen_agent_identity_scopes(
        &mut *tx,
        &registration_id,
        &identity.scopes,
        &scopes_to_json(&after),
    )
    .await?
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the agent changed while this request was in flight; reload and try again",
        ));
    }
    insert_agent_audit_event(
        &mut *tx,
        &Uuid::new_v4().to_string(),
        &registration_id,
        Some(&did),
        AgentAuditEventType::ScopesWidened,
        Some(&detail.to_string()),
    )
    .await?;
    tx.commit().await.or_internal_as(
        "failed to commit agent scope widening",
        "failed to widen agent scopes",
    )?;

    Ok(Json(WidenScopesResponse::new(after, profile)))
}

// ── GET /v1/agents/{registration_id}/audit ──────────────────────────────────────

pub async fn agent_audit_log(
    State(state): State<CoreState>,
    Path(registration_id): Path<String>,
    Query(query): Query<AuditQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<AuditListResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    owned_identity(&state, &registration_id, &did).await?;

    let limit = query
        .limit
        .unwrap_or(AUDIT_PAGE_DEFAULT)
        .clamp(1, AUDIT_PAGE_MAX);
    let before_seq = match query.cursor.as_deref() {
        None => None,
        Some(raw) => Some(
            raw.parse::<i64>()
                .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "malformed cursor"))?,
        ),
    };

    let rows = list_agent_audit_events(&state.db, &registration_id, before_seq, limit).await?;
    // A full page may have more behind it; hand back the last row's seq as the next cursor. A
    // short page is the end of the trail.
    let cursor = if rows.len() as i64 == limit {
        rows.last().map(|row| row.seq.to_string())
    } else {
        None
    };
    let events = rows
        .into_iter()
        .map(|row| AuditEventView {
            id: row.id,
            event_type: row.event_type,
            did: row.did,
            // `detail` is written as compact JSON; surface it structurally. A malformed value
            // (impossible via the writers) degrades to the raw string rather than vanishing.
            detail: row
                .detail
                .map(|raw| serde_json::from_str(&raw).unwrap_or(serde_json::Value::String(raw))),
            created_at: rfc3339(&row.created_at),
        })
        .collect();

    Ok(Json(AuditListResponse { events, cursor }))
}

// ── POST /v1/agents/claim-preview ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPreviewRequest {
    user_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPreviewResponse {
    registration_id: String,
    registration_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    /// The scopes confirmation would grant — the operator's *current* granted-scope profile,
    /// canonicalized exactly as the confirm endpoint will store it.
    scopes: Vec<String>,
    user_code_expires_at: String,
    /// The handle an `anonymous` agent proposed for a child account of its own (V071). Present
    /// only when the agent asked; the screen offers it as an editable default, never a commitment.
    #[serde(skip_serializing_if = "Option::is_none")]
    handle_hint: Option<String>,
}

/// What would the caller be approving? The wallet's claim-approval screen shows the agent's
/// registration type, issuer/subject, and the exact scope list *before* the biometric gate —
/// consent must be informed, so approving requires seeing this first.
///
/// Owner-authenticated, and authorization mirrors the confirm endpoint: a registration bound to
/// an owner may be previewed only by that owner; an ownerless anonymous registration is
/// previewable by whoever holds the code (the code is the authorization, exactly as at confirm).
/// Every failure shape — unknown code, expired attempt, foreign owner, already claimed/revoked —
/// is the same uniform 404, and the endpoint shares the confirm endpoint's per-IP rate-limit
/// budget: it validates a guessable 6-digit code, so it is the same guessing surface.
pub async fn claim_preview(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<ClaimPreviewRequest>,
) -> Result<Json<ClaimPreviewResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    let not_found = || ApiError::new(ErrorCode::NotFound, "unknown or expired code");

    let user_code = request
        .user_code
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidClaim, "missing required field: userCode")
        })?;

    let attempt = get_agent_claim_attempt_by_user_code(&state.db, user_code)
        .await?
        .filter(|attempt| attempt.is_pending())
        .ok_or_else(not_found)?;
    let identity = get_agent_identity(&state.db, &attempt.identity_id)
        .await?
        .ok_or_else(not_found)?;
    if identity.status != AgentIdentityStatus::Active {
        return Err(not_found());
    }
    if let Some(bound) = identity.did.as_deref() {
        if bound != did {
            return Err(not_found());
        }
    }

    // Same canonicalization the confirm endpoint applies before storing (see agent_claim.rs).
    let granted = &state.config.agent_auth.granted_scopes;
    let scopes = intersect_scope_tokens(granted, granted);

    Ok(Json(ClaimPreviewResponse {
        registration_id: identity.id,
        registration_type: identity.registration_type.as_str(),
        issuer: identity.issuer,
        subject: identity.subject,
        scopes,
        user_code_expires_at: rfc3339(&attempt.user_code_expires_at),
        handle_hint: identity.handle_hint,
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    use std::sync::Arc;

    use tower::ServiceExt;

    use crate::test_support::{
        access_jwt, agent_jwt, app_pass_jwt, body_json, get_request, insert_account_with_email,
        post_json_with_bearer, state_with_agent_auth, test_app,
    };
    use custos_core::CoreState;

    const OWNER: &str = "did:plc:widenowner11111111111111";
    const SECRET: [u8; 32] = [0x42; 32];

    /// A state whose scope profile is exactly `profile`.
    async fn state_with_profile(profile: &[&str]) -> CoreState {
        state_with_agent_auth(common::AgentAuthConfig {
            granted_scopes: profile.iter().map(|s| s.to_string()).collect(),
            ..common::AgentAuthConfig::default()
        })
        .await
    }

    /// Seed one registration owned by `did` (or, for a child, parented by it) with `scopes`.
    async fn seed_agent(
        state: &CoreState,
        did: &str,
        registration_type: &str,
        status: &str,
        scopes: &[&str],
    ) -> (String, String) {
        let id = format!("reg_{}", uuid::Uuid::new_v4().simple());
        let (owner_did, parent_did) = if registration_type == "child" {
            let child = format!(
                "did:plc:child{}",
                &uuid::Uuid::new_v4().simple().to_string()[..19]
            );
            insert_account_with_email(&state.db, &child, &format!("{child}@example.com")).await;
            (child, Some(did.to_string()))
        } else {
            (did.to_string(), None)
        };
        let client_id = matches!(registration_type, "connector" | "oauth_app")
            .then_some("https://client.example.com/metadata.json");
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, parent_did, registration_type, client_id, scopes, assertion_expires_at, \
              status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+1 day'), ?, datetime('now'), datetime('now'))",
        )
        .bind(&id)
        .bind(&owner_did)
        .bind(parent_did)
        .bind(registration_type)
        .bind(client_id)
        .bind(serde_json::to_string(scopes).unwrap())
        .bind(status)
        .execute(&state.db)
        .await
        .unwrap();
        (id, owner_did)
    }

    async fn owner_state(profile: &[&str]) -> CoreState {
        let state = state_with_profile(profile).await;
        insert_account_with_email(&state.db, OWNER, "widen-owner@example.com").await;
        state
    }

    async fn widen(
        state: &CoreState,
        id: &str,
        shown: &[&str],
        token: &str,
    ) -> (StatusCode, Value) {
        post_json_with_bearer(
            state.clone(),
            &format!("/v1/agents/{id}/scopes"),
            json!({ "scopes": shown }),
            Some(token),
        )
        .await
    }

    async fn stored_scopes(state: &CoreState, id: &str) -> Vec<String> {
        let raw: String = sqlx::query_scalar("SELECT scopes FROM agent_identities WHERE id = ?")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[tokio::test]
    async fn widening_unions_the_shown_set_clamped_to_the_profile() {
        let state = owner_state(&["atproto", "blob:*/*", "repo:*?action=delete"]).await;
        let (id, _) = seed_agent(&state, OWNER, "service_auth", "claimed", &["atproto"]).await;

        // `identity:*` was shown but is outside the profile: it must never be stored.
        let (status, body) = widen(
            &state,
            &id,
            &["atproto", "blob:*/*", "identity:*"],
            &access_jwt(&SECRET, OWNER),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({ "scopes": ["atproto", "blob:*/*"], "effectiveScopes": ["atproto", "blob:*/*"] })
        );
        assert_eq!(
            stored_scopes(&state, &id).await,
            vec!["atproto", "blob:*/*"]
        );
    }

    /// The same database under a different scope profile: the operator changing `granted_scopes`.
    fn with_profile(state: &CoreState, profile: &[&str]) -> CoreState {
        let mut config = (*state.config).clone();
        config.agent_auth.granted_scopes = profile.iter().map(|s| s.to_string()).collect();
        CoreState {
            config: Arc::new(config),
            ..state.clone()
        }
    }

    async fn get_json(state: &CoreState, uri: &str, token: &str) -> (StatusCode, Value) {
        let response = test_app(state.clone())
            .oneshot(get_request(uri, token))
            .await
            .unwrap();
        (response.status(), body_json(response).await)
    }

    async fn audit_events(state: &CoreState, id: &str, event_type: &str) -> Vec<Value> {
        let (status, body) = get_json(
            state,
            &format!("/v1/agents/{id}/audit"),
            &access_jwt(&SECRET, OWNER),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["eventType"] == event_type)
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn a_suspended_scope_is_kept_but_not_effective() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        // `identity:*` was granted under an earlier, wider profile: suspended now.
        let (id, _) = seed_agent(
            &state,
            OWNER,
            "identity_assertion",
            "claimed",
            &["atproto", "identity:*"],
        )
        .await;

        let (status, body) = widen(
            &state,
            &id,
            &["atproto", "blob:*/*"],
            &access_jwt(&SECRET, OWNER),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({
                "scopes": ["atproto", "blob:*/*", "identity:*"],
                "effectiveScopes": ["atproto", "blob:*/*"],
            })
        );
    }

    #[tokio::test]
    async fn widening_a_child_is_audited_once_under_the_parent() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let (id, _child) = seed_agent(&state, OWNER, "child", "claimed", &["atproto"]).await;

        let (status, _) = widen(
            &state,
            &id,
            &["blob:*/*", "atproto", "identity:*"],
            &access_jwt(&SECRET, OWNER),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = audit_events(&state, &id, "scopes_widened").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["did"], OWNER, "attributed to the acting parent");
        assert_eq!(
            events[0]["detail"],
            json!({
                "before": ["atproto"],
                "shown": ["atproto", "blob:*/*", "identity:*"],
                "after": ["atproto", "blob:*/*"],
            })
        );
    }

    #[tokio::test]
    async fn the_grant_and_its_audit_row_commit_together() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let (id, _) = seed_agent(&state, OWNER, "service_auth", "claimed", &["atproto"]).await;
        let token = access_jwt(&SECRET, OWNER);

        // A failing audit insert must roll the UPDATE back. (The reverse needs no test: the
        // audit row is written only after the UPDATE succeeds.)
        sqlx::query(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON agent_audit_events \
             WHEN NEW.event_type = 'scopes_widened' BEGIN SELECT RAISE(ABORT, 'forced'); END",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let (status, _) = widen(&state, &id, &["atproto", "blob:*/*"], &token).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(stored_scopes(&state, &id).await, vec!["atproto"]);
        assert!(audit_events(&state, &id, "scopes_widened").await.is_empty());
    }

    #[tokio::test]
    async fn a_request_that_adds_nothing_writes_nothing() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let (id, _) = seed_agent(
            &state,
            OWNER,
            "anonymous",
            "claimed",
            &["atproto", "blob:*/*"],
        )
        .await;
        sqlx::query("UPDATE agent_identities SET updated_at = '2000-01-01 00:00:00' WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
            .unwrap();

        let (status, body) = widen(
            &state,
            &id,
            &["atproto", "identity:*"],
            &access_jwt(&SECRET, OWNER),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "scopes": ["atproto", "blob:*/*"], "effectiveScopes": ["atproto", "blob:*/*"] })
        );
        let updated_at: String =
            sqlx::query_scalar("SELECT updated_at FROM agent_identities WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(updated_at, "2000-01-01 00:00:00", "no UPDATE ran");
        assert!(audit_events(&state, &id, "scopes_widened").await.is_empty());
    }

    #[tokio::test]
    async fn oauth_grant_records_are_refused_toward_re_consent() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        for registration_type in ["connector", "oauth_app"] {
            let (id, _) =
                seed_agent(&state, OWNER, registration_type, "claimed", &["atproto"]).await;
            let (status, body) = widen(
                &state,
                &id,
                &["atproto", "blob:*/*"],
                &access_jwt(&SECRET, OWNER),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{registration_type}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("OAuth consent"),
                "{body}"
            );
            assert_eq!(stored_scopes(&state, &id).await, vec!["atproto"]);
        }
    }

    #[tokio::test]
    async fn only_a_claimed_agent_can_be_widened() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        for agent_status in ["active", "revoked"] {
            let (id, _) =
                seed_agent(&state, OWNER, "service_auth", agent_status, &["atproto"]).await;
            let (status, _) = widen(
                &state,
                &id,
                &["atproto", "blob:*/*"],
                &access_jwt(&SECRET, OWNER),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{agent_status}");
            assert_eq!(stored_scopes(&state, &id).await, vec!["atproto"]);
        }
    }

    #[tokio::test]
    async fn unknown_and_foreign_ids_are_the_same_404() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let other = "did:plc:widenother11111111111111";
        insert_account_with_email(&state.db, other, "widen-other@example.com").await;
        let (foreign, _) = seed_agent(&state, other, "service_auth", "claimed", &["atproto"]).await;
        let token = access_jwt(&SECRET, OWNER);

        let (fstatus, fbody) = widen(&state, &foreign, &["blob:*/*"], &token).await;
        let (ustatus, ubody) = widen(&state, "reg_missing", &["blob:*/*"], &token).await;

        assert_eq!(fstatus, StatusCode::NOT_FOUND);
        assert_eq!((fstatus, fbody), (ustatus, ubody));
        assert_eq!(stored_scopes(&state, &foreign).await, vec!["atproto"]);
    }

    #[tokio::test]
    async fn agent_and_app_password_credentials_are_refused() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let (id, _) = seed_agent(&state, OWNER, "service_auth", "claimed", &["atproto"]).await;

        let (astatus, _) = widen(
            &state,
            &id,
            &["blob:*/*"],
            &agent_jwt(&SECRET, OWNER, "com.atproto.access", &id),
        )
        .await;
        let (pstatus, _) = widen(
            &state,
            &id,
            &["blob:*/*"],
            &app_pass_jwt(&SECRET, OWNER, true),
        )
        .await;

        assert_eq!(astatus, StatusCode::FORBIDDEN);
        assert_eq!(pstatus, StatusCode::UNAUTHORIZED);
        assert_eq!(stored_scopes(&state, &id).await, vec!["atproto"]);
    }

    /// The child re-mint route carries the widened grant, clamped to whatever the profile is at
    /// renewal time: lowering it suspends a scope with no write, raising it back restores it.
    #[tokio::test]
    async fn child_renewals_follow_the_widened_grant_through_profile_changes() {
        let state = owner_state(&["atproto", "blob:*/*"]).await;
        let (id, child) = seed_agent(&state, OWNER, "child", "claimed", &["atproto"]).await;
        let token = access_jwt(&SECRET, OWNER);
        let remint = |state: CoreState| {
            let (child, token) = (child.clone(), token.clone());
            async move {
                let (status, body) = post_json_with_bearer(
                    state,
                    "/agent/child/assertion",
                    json!({ "did": child }),
                    Some(&token),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                body["scopes"].clone()
            }
        };

        widen(&state, &id, &["atproto", "blob:*/*"], &token).await;
        assert_eq!(remint(state.clone()).await, json!(["atproto", "blob:*/*"]));

        let lowered = with_profile(&state, &["atproto"]);
        assert_eq!(remint(lowered).await, json!(["atproto"]));
        assert_eq!(
            stored_scopes(&state, &id).await,
            vec!["atproto", "blob:*/*"]
        );

        assert_eq!(remint(state.clone()).await, json!(["atproto", "blob:*/*"]));
    }

    /// The wallet's banner and consent screen need the profile and each agent's held set without
    /// a `user_code`. An OAuth grant record isn't governed by the profile, so its effective set is
    /// its grant.
    #[tokio::test]
    async fn the_agent_lists_carry_the_profile_and_each_effective_set() {
        let state = owner_state(&["blob:*/*", "atproto"]).await;
        seed_agent(
            &state,
            OWNER,
            "service_auth",
            "claimed",
            &["atproto", "identity:*"],
        )
        .await;
        seed_agent(
            &state,
            OWNER,
            "oauth_app",
            "revoked",
            &["atproto", "identity:*"],
        )
        .await;

        let (status, body) = get_json(&state, "/v1/agents", &access_jwt(&SECRET, OWNER)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scopeProfile"], json!(["atproto", "blob:*/*"]));
        let effective = |registration_type: &str| {
            body["agents"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["registrationType"] == registration_type)
                .unwrap()["effectiveScopes"]
                .clone()
        };
        assert_eq!(effective("service_auth"), json!(["atproto"]));
        assert_eq!(effective("oauth_app"), json!(["atproto", "identity:*"]));

        // Children are listed by the parent's child list, which carries the same held set.
        seed_agent(
            &state,
            OWNER,
            "child",
            "claimed",
            &["atproto", "identity:*"],
        )
        .await;
        let (status, body) = get_json(&state, "/agent/child", &access_jwt(&SECRET, OWNER)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["children"][0]["effectiveScopes"], json!(["atproto"]));
    }
}
