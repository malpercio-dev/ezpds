// pattern: Imperative Shell
//
// Per-account agent management for the wallet's "My agents" surface:
//   GET  /v1/agents                            — list agent identities bound to the caller's DID
//   POST /v1/agents/{registration_id}/revoke   — turn an agent off (idempotent)
//   GET  /v1/agents/{registration_id}/audit    — page that agent's audit trail, newest first
//
// These are account-holder routes, not operator/admin ones: the caller authenticates as the
// account the agents are bound to, with either a wallet session token (`sessions` table) or a
// full-access OAuth/XRPC access token — the same dual-credential posture as `transfer/complete`.
// Agent-derived and app-password credentials are refused: an agent must never list, audit, or
// revoke agents (including itself), and a scoped app password is below this trust bar.
//
// An unknown registration id and one bound to a different account are both a uniform 404, so the
// endpoint is not an existence oracle for other accounts' registration ids.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use common::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::agent_assertion::parse_sqlite_datetime;
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::auth::oauth_scopes::intersect_scope_tokens;
use crate::db::agent_audit::{
    insert_agent_audit_event, list_agent_audit_events, AgentAuditEventType,
};
use crate::db::agent_auth::{
    get_agent_claim_attempt_by_user_code, get_agent_identity, list_agent_identities_for_did,
    revoke_agent_identity, AgentIdentityRow, AgentIdentityStatus,
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
    scopes: Vec<String>,
    status: &'static str,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListAgentsResponse {
    agents: Vec<AgentView>,
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

/// Authenticate the account owner: a wallet session token first, then a full-access OAuth/XRPC
/// access token. Agent-derived tokens (`registration_id` claim) and non-full-access scopes
/// (app passwords) are refused. Returns the caller's DID.
///
/// The credential logic is `auth::guards::authenticate_account_owner`, shared with the claim
/// ceremony's confirm gate (`agent_claim.rs` — routes may not import one another); this wrapper
/// maps its neutral rejection into this surface's XRPC vocabulary.
async fn authenticate_owner(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    state: &AppState,
) -> Result<String, ApiError> {
    authenticate_account_owner(headers, method, uri, state)
        .await
        .map_err(|err| match err {
            OwnerAuthError::Unauthenticated(e) => e,
            OwnerAuthError::AgentDerived => ApiError::new(
                ErrorCode::InsufficientScope,
                "this operation is not available to agent-derived credentials",
            ),
            OwnerAuthError::NotFullAccess => ApiError::new(
                ErrorCode::InvalidToken,
                "a session or full-access token is required",
            ),
        })
}

/// Load a registration and require `did` to own it — as the account it acts as, or as the
/// parent of a sovereign child (the parent provisions, revokes, and audits its children; the
/// child's own tokens are agent-derived and never pass the owner guard, so without the parent
/// arm a child's audit trail would be readable by no one). Unknown and foreign registrations
/// are the same uniform 404 (no cross-account existence oracle).
async fn owned_identity(
    state: &AppState,
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
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<ListAgentsResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    let rows = list_agent_identities_for_did(&state.db, &did).await?;
    let agents = rows
        .into_iter()
        .map(|row| AgentView {
            registration_id: row.id,
            registration_type: row.registration_type.as_str(),
            issuer: row.issuer,
            subject: row.subject,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
            status: row.status.as_str(),
            created_at: rfc3339(&row.created_at),
            updated_at: rfc3339(&row.updated_at),
            last_used_at: row.last_used_at.as_deref().map(rfc3339),
        })
        .collect();
    Ok(Json(ListAgentsResponse { agents }))
}

// ── POST /v1/agents/{registration_id}/revoke ────────────────────────────────────

pub async fn revoke_agent(
    State(state): State<AppState>,
    Path(registration_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<RevokeAgentResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    owned_identity(&state, &registration_id, &did).await?;

    // The status flip and its audit row commit atomically; the `status != 'revoked'` guard in
    // `revoke_agent_identity` makes a repeat revoke an idempotent 200 with no duplicate event.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to open transaction for agent revocation");
        ApiError::new(ErrorCode::InternalError, "failed to revoke agent")
    })?;
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
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit agent revocation");
        ApiError::new(ErrorCode::InternalError, "failed to revoke agent")
    })?;

    Ok(Json(RevokeAgentResponse {
        registration_id,
        status: "revoked",
    }))
}

// ── GET /v1/agents/{registration_id}/audit ──────────────────────────────────────

pub async fn agent_audit_log(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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
    }))
}
