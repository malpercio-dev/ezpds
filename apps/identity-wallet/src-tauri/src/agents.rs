// Agent consent + audit commands — the wallet side of the auth.md claim ceremony and the
// "My agents" management surface. Five Tauri IPC commands against the configured PDS:
//
//   preview_agent_claim(user_code)  — what would approving this code grant? (shown pre-biometric)
//   confirm_agent_claim(user_code)  — the human gate: flip the agent identity `active → claimed`
//   list_agents()                   — agent identities bound to this account
//   revoke_agent(registration_id)   — turn an agent off (idempotent on the server)
//   get_agent_audit(registration_id, cursor) — page an agent's append-only audit trail
//
// All five authenticate with the wallet's full session token (Keychain `"session-token"`, the
// credential the create flow leaves behind) — the PDS accepts it via its owner guard. Network
// cores are `_impl` functions taking `&CustosClient` so tests drive them against httpmock,
// mirroring `claim.rs`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http::CustosClient;
use crate::keychain;

// ── Frontend-facing types (camelCase, mirroring the PDS responses) ─────────────

/// One agent identity bound to this account (`GET /v1/agents` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSummary {
    pub registration_id: String,
    pub registration_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub scopes: Vec<String>,
    /// `active` (awaiting the claim ceremony), `claimed`, or `revoked`.
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListAgentsResponse {
    agents: Vec<AgentSummary>,
}

/// One audit event (`GET /v1/agents/{id}/audit` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuditEvent {
    pub id: String,
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
    pub created_at: String,
}

/// One page of an agent's audit trail, newest first. `cursor` present means more pages exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuditPage {
    pub events: Vec<AgentAuditEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// What confirming a `user_code` would grant (`POST /v1/agents/claim-preview`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClaimPreview {
    pub registration_id: String,
    pub registration_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub scopes: Vec<String>,
    pub user_code_expires_at: String,
}

/// Result of a confirmed claim (`POST /agent/identity/claim/confirm`).
///
/// The ceremony endpoint answers in auth.md snake_case (`registration_id`) while the frontend
/// receives camelCase like every other IPC type — the alias accepts the server shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClaimConfirmation {
    #[serde(alias = "registration_id")]
    pub registration_id: String,
    pub status: String,
    pub did: String,
}

// ── Error type ──────────────────────────────────────────────────────────────────

/// Errors for the agent consent/management commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the existing error pattern. The
/// ceremony errors are distinct because the approval screen renders each as its own explicit
/// state (denial and expiry are never silent, per the design plan).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentsError {
    /// No wallet session token in the Keychain — onboarding never completed on this device.
    #[error("not authenticated")]
    NotAuthenticated,
    /// The code is unknown (mistyped, or the ceremony was restarted).
    #[error("unknown code")]
    CodeNotFound,
    /// The code's window lapsed; the agent must restart the ceremony.
    #[error("code expired")]
    CodeExpired,
    /// The code was already used.
    #[error("code already used")]
    AlreadyClaimed,
    /// The claim (or agent) belongs to a different account, or the identity was revoked.
    #[error("access denied")]
    AccessDenied,
    /// Unknown registration id (or one not bound to this account).
    #[error("unknown agent registration")]
    AgentNotFound,
    /// Too many attempts in the window (the claim endpoints share a tight per-IP limiter);
    /// the caller should back off and retry.
    #[error("rate limited")]
    RateLimited,
    /// Transport-level failure reaching the PDS.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The PDS answered with something this wallet does not understand.
    #[error("unexpected response: {message}")]
    Unknown { message: String },
}

/// auth.md-style `{ error, error_description }` body the ceremony endpoints return.
#[derive(Debug, Deserialize)]
struct CeremonyErrorBody {
    error: String,
}

/// Map a confirm/preview ceremony error code to the typed variant the frontend renders.
fn map_ceremony_error(error_code: &str) -> AgentsError {
    match error_code {
        "invalid_user_code" | "invalid_request" => AgentsError::CodeNotFound,
        "claim_expired" => AgentsError::CodeExpired,
        "claimed_or_in_flight" => AgentsError::AlreadyClaimed,
        "access_denied" => AgentsError::AccessDenied,
        other => AgentsError::Unknown {
            message: format!("ceremony error: {other}"),
        },
    }
}

fn network_error(e: reqwest::Error) -> AgentsError {
    AgentsError::NetworkError {
        message: e.to_string(),
    }
}

/// Read the wallet's full session token from the Keychain.
fn session_token() -> Result<String, AgentsError> {
    let bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "no session-token in Keychain for agent command");
        AgentsError::NotAuthenticated
    })?;
    String::from_utf8(bytes).map_err(|_| AgentsError::NotAuthenticated)
}

// ── Network cores (testable against httpmock) ──────────────────────────────────

async fn list_agents_impl(
    client: &CustosClient,
    token: &str,
) -> Result<Vec<AgentSummary>, AgentsError> {
    let resp = client
        .get_with_bearer("/v1/agents", token)
        .await
        .map_err(network_error)?;
    match resp.status().as_u16() {
        200 => {
            let body: ListAgentsResponse = resp.json().await.map_err(|e| AgentsError::Unknown {
                message: format!("failed to parse /v1/agents response: {e}"),
            })?;
            Ok(body.agents)
        }
        401 | 403 => Err(AgentsError::NotAuthenticated),
        429 => Err(AgentsError::RateLimited),
        other => Err(AgentsError::Unknown {
            message: format!("GET /v1/agents returned {other}"),
        }),
    }
}

async fn revoke_agent_impl(
    client: &CustosClient,
    token: &str,
    registration_id: &str,
) -> Result<(), AgentsError> {
    let resp = client
        .post_with_bearer(
            &format!("/v1/agents/{registration_id}/revoke"),
            &serde_json::json!({}),
            token,
        )
        .await
        .map_err(network_error)?;
    match resp.status().as_u16() {
        200 => Ok(()),
        401 | 403 => Err(AgentsError::NotAuthenticated),
        404 => Err(AgentsError::AgentNotFound),
        429 => Err(AgentsError::RateLimited),
        other => Err(AgentsError::Unknown {
            message: format!("revoke returned {other}"),
        }),
    }
}

async fn get_agent_audit_impl(
    client: &CustosClient,
    token: &str,
    registration_id: &str,
    cursor: Option<&str>,
) -> Result<AgentAuditPage, AgentsError> {
    let path = match cursor {
        Some(c) => format!(
            "/v1/agents/{registration_id}/audit?cursor={}",
            urlencoding::encode(c)
        ),
        None => format!("/v1/agents/{registration_id}/audit"),
    };
    let resp = client
        .get_with_bearer(&path, token)
        .await
        .map_err(network_error)?;
    match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| AgentsError::Unknown {
            message: format!("failed to parse audit response: {e}"),
        }),
        401 | 403 => Err(AgentsError::NotAuthenticated),
        404 => Err(AgentsError::AgentNotFound),
        429 => Err(AgentsError::RateLimited),
        other => Err(AgentsError::Unknown {
            message: format!("audit returned {other}"),
        }),
    }
}

async fn preview_agent_claim_impl(
    client: &CustosClient,
    token: &str,
    user_code: &str,
) -> Result<AgentClaimPreview, AgentsError> {
    let resp = client
        .post_with_bearer(
            "/v1/agents/claim-preview",
            &serde_json::json!({ "userCode": user_code }),
            token,
        )
        .await
        .map_err(network_error)?;
    match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| AgentsError::Unknown {
            message: format!("failed to parse claim preview: {e}"),
        }),
        401 | 403 => Err(AgentsError::NotAuthenticated),
        // The preview endpoint deliberately collapses every failure shape into one uniform 404.
        404 => Err(AgentsError::CodeNotFound),
        429 => Err(AgentsError::RateLimited),
        other => Err(AgentsError::Unknown {
            message: format!("claim preview returned {other}"),
        }),
    }
}

async fn confirm_agent_claim_impl(
    client: &CustosClient,
    token: &str,
    user_code: &str,
) -> Result<AgentClaimConfirmation, AgentsError> {
    let resp = client
        .post_with_bearer(
            "/agent/identity/claim/confirm",
            &serde_json::json!({ "user_code": user_code }),
            token,
        )
        .await
        .map_err(network_error)?;
    let status = resp.status();
    if status.is_success() {
        return resp.json().await.map_err(|e| AgentsError::Unknown {
            message: format!("failed to parse confirm response: {e}"),
        });
    }
    if status.as_u16() == 401 {
        return Err(AgentsError::NotAuthenticated);
    }
    if status.as_u16() == 429 {
        return Err(AgentsError::RateLimited);
    }
    match resp.json::<CeremonyErrorBody>().await {
        Ok(body) => Err(map_ceremony_error(&body.error)),
        Err(_) => Err(AgentsError::Unknown {
            message: format!("confirm returned {status}"),
        }),
    }
}

// ── Tauri commands ──────────────────────────────────────────────────────────────

/// List the agent identities bound to this account.
#[tauri::command]
pub async fn list_agents(
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<Vec<AgentSummary>, AgentsError> {
    let token = session_token()?;
    list_agents_impl(state.custos_client(), &token).await
}

/// Revoke an agent identity. Idempotent on the server; the next token exchange is refused.
#[tauri::command]
pub async fn revoke_agent(
    registration_id: String,
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<(), AgentsError> {
    let token = session_token()?;
    revoke_agent_impl(state.custos_client(), &token, &registration_id).await
}

/// Page an agent's audit trail, newest first. Pass the previous page's `cursor` to continue.
#[tauri::command]
pub async fn get_agent_audit(
    registration_id: String,
    cursor: Option<String>,
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<AgentAuditPage, AgentsError> {
    let token = session_token()?;
    get_agent_audit_impl(
        state.custos_client(),
        &token,
        &registration_id,
        cursor.as_deref(),
    )
    .await
}

/// Preview what confirming a claim-ceremony `user_code` would grant (shown before the
/// biometric approval gate — consent must be informed).
#[tauri::command]
pub async fn preview_agent_claim(
    user_code: String,
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<AgentClaimPreview, AgentsError> {
    let token = session_token()?;
    preview_agent_claim_impl(state.custos_client(), &token, &user_code).await
}

/// Confirm a claim ceremony: the human gate that flips the agent identity `active → claimed`.
/// The frontend gates this call behind biometric authentication.
#[tauri::command]
pub async fn confirm_agent_claim(
    user_code: String,
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<AgentClaimConfirmation, AgentsError> {
    let token = session_token()?;
    confirm_agent_claim_impl(state.custos_client(), &token, &user_code).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn client_for(server: &MockServer) -> CustosClient {
        CustosClient::new_with_url(server.base_url())
    }

    #[tokio::test]
    async fn list_agents_parses_summaries() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/agents")
                .header("authorization", "Bearer tok");
            then.status(200).json_body(serde_json::json!({
                "agents": [{
                    "registrationId": "reg_1",
                    "registrationType": "service_auth",
                    "scopes": ["blob:image/*"],
                    "status": "claimed",
                    "createdAt": "2026-01-01T00:00:00.000Z",
                    "updatedAt": "2026-01-01T00:05:00.000Z",
                    "lastUsedAt": "2026-01-02T00:00:00.000Z"
                }]
            }));
        });

        let agents = list_agents_impl(&client_for(&server), "tok").await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].registration_id, "reg_1");
        assert_eq!(agents[0].status, "claimed");
        assert_eq!(agents[0].scopes, vec!["blob:image/*"]);
        assert_eq!(
            agents[0].last_used_at.as_deref(),
            Some("2026-01-02T00:00:00.000Z")
        );
    }

    #[tokio::test]
    async fn audit_page_round_trips_cursor() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/agents/reg_1/audit")
                .query_param("cursor", "42");
            then.status(200).json_body(serde_json::json!({
                "events": [{
                    "id": "evt_1",
                    "eventType": "repo_write",
                    "did": "did:plc:me",
                    "detail": { "creates": 1 },
                    "createdAt": "2026-01-02T00:00:00.000Z"
                }],
                "cursor": "41"
            }));
        });

        let page = get_agent_audit_impl(&client_for(&server), "tok", "reg_1", Some("42"))
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event_type, "repo_write");
        assert_eq!(page.cursor.as_deref(), Some("41"));
    }

    #[tokio::test]
    async fn revoke_maps_404_to_agent_not_found() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/agents/reg_x/revoke");
            then.status(404)
                .json_body(serde_json::json!({ "error": { "code": "NOT_FOUND" } }));
        });

        let err = revoke_agent_impl(&client_for(&server), "tok", "reg_x")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentsError::AgentNotFound));
    }

    #[tokio::test]
    async fn preview_maps_429_to_rate_limited() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/agents/claim-preview");
            then.status(429)
                .json_body(serde_json::json!({ "error": { "code": "RATE_LIMITED" } }));
        });

        let err = preview_agent_claim_impl(&client_for(&server), "tok", "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentsError::RateLimited));
    }

    #[tokio::test]
    async fn preview_maps_uniform_404_to_code_not_found() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/agents/claim-preview");
            then.status(404)
                .json_body(serde_json::json!({ "error": { "code": "NOT_FOUND" } }));
        });

        let err = preview_agent_claim_impl(&client_for(&server), "tok", "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentsError::CodeNotFound));
    }

    #[tokio::test]
    async fn confirm_success_parses_confirmation() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/agent/identity/claim/confirm");
            then.status(200).json_body(serde_json::json!({
                "registration_id": "reg_1",
                "status": "claimed",
                "did": "did:plc:me"
            }));
        });

        let confirmation = confirm_agent_claim_impl(&client_for(&server), "tok", "123456")
            .await
            .unwrap();
        assert_eq!(confirmation.registration_id, "reg_1");
        assert_eq!(confirmation.status, "claimed");
    }

    #[test]
    fn ceremony_error_codes_map_to_explicit_states() {
        assert!(matches!(
            map_ceremony_error("invalid_user_code"),
            AgentsError::CodeNotFound
        ));
        assert!(matches!(
            map_ceremony_error("claim_expired"),
            AgentsError::CodeExpired
        ));
        assert!(matches!(
            map_ceremony_error("claimed_or_in_flight"),
            AgentsError::AlreadyClaimed
        ));
        assert!(matches!(
            map_ceremony_error("access_denied"),
            AgentsError::AccessDenied
        ));
        assert!(matches!(
            map_ceremony_error("something_else"),
            AgentsError::Unknown { .. }
        ));
    }

    #[test]
    fn errors_serialize_as_screaming_snake_codes() {
        let json = serde_json::to_value(AgentsError::CodeExpired).unwrap();
        assert_eq!(json["code"], "CODE_EXPIRED");
        let json = serde_json::to_value(AgentsError::NotAuthenticated).unwrap();
        assert_eq!(json["code"], "NOT_AUTHENTICATED");
    }
}
