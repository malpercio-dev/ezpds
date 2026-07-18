// Agent consent + audit commands — the wallet side of the auth.md claim ceremony and the
// "My agents" management surface. Five per-identity Tauri IPC commands, each taking a `did`:
//
//   preview_agent_claim(did, user_code)  — what would approving this code grant? (pre-biometric)
//   confirm_agent_claim(did, user_code)  — the human gate: flip the agent identity active → claimed
//   list_agents(did)                     — agent identities bound to this identity's account
//   revoke_agent(did, registration_id)   — turn an agent off (idempotent on the server)
//   get_agent_audit(did, registration_id, cursor) — page an agent's append-only audit trail
//
// Each resolves a per-DID full-access session through `SessionProvider::full_access_client`
// (like `app_passwords.rs`), so an expired session self-heals via `refreshSession` or, failing
// that, `SessionLocked` cues the frontend to run the biometric `sovereignLogin(did)` and retry —
// instead of dead-ending against the never-refreshed global session token this flow used before.
// Request cores are `_impl` functions taking `&OAuthClient` so tests drive them against httpmock.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity_store::IdentityStore;
use crate::oauth::OAuthError;
use crate::oauth_client::OAuthClient;
use crate::pds_client::PdsClient;
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};

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
    /// The identity's session could not be resolved without a passwordless unlock — the
    /// frontend should run the biometric `sovereignLogin(did)` and retry. Replaces the old
    /// dead-end where an expired global session token surfaced as a bogus connection error.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
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

/// Map an `OAuthClient` request failure into the agents surface. The session is resolved (and
/// refreshed) up front, so a failure here is a transport error on the request itself — and the
/// redacted breadcrumb was already recorded inside `OAuthClient`.
fn oauth_err(e: OAuthError) -> AgentsError {
    AgentsError::NetworkError {
        message: e.to_string(),
    }
}

/// Map a session-lifecycle failure into the agents surface. Only a genuine transport failure
/// becomes `NetworkError`; a `NeedsUnlock` becomes `SessionLocked` (the cue to run
/// `sovereignLogin(did)` and retry), and every other server/storage verdict is surfaced as
/// `Unknown` carrying the real cause — never mislabelled as connectivity.
fn map_session_error(error: SessionError) -> AgentsError {
    match error {
        SessionError::NeedsUnlock { reason } => AgentsError::SessionLocked { reason },
        SessionError::RateLimited { .. } => AgentsError::RateLimited,
        SessionError::Offline { message } => AgentsError::NetworkError { message },
        SessionError::IdentityNotFound => AgentsError::Unknown {
            message: "identity not found in wallet".to_string(),
        },
        SessionError::ServerFailure { status } => AgentsError::Unknown {
            message: format!("session request failed with status {status}"),
        },
        SessionError::UnsupportedHost => AgentsError::Unknown {
            message: "the identity's hosting server does not support session refresh".to_string(),
        },
        SessionError::Keychain { message } => AgentsError::Unknown {
            message: format!("session keychain failure: {message}"),
        },
        SessionError::InvalidResponse { message } => AgentsError::Unknown {
            message: format!("invalid session response: {message}"),
        },
    }
}

/// Resolve the DID's full-access session (restore / refresh, or `SessionLocked`).
async fn full_access_session(
    pds_client: &PdsClient,
    did: &str,
) -> Result<crate::session_provider::ActiveSession, AgentsError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| AgentsError::NetworkError {
            message: "system clock is unavailable".to_string(),
        })?;
    SessionProvider
        .full_access_client(pds_client, &IdentityStore, did, now)
        .await
        .map_err(map_session_error)
}

// ── Network cores (testable against httpmock) ──────────────────────────────────

async fn list_agents_impl(client: &OAuthClient) -> Result<Vec<AgentSummary>, AgentsError> {
    let resp = client.get("/v1/agents").await.map_err(oauth_err)?;
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
    client: &OAuthClient,
    registration_id: &str,
) -> Result<(), AgentsError> {
    let resp = client
        .post(
            &format!("/v1/agents/{registration_id}/revoke"),
            &serde_json::json!({}),
        )
        .await
        .map_err(oauth_err)?;
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
    client: &OAuthClient,
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
    let resp = client.get(&path).await.map_err(oauth_err)?;
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
    client: &OAuthClient,
    user_code: &str,
) -> Result<AgentClaimPreview, AgentsError> {
    let resp = client
        .post(
            "/v1/agents/claim-preview",
            &serde_json::json!({ "userCode": user_code }),
        )
        .await
        .map_err(oauth_err)?;
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
    client: &OAuthClient,
    user_code: &str,
) -> Result<AgentClaimConfirmation, AgentsError> {
    let resp = client
        .post(
            "/agent/identity/claim/confirm",
            &serde_json::json!({ "user_code": user_code }),
        )
        .await
        .map_err(oauth_err)?;
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

/// List the agent identities bound to this identity's account.
#[tauri::command]
pub async fn list_agents(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<Vec<AgentSummary>, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    list_agents_impl(&session.client).await
}

/// Revoke an agent identity. Idempotent on the server; the next token exchange is refused.
#[tauri::command]
pub async fn revoke_agent(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    registration_id: String,
) -> Result<(), AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    revoke_agent_impl(&session.client, &registration_id).await
}

/// Page an agent's audit trail, newest first. Pass the previous page's `cursor` to continue.
#[tauri::command]
pub async fn get_agent_audit(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    registration_id: String,
    cursor: Option<String>,
) -> Result<AgentAuditPage, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    get_agent_audit_impl(&session.client, &registration_id, cursor.as_deref()).await
}

/// Preview what confirming a claim-ceremony `user_code` would grant (shown before the
/// biometric approval gate — consent must be informed).
#[tauri::command]
pub async fn preview_agent_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    user_code: String,
) -> Result<AgentClaimPreview, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    preview_agent_claim_impl(&session.client, &user_code).await
}

/// Confirm a claim ceremony: the human gate that flips the agent identity `active → claimed`.
/// The frontend gates this call behind biometric authentication.
#[tauri::command]
pub async fn confirm_agent_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    user_code: String,
) -> Result<AgentClaimConfirmation, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    confirm_agent_claim_impl(&session.client, &user_code).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn make_bearer_jwt(exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#).as_bytes());
        format!("{header}.{payload}.sig")
    }

    /// A Bearer-mode client pointed at the mock server, with a far-future access token so no
    /// refresh fires before the request under test.
    fn bearer_client(server: &MockServer) -> OAuthClient {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        OAuthClient::new_bearer(make_bearer_jwt(exp), "refresh".to_string(), server.base_url())
            .expect("new_bearer must succeed")
    }

    #[tokio::test]
    async fn list_agents_parses_summaries() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/agents")
                .header_exists("authorization");
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

        let agents = list_agents_impl(&bearer_client(&server)).await.unwrap();
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

        let page = get_agent_audit_impl(&bearer_client(&server), "reg_1", Some("42"))
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

        let err = revoke_agent_impl(&bearer_client(&server), "reg_x")
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

        let err = preview_agent_claim_impl(&bearer_client(&server), "123456")
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

        let err = preview_agent_claim_impl(&bearer_client(&server), "123456")
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

        let confirmation = confirm_agent_claim_impl(&bearer_client(&server), "123456")
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

    #[test]
    fn session_needs_unlock_maps_to_session_locked() {
        let err = map_session_error(SessionError::NeedsUnlock {
            reason: UnlockReason::NoRefreshChain,
        });
        assert!(matches!(
            err,
            AgentsError::SessionLocked {
                reason: UnlockReason::NoRefreshChain
            }
        ));
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], "SESSION_LOCKED");
        assert_eq!(json["reason"], "NO_REFRESH_CHAIN");
    }

    /// A session failure keeps its nature: only a genuine transport failure is NETWORK_ERROR;
    /// a rate limit is RATE_LIMITED and a server/host verdict is UNKNOWN (never "check your
    /// connection"), so the "My agents" screen can tell an expired session from an outage.
    #[test]
    fn session_errors_do_not_flatten_to_network_error() {
        assert!(matches!(
            map_session_error(SessionError::RateLimited { retry_after: None }),
            AgentsError::RateLimited
        ));
        assert!(matches!(
            map_session_error(SessionError::ServerFailure { status: 503 }),
            AgentsError::Unknown { .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::UnsupportedHost),
            AgentsError::Unknown { .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::Offline {
                message: "timeout".to_string()
            }),
            AgentsError::NetworkError { .. }
        ));
    }
}
