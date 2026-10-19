// pattern: Functional Core

//! Typed methods for the auth.md agent-consent ceremony and the sovereign-child parent
//! console, over an authenticated [`OAuthClient`]: `/v1/agents/*`, `/agent/child/*`, and
//! `/agent/identity/claim/confirm`. These are auth.md's own bespoke endpoints, not
//! `com.atproto.*` XRPC — their `{error, error_description}` failure shape and per-route
//! status-code vocabulary differ from the `xrpc_ok`/`xrpc_json` envelope tail in
//! [`crate::error`], so this module classifies responses itself into [`AgentError`]
//! rather than [`crate::error::PdsClientError`].
//!
//! Minting a child account of its own (`mint_child_from_claim`) and reconciling children
//! after a recovery (`reconcile_children`) stay in identity-wallet: both derive rotation
//! keys off the wallet's delegation seed and sign a did:plc genesis operation, which is
//! wallet key-material, not client machinery. This module owns exactly the network round
//! trips those callers — and the plain claim/audit/list/revoke surface — issue over an
//! `OAuthClient`, which already records its own transport breadcrumbs via the observer it
//! was constructed with, so none of these methods take a separate observer parameter.

use serde::{Deserialize, Serialize};

use crate::oauth_client::{OAuthClient, OAuthError};

// ── Types (camelCase over the wire, mirroring the PDS responses) ────────────────

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
    pub detail: Option<serde_json::Value>,
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
    /// The handle an `anonymous` agent proposed for an account of its own. Present only when
    /// it asked; the approval screen offers it as an editable default, never a commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_hint: Option<String>,
}

/// Result of a confirmed claim (`POST /agent/identity/claim/confirm`).
///
/// The ceremony endpoint answers in auth.md snake_case (`registration_id`) while callers
/// receive camelCase like every other typed method — the alias accepts the server shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClaimConfirmation {
    #[serde(alias = "registration_id")]
    pub registration_id: String,
    pub status: String,
    pub did: String,
}

/// One sovereign child under this account (`GET /agent/child` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildSummary {
    pub registration_id: String,
    /// The child's own `did:plc` — how every lifecycle method addresses it.
    pub did: String,
    pub handle: String,
    /// `claimed` (live), `active` (mid-provisioning), or `revoked`.
    pub status: String,
    pub created_at: String,
    pub scopes: Vec<String>,
    /// Set only once deletion is scheduled: the instant after which the server purges the
    /// child permanently. Deletion revokes as a side effect, so `status` alone cannot
    /// distinguish a retired child from a merely revoked one — this is what tells them apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListChildrenResponse {
    children: Vec<ChildSummary>,
}

/// Result of scheduling a child's deletion (`POST /agent/child/delete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildDeletion {
    pub did: String,
    pub status: String,
    /// The instant after which the child is purged permanently — the date a caller shows the
    /// user so they know how long the decision stays reversible on the server side.
    pub delete_after: String,
}

/// A freshly renewed child credential (`POST /agent/child/assertion`).
///
/// `identity_assertion` is a live credential for the child account, so a caller showing it
/// should treat it like an app-password reveal: shown once, offered for copy, never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildAssertion {
    pub did: String,
    pub registration_id: String,
    pub identity_assertion: String,
    pub assertion_expires: String,
    pub scopes: Vec<String>,
}

// ── Error type ──────────────────────────────────────────────────────────────────

/// Errors from the agent consent/management endpoints.
///
/// The ceremony errors are distinct because an approval screen renders each as its own
/// explicit state (denial and expiry are never silent). This does not carry
/// `NotProvisioned`/`HandleRejected`/session-lifecycle variants — those depend on wallet
/// state (a delegation seed, `SessionProvider`) this crate does not model; the wallet's own
/// error enum stays a superset with a `From` conversion for the variants below.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// No Bearer/DPoP credential the server accepts.
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
    /// Too many attempts in the window; the caller should back off and retry.
    #[error("rate limited")]
    RateLimited,
    /// Transport-level failure reaching the PDS. `message` is diagnostic only (ADR-0031) — a
    /// transport failure is never the server's words.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The PDS answered with something this method does not understand — an unparseable body
    /// or an unclassified status/ceremony code. `message` is diagnostic only (ADR-0031): it may
    /// echo a short server-supplied code (e.g. an unrecognized ceremony `error` value) inside
    /// Rust-authored wrapping text, which is not the same as carrying the server's own prose,
    /// so it must never render with server attribution.
    #[error("unexpected response: {message}")]
    Unknown { message: String },
}

fn oauth_err(e: OAuthError) -> AgentError {
    AgentError::NetworkError {
        message: e.to_string(),
    }
}

/// Shared status mapping for the four child routes. They are deliberately uniform: an
/// unknown or foreign child DID is the same 404 as one belonging to another parent, so none
/// of them is an existence oracle. 403 is the assertion route's "child is not active"
/// refusal — revocation is a one-way rung on the custody ladder.
fn child_route_error(status: u16, path: &str) -> AgentError {
    match status {
        401 => AgentError::NotAuthenticated,
        403 => AgentError::AccessDenied,
        404 => AgentError::AgentNotFound,
        429 => AgentError::RateLimited,
        other => AgentError::Unknown {
            message: format!("{path} returned {other}"),
        },
    }
}

/// auth.md-style `{ error, error_description }` body the ceremony endpoints return.
///
/// Exported so a caller with its own widened classification (identity-wallet's child-mint
/// confirm, which treats `invalid_request` specially before falling back to
/// [`map_ceremony_error`]) can decode the same shape rather than redefining it.
#[derive(Debug, Deserialize)]
pub struct CeremonyErrorBody {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Map a confirm/preview ceremony error code to the typed variant a caller renders.
pub fn map_ceremony_error(error_code: &str) -> AgentError {
    match error_code {
        "invalid_user_code" | "invalid_request" => AgentError::CodeNotFound,
        "claim_expired" => AgentError::CodeExpired,
        "claimed_or_in_flight" => AgentError::AlreadyClaimed,
        "access_denied" => AgentError::AccessDenied,
        other => AgentError::Unknown {
            message: format!("ceremony error: {other}"),
        },
    }
}

// ── Network methods ──────────────────────────────────────────────────────────────

/// List the agent identities bound to this account (`GET /v1/agents`).
pub async fn list_agents(client: &OAuthClient) -> Result<Vec<AgentSummary>, AgentError> {
    let resp = client.get("/v1/agents").await.map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => {
            let body: ListAgentsResponse = resp.json().await.map_err(|e| AgentError::Unknown {
                message: format!("failed to parse /v1/agents response: {e}"),
            })?;
            Ok(body.agents)
        }
        401 | 403 => Err(AgentError::NotAuthenticated),
        429 => Err(AgentError::RateLimited),
        other => Err(AgentError::Unknown {
            message: format!("GET /v1/agents returned {other}"),
        }),
    }
}

/// Revoke an agent identity. Idempotent on the server; the next token exchange is refused.
pub async fn revoke_agent(client: &OAuthClient, registration_id: &str) -> Result<(), AgentError> {
    let resp = client
        .post(
            &format!("/v1/agents/{registration_id}/revoke"),
            &serde_json::json!({}),
        )
        .await
        .map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => Ok(()),
        401 | 403 => Err(AgentError::NotAuthenticated),
        404 => Err(AgentError::AgentNotFound),
        429 => Err(AgentError::RateLimited),
        other => Err(AgentError::Unknown {
            message: format!("revoke returned {other}"),
        }),
    }
}

/// List the sovereign child accounts this identity has minted for agents (`GET /agent/child`).
pub async fn list_children(client: &OAuthClient) -> Result<Vec<ChildSummary>, AgentError> {
    let resp = client.get("/agent/child").await.map_err(oauth_err)?;
    if resp.status().as_u16() != 200 {
        return Err(child_route_error(
            resp.status().as_u16(),
            "GET /agent/child",
        ));
    }
    let body: ListChildrenResponse = resp.json().await.map_err(|e| AgentError::Unknown {
        message: format!("failed to parse /agent/child response: {e}"),
    })?;
    Ok(body.children)
}

/// Revoke a child's delegated capability, keeping its account, repo, and DID intact.
pub async fn revoke_child(client: &OAuthClient, child_did: &str) -> Result<(), AgentError> {
    let resp = client
        .post(
            "/agent/child/revoke",
            &serde_json::json!({ "did": child_did }),
        )
        .await
        .map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => Ok(()),
        other => Err(child_route_error(other, "child revoke")),
    }
}

/// Retire a child's hosting: revoke it, deactivate it now, and schedule the permanent purge.
pub async fn delete_child(
    client: &OAuthClient,
    child_did: &str,
) -> Result<ChildDeletion, AgentError> {
    let resp = client
        .post(
            "/agent/child/delete",
            &serde_json::json!({ "did": child_did }),
        )
        .await
        .map_err(oauth_err)?;
    if resp.status().as_u16() != 200 {
        return Err(child_route_error(resp.status().as_u16(), "child delete"));
    }
    resp.json().await.map_err(|e| AgentError::Unknown {
        message: format!("failed to parse child delete response: {e}"),
    })
}

/// Renew a live child's identity assertion — its credential for the token endpoint.
pub async fn remint_child_assertion(
    client: &OAuthClient,
    child_did: &str,
) -> Result<ChildAssertion, AgentError> {
    let resp = client
        .post(
            "/agent/child/assertion",
            &serde_json::json!({ "did": child_did }),
        )
        .await
        .map_err(oauth_err)?;
    if resp.status().as_u16() != 200 {
        return Err(child_route_error(resp.status().as_u16(), "child assertion"));
    }
    resp.json().await.map_err(|e| AgentError::Unknown {
        message: format!("failed to parse child assertion response: {e}"),
    })
}

/// Page an agent's audit trail, newest first (`GET /v1/agents/{id}/audit`).
pub async fn get_agent_audit(
    client: &OAuthClient,
    registration_id: &str,
    cursor: Option<&str>,
) -> Result<AgentAuditPage, AgentError> {
    let path = match cursor {
        Some(c) => format!(
            "/v1/agents/{registration_id}/audit?cursor={}",
            urlencoding::encode(c)
        ),
        None => format!("/v1/agents/{registration_id}/audit"),
    };
    let resp = client.get(&path).await.map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| AgentError::Unknown {
            message: format!("failed to parse audit response: {e}"),
        }),
        401 | 403 => Err(AgentError::NotAuthenticated),
        404 => Err(AgentError::AgentNotFound),
        429 => Err(AgentError::RateLimited),
        other => Err(AgentError::Unknown {
            message: format!("audit returned {other}"),
        }),
    }
}

/// Preview what confirming a claim-ceremony `user_code` would grant
/// (`POST /v1/agents/claim-preview`).
pub async fn preview_agent_claim(
    client: &OAuthClient,
    user_code: &str,
) -> Result<AgentClaimPreview, AgentError> {
    let resp = client
        .post(
            "/v1/agents/claim-preview",
            &serde_json::json!({ "userCode": user_code }),
        )
        .await
        .map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => resp.json().await.map_err(|e| AgentError::Unknown {
            message: format!("failed to parse claim preview: {e}"),
        }),
        401 | 403 => Err(AgentError::NotAuthenticated),
        // The preview endpoint deliberately collapses every failure shape into one uniform 404.
        404 => Err(AgentError::CodeNotFound),
        429 => Err(AgentError::RateLimited),
        other => Err(AgentError::Unknown {
            message: format!("claim preview returned {other}"),
        }),
    }
}

/// Confirm a claim ceremony: the human gate flipping the agent identity `active → claimed`
/// (`POST /agent/identity/claim/confirm`).
pub async fn confirm_agent_claim(
    client: &OAuthClient,
    user_code: &str,
) -> Result<AgentClaimConfirmation, AgentError> {
    let resp = client
        .post(
            "/agent/identity/claim/confirm",
            &serde_json::json!({ "user_code": user_code }),
        )
        .await
        .map_err(oauth_err)?;
    let status = resp.status();
    if status.is_success() {
        return resp.json().await.map_err(|e| AgentError::Unknown {
            message: format!("failed to parse confirm response: {e}"),
        });
    }
    if status.as_u16() == 401 {
        return Err(AgentError::NotAuthenticated);
    }
    if status.as_u16() == 429 {
        return Err(AgentError::RateLimited);
    }
    match resp.json::<CeremonyErrorBody>().await {
        Ok(body) => Err(map_ceremony_error(&body.error)),
        Err(_) => Err(AgentError::Unknown {
            message: format!("confirm returned {status}"),
        }),
    }
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
        OAuthClient::new_bearer(
            make_bearer_jwt(exp),
            "refresh".to_string(),
            server.base_url(),
        )
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

        let agents = list_agents(&bearer_client(&server)).await.unwrap();
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
    async fn list_children_parses_scopes_and_purge_date() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/agent/child")
                .header_exists("authorization");
            then.status(200).json_body(serde_json::json!({
                "children": [
                    {
                        "registrationId": "reg_live",
                        "did": "did:plc:childlive",
                        "handle": "scribe.example.com",
                        "status": "claimed",
                        "createdAt": "2026-01-01T00:00:00.000Z",
                        "scopes": ["repo:write"]
                    },
                    {
                        "registrationId": "reg_gone",
                        "did": "did:plc:childgone",
                        "handle": "old.example.com",
                        "status": "revoked",
                        "createdAt": "2026-01-01T00:00:00.000Z",
                        "scopes": [],
                        "deleteAfter": "2026-02-01T00:00:00Z"
                    }
                ]
            }));
        });

        let children = list_children(&bearer_client(&server)).await.unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].scopes, vec!["repo:write"]);
        // A live child carries no purge date; only a scheduled deletion does. Without this the
        // caller could not tell a revoked child from one counting down to permanent removal.
        assert!(children[0].delete_after.is_none());
        assert_eq!(
            children[1].delete_after.as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
    }

    #[tokio::test]
    async fn delete_child_returns_the_purge_deadline() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/agent/child/delete")
                .json_body(serde_json::json!({ "did": "did:plc:childgone" }));
            then.status(200).json_body(serde_json::json!({
                "did": "did:plc:childgone",
                "status": "deletion_scheduled",
                "deleteAfter": "2026-02-01T00:00:00Z"
            }));
        });

        let scheduled = delete_child(&bearer_client(&server), "did:plc:childgone")
            .await
            .unwrap();
        assert_eq!(scheduled.status, "deletion_scheduled");
        assert_eq!(scheduled.delete_after, "2026-02-01T00:00:00Z");
    }

    #[tokio::test]
    async fn reminting_a_revoked_child_is_access_denied_not_a_retryable_error() {
        // The server refuses renewal for a revoked child with 403. Surfacing that as a distinct
        // state matters: revocation is one-way, so a caller must say so rather than invite a
        // retry that can never succeed.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/agent/child/assertion");
            then.status(403)
                .json_body(serde_json::json!({ "error": "Forbidden" }));
        });

        let err = remint_child_assertion(&bearer_client(&server), "did:plc:childgone")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::AccessDenied), "got {err:?}");
    }

    #[tokio::test]
    async fn remint_child_assertion_parses_the_renewed_credential() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/agent/child/assertion")
                .json_body(serde_json::json!({ "did": "did:plc:childlive" }));
            then.status(200).json_body(serde_json::json!({
                "did": "did:plc:childlive",
                "registrationId": "reg_live",
                "identityAssertion": "header.payload.sig",
                "assertionExpires": "2026-01-02T00:00:00.000Z",
                "scopes": ["repo:write"]
            }));
        });

        let renewed = remint_child_assertion(&bearer_client(&server), "did:plc:childlive")
            .await
            .unwrap();
        assert_eq!(renewed.identity_assertion, "header.payload.sig");
        assert_eq!(renewed.scopes, vec!["repo:write"]);
    }

    #[tokio::test]
    async fn an_unknown_child_is_not_found_on_every_lifecycle_route() {
        // Uniform 404 across the three mutating routes — a foreign child DID answers the same as
        // a nonexistent one, so none of them is an existence oracle for another account.
        let server = MockServer::start();
        for path in [
            "/agent/child/revoke",
            "/agent/child/delete",
            "/agent/child/assertion",
        ] {
            server.mock(|when, then| {
                when.method(POST).path(path);
                then.status(404)
                    .json_body(serde_json::json!({ "error": "NotFound" }));
            });
        }
        let client = bearer_client(&server);

        assert!(matches!(
            revoke_child(&client, "did:plc:nope").await.unwrap_err(),
            AgentError::AgentNotFound
        ));
        assert!(matches!(
            delete_child(&client, "did:plc:nope").await.unwrap_err(),
            AgentError::AgentNotFound
        ));
        assert!(matches!(
            remint_child_assertion(&client, "did:plc:nope")
                .await
                .unwrap_err(),
            AgentError::AgentNotFound
        ));
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

        let page = get_agent_audit(&bearer_client(&server), "reg_1", Some("42"))
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

        let err = revoke_agent(&bearer_client(&server), "reg_x")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::AgentNotFound));
    }

    #[tokio::test]
    async fn preview_maps_429_to_rate_limited() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/agents/claim-preview");
            then.status(429)
                .json_body(serde_json::json!({ "error": { "code": "RATE_LIMITED" } }));
        });

        let err = preview_agent_claim(&bearer_client(&server), "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::RateLimited));
    }

    #[tokio::test]
    async fn preview_maps_uniform_404_to_code_not_found() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/agents/claim-preview");
            then.status(404)
                .json_body(serde_json::json!({ "error": { "code": "NOT_FOUND" } }));
        });

        let err = preview_agent_claim(&bearer_client(&server), "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::CodeNotFound));
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

        let confirmation = confirm_agent_claim(&bearer_client(&server), "123456")
            .await
            .unwrap();
        assert_eq!(confirmation.registration_id, "reg_1");
        assert_eq!(confirmation.status, "claimed");
    }

    #[test]
    fn ceremony_error_codes_map_to_explicit_states() {
        assert!(matches!(
            map_ceremony_error("invalid_user_code"),
            AgentError::CodeNotFound
        ));
        assert!(matches!(
            map_ceremony_error("claim_expired"),
            AgentError::CodeExpired
        ));
        assert!(matches!(
            map_ceremony_error("claimed_or_in_flight"),
            AgentError::AlreadyClaimed
        ));
        assert!(matches!(
            map_ceremony_error("access_denied"),
            AgentError::AccessDenied
        ));
        assert!(matches!(
            map_ceremony_error("something_else"),
            AgentError::Unknown { .. }
        ));
    }
}
