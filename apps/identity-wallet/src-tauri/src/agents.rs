// pattern: Mixed (Functional Core error mapping; Imperative Shell commands)

//! Agent consent + audit — the wallet side of the auth.md claim ceremony and the
//! "My agents" surface. Seven per-identity Tauri IPC commands, each taking a `did`:
//!
//! - `preview_agent_claim(did, user_code) -> AgentClaimPreview` — `POST /v1/agents/claim-preview`:
//!   what approving this code would grant, shown before the biometric gate.
//! - `confirm_agent_claim(did, user_code) -> AgentClaimConfirmation` —
//!   `POST /agent/identity/claim/confirm`, the human gate flipping the agent identity
//!   `active → claimed`; the frontend wraps it in `authenticateBiometric()`, so the
//!   prompt precedes the network call and a rejected gate grants nothing.
//! - `list_agents(did) -> Vec<AgentSummary>` — the identities bound to this account.
//! - `revoke_agent(did, registration_id)` — turn an agent off (idempotent on the server).
//! - `get_agent_audit(did, registration_id, cursor?) -> AgentAuditPage` — page the
//!   agent's append-only audit trail.
//! - `agent_accounts_provisioned(did) -> bool` — whether the identity holds a delegation
//!   seed, and so can mint an agent an account of its own. The one command here that
//!   touches no network: it reads the Keychain slot the share ceremony writes.
//! - `mint_child_from_claim(did, user_code, handle) -> MintedChild` — the cooperative arm of
//!   the same gate: reserve a repo key, derive the child's rotation key off the delegation
//!   seed, sign its genesis op, and confirm the claim with it, so the agent ends up with an
//!   account of its own instead of a credential for this one.
//!
//! Five more manage the children that arm creates — the parent console. They address a child by
//! *its own DID*, not a registration id, since a child is an account first and a capability
//! second; `did` stays the authenticating parent:
//!
//! - `list_children(did) -> Vec<ChildSummary>` — `GET /agent/child`.
//! - `revoke_child(did, child_did)` — `POST /agent/child/revoke`: kill the capability, keep the
//!   account (the ADR-0023 custody ladder's lower rung).
//! - `delete_child(did, child_did) -> ChildDeletion` — `POST /agent/child/delete`: the higher
//!   rung, retiring the hosting itself; returns the purge deadline to show the user.
//! - `remint_child_assertion(did, child_did) -> ChildAssertion` — `POST /agent/child/assertion`:
//!   a fresh credential for a child that lay dormant past its assertion lifetime. Refused for a
//!   revoked child, so renewal is never a way back up the ladder revocation walked down.
//! - `reconcile_children(did) -> ChildReconciliation` — the recovery epilogue for children: after
//!   a restore has put the delegation seed back, re-derive candidate keys by index and check each
//!   against the child's plc.directory audit log, rebuilding the local child index from the
//!   server's list. Short-circuits without plc traffic when the index already covers that list.
//!
//! Each resolves a refreshable per-DID full-access session via
//! `SessionProvider::full_access_client` (like `app_passwords.rs`) and issues the
//! request through `session.client` (an `OAuthClient`), so an expired session
//! self-heals via `refreshSession` or, failing that, `SESSION_LOCKED { reason }` cues
//! the frontend to run `unlockIdentity(did)` and retry. This replaced auth on the
//! never-refreshed global `"session-token"`, whose lapse dead-ended every agent
//! command as a bogus connection error. Request cores are `_impl` functions taking
//! `&OAuthClient`, tested against httpmock.
//!
//! `AgentsError` (NOT_AUTHENTICATED, CODE_NOT_FOUND, CODE_EXPIRED, ALREADY_CLAIMED,
//! ACCESS_DENIED, AGENT_NOT_FOUND, RATE_LIMITED, NOT_PROVISIONED, HANDLE_REJECTED,
//! SESSION_LOCKED, NETWORK_ERROR, UNKNOWN) serializes as `{ code: "SCREAMING_SNAKE_CASE" }`; the TypeScript union in
//! `$lib/ipc` must match exactly, and `SESSION_LOCKED` carries
//! `reason: UnlockReason`. The ceremony's `{error}` codes map onto it in
//! `map_ceremony_error`; a session-lifecycle failure maps via `map_session_error` —
//! only a genuine transport failure is NETWORK_ERROR (a `NeedsUnlock` is
//! SESSION_LOCKED, every other verdict UNKNOWN) — so denial, expiry, and lock render
//! as explicit states. The IPC types (`AgentSummary`, `AgentAuditEvent`,
//! `AgentAuditPage`, `AgentClaimPreview`, `AgentClaimConfirmation`, `MintedChild`,
//! `ChildReconciliation`) serialize
//! camelCase and must match their `$lib/ipc` counterparts.

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
    /// The handle an `anonymous` agent proposed for an account of its own. Present only when it
    /// asked; the approval screen offers it as an editable default, never a commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_hint: Option<String>,
}

/// A child account minted by [`mint_child_from_claim`] — the agent's own identity, under this
/// account's rotation authority. The agent collects its credential through the claim-grant poll it
/// was already running, so nothing here is secret; it is what the wallet shows the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintedChild {
    pub registration_id: String,
    /// The child's own `did:plc` — the hash of the genesis op the wallet just signed.
    pub did: String,
    pub handle: String,
}

/// The child block on a successful confirm-with-child response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmedChildBody {
    did: String,
    handle: String,
}

#[derive(Debug, Deserialize)]
struct ChildConfirmResponse {
    #[serde(alias = "registration_id")]
    registration_id: String,
    child: Option<ConfirmedChildBody>,
}

/// One sovereign child under this account (`GET /agent/child` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildSummary {
    pub registration_id: String,
    /// The child's own `did:plc` — how every lifecycle command addresses it.
    pub did: String,
    pub handle: String,
    /// `claimed` (live), `active` (mid-provisioning), or `revoked`.
    pub status: String,
    pub created_at: String,
    pub scopes: Vec<String>,
    /// Set only once deletion is scheduled: the instant after which the server purges the child
    /// permanently. Deletion revokes as a side effect, so `status` alone cannot distinguish a
    /// retired child from a merely revoked one — this is what tells them apart.
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
    /// The instant after which the child is purged permanently — the date the wallet shows so
    /// the user knows how long the decision stays reversible on the server side.
    pub delete_after: String,
}

/// A freshly renewed child credential (`POST /agent/child/assertion`).
///
/// `identity_assertion` is a live credential for the child account, so the screen showing it
/// treats it like the app-password reveal: shown once, offered for copy, never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildAssertion {
    pub did: String,
    pub registration_id: String,
    pub identity_assertion: String,
    pub assertion_expires: String,
    pub scopes: Vec<String>,
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
    /// This identity holds no delegation seed, so there is no key to sign a child's genesis
    /// operation with. The frontend gates on `agent_accounts_provisioned` first; reaching this
    /// means the seed vanished between the gate and the mint.
    #[error("this identity is not provisioned for agent accounts")]
    NotProvisioned,
    /// The server refused the proposed child handle or the genesis operation built around it.
    /// Recoverable by construction: the mint rejects strictly before the claim attempt is spent,
    /// so the registration stays claimable and a corrected handle can be submitted.
    #[error("handle rejected: {message}")]
    HandleRejected { message: String },
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
    #[serde(default)]
    error_description: Option<String>,
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

async fn revoke_agent_impl(client: &OAuthClient, registration_id: &str) -> Result<(), AgentsError> {
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

/// Shared status mapping for the four child routes. They are deliberately uniform: an unknown or
/// foreign child DID is the same 404 as one belonging to another parent, so none of them is an
/// existence oracle. 403 is the assertion route's "child is not active" refusal — revocation is a
/// one-way rung on the custody ladder, and the frontend says so rather than offering a retry.
fn child_route_error(status: u16, path: &str) -> AgentsError {
    match status {
        401 => AgentsError::NotAuthenticated,
        403 => AgentsError::AccessDenied,
        404 => AgentsError::AgentNotFound,
        429 => AgentsError::RateLimited,
        other => AgentsError::Unknown {
            message: format!("{path} returned {other}"),
        },
    }
}

async fn list_children_impl(client: &OAuthClient) -> Result<Vec<ChildSummary>, AgentsError> {
    let resp = client.get("/agent/child").await.map_err(oauth_err)?;
    if resp.status().as_u16() != 200 {
        return Err(child_route_error(
            resp.status().as_u16(),
            "GET /agent/child",
        ));
    }
    let body: ListChildrenResponse = resp.json().await.map_err(|e| AgentsError::Unknown {
        message: format!("failed to parse /agent/child response: {e}"),
    })?;
    Ok(body.children)
}

/// Extra derivation indices scanned past the number of children the server lists.
///
/// Indices are consumed one per *successful* mint and never reused, so the highest live child's
/// index exceeds the list length only by however many siblings have since been purged. Scanning
/// a fixed window past the end covers that gap without an unbounded search; a child whose index
/// lies beyond it reports [`ChildKeyStatus::Unmatched`] — surfaced to the user, which is the
/// honest answer for a key this device cannot derive.
const CHILD_INDEX_SCAN_SLACK: u32 = 32;

/// What the recovery check concluded about one child's rotation key.
///
/// The three verdicts are deliberately distinct. `Unmatched` is a custody finding — plc.directory
/// was read and names no key this delegation seed derives — while `Unchecked` means the question
/// could not be asked. Collapsing them would either cry wolf over a network blip or, worse, let a
/// genuine mismatch hide inside one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ChildKeyStatus {
    /// The key derived at `index` is live in the child's `rotationKeys`.
    Matched { index: u32 },
    /// The child's audit log was read and names no key this delegation seed derives.
    Unmatched,
    /// plc.directory could not be read or parsed. Custody is unknown, not disproven.
    Unchecked { message: String },
}

/// One child's entry in a recovery reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildKeyCheck {
    pub did: String,
    pub handle: String,
    #[serde(flatten)]
    pub status: ChildKeyStatus,
}

/// The result of re-deriving this identity's children against plc.directory after a recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildReconciliation {
    /// False when this device's index already covered the server's list, so nothing was
    /// re-derived and no plc.directory request was made. `children` is then empty — an
    /// absence of findings, never a claim that every child checked out.
    pub rebuilt: bool,
    pub children: Vec<ChildKeyCheck>,
    /// The child index this device will mint at next.
    pub next_index: u32,
}

/// Re-derive this identity's children from the delegation seed and check each against the
/// authoritative plc.directory audit log — the recovery epilogue for child accounts.
///
/// The server's child list is the discovery mechanism (no BIP-44-style gap scan): it says which
/// children exist, and derivation says which of them this device still holds the rotation key
/// for. Verification reads the child's audit log rather than any cached DID document, the same
/// trust posture `verify_recovery_shares` takes for the parent.
///
/// Short-circuits without touching plc.directory when the stored index already covers the list —
/// the case on the device that minted them. `rebuilt` reports which of the two happened, so a
/// caller can never read "nothing to do" as "everything verified".
///
/// A per-child failure is recorded, never propagated: one unreachable child must not suppress a
/// genuine mismatch found on another.
async fn reconcile_children_impl(
    client: &OAuthClient,
    pds_client: &PdsClient,
    delegation_seed: &[u8; 32],
    stored_index: u32,
) -> Result<ChildReconciliation, AgentsError> {
    let children = list_children_impl(client).await?;
    let count = u32::try_from(children.len()).unwrap_or(u32::MAX);
    if stored_index >= count {
        return Ok(ChildReconciliation {
            rebuilt: false,
            children: Vec::new(),
            next_index: stored_index,
        });
    }

    // Derive the candidate window once — the same key is looked up by every child, and each
    // derivation is an HKDF plus a P-256 scalar.
    let mut candidates: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for index in 0..count.saturating_add(CHILD_INDEX_SCAN_SLACK) {
        let child_seed = crypto::derive_child_seed(delegation_seed, index);
        let keypair =
            crypto::derive_recovery_keypair(&child_seed).map_err(|e| AgentsError::Unknown {
                message: format!("child key derivation failed at index {index}: {e}"),
            })?;
        candidates.entry(keypair.key_id.0).or_insert(index);
    }

    let mut checks = Vec::with_capacity(children.len());
    let mut highest_match: Option<u32> = None;
    for child in children {
        let status = match child_rotation_keys(pds_client, &child.did).await {
            Ok(rotation_keys) => match rotation_keys.iter().find_map(|k| candidates.get(k)) {
                Some(&index) => {
                    highest_match = Some(highest_match.map_or(index, |h: u32| h.max(index)));
                    ChildKeyStatus::Matched { index }
                }
                None => ChildKeyStatus::Unmatched,
            },
            Err(message) => ChildKeyStatus::Unchecked { message },
        };
        checks.push(ChildKeyCheck {
            did: child.did,
            handle: child.handle,
            status,
        });
    }

    // Never lower the counter. A stored index above every match means this device already minted
    // past the children the server still lists (purged siblings), and rewinding it would re-derive
    // a key some existing child already holds.
    let next_index = highest_match
        .map(|h| h.saturating_add(1))
        .unwrap_or(stored_index)
        .max(stored_index);

    Ok(ChildReconciliation {
        rebuilt: true,
        children: checks,
        next_index,
    })
}

/// Read a child's current `rotationKeys` from its plc.directory audit log. The error is a
/// caller-facing sentence fragment, since it lands in [`ChildKeyStatus::Unchecked`] rather than
/// failing the reconciliation.
async fn child_rotation_keys(
    pds_client: &PdsClient,
    child_did: &str,
) -> Result<Vec<String>, String> {
    let raw = pds_client
        .fetch_audit_log(child_did)
        .await
        .map_err(|e| format!("plc.directory could not be read: {e}"))?;
    let log = crypto::parse_audit_log(&raw).map_err(|e| format!("audit log is unreadable: {e}"))?;
    // The strict reader, not `rotation_keys_from_audit_log`: it skips nullified entries and says
    // so when a field is missing, where the lenient helper returns an empty list that would read
    // here as a custody mismatch.
    crate::handle_change::latest_full_state(&log)
        .map(|state| state.rotation_keys)
        .map_err(|e| format!("audit log is unreadable: {e}"))
}

async fn revoke_child_impl(client: &OAuthClient, child_did: &str) -> Result<(), AgentsError> {
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

async fn delete_child_impl(
    client: &OAuthClient,
    child_did: &str,
) -> Result<ChildDeletion, AgentsError> {
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
    resp.json().await.map_err(|e| AgentsError::Unknown {
        message: format!("failed to parse child delete response: {e}"),
    })
}

async fn remint_child_assertion_impl(
    client: &OAuthClient,
    child_did: &str,
) -> Result<ChildAssertion, AgentsError> {
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
    resp.json().await.map_err(|e| AgentsError::Unknown {
        message: format!("failed to parse child assertion response: {e}"),
    })
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

/// Build and sign the child's did:plc genesis operation — the functional core of the mint.
///
/// `rotationKeys = [derived child key, PDS repo key]`, signed by `rotationKeys[0]`, which is what
/// the server pins as the signer and what keeps the child's recovery authority on this device. The
/// parent's device key is deliberately absent: naming it would publish a parent↔child link in the
/// child's public PLC audit log.
///
/// The returned op carries the child's DID, since a did:plc *is* the hash of its genesis op — the
/// caller cross-checks the server's answer against it.
fn build_child_genesis_op(
    delegation_seed: &[u8; 32],
    index: u32,
    repo_key_id: &crypto::DidKeyUri,
    handle: &str,
    pds_url: &str,
) -> Result<crypto::PlcGenesisOp, AgentsError> {
    let child_seed = crypto::derive_child_seed(delegation_seed, index);
    let child_key =
        crypto::derive_recovery_keypair(&child_seed).map_err(|e| AgentsError::Unknown {
            message: format!("child key derivation failed: {e}"),
        })?;
    let rotation_keys = [child_key.key_id.clone(), repo_key_id.clone()];
    crypto::build_did_plc_genesis_op_multi_rotation_with_external_signer(
        &rotation_keys,
        repo_key_id,
        handle,
        pds_url,
        crate::disaster_recovery::recovery_sign_closure(child_key.private_key_bytes.clone()),
    )
    .map_err(|e| AgentsError::Unknown {
        message: format!("genesis op signing failed: {e}"),
    })
}

/// Mint the agent an account of its own, then confirm the claim with it.
///
/// The order matters and is not rearrangeable. The child's `did:plc` *is* the hash of the genesis
/// operation, so every key the operation names has to exist first: the repo-signing key is reserved
/// anonymously from the PDS (there is no DID yet to reserve it against), and the rotation key is
/// derived locally at `index` off the delegation seed.
///
/// Everything that can reject — handle validation, genesis verification, the reserved-key check,
/// plc.directory publication — happens on the server strictly before the claim attempt is spent,
/// so a [`AgentsError::HandleRejected`] leaves the registration claimable and the caller may retry
/// with a corrected handle. The index is therefore advanced by the caller only on success.
#[allow(clippy::too_many_arguments)]
async fn mint_child_from_claim_impl(
    client: &OAuthClient,
    pds_client: &PdsClient,
    pds_url: &str,
    delegation_seed: &[u8; 32],
    index: u32,
    user_code: &str,
    handle: &str,
) -> Result<MintedChild, AgentsError> {
    let repo_key = pds_client
        .reserve_signing_key(pds_url, None)
        .await
        .map_err(|e| AgentsError::NetworkError {
            message: format!("could not reserve a signing key: {e}"),
        })?;

    let genesis = build_child_genesis_op(
        delegation_seed,
        index,
        &crypto::DidKeyUri(repo_key),
        handle,
        pds_url,
    )?;
    let plc_op: Value =
        serde_json::from_str(&genesis.signed_op_json).map_err(|e| AgentsError::Unknown {
            message: format!("genesis op is not valid JSON: {e}"),
        })?;

    let resp = client
        .post(
            "/agent/identity/claim/confirm",
            &serde_json::json!({
                "user_code": user_code,
                "child": { "handle": handle, "plcOp": plc_op },
            }),
        )
        .await
        .map_err(oauth_err)?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_child_confirm_error(status.as_u16(), resp).await);
    }
    let body: ChildConfirmResponse = resp.json().await.map_err(|e| AgentsError::Unknown {
        message: format!("failed to parse confirm response: {e}"),
    })?;
    let child = body.child.ok_or_else(|| AgentsError::Unknown {
        message: "confirm succeeded without a child block".to_string(),
    })?;
    // A did:plc is the hash of its genesis op, so the wallet already knows what the server had to
    // arrive at. A different DID means the account the user was shown is not the one whose keys
    // this device holds — never reported as a success.
    if child.did != genesis.did {
        return Err(AgentsError::Unknown {
            message: "the server minted a different DID than the wallet signed".to_string(),
        });
    }
    Ok(MintedChild {
        registration_id: body.registration_id,
        did: child.did,
        handle: child.handle,
    })
}

/// Map a failed confirm-with-child into the agents surface.
///
/// The child arm widens what `invalid_request` means: on the plain arm it can only be a bad code,
/// but here it is also every mint rejection the server describes in words — a taken or malformed
/// handle, an unreserved signing key, a genesis op that does not verify. Those are recoverable and
/// the description is caller-facing, so they surface as [`AgentsError::HandleRejected`] rather than
/// being flattened into "code not found".
async fn map_child_confirm_error(status: u16, resp: reqwest::Response) -> AgentsError {
    if status == 401 {
        return AgentsError::NotAuthenticated;
    }
    if status == 429 {
        return AgentsError::RateLimited;
    }
    match resp.json::<CeremonyErrorBody>().await {
        Ok(body) if body.error == "invalid_request" => AgentsError::HandleRejected {
            message: body
                .error_description
                .unwrap_or_else(|| "the server refused this handle".to_string()),
        },
        Ok(body) => map_ceremony_error(&body.error),
        Err(_) => AgentsError::Unknown {
            message: format!("confirm returned {status}"),
        },
    }
}

// ── Tauri commands ──────────────────────────────────────────────────────────────

/// Whether this identity is provisioned to give an agent an account of its own.
///
/// True once the delegation seed — the root every child account's rotation key derives
/// from — is in the Keychain: written by the create ceremony for identities made since,
/// and by "Enable agent accounts" (share verification) for any made before. The frontend
/// gates the child-mint path on this, routing an unprovisioned identity to provisioning
/// rather than letting a mint start with no key to sign the child's genesis op.
///
/// Local-only, so a Keychain failure reads as "unprovisioned": the honest answer for a
/// gate, and the route it sends the user down re-checks rather than trusting it.
#[tauri::command]
pub fn agent_accounts_provisioned(did: String) -> bool {
    IdentityStore
        .is_delegation_provisioned(&did)
        .unwrap_or_else(|e| {
            tracing::warn!(did = %did, error = %e, "delegation-seed probe failed; reporting unprovisioned");
            false
        })
}

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

/// Confirm a claim ceremony the *cooperative* way: instead of handing the agent a credential for
/// this account, mint it an account of its own under this account's rotation authority.
///
/// Only an ownerless `anonymous` registration qualifies — the server refuses the rest, since a
/// registration already bound to an account asked for "act for me" and re-pointing it mid-ceremony
/// would answer a different question than the one on the approval screen. Like
/// [`confirm_agent_claim`], the frontend gates this behind the biometric prompt.
///
/// The child's rotation key is derived at the identity's next unused index, and the index advances
/// only after the server confirms the mint — so a rejected handle costs nothing and the retry
/// re-derives the same key rather than burning an index per attempt.
#[tauri::command]
pub async fn mint_child_from_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    user_code: String,
    handle: String,
) -> Result<MintedChild, AgentsError> {
    let delegation_seed = IdentityStore
        .load_delegation_seed(&did)
        .map_err(|e| AgentsError::Unknown {
            message: format!("delegation seed read failed: {e}"),
        })?
        .ok_or(AgentsError::NotProvisioned)?;
    let index = IdentityStore
        .load_child_index(&did)
        .map_err(|e| AgentsError::Unknown {
            message: format!("child index read failed: {e}"),
        })?;

    let session = full_access_session(state.pds_client(), &did).await?;
    let minted = mint_child_from_claim_impl(
        &session.client,
        state.pds_client(),
        &session.pds_url,
        &delegation_seed,
        index,
        &user_code,
        handle.trim(),
    )
    .await?;

    // Best-effort: the child exists on the server either way, and the PDS child list is the
    // authoritative index record (recovery rebuilds the counter from it). A failure here costs a
    // collision on the next mint, not this one — so it is logged, never surfaced as a mint failure.
    if let Err(e) = IdentityStore.store_child_index(&did, index.saturating_add(1)) {
        tracing::error!(did = %did, error = %e, "failed to advance the child index after a mint");
    }
    Ok(minted)
}

/// List the sovereign child accounts this identity has minted for agents.
///
/// Separate from [`list_agents`] on purpose: a child is an account of its own, not a capability
/// on this one, so it never appears on `GET /v1/agents` (that lists registrations bound to the
/// caller's DID, and a child's is bound to the child's). Its *audit trail* still reads through
/// `get_agent_audit` — the `/v1/agents` routes accept the parent as owner of a child's
/// registration precisely because the child's own tokens never pass the owner guard.
#[tauri::command]
pub async fn list_children(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<Vec<ChildSummary>, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    list_children_impl(&session.client).await
}

/// Revoke a child's delegated capability, keeping its account, repo, and DID intact.
///
/// The lower rung of the custody ladder: the agent stops getting credentials, but the identity
/// the user gave it still exists and its history is still readable. Idempotent on the server.
#[tauri::command]
pub async fn revoke_child(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    child_did: String,
) -> Result<(), AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    revoke_child_impl(&session.client, &child_did).await
}

/// Retire a child's hosting: revoke it, deactivate it now, and schedule the permanent purge.
///
/// The returned `delete_after` is the whole point of surfacing this to the user — until it
/// passes, the child's data is deactivated rather than gone. The did:plc identity is untouched
/// either way; this server holds no rotation key for it.
#[tauri::command]
pub async fn delete_child(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    child_did: String,
) -> Result<ChildDeletion, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    delete_child_impl(&session.client, &child_did).await
}

/// Renew a live child's identity assertion — its credential for the token endpoint.
///
/// An *active* child renews automatically at every token exchange, so this is for one that lay
/// dormant past a full assertion lifetime and can no longer bootstrap. The response carries a
/// live credential; the caller shows it once for the user to hand back to the agent and keeps
/// no copy. A revoked child is refused ([`AgentsError::AccessDenied`]).
/// Re-derive this identity's children after a recovery and rebuild the local child index.
///
/// The recovery epilogue for child accounts. Once the delegation seed is back in the Keychain —
/// re-derived from the recovery seed during share verification — this asks the server which
/// children exist and checks each one's live `rotationKeys` against the keys this seed derives,
/// so a restored wallet can say which of its agents' accounts it still holds recovery authority
/// for. The rebuilt index is what keeps the next mint from colliding with a child already out
/// there.
///
/// Cheap and idempotent on a device that is not recovering: it short-circuits before any
/// plc.directory traffic when the local index already covers the server's list, reporting
/// `rebuilt: false` so the caller never mistakes that for a clean bill of health.
#[tauri::command]
pub async fn reconcile_children(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ChildReconciliation, AgentsError> {
    let delegation_seed = IdentityStore
        .load_delegation_seed(&did)
        .map_err(|e| AgentsError::Unknown {
            message: format!("delegation seed read failed: {e}"),
        })?
        .ok_or(AgentsError::NotProvisioned)?;
    let stored_index = IdentityStore
        .load_child_index(&did)
        .map_err(|e| AgentsError::Unknown {
            message: format!("child index read failed: {e}"),
        })?;

    let session = full_access_session(state.pds_client(), &did).await?;
    let result = reconcile_children_impl(
        &session.client,
        state.pds_client(),
        &delegation_seed,
        stored_index,
    )
    .await?;

    // Best-effort, matching the mint path: the reconciliation the user is about to read is worth
    // showing even if the counter write fails, and the server list stays the authoritative record
    // either way. The cost of a failure is a colliding index on the next mint, not a lost child.
    if result.rebuilt && result.next_index != stored_index {
        if let Err(e) = IdentityStore.store_child_index(&did, result.next_index) {
            tracing::error!(did = %did, error = %e, "failed to rebuild the child index after recovery");
        }
    }
    Ok(result)
}

#[tauri::command]
pub async fn remint_child_assertion(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    child_did: String,
) -> Result<ChildAssertion, AgentsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    remint_child_assertion_impl(&session.client, &child_did).await
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

        let children = list_children_impl(&bearer_client(&server)).await.unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].scopes, vec!["repo:write"]);
        // A live child carries no purge date; only a scheduled deletion does. Without this the
        // wallet could not tell a revoked child from one counting down to permanent removal.
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

        let scheduled = delete_child_impl(&bearer_client(&server), "did:plc:childgone")
            .await
            .unwrap();
        assert_eq!(scheduled.status, "deletion_scheduled");
        assert_eq!(scheduled.delete_after, "2026-02-01T00:00:00Z");
    }

    #[tokio::test]
    async fn reminting_a_revoked_child_is_access_denied_not_a_retryable_error() {
        // The server refuses renewal for a revoked child with 403. Surfacing that as a distinct
        // state matters: revocation is one-way, so the screen must say so rather than invite a
        // retry that can never succeed.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/agent/child/assertion");
            then.status(403)
                .json_body(serde_json::json!({ "error": "Forbidden" }));
        });

        let err = remint_child_assertion_impl(&bearer_client(&server), "did:plc:childgone")
            .await
            .unwrap_err();
        assert!(matches!(err, AgentsError::AccessDenied), "got {err:?}");
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

        let renewed = remint_child_assertion_impl(&bearer_client(&server), "did:plc:childlive")
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
            revoke_child_impl(&client, "did:plc:nope")
                .await
                .unwrap_err(),
            AgentsError::AgentNotFound
        ));
        assert!(matches!(
            delete_child_impl(&client, "did:plc:nope")
                .await
                .unwrap_err(),
            AgentsError::AgentNotFound
        ));
        assert!(matches!(
            remint_child_assertion_impl(&client, "did:plc:nope")
                .await
                .unwrap_err(),
            AgentsError::AgentNotFound
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

    // ── cooperative child mint ───────────────────────────────────────────────

    const TEST_SEED: [u8; 32] = [0x5a; 32];
    const TEST_PDS: &str = "https://pds.example.com";

    fn test_repo_key() -> crypto::DidKeyUri {
        crypto::generate_p256_keypair().unwrap().key_id
    }

    /// The genesis op the wallet signs is the whole custody claim: `rotationKeys[0]` must be the
    /// key derived from *this* identity's delegation seed (the server pins it as the signer), and
    /// the parent's device key must be absent — naming it would publish a parent↔child link.
    #[test]
    fn child_genesis_is_signed_by_the_derived_child_key() {
        let repo_key = test_repo_key();
        let genesis =
            build_child_genesis_op(&TEST_SEED, 0, &repo_key, "scribe.example.com", TEST_PDS)
                .unwrap();

        let expected = crypto::derive_recovery_keypair(&crypto::derive_child_seed(&TEST_SEED, 0))
            .unwrap()
            .key_id;
        let verified = crypto::verify_genesis_op(&genesis.signed_op_json, &expected)
            .expect("the op must verify under the derived child key");
        assert_eq!(verified.did, genesis.did);
        assert_eq!(
            verified.rotation_keys,
            vec![expected.0.clone(), repo_key.0.clone()],
            "child rotation keys are exactly [derived child key, PDS repo key]"
        );
        assert_eq!(
            verified.verification_methods.get("atproto"),
            Some(&repo_key.0)
        );
    }

    /// Distinct indices must yield distinct children — the whole point of the counter.
    #[test]
    fn each_index_derives_a_distinct_child() {
        let repo_key = test_repo_key();
        let dids: Vec<String> = (0..3)
            .map(|i| {
                build_child_genesis_op(&TEST_SEED, i, &repo_key, "scribe.example.com", TEST_PDS)
                    .unwrap()
                    .did
            })
            .collect();
        assert_eq!(
            dids.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "three indices must mint three different DIDs"
        );
    }

    /// Re-deriving at the same index reproduces the same child — a rejected handle costs no index.
    #[test]
    fn the_same_index_re_derives_the_same_child_key() {
        let repo_key = test_repo_key();
        let a =
            build_child_genesis_op(&TEST_SEED, 2, &repo_key, "a.example.com", TEST_PDS).unwrap();
        let b =
            build_child_genesis_op(&TEST_SEED, 2, &repo_key, "a.example.com", TEST_PDS).unwrap();
        assert_eq!(a.did, b.did);
    }

    // ── Recovery reconciliation ────────────────────────────────────────────────

    /// The did:key this delegation seed derives at `index` — what a child minted at that index
    /// carries as `rotationKeys[0]`.
    fn child_key_at(index: u32) -> String {
        let seed = crypto::derive_child_seed(&TEST_SEED, index);
        crypto::derive_recovery_keypair(&seed).unwrap().key_id.0
    }

    /// A one-entry plc.directory audit log whose current state names `rotation_keys`.
    fn audit_log(did: &str, rotation_keys: &[&str]) -> serde_json::Value {
        serde_json::json!([{
            "did": did,
            "cid": "bafyreigenesis",
            "createdAt": "2026-08-01T00:00:00.000Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "rotationKeys": rotation_keys,
                "verificationMethods": { "atproto": test_repo_key().0 },
                "alsoKnownAs": [format!("at://{did}.example.com")],
                "services": {
                    "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": TEST_PDS },
                },
            },
        }])
    }

    /// A server answering `GET /agent/child` with `children`, and each child's audit log at the
    /// plc.directory path `PdsClient::new_for_test` will read.
    fn reconcile_server(children: &[(&str, serde_json::Value)]) -> MockServer {
        let server = MockServer::start();
        let list: Vec<serde_json::Value> = children
            .iter()
            .enumerate()
            .map(|(n, (did, _))| {
                serde_json::json!({
                    "registrationId": format!("reg-{n}"),
                    "did": did,
                    "handle": format!("child{n}.example.com"),
                    "status": "claimed",
                    "createdAt": "2026-08-01T00:00:00.000Z",
                    "scopes": ["repo:write"],
                })
            })
            .collect();
        server.mock(|when, then| {
            when.method(GET).path("/agent/child");
            then.status(200)
                .json_body(serde_json::json!({ "children": list }));
        });
        for (did, log) in children {
            server.mock(|when, then| {
                when.method(GET).path(format!("/{did}/log/audit"));
                then.status(200).json_body(log.clone());
            });
        }
        server
    }

    async fn reconcile(
        server: &MockServer,
        stored_index: u32,
    ) -> Result<ChildReconciliation, AgentsError> {
        reconcile_children_impl(
            &bearer_client(server),
            &PdsClient::new_for_test(server.base_url()),
            &TEST_SEED,
            stored_index,
        )
        .await
    }

    /// The recovery case: a restored device holds the delegation seed but no counter, and the
    /// server's list is what says which children exist. Each one's index comes back from the
    /// child's own audit log, and the counter is rebuilt past the highest of them.
    #[tokio::test]
    async fn reconcile_matches_each_child_to_its_index_and_rebuilds_the_counter() {
        let server = reconcile_server(&[
            (
                "did:plc:childzero",
                audit_log("did:plc:childzero", &[&child_key_at(0)]),
            ),
            (
                "did:plc:childone",
                audit_log("did:plc:childone", &[&child_key_at(1)]),
            ),
        ]);

        let result = reconcile(&server, 0).await.unwrap();

        assert!(result.rebuilt);
        assert_eq!(
            result.next_index, 2,
            "the counter must clear the highest match"
        );
        let indices: Vec<Option<u32>> = result
            .children
            .iter()
            .map(|c| match c.status {
                ChildKeyStatus::Matched { index } => Some(index),
                _ => None,
            })
            .collect();
        assert_eq!(indices, vec![Some(0), Some(1)]);
    }

    /// A child is matched by whichever index derives a key it actually lists, not by its position
    /// in the server's list — mints are not guaranteed to survive in derivation order.
    #[tokio::test]
    async fn reconcile_matches_out_of_order_children() {
        let server = reconcile_server(&[(
            "did:plc:childfive",
            audit_log(
                "did:plc:childfive",
                &["did:key:zSomeOtherKey", &child_key_at(5)],
            ),
        )]);

        let result = reconcile(&server, 0).await.unwrap();

        assert!(matches!(
            result.children[0].status,
            ChildKeyStatus::Matched { index: 5 }
        ));
        assert_eq!(result.next_index, 6);
    }

    /// A child whose live rotation keys name nothing this seed derives is a custody finding: the
    /// wallet cannot recover that account. It is reported, never dropped from the list, and never
    /// allowed to fail the children around it.
    #[tokio::test]
    async fn reconcile_surfaces_a_child_whose_key_does_not_derive_from_this_seed() {
        let server = reconcile_server(&[
            (
                "did:plc:childzero",
                audit_log("did:plc:childzero", &[&child_key_at(0)]),
            ),
            (
                "did:plc:stranger",
                audit_log("did:plc:stranger", &["did:key:zNotOurs"]),
            ),
        ]);

        let result = reconcile(&server, 0).await.unwrap();

        assert_eq!(result.children.len(), 2);
        assert!(matches!(
            result.children[0].status,
            ChildKeyStatus::Matched { index: 0 }
        ));
        assert!(matches!(
            result.children[1].status,
            ChildKeyStatus::Unmatched
        ));
        assert_eq!(result.children[1].did, "did:plc:stranger");
    }

    /// An unreadable audit log is not a mismatch. Reporting it as one would accuse the user's
    /// wallet of having lost a key over what is usually a network blip.
    #[tokio::test]
    async fn reconcile_reports_an_unreachable_child_as_unchecked_not_unmatched() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/agent/child");
            then.status(200).json_body(serde_json::json!({
                "children": [{
                    "registrationId": "reg-0",
                    "did": "did:plc:childzero",
                    "handle": "child0.example.com",
                    "status": "claimed",
                    "createdAt": "2026-08-01T00:00:00.000Z",
                    "scopes": [],
                }],
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/did:plc:childzero/log/audit");
            then.status(500);
        });

        let result = reconcile(&server, 0).await.unwrap();

        assert!(matches!(
            result.children[0].status,
            ChildKeyStatus::Unchecked { .. }
        ));
        assert_eq!(
            result.next_index, 0,
            "a child that could not be checked must not advance the counter"
        );
    }

    /// The minting device's case: its counter already covers the server's list, so there is
    /// nothing to rebuild and no plc.directory request is made. `rebuilt: false` is what stops a
    /// caller reading that silence as "every child verified".
    #[tokio::test]
    async fn reconcile_short_circuits_when_the_local_counter_already_covers_the_list() {
        let server = reconcile_server(&[(
            "did:plc:childzero",
            audit_log("did:plc:childzero", &[&child_key_at(0)]),
        )]);

        let result = reconcile(&server, 1).await.unwrap();

        assert!(!result.rebuilt);
        assert!(result.children.is_empty());
        assert_eq!(result.next_index, 1);
    }

    /// Purged siblings leave the counter ahead of every surviving child's index. Rewinding it
    /// would re-derive a key a live child already holds, so the higher value wins.
    #[tokio::test]
    async fn reconcile_never_lowers_the_stored_counter() {
        let server = reconcile_server(&[
            (
                "did:plc:childzero",
                audit_log("did:plc:childzero", &[&child_key_at(0)]),
            ),
            (
                "did:plc:childone",
                audit_log("did:plc:childone", &[&child_key_at(1)]),
            ),
            (
                "did:plc:childtwo",
                audit_log("did:plc:childtwo", &[&child_key_at(2)]),
            ),
        ]);

        // Two children exist at indices 0-2 but the counter says 9 — every index up to 8 was
        // spent on children since purged.
        let result = reconcile(&server, 2).await.unwrap();
        assert_eq!(result.next_index, 3);

        let result = reconcile(&server, 9).await.unwrap();
        assert!(!result.rebuilt);
        assert_eq!(result.next_index, 9);
    }

    fn mint_server(confirm_status: u16, confirm_body: serde_json::Value) -> MockServer {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(200)
                .json_body(serde_json::json!({ "signingKey": test_repo_key().0 }));
        });
        server.mock(|when, then| {
            when.method(POST).path("/agent/identity/claim/confirm");
            then.status(confirm_status).json_body(confirm_body);
        });
        server
    }

    async fn mint(server: &MockServer) -> Result<MintedChild, AgentsError> {
        mint_child_from_claim_impl(
            &bearer_client(server),
            &PdsClient::new(),
            &server.base_url(),
            &TEST_SEED,
            0,
            "4QX9TX",
            "scribe.example.com",
        )
        .await
    }

    /// A DID the wallet did not compute means the account the user was shown is not the one whose
    /// keys this device holds. Never reported as a success, however well-formed the response is.
    #[tokio::test]
    async fn mint_refuses_a_child_did_the_wallet_did_not_sign() {
        let server = mint_server(
            200,
            serde_json::json!({
                "registration_id": "reg_child",
                "status": "claimed",
                "did": "did:plc:parent",
                "child": {
                    "did": "did:plc:somethingelseentirely",
                    "handle": "scribe.example.com",
                    "didDocument": {},
                },
            }),
        );
        assert!(matches!(
            mint(&server).await.unwrap_err(),
            AgentsError::Unknown { .. }
        ));
    }

    /// A taken handle is recoverable, not terminal: the server rejects before spending the claim
    /// attempt, so the wallet must surface the reason for a corrected retry rather than flattening
    /// it into "code not found" the way the plain confirm arm does with `invalid_request`.
    #[tokio::test]
    async fn mint_surfaces_a_taken_handle_as_a_recoverable_rejection() {
        let server = mint_server(
            400,
            serde_json::json!({
                "error": "invalid_request",
                "error_description": "handle is already taken",
            }),
        );
        match mint(&server).await.unwrap_err() {
            AgentsError::HandleRejected { message } => {
                assert_eq!(message, "handle is already taken");
            }
            other => panic!("expected HandleRejected, got {other:?}"),
        }
    }

    /// Everything that is *not* a mint rejection keeps its plain-arm meaning.
    #[tokio::test]
    async fn mint_keeps_the_ceremony_error_vocabulary_for_non_handle_failures() {
        let server = mint_server(
            400,
            serde_json::json!({
                "error": "claim_expired",
                "error_description": "this claim attempt has expired",
            }),
        );
        assert!(matches!(
            mint(&server).await.unwrap_err(),
            AgentsError::CodeExpired
        ));
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
