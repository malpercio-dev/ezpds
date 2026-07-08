// pattern: Mixed (unavoidable)
//
// Shared machinery for the auth.md agent claim ceremony, used by both the registration endpoint
// (`routes/agent_identity.rs`) and the claim-ceremony endpoints (`routes/agent_claim.rs`). Routes
// may not import from one another (crate hard rule), so the service-signed `identity_assertion`
// minting, the claim-block / verification-URI builders, and the auth.md-style `AgentAuthError`
// response type live here where both can reach them.
//
// Pure ES256 minting (Functional Core) sits alongside the HTTP `AgentAuthError` `IntoResponse`
// (Imperative Shell), hence the Mixed pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, NaiveDateTime, SecondsFormat, Utc};
use common::{AgentAuthConfig, ApiError};
use jsonwebtoken::Algorithm;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::auth::OAuthSigningKey;

// ── Claim-poll pacing (auth.md `interval` / RFC 8628 `slow_down`) ──────────────

/// Minimum seconds an agent must wait between claim-status polls — the auth.md claim block's
/// advertised `interval`. Read by both the claim-block emitter (`routes/agent_claim.rs`, which
/// advertises it) and the claim-polling grant's `slow_down` gate (`routes/oauth_token.rs`, which
/// enforces it) so the advertised and enforced values can never drift apart.
pub(crate) const POLL_INTERVAL_SECS: u64 = 5;

/// In-memory last-poll clock for the claim-polling grant (`urn:workos:agent-auth:grant-type:claim`).
/// Keyed by the SHA-256 hex of the agent's `claim_token` (never the raw secret), the value is the
/// `Instant` of that agent's last *accepted* poll; a poll within [`POLL_INTERVAL_SECS`] of it is
/// refused with `slow_down`. Ephemeral by design — a claim ceremony is short-lived, so a reset on
/// process restart at most grants one extra fast poll, which is harmless.
pub type ClaimPollTracker = Arc<Mutex<HashMap<String, Instant>>>;

/// Create an empty [`ClaimPollTracker`].
pub fn new_claim_poll_tracker() -> ClaimPollTracker {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── auth.md / OAuth-style error ───────────────────────────────────────────────

/// auth.md / OAuth-style error body, distinct from the codebase's XRPC `ApiError` envelope. Carries
/// an optional `claim` block and `claim_token` for the `interaction_required` / claim-ceremony
/// responses.
pub(crate) struct AgentAuthError {
    status: StatusCode,
    error: &'static str,
    error_description: String,
    claim: Option<Value>,
    claim_token: Option<String>,
}

impl AgentAuthError {
    pub(crate) fn new(
        status: StatusCode,
        error: &'static str,
        error_description: impl Into<String>,
    ) -> Self {
        Self {
            status,
            error,
            error_description: error_description.into(),
            claim: None,
            claim_token: None,
        }
    }

    pub(crate) fn server_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal server error",
        )
    }

    /// The `interaction_required` response: 401 with a claim block the user must confirm.
    pub(crate) fn interaction_required(claim: Value, claim_token: String) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "interaction_required",
            error_description: "user confirmation is required to bind this agent to the account"
                .to_string(),
            claim: Some(claim),
            claim_token: Some(claim_token),
        }
    }
}

impl From<ApiError> for AgentAuthError {
    /// DB / internal errors collapse to a 500 `server_error` — the agent-auth surface never leaks
    /// the XRPC envelope.
    fn from(_: ApiError) -> Self {
        AgentAuthError::server_error()
    }
}

impl IntoResponse for AgentAuthError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "error": self.error,
            "error_description": self.error_description,
        });
        if let Some(claim) = self.claim {
            body["claim"] = claim;
        }
        if let Some(claim_token) = self.claim_token {
            body["claim_token"] = Value::String(claim_token);
        }
        (self.status, Json(body)).into_response()
    }
}

// ── Service-signed identity_assertion minting ─────────────────────────────────

pub(crate) struct MintedAssertion {
    pub(crate) jwt: String,
    pub(crate) expires_sqlite: String,
    pub(crate) expires_rfc3339: String,
}

/// Claims of a service-signed `identity_assertion` — the token the confirmed agent later exchanges
/// at the token endpoint (jwt-bearer grant). Signed with the server's ES256 OAuth key.
#[derive(Debug, Serialize)]
struct ServiceAssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    jti: String,
    scope: String,
    registration_id: String,
    registration_type: &'static str,
}

/// Mint a service-signed `identity_assertion` bound to `subject` (the account DID once claimed, or
/// the registration id for a pre-claim anonymous assertion), carrying the granted `scopes` and the
/// registration's id/type. Signed with the server's ES256 OAuth key.
pub(crate) fn mint_identity_assertion(
    keypair: &OAuthSigningKey,
    public_url: &str,
    ttl_secs: u64,
    subject: &str,
    registration_id: &str,
    registration_type: &'static str,
    scopes: &[String],
) -> Result<MintedAssertion, AgentAuthError> {
    let issued = Utc::now();
    let expires = issued + Duration::seconds(ttl_secs as i64);
    let base = public_url.trim_end_matches('/').to_string();

    let claims = ServiceAssertionClaims {
        iss: base.clone(),
        sub: subject.to_string(),
        aud: base,
        iat: issued.timestamp().max(0) as u64,
        exp: expires.timestamp().max(0) as u64,
        jti: Uuid::new_v4().to_string(),
        scope: scopes.join(" "),
        registration_id: registration_id.to_string(),
        registration_type,
    };

    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(keypair.key_id.clone());
    let jwt = jsonwebtoken::encode(&header, &claims, &keypair.encoding_key).map_err(|e| {
        tracing::error!(error = %e, "failed to sign agent identity assertion");
        AgentAuthError::server_error()
    })?;

    Ok(MintedAssertion {
        jwt,
        expires_sqlite: to_sqlite_datetime(&expires),
        expires_rfc3339: expires.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

// ── Claim-ceremony helpers ────────────────────────────────────────────────────

/// Where the user enters the claim `user_code`. Configurable; defaults to `{public_url}/agent/claim`.
pub(crate) fn verification_uri(agent_auth: &AgentAuthConfig, public_url: &str) -> String {
    agent_auth
        .verification_uri
        .clone()
        .unwrap_or_else(|| format!("{}/agent/claim", public_url.trim_end_matches('/')))
}

/// The `claim` block an agent shows the user to route them through a confirmation ceremony.
pub(crate) fn claim_block(
    user_code: &str,
    verification_uri: &str,
    expires: &DateTime<Utc>,
) -> Value {
    json!({
        "user_code": user_code,
        "verification_uri": verification_uri,
        "expires_at": expires.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

/// A fresh `cla_`-prefixed claim-attempt id.
pub(crate) fn new_claim_attempt_id() -> String {
    format!("cla_{}", Uuid::new_v4().simple())
}

/// Serialize a scope list to the JSON array string stored in `agent_identities.scopes`.
pub(crate) fn scopes_to_json(scopes: &[String]) -> String {
    serde_json::to_string(scopes).unwrap_or_else(|_| "[]".to_string())
}

/// SQLite `datetime()`-comparable timestamp (`YYYY-MM-DD HH:MM:SS`, UTC), matching the format
/// `datetime('now')` produces so the DB layer's expiry comparisons parse it reliably.
pub(crate) fn to_sqlite_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Parse a SQLite `datetime()` timestamp (`YYYY-MM-DD HH:MM:SS`, UTC) back into a `DateTime<Utc>`.
/// Falls back to "now" on a malformed value (defensive — the DB always writes this format).
pub(crate) fn parse_sqlite_datetime(s: &str) -> DateTime<Utc> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .map(|n| n.and_utc())
        .unwrap_or_else(|_| Utc::now())
}
