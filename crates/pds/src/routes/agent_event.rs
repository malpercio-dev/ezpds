// pattern: Imperative Shell
//
// Gathers: AppState (config, JWKS cache, DB), request headers + raw body
// Processes: verify a provider Security Event Token → resolve the target registration → revoke it
// Returns: `202 Accepted` (empty) on success; RFC 8935 `{ "err", "description" }` JSON on failure
//
// `POST /agent/event/notify` — the auth.md `events_endpoint` (advertised in the AS metadata). It
// receives a **Security Event Token** (SET, RFC 8417) pushed by a trusted identity provider
// (RFC 8935 push-based delivery, `application/secevent+jwt`) and, for the sole supported event type
// (`issuer_trust::REVOKED_EVENT_TYPE`), revokes the matching agent registration at the registration
// layer. This is the provider-initiated counterpart to the account-owner's
// `POST /v1/agents/{registration_id}/revoke` (`routes/agents.rs`): the same identity provider whose
// ID-JAG vouched for an `identity_assertion` agent (§3.1) can retract that trust.
//
// Trust model (implicit gating): a SET is honored iff its `iss` is on the `[agent_auth]
// trusted_issuers` list — the same trust anchor that mints `identity_assertion` registrations. A
// deployment with no trusted issuers (the default) answers every SET with `invalid_issuer`, so
// nothing is exposed until an operator deliberately trusts a provider. Only `identity_assertion`
// registrations are reachable: they are the only ones keyed by an `(issuer, subject)` pair, which is
// exactly how a SET names its target.
//
// Idempotent by construction: a SET whose subject is unknown or already revoked is still accepted
// (`202`) with no state change and no existence oracle, so replaying a revocation SET is harmless —
// there is deliberately no `jti` dedup store.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::issuer_trust::{
    select_issuer, unverified_claim, verify_trusted_jwt, TrustedJwtError, REVOKED_EVENT_TYPE,
};
use crate::db::agent_audit::{insert_agent_audit_event, AgentAuditEventType};
use crate::db::agent_auth::{get_agent_identity_by_issuer_subject, revoke_agent_identity};

/// The media type a SET is delivered as (RFC 8935 §2.1).
const SECEVENT_CONTENT_TYPE: &str = "application/secevent+jwt";

/// Claims read out of a verified SET. `iss`/`aud`/`exp` are enforced by `verify_trusted_jwt` and
/// need not appear here; `sub` names the target registration's subject and `events` must carry the
/// revocation event type.
#[derive(Debug, Deserialize)]
struct SetClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    events: Map<String, Value>,
}

/// `POST /agent/event/notify` — receive and process a provider SET.
pub async fn post_agent_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match process_set(&state, &headers, &body).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(err) => err.into_response(),
    }
}

async fn process_set(state: &AppState, headers: &HeaderMap, body: &Bytes) -> Result<(), SetError> {
    // A SET is delivered as `application/secevent+jwt` (RFC 8935). Reject a present-but-wrong content
    // type; tolerate an absent one (the signature is the real security boundary).
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        let essence = ct
            .to_str()
            .ok()
            .and_then(|s| s.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        if !essence.eq_ignore_ascii_case(SECEVENT_CONTENT_TYPE) {
            return Err(SetError::invalid_request(
                "content type must be application/secevent+jwt",
            ));
        }
    }

    let token = std::str::from_utf8(body)
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SetError::invalid_request("request body must be a Security Event Token"))?;

    // Read the unverified `iss` to select a trusted issuer before doing any signature work. A body
    // that isn't a JWT (no readable `iss`) is a malformed SET.
    let iss = unverified_claim(token, "iss")
        .ok_or_else(|| SetError::invalid_request("SET is malformed or missing an iss claim"))?;
    let issuer_cfg = select_issuer(&state.config.agent_auth, &iss).ok_or_else(|| {
        SetError::new(
            "invalid_issuer",
            "the SET issuer is not on this server's trust list",
        )
    })?;

    // Verify the SET's signature plus `iss`/`aud` (and `exp` if present — a SET need not carry one).
    let claims: SetClaims = verify_trusted_jwt(
        &state.jwks_cache,
        issuer_cfg,
        &state.config.public_url,
        token,
        &["iss", "aud"],
    )
    .await
    .map_err(map_set_verify_err)?;

    // The SET must carry the one event type this endpoint understands.
    if !claims.events.contains_key(REVOKED_EVENT_TYPE) {
        return Err(SetError::invalid_request(
            "the SET does not carry a supported event type",
        ));
    }

    let subject = revocation_subject(&claims)
        .ok_or_else(|| SetError::invalid_request("the SET names no subject to revoke"))?;

    // Look up the `identity_assertion` registration this provider vouched for. An unknown
    // `(iss, subject)` is accepted as a no-op (idempotent, no existence oracle).
    let Some(identity) = get_agent_identity_by_issuer_subject(&state.db, &iss, &subject)
        .await
        .map_err(|_| SetError::server_error())?
    else {
        return Ok(());
    };

    revoke_with_audit(state, &identity.id, identity.did.as_deref()).await
}

/// Flip the identity to `revoked` and record one provider-driven `revoked` audit event, atomically.
/// The `status != 'revoked'` guard in `revoke_agent_identity` makes a repeat SET an idempotent
/// no-op with no duplicate audit event — the same pattern as `routes/agents.rs::revoke_agent`, with
/// a `source` marker distinguishing the provider-initiated path from the account-owner one.
async fn revoke_with_audit(
    state: &AppState,
    registration_id: &str,
    did: Option<&str>,
) -> Result<(), SetError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to open transaction for provider-driven agent revocation");
        SetError::server_error()
    })?;
    let transitioned = revoke_agent_identity(&mut *tx, registration_id)
        .await
        .map_err(|_| SetError::server_error())?;
    if transitioned {
        insert_agent_audit_event(
            &mut *tx,
            &Uuid::new_v4().to_string(),
            registration_id,
            did,
            AgentAuditEventType::Revoked,
            Some(&json!({ "source": "provider_set" }).to_string()),
        )
        .await
        .map_err(|_| SetError::server_error())?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit provider-driven agent revocation");
        SetError::server_error()
    })?;
    Ok(())
}

/// Extract the ID-JAG subject the SET targets. Prefer the top-level `sub` (RFC 8417); otherwise
/// accept a `subject` inside the revoked-event payload — either a bare string or an object carrying a
/// `sub` string (a CAEP / RFC 9493-style subject identifier) — so the endpoint is robust to either
/// placement.
fn revocation_subject(claims: &SetClaims) -> Option<String> {
    if let Some(sub) = claims.sub.as_deref().filter(|s| !s.is_empty()) {
        return Some(sub.to_string());
    }
    let subject = claims.events.get(REVOKED_EVENT_TYPE)?.get("subject")?;
    match subject {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(o) => o
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

/// Map a shared trusted-JWT verification failure (`auth/issuer_trust.rs`) into a SET error. An
/// unusable configured key / transport failure is a server error; a signing key absent from the
/// issuer's JWKS or a failed signature/claim check is `authentication_failed` (RFC 8935 §2.4).
fn map_set_verify_err(err: TrustedJwtError) -> SetError {
    match err {
        TrustedJwtError::ServerError => SetError::server_error(),
        TrustedJwtError::UnknownKey | TrustedJwtError::Invalid(_) => SetError::new(
            "authentication_failed",
            "the SET signature could not be verified",
        ),
    }
}

// ── SET error responder (RFC 8935 §2.4: `{ "err", "description" }`) ────────────────

/// An RFC 8935 SET-delivery error. Distinct from the XRPC `ApiError` envelope and the auth.md
/// `{error, error_description}` envelope: SET delivery uses `{err, description}`.
struct SetError {
    status: StatusCode,
    err: &'static str,
    description: String,
}

impl SetError {
    fn new(err: &'static str, description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            err,
            description: description.into(),
        }
    }

    fn invalid_request(description: impl Into<String>) -> Self {
        Self::new("invalid_request", description)
    }

    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            err: "server_error",
            description: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for SetError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({ "err": self.err, "description": self.description })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::Utc;
    use common::{AgentAuthConfig, TrustedIssuer};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use p256::pkcs8::{spki::EncodePublicKey, EncodePrivateKey};
    use rand_core::OsRng;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    const PUBLIC_URL: &str = "https://test.example.com";
    const ISSUER: &str = "https://trusted.example";

    // ── key + SET helpers ────────────────────────────────────────────────

    fn der_to_pem(label: &str, der: &[u8]) -> String {
        let b64 = STANDARD.encode(der);
        let mut body = String::new();
        for chunk in b64.as_bytes().chunks(64) {
            body.push_str(std::str::from_utf8(chunk).unwrap());
            body.push('\n');
        }
        format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
    }

    /// A fresh ES256 keypair as (PKCS#8 private PEM, SPKI public PEM).
    fn es256_keys() -> (String, String) {
        let sk = p256::SecretKey::random(&mut OsRng);
        let priv_pem = der_to_pem("PRIVATE KEY", sk.to_pkcs8_der().unwrap().as_bytes());
        let pub_pem = der_to_pem(
            "PUBLIC KEY",
            sk.public_key().to_public_key_der().unwrap().as_bytes(),
        );
        (priv_pem, pub_pem)
    }

    /// Sign a SET carrying the revocation event, with a top-level `sub` and a JSON `events` body.
    fn make_set(priv_pem: &str, iss: &str, aud: &str, sub: &str, events: Value) -> String {
        #[derive(serde::Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            aud: &'a str,
            iat: u64,
            jti: String,
            sub: &'a str,
            events: Value,
        }
        let now = Utc::now().timestamp().max(0) as u64;
        let claims = Claims {
            iss,
            aud,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            sub,
            events,
        };
        let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
    }

    /// The standard single-event revocation body.
    fn revoked_events() -> Value {
        json!({ REVOKED_EVENT_TYPE: {} })
    }

    fn trusted(pub_pem: String) -> TrustedIssuer {
        TrustedIssuer {
            issuer: ISSUER.to_string(),
            audience: None,
            public_key_pem: Some(pub_pem),
            jwks_url: None,
            algorithm: "ES256".to_string(),
        }
    }

    async fn state_with(agent_auth: AgentAuthConfig) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.agent_auth = agent_auth;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
        .execute(db)
        .await
        .unwrap();
    }

    /// Seed a confirmed (`claimed`) `identity_assertion` registration for `(ISSUER, subject)`.
    async fn seed_claimed_identity(db: &sqlx::SqlitePool, id: &str, did: &str, subject: &str) {
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, status, created_at, updated_at) \
             VALUES (?, ?, 'identity_assertion', ?, ?, 'agent@example.com', '[\"atproto\"]', NULL, \
                     datetime('now', '+1 hour'), 'claimed', datetime('now'), datetime('now'))",
        )
        .bind(id)
        .bind(did)
        .bind(ISSUER)
        .bind(subject)
        .execute(db)
        .await
        .unwrap();
    }

    async fn post_set(state: AppState, body: &str) -> (StatusCode, Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/event/notify")
                    .header("content-type", "application/secevent+jwt")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    async fn identity_status(db: &sqlx::SqlitePool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM agent_identities WHERE id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn revoked_event_count(db: &sqlx::SqlitePool, id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_events WHERE registration_id = ? AND event_type = 'revoked'",
        )
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
    }

    // ── tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn untrusted_issuer_is_invalid_issuer() {
        let (unknown_priv, _pub) = es256_keys();
        let (_priv, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        let set = make_set(
            &unknown_priv,
            "https://evil.example",
            PUBLIC_URL,
            "sub-1",
            revoked_events(),
        );
        let (status, body) = post_set(state, &set).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["err"], "invalid_issuer");
    }

    #[tokio::test]
    async fn malformed_body_is_invalid_request() {
        let (_priv, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        let (status, body) = post_set(state, "not-a-jwt").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["err"], "invalid_request");
    }

    #[tokio::test]
    async fn bad_signature_is_authentication_failed() {
        let (_priv, pub_pem) = es256_keys();
        let (wrong_priv, _wrong_pub) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        // Correct iss (so verification runs) but signed by a different key.
        let set = make_set(&wrong_priv, ISSUER, PUBLIC_URL, "sub-1", revoked_events());
        let (status, body) = post_set(state, &set).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["err"], "authentication_failed");
    }

    #[tokio::test]
    async fn missing_event_type_is_invalid_request() {
        let (priv_pem, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        // A well-signed SET carrying some *other* event type.
        let set = make_set(
            &priv_pem,
            ISSUER,
            PUBLIC_URL,
            "sub-1",
            json!({ "https://schemas.example.com/other": {} }),
        );
        let (status, body) = post_set(state, &set).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["err"], "invalid_request");
    }

    #[tokio::test]
    async fn unknown_subject_is_accepted_noop() {
        let (priv_pem, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        // A valid SET for a subject with no registration → accepted, nothing to revoke.
        let set = make_set(
            &priv_pem,
            ISSUER,
            PUBLIC_URL,
            "sub-nobody",
            revoked_events(),
        );
        let (status, _body) = post_set(state, &set).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn revokes_matching_identity_and_is_idempotent() {
        let (priv_pem, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        let did = "did:plc:setrevoke1111111";
        insert_account(&state.db, did, "agent@example.com").await;
        seed_claimed_identity(&state.db, "reg_set", did, "sub-revoke").await;

        // First SET revokes and records exactly one audit event.
        let set = make_set(
            &priv_pem,
            ISSUER,
            PUBLIC_URL,
            "sub-revoke",
            revoked_events(),
        );
        let (status, _body) = post_set(state.clone(), &set).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(identity_status(&state.db, "reg_set").await, "revoked");
        assert_eq!(revoked_event_count(&state.db, "reg_set").await, 1);

        // A repeat (or replayed) SET is an idempotent no-op — still revoked, still one event.
        let set2 = make_set(
            &priv_pem,
            ISSUER,
            PUBLIC_URL,
            "sub-revoke",
            revoked_events(),
        );
        let (status2, _b2) = post_set(state.clone(), &set2).await;
        assert_eq!(status2, StatusCode::ACCEPTED);
        assert_eq!(identity_status(&state.db, "reg_set").await, "revoked");
        assert_eq!(
            revoked_event_count(&state.db, "reg_set").await,
            1,
            "idempotent revoke must not duplicate the audit event"
        );

        // The audit event marks the provider-driven source.
        let detail: String = sqlx::query_scalar(
            "SELECT detail FROM agent_audit_events WHERE registration_id = 'reg_set' AND event_type = 'revoked'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert!(detail.contains("provider_set"));
    }

    #[tokio::test]
    async fn subject_from_event_payload_is_accepted() {
        // No top-level `sub`; the target is named inside the event payload instead.
        let (priv_pem, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        let did = "did:plc:setpayload111111";
        insert_account(&state.db, did, "agent@example.com").await;
        seed_claimed_identity(&state.db, "reg_payload", did, "sub-payload").await;

        // A SET with an empty top-level `sub` but a subject object inside the event.
        let set = make_set(
            &priv_pem,
            ISSUER,
            PUBLIC_URL,
            "",
            json!({ REVOKED_EVENT_TYPE: { "subject": { "sub": "sub-payload" } } }),
        );
        let (status, _body) = post_set(state.clone(), &set).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(identity_status(&state.db, "reg_payload").await, "revoked");
    }

    #[tokio::test]
    async fn wrong_content_type_is_invalid_request() {
        let (priv_pem, pub_pem) = es256_keys();
        let state = state_with(AgentAuthConfig {
            trusted_issuers: vec![trusted(pub_pem)],
            ..AgentAuthConfig::default()
        })
        .await;
        let set = make_set(&priv_pem, ISSUER, PUBLIC_URL, "sub-1", revoked_events());
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/event/notify")
                    .header("content-type", "application/json")
                    .body(Body::from(set))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["err"], "invalid_request");
    }
}
