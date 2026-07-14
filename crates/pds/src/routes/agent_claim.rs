// pattern: Imperative Shell
//
// The auth.md agent claim ceremony (spec Step 4). Two endpoints, split by audience:
//
//   - `POST /agent/identity/claim` — the *agent* starts (or resumes) a ceremony for a registration
//     it holds a `claim_token` for. Public: the `claim_token` is the agent's credential, so no user
//     session is required here. Mainly serves the `anonymous` flow, whose registration returned only
//     a `claim_token` and no `user_code`; `service_auth` / first-seen `identity_assertion` already
//     minted a `user_code` at registration, so re-initiating idempotently re-emits the pending one.
//   - `POST /agent/identity/claim/confirm` — the *account owner* (full-access session/OAuth token)
//     submits the `user_code` the agent showed them. This binds the registration to their DID (for
//     an ownerless `anonymous` identity), mints the post-claim `identity_assertion`, and flips the
//     identity `active → claimed` so its assertion can be exchanged at the token endpoint. This is
//     the wallet-facing surface (Obsign's claim-approval screen).
//
// Registration lives in `agent_identity.rs`; the assertion-minting / claim-block / error helpers are
// shared via `auth::agent_assertion` (routes may not import from one another).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::agent_assertion::{
    mint_identity_assertion, new_claim_attempt_id, parse_sqlite_datetime, record_agent_audit,
    scopes_to_json, to_sqlite_datetime, verification_uri, AgentAuthError, POLL_INTERVAL_SECS,
};
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::auth::oauth_scopes::intersect_scope_tokens;
use crate::code_gen::generate_code;
use crate::db::agent_auth::{
    claim_agent_identity, complete_agent_claim_attempt, get_agent_claim_attempt_by_user_code,
    get_agent_identity, get_agent_identity_by_claim_token, insert_agent_claim_attempt,
    latest_agent_claim_attempt_for_identity, AgentIdentityStatus, ClaimAttemptStatus,
    NewAgentClaimAttempt,
};

// ── POST /agent/identity/claim (initiate) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClaimInitiateRequest {
    pub claim_token: Option<String>,
    /// Optional email the user wants the ceremony associated with (informational; the binding is by
    /// the confirming user's authenticated DID, not this field).
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClaimAttemptBlock {
    user_code: String,
    expires_in: i64,
    verification_uri: String,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct ClaimInitiateResponse {
    registration_id: String,
    claim_attempt_id: String,
    status: &'static str,
    expires_at: String,
    claim_attempt: ClaimAttemptBlock,
}

/// `POST /agent/identity/claim` — start or resume a claim ceremony (no auth; the `claim_token` is
/// the credential).
pub async fn post_agent_claim(
    State(state): State<AppState>,
    Json(req): Json<ClaimInitiateRequest>,
) -> Response {
    match initiate(&state, &req).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn initiate(
    state: &AppState,
    req: &ClaimInitiateRequest,
) -> Result<Response, AgentAuthError> {
    let claim_token = req
        .claim_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing required field: claim_token",
            )
        })?;

    let identity = get_agent_identity_by_claim_token(&state.db, claim_token)
        .await?
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_claim_token",
                "the claim token is unknown",
            )
        })?;

    match identity.status {
        AgentIdentityStatus::Claimed => {
            return Err(AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "claimed_or_in_flight",
                "this registration has already been claimed",
            ));
        }
        // A revoked identity is not distinguished from an unknown token (don't leak state).
        AgentIdentityStatus::Revoked => {
            return Err(AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_claim_token",
                "the claim token is unknown",
            ));
        }
        AgentIdentityStatus::Active => {}
    }

    // The claim token has its own TTL (the auth.md pre-claim window). Its stored expiry uses the
    // sqlite `YYYY-MM-DD HH:MM:SS` format, which sorts chronologically, so a lexicographic compare
    // against "now" in the same format is a correct expiry check.
    let now_sqlite = to_sqlite_datetime(&Utc::now());
    if identity
        .claim_token_expires_at
        .as_deref()
        .map(|exp| exp <= now_sqlite.as_str())
        .unwrap_or(false)
    {
        return Err(AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "claim_expired",
            "the claim token has expired; re-register",
        ));
    }

    // Resume an in-flight ceremony rather than minting a second user_code: an agent that lost the
    // response, or is polling, gets the same code back. Otherwise open a fresh attempt.
    let (attempt_id, user_code, expiry) =
        match latest_agent_claim_attempt_for_identity(&state.db, &identity.id).await? {
            Some(attempt) if attempt.is_pending() => (
                attempt.id,
                attempt.user_code,
                parse_sqlite_datetime(&attempt.user_code_expires_at),
            ),
            _ => {
                let attempt_id = new_claim_attempt_id();
                let user_code = generate_code();
                let expiry = Utc::now()
                    + Duration::seconds(state.config.agent_auth.user_code_ttl_secs as i64);
                insert_agent_claim_attempt(
                    &state.db,
                    &NewAgentClaimAttempt {
                        id: &attempt_id,
                        identity_id: &identity.id,
                        user_code: &user_code,
                        user_code_expires_at: &to_sqlite_datetime(&expiry),
                        email: req.email.as_deref().or(identity.email.as_deref()),
                    },
                )
                .await?;
                record_agent_audit(
                    &state.db,
                    &identity.id,
                    identity.did.as_deref(),
                    crate::db::agent_audit::AgentAuditEventType::ClaimInitiated,
                    serde_json::json!({ "claim_attempt_id": attempt_id }),
                )
                .await?;
                (attempt_id, user_code, expiry)
            }
        };

    let expires_in = (expiry - Utc::now()).num_seconds().max(0);
    let body = ClaimInitiateResponse {
        registration_id: identity.id,
        claim_attempt_id: attempt_id,
        status: "initiated",
        expires_at: expiry.to_rfc3339_opts(SecondsFormat::Millis, true),
        claim_attempt: ClaimAttemptBlock {
            user_code,
            expires_in,
            verification_uri: verification_uri(&state.config.agent_auth, &state.config.public_url),
            interval: POLL_INTERVAL_SECS,
        },
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ── POST /agent/identity/claim/confirm (confirm) ──────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClaimConfirmRequest {
    pub user_code: Option<String>,
    /// Optional cross-check: when present, must name the registration this `user_code` belongs to.
    #[serde(default)]
    pub registration_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClaimConfirmResponse {
    registration_id: String,
    status: &'static str,
    did: String,
}

/// `POST /agent/identity/claim/confirm` — the account owner confirms a claim (full-access authed).
pub async fn post_agent_claim_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ClaimConfirmRequest>,
) -> Response {
    match confirm(&headers, &state, &req).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn confirm(
    headers: &HeaderMap,
    state: &AppState,
    req: &ClaimConfirmRequest,
) -> Result<Response, AgentAuthError> {
    // Only the account holder's own full-access credential may confirm — a wallet session token
    // or a full-access OAuth/XRPC access token, the same dual posture as the `/v1/agents` owner
    // surface (Obsign confirms with its opaque session token, so a JWT-only gate strands the
    // ceremony at its last step). App-password scopes are below this trust bar, and an
    // agent-derived token must never confirm a claim — least of all its own.
    let caller_did = authenticate_account_owner(headers, state)
        .await
        .map_err(|err| match err {
            OwnerAuthError::AgentDerived => AgentAuthError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "agent-derived credentials cannot confirm a claim",
            ),
            OwnerAuthError::Unauthenticated(_) | OwnerAuthError::NotFullAccess => {
                AgentAuthError::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "a session or full-access token is required to confirm an agent claim",
                )
            }
        })?;

    let user_code = req
        .user_code
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing required field: user_code",
            )
        })?;

    // Brute-forcing the `user_code` is bounded by the tight per-endpoint IP limiter this route
    // shares with `/v1/agents/claim-preview` (`rate_limit.rs`, `agent_claim_confirm_per_5min` —
    // the same short-code posture as `/v1/transfer/accept`), on top of the full-access auth
    // requirement — so the guessing surface is an *authenticated* caller racing a ~36^6-wide code
    // within its short TTL and a shared per-IP budget (and success only lets them bind an
    // ownerless anonymous registration to their own account, not take over a victim's).
    let attempt = get_agent_claim_attempt_by_user_code(&state.db, user_code)
        .await?
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_user_code",
                "the user code is unknown",
            )
        })?;
    if !attempt.is_pending() {
        // An already-consumed attempt is `claimed_or_in_flight`; anything else non-pending (swept
        // expired, or pending-but-past-expiry) is a lapsed code.
        return Err(if attempt.status == ClaimAttemptStatus::Completed {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "claimed_or_in_flight",
                "this user code has already been used",
            )
        } else {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "claim_expired",
                "the user code has expired; restart the claim",
            )
        });
    }

    let identity = get_agent_identity(&state.db, &attempt.identity_id)
        .await?
        .ok_or_else(AgentAuthError::server_error)?;

    if let Some(req_reg) = req.registration_id.as_deref().filter(|s| !s.is_empty()) {
        if req_reg != identity.id {
            return Err(AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "registration_id does not match this user code",
            ));
        }
    }

    match identity.status {
        AgentIdentityStatus::Claimed => {
            return Err(AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "claimed_or_in_flight",
                "this registration has already been claimed",
            ));
        }
        AgentIdentityStatus::Revoked => {
            return Err(AgentAuthError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "this agent identity has been revoked",
            ));
        }
        AgentIdentityStatus::Active => {}
    }

    // Authorization. A registration already bound to an owner (service_auth / identity_assertion)
    // may be confirmed only by that owner. An ownerless anonymous registration is bound to whoever
    // completes the ceremony — the `user_code` they were shown is the authorization.
    let bind_did = match identity.did.as_deref() {
        Some(bound) => {
            if bound != caller_did {
                return Err(AgentAuthError::new(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "this claim is bound to a different account",
                ));
            }
            None
        }
        None => Some(caller_did.as_str()),
    };

    // The post-claim assertion carries the operator's current full granted-scope profile. Normalize
    // it into a deterministic, deduplicated set so this mint matches the `identity_assertion` mint
    // path byte-for-byte: `intersect_scope_tokens(xs, xs)` is the crate's canonicalizer — it returns
    // the tokens of `xs` sorted and deduped (a self-intersection, since every token is in both
    // operands). There is no separate infallible canonicalizer helper; `canonicalize_agent_scopes`
    // is the fallible startup validator, not this hot path.
    let granted = &state.config.agent_auth.granted_scopes;
    let scopes = intersect_scope_tokens(granted, granted);
    let minted = mint_identity_assertion(
        &state.oauth_signing_keypair,
        &state.config.public_url,
        state.config.agent_auth.assertion_ttl_secs,
        &caller_did,
        &identity.id,
        identity.registration_type.as_str(),
        &scopes,
    )?;
    let scopes_json = scopes_to_json(&scopes);

    // One transaction: consume the pending attempt, then claim the identity. Each write carries its
    // own guard (`status = 'pending'` / `status = 'active'`), so a lost race rolls back cleanly
    // rather than double-claiming. Every read (and the pure mint) ran before `begin()` — the
    // single-connection pool cannot serve a `&SqlitePool` read while a transaction holds the
    // connection.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to open transaction for agent claim confirm");
        AgentAuthError::server_error()
    })?;
    if !complete_agent_claim_attempt(&mut *tx, &attempt.id).await? {
        return Err(AgentAuthError::new(
            StatusCode::CONFLICT,
            "claimed_or_in_flight",
            "this claim attempt is no longer pending",
        ));
    }
    if !claim_agent_identity(
        &mut *tx,
        &identity.id,
        bind_did,
        &scopes_json,
        &minted.jwt,
        &minted.expires_sqlite,
    )
    .await?
    {
        return Err(AgentAuthError::new(
            StatusCode::CONFLICT,
            "claimed_or_in_flight",
            "this registration is no longer active",
        ));
    }
    // The confirmation audit row commits atomically with the claim itself: the human gate is the
    // audit trail's anchor event, so it must never be missing from a claimed identity's history.
    let confirm_detail = serde_json::json!({
        "claim_attempt_id": attempt.id,
        "scopes": scopes,
    })
    .to_string();
    crate::db::agent_audit::insert_agent_audit_event(
        &mut *tx,
        &uuid::Uuid::new_v4().to_string(),
        &identity.id,
        Some(&caller_did),
        crate::db::agent_audit::AgentAuditEventType::ClaimConfirmed,
        Some(&confirm_detail),
    )
    .await?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit agent claim confirm");
        AgentAuthError::server_error()
    })?;

    Ok((
        StatusCode::OK,
        Json(ClaimConfirmResponse {
            registration_id: identity.id,
            status: "claimed",
            did: caller_did,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use common::AgentAuthConfig;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    // ── harness ──────────────────────────────────────────────────────────────

    async fn state_with(agent_auth: AgentAuthConfig) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.agent_auth = agent_auth;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    async fn insert_account(db: &SqlitePool, did: &str, email: &str) {
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

    /// Mint a full-access HS256 access token for `did` (the shape the extractor accepts, mirroring
    /// `auth::mod` test helpers). `scope` selects full access vs app-pass.
    fn access_token(state: &AppState, did: &str, scope: &str) -> String {
        #[derive(serde::Serialize)]
        struct Claims {
            sub: String,
            aud: String,
            exp: u64,
            scope: String,
        }
        let exp = (Utc::now().timestamp() + 3600) as u64;
        let claims = Claims {
            sub: did.to_string(),
            aud: "did:plc:test".to_string(),
            exp,
            scope: scope.to_string(),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap()
    }

    async fn post_json(
        state: AppState,
        uri: &str,
        body: Value,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        let response = app(state)
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    async fn register(state: AppState, body: Value) -> Value {
        let (_status, json) = post_json(state, "/agent/identity", body, None).await;
        json
    }

    fn anonymous_cfg() -> AgentAuthConfig {
        AgentAuthConfig {
            anonymous_enabled: true,
            ..AgentAuthConfig::default()
        }
    }

    fn service_auth_cfg() -> AgentAuthConfig {
        AgentAuthConfig {
            service_auth_enabled: true,
            ..AgentAuthConfig::default()
        }
    }

    // ── initiate ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn anonymous_claim_token_mints_first_user_code() {
        let state = state_with(anonymous_cfg()).await;
        let reg = register(state.clone(), json!({ "type": "anonymous" })).await;
        let claim_token = reg["claim_token"].as_str().unwrap().to_string();
        let registration_id = reg["registration_id"].as_str().unwrap().to_string();

        let (status, body) = post_json(
            state.clone(),
            "/agent/identity/claim",
            json!({ "claim_token": claim_token }),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "initiated");
        assert_eq!(body["registration_id"], registration_id);
        assert!(body["claim_attempt_id"]
            .as_str()
            .unwrap()
            .starts_with("cla_"));
        assert_eq!(
            body["claim_attempt"]["user_code"].as_str().unwrap().len(),
            6
        );
        assert_eq!(body["claim_attempt"]["interval"], 5);
        assert_eq!(
            body["claim_attempt"]["verification_uri"],
            "https://test.example.com/agent/claim"
        );
        // Exactly one pending attempt now exists for this identity.
        let attempts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_claim_attempts WHERE identity_id = ?")
                .bind(&registration_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn service_auth_claim_reuses_pending_user_code() {
        let state = state_with(service_auth_cfg()).await;
        insert_account(&state.db, "did:plc:svcclaim1111111111", "agent@example.com").await;
        let reg = register(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "agent@example.com" }),
        )
        .await;
        let claim_token = reg["claim_token"].as_str().unwrap().to_string();
        // Registration already minted a user_code; re-initiating must return the SAME one.
        let original_code = reg["claim"]["user_code"].as_str().unwrap().to_string();

        let (status, body) = post_json(
            state.clone(),
            "/agent/identity/claim",
            json!({ "claim_token": claim_token }),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["claim_attempt"]["user_code"], original_code);
        // No second attempt was created.
        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_claim_attempts")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn missing_claim_token_is_invalid_request() {
        let state = state_with(anonymous_cfg()).await;
        let (status, body) = post_json(state, "/agent/identity/claim", json!({}), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn unknown_claim_token_is_invalid_claim_token() {
        let state = state_with(anonymous_cfg()).await;
        let (status, body) = post_json(
            state,
            "/agent/identity/claim",
            json!({ "claim_token": "clm_nope" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_claim_token");
    }

    #[tokio::test]
    async fn expired_claim_token_is_claim_expired() {
        let state = state_with(anonymous_cfg()).await;
        // Seed an active anonymous identity whose claim token expired in the past.
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, claim_token, \
              claim_token_expires_at, status, created_at, updated_at) \
             VALUES ('reg_exp', NULL, 'anonymous', '[]', datetime('now', '+1 hour'), \
                     'clm_expired', datetime('now', '-1 minute'), 'active', datetime('now'), \
                     datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = post_json(
            state,
            "/agent/identity/claim",
            json!({ "claim_token": "clm_expired" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "claim_expired");
    }

    #[tokio::test]
    async fn already_claimed_is_claimed_or_in_flight() {
        let state = state_with(anonymous_cfg()).await;
        insert_account(&state.db, "did:plc:claimeddid1111111", "u@example.com").await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, claim_token, \
              claim_token_expires_at, status, created_at, updated_at) \
             VALUES ('reg_done', 'did:plc:claimeddid1111111', 'anonymous', '[]', \
                     datetime('now', '+1 hour'), 'clm_done', datetime('now', '+1 hour'), \
                     'claimed', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = post_json(
            state,
            "/agent/identity/claim",
            json!({ "claim_token": "clm_done" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "claimed_or_in_flight");
    }

    // ── confirm ──────────────────────────────────────────────────────────────

    /// Register anonymously, initiate the ceremony, and return `(user_code, registration_id)`.
    async fn anonymous_ceremony(state: &AppState) -> (String, String) {
        let reg = register(state.clone(), json!({ "type": "anonymous" })).await;
        let claim_token = reg["claim_token"].as_str().unwrap().to_string();
        let registration_id = reg["registration_id"].as_str().unwrap().to_string();
        let (_s, body) = post_json(
            state.clone(),
            "/agent/identity/claim",
            json!({ "claim_token": claim_token }),
            None,
        )
        .await;
        let user_code = body["claim_attempt"]["user_code"]
            .as_str()
            .unwrap()
            .to_string();
        (user_code, registration_id)
    }

    #[tokio::test]
    async fn confirm_binds_anonymous_owner_and_enables_exchange() {
        let state = state_with(anonymous_cfg()).await;
        let did = "did:plc:anonowner111111111";
        insert_account(&state.db, did, "owner@example.com").await;
        let (user_code, registration_id) = anonymous_ceremony(&state).await;
        let token = access_token(&state, did, "com.atproto.access");

        let (status, body) = post_json(
            state.clone(),
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "claimed");
        assert_eq!(body["did"], did);

        // The identity is now claimed, bound to the owner, with a fresh assertion stored.
        let row: (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT did, status, identity_assertion FROM agent_identities WHERE id = ?",
        )
        .bind(&registration_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(did));
        assert_eq!(row.1, "claimed");
        let stored_assertion = row.2.expect("post-claim assertion stored");

        // End-to-end: the stored post-claim assertion now exchanges at the token endpoint.
        let (tstatus, tbody) = post_form(
            state,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={stored_assertion}"
            ),
        )
        .await;
        assert_eq!(
            tstatus,
            StatusCode::OK,
            "post-claim assertion must exchange"
        );
        assert_eq!(tbody["token_type"], "Bearer");
        assert!(tbody["access_token"].as_str().unwrap().split('.').count() == 3);
    }

    async fn post_form(state: AppState, uri: &str, body: &str) -> (StatusCode, Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn confirm_service_auth_binding_succeeds() {
        let state = state_with(service_auth_cfg()).await;
        let did = "did:plc:svcowner1111111111";
        insert_account(&state.db, did, "svc@example.com").await;
        let reg = register(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "svc@example.com" }),
        )
        .await;
        let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();
        let token = access_token(&state, did, "com.atproto.access");

        let (status, body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "claimed");
        assert_eq!(body["did"], did);
    }

    #[tokio::test]
    async fn confirm_by_wrong_account_is_access_denied() {
        let state = state_with(service_auth_cfg()).await;
        let owner = "did:plc:rightowner111111111";
        let intruder = "did:plc:wrongowner111111111";
        insert_account(&state.db, owner, "right@example.com").await;
        insert_account(&state.db, intruder, "wrong@example.com").await;
        let reg = register(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "right@example.com" }),
        )
        .await;
        let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();
        // The intruder holds a valid full-access token, but for the wrong account.
        let token = access_token(&state, intruder, "com.atproto.access");

        let (status, body) = post_json(
            state.clone(),
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "access_denied");
        // Nothing was claimed.
        let claimed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_identities WHERE status = 'claimed'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(claimed, 0);
    }

    #[tokio::test]
    async fn confirm_unknown_user_code_is_invalid() {
        let state = state_with(anonymous_cfg()).await;
        let did = "did:plc:nocode11111111111";
        insert_account(&state.db, did, "n@example.com").await;
        let token = access_token(&state, did, "com.atproto.access");
        let (status, body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": "ZZZZZZ" }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_user_code");
    }

    #[tokio::test]
    async fn confirm_second_time_is_claimed_or_in_flight() {
        let state = state_with(anonymous_cfg()).await;
        let did = "did:plc:twice1111111111111";
        insert_account(&state.db, did, "t@example.com").await;
        let (user_code, _reg) = anonymous_ceremony(&state).await;
        let token = access_token(&state, did, "com.atproto.access");

        let (first, _) = post_json(
            state.clone(),
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code.clone() }),
            Some(&token),
        )
        .await;
        assert_eq!(first, StatusCode::OK);

        let (second, body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token),
        )
        .await;
        assert_eq!(second, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "claimed_or_in_flight");
    }

    #[tokio::test]
    async fn confirm_app_password_token_is_refused() {
        let state = state_with(anonymous_cfg()).await;
        let did = "did:plc:apppass1111111111";
        insert_account(&state.db, did, "a@example.com").await;
        let (user_code, _reg) = anonymous_ceremony(&state).await;
        // App-password scope is narrower than full access → refused before any lookup.
        let token = access_token(&state, did, "com.atproto.appPass");

        let (status, body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_token");
    }

    #[tokio::test]
    async fn confirm_without_auth_is_unauthorized() {
        let state = state_with(anonymous_cfg()).await;
        let (user_code, _reg) = anonymous_ceremony(&state).await;
        let (status, _body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// The wallet confirms with its opaque session token (`sessions` table), not an OAuth JWT.
    /// The human gate must accept the same dual credential as the `/v1/agents` owner surface —
    /// preview accepting a session the confirm then refuses strands the ceremony at its last step.
    #[tokio::test]
    async fn confirm_with_wallet_session_token_succeeds() {
        let state = state_with(service_auth_cfg()).await;
        let did = "did:plc:sessowner1111111111";
        insert_account(&state.db, did, "sess@example.com").await;
        let reg = register(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "sess@example.com" }),
        )
        .await;
        let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();

        let token = crate::auth::token::generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = post_json(
            state,
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token.plaintext),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "claimed");
        assert_eq!(body["did"], did);
    }

    /// A session token held by a different account than the pre-bound owner must still be refused.
    #[tokio::test]
    async fn confirm_with_wrong_accounts_session_token_is_access_denied() {
        let state = state_with(service_auth_cfg()).await;
        let owner = "did:plc:sessright1111111111";
        let intruder = "did:plc:sesswrong1111111111";
        insert_account(&state.db, owner, "sright@example.com").await;
        insert_account(&state.db, intruder, "swrong@example.com").await;
        let reg = register(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "sright@example.com" }),
        )
        .await;
        let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();

        let token = crate::auth::token::generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(intruder)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = post_json(
            state.clone(),
            "/agent/identity/claim/confirm",
            json!({ "user_code": user_code }),
            Some(&token.plaintext),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "access_denied");
        let claimed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_identities WHERE status = 'claimed'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(claimed, 0);
    }
}
