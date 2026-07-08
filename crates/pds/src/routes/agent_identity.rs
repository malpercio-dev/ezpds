// pattern: Imperative Shell
//
// Gathers: AppState (config, OAuth signing key, DB), JSON request body
// Processes: dispatch on registration `type` → validate/mint → persist agent-identity state
// Returns: JSON registration result on success; OAuth-style `{error, error_description}` on failure
//
// `POST /agent/identity` — the auth.md agent-registration endpoint (auth.md spec Step 3). Three
// registration flows are advertised in the AS metadata, and this handler implements all three:
//
//   - `identity_assertion` — the agent presents an ID-JAG (a JWT issued by a trusted external
//     identity provider). The ID-JAG is verified against a configured issuer trust list; a known
//     `(iss, sub)` that has been confirmed yields a fresh service-signed `identity_assertion`,
//     while a first-seen `(iss, sub)` (whose asserted email matches a local account) starts a claim
//     ceremony and returns `interaction_required`.
//   - `service_auth` — the agent knows only the user's email (`login_hint`). We start a claim
//     ceremony bound to that account and return the `claim_token` + claim block.
//   - `anonymous` — the agent has no user identity yet. We register an ownerless identity
//     (`agent_identities.did` is NULL until a claim binds one — V038 made it nullable), mint a
//     pre-claim service-signed `identity_assertion` carrying the operator's `pre_claim_scopes`, and
//     return it alongside a `claim_token` for an optional later claim ceremony. The pre-claim
//     identity stays `active` (unclaimed), so its assertion cannot yet be exchanged at the token
//     endpoint (the jwt-bearer grant requires a `claimed` identity with a bound DID).
//
// Claim-lifecycle interpretation (documented because auth.md leaves the exact status transitions to
// the claim-ceremony endpoint): an `agent_identities.status` of `active` means "registered,
// awaiting the user's claim confirmation" and `claimed` means "confirmed and bound". This handler
// only ever *initiates* a registration (persisting the identity + a pending claim attempt and
// returning the claim materials); the confirmation transition that flips `active → claimed` lives in
// the claim-ceremony endpoint (`routes/agent_claim.rs`), and the polling exchange in the claim grant
// type (a separate ticket).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use common::TrustedIssuer;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::agent_assertion::{
    claim_block, mint_identity_assertion, new_claim_attempt_id, scopes_to_json, to_sqlite_datetime,
    verification_uri, AgentAuthError,
};
use crate::code_gen::generate_code;
use crate::db::accounts::resolve_by_email;
use crate::db::agent_auth::{
    get_agent_identity_by_issuer_subject, insert_agent_claim_attempt, insert_agent_identity,
    set_agent_identity_assertion, AgentIdentityRow, AgentIdentityStatus,
    InsertAgentIdentityOutcome, NewAgentClaimAttempt, NewAgentIdentity, RegistrationType,
};
use crate::token::generate_token;

/// The one assertion type this server accepts for the `identity_assertion` flow.
const ID_JAG_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";

// ── Request / response types ────────────────────────────────────────────────────

/// Permissive body for `POST /agent/identity`. All fields optional so the handler can return
/// auth.md-shaped errors for a missing/unknown `type` rather than Axum's default rejection.
#[derive(Debug, Deserialize)]
pub struct AgentIdentityRequest {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    // identity_assertion
    pub assertion_type: Option<String>,
    pub assertion: Option<String>,
    // service_auth
    pub login_hint: Option<String>,
}

/// Success body for an `identity_assertion` that needed no confirmation.
#[derive(Debug, Serialize)]
struct IdentityAssertionResponse {
    registration_id: String,
    registration_type: &'static str,
    identity_assertion: String,
    assertion_expires: String,
    scopes: Vec<String>,
}

/// Success body for an `anonymous` registration: a pre-claim assertion plus the `claim_token` for
/// an optional later claim ceremony.
#[derive(Debug, Serialize)]
struct AnonymousResponse {
    registration_id: String,
    registration_type: &'static str,
    identity_assertion: String,
    assertion_expires: String,
    scopes: Vec<String>,
    claim_token: String,
}

/// Success body for a `service_auth` registration (a started claim ceremony).
#[derive(Debug, Serialize)]
struct ServiceAuthResponse {
    registration_id: String,
    registration_type: &'static str,
    claim_token: String,
    claim: Value,
}

// ── Handler ─────────────────────────────────────────────────────────────────────

/// `POST /agent/identity` — dispatch on the registration `type`.
pub async fn post_agent_identity(
    State(state): State<AppState>,
    Json(req): Json<AgentIdentityRequest>,
) -> Response {
    let result = match req.typ.as_deref() {
        Some("identity_assertion") => handle_identity_assertion(&state, &req).await,
        Some("service_auth") => handle_service_auth(&state, &req).await,
        Some("anonymous") => handle_anonymous(&state).await,
        Some(other) => Err(AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("unsupported registration type: {other:?}"),
        )),
        None => Err(AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing required field: type",
        )),
    };
    match result {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// `anonymous` — register an ownerless agent identity (auth.md §3.3). Mints a pre-claim service
/// assertion carrying `pre_claim_scopes` and returns it plus a `claim_token` for an optional later
/// claim ceremony. The identity persists with a NULL `did` (V038) and `active` status until a claim
/// binds an account.
async fn handle_anonymous(state: &AppState) -> Result<Response, AgentAuthError> {
    if !state.config.agent_auth.anonymous_enabled {
        return Err(AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "anonymous_not_enabled",
            "anonymous agent registration is not enabled on this server",
        ));
    }

    let registration_id = new_registration_id();
    let claim_token = new_claim_token();
    let pre_claim_scopes = &state.config.agent_auth.pre_claim_scopes;
    let scopes_json = scopes_to_json(pre_claim_scopes);
    let claim_expiry =
        Utc::now() + Duration::seconds(state.config.agent_auth.claim_token_ttl_secs as i64);

    // The pre-claim assertion's subject is the registration id — an anonymous identity has no DID to
    // name yet. It carries the pre-claim scope set and is marked `anonymous` in its claims.
    let minted = mint_identity_assertion(
        &state.oauth_signing_keypair,
        &state.config.public_url,
        state.config.agent_auth.assertion_ttl_secs,
        &registration_id,
        &registration_id,
        RegistrationType::Anonymous.as_str(),
        pre_claim_scopes,
    )?;

    let outcome = insert_agent_identity(
        &state.db,
        &NewAgentIdentity {
            id: &registration_id,
            did: None,
            registration_type: RegistrationType::Anonymous,
            issuer: None,
            subject: None,
            email: None,
            scopes: &scopes_json,
            identity_assertion: Some(&minted.jwt),
            assertion_expires_at: &minted.expires_sqlite,
            pre_claim_scopes: Some(&scopes_json),
            claim_token: Some(&claim_token),
            claim_token_expires_at: Some(&to_sqlite_datetime(&claim_expiry)),
        },
    )
    .await?;
    if outcome == InsertAgentIdentityOutcome::Duplicate {
        // Random registration id / claim token collided — astronomically unlikely; treat as a
        // transient server fault rather than a client error.
        tracing::error!(registration_id = %registration_id, "anonymous agent identity insert reported an unexpected duplicate");
        return Err(AgentAuthError::server_error());
    }

    Ok(ok_json(&AnonymousResponse {
        registration_id,
        registration_type: RegistrationType::Anonymous.as_str(),
        identity_assertion: minted.jwt,
        assertion_expires: minted.expires_rfc3339,
        scopes: pre_claim_scopes.clone(),
        claim_token,
    }))
}

// ── service_auth ─────────────────────────────────────────────────────────────────

async fn handle_service_auth(
    state: &AppState,
    req: &AgentIdentityRequest,
) -> Result<Response, AgentAuthError> {
    if !state.config.agent_auth.service_auth_enabled {
        return Err(AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "service_auth_not_enabled",
            "service_auth agent registration is not enabled on this server",
        ));
    }
    let login_hint = req
        .login_hint
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "service_auth requires a non-empty login_hint",
            )
        })?;

    // The identity must be owned by an existing local account (V037 FK). No match → refuse.
    let account = resolve_by_email(&state.db, login_hint)
        .await?
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "no local account matches login_hint",
            )
        })?;

    let registration_id = new_registration_id();
    let claim_token = new_claim_token();
    let user_code = generate_code();
    let scopes_json = scopes_to_json(&state.config.agent_auth.granted_scopes);

    let claim_expiry =
        Utc::now() + Duration::seconds(state.config.agent_auth.claim_token_ttl_secs as i64);
    let user_code_expiry =
        Utc::now() + Duration::seconds(state.config.agent_auth.user_code_ttl_secs as i64);

    // No assertion is minted until the ceremony completes; `assertion_expires_at` is NOT NULL, so
    // park it at the claim-token expiry (overwritten by `set_agent_identity_assertion` on claim).
    let outcome = insert_agent_identity(
        &state.db,
        &NewAgentIdentity {
            id: &registration_id,
            did: Some(&account.did),
            registration_type: RegistrationType::ServiceAuth,
            issuer: None,
            subject: None,
            email: Some(login_hint),
            scopes: &scopes_json,
            identity_assertion: None,
            assertion_expires_at: &to_sqlite_datetime(&claim_expiry),
            pre_claim_scopes: None,
            claim_token: Some(&claim_token),
            claim_token_expires_at: Some(&to_sqlite_datetime(&claim_expiry)),
        },
    )
    .await?;
    if outcome == InsertAgentIdentityOutcome::Duplicate {
        // Random registration id / claim token collided — astronomically unlikely; treat as a
        // transient server fault rather than a client error.
        tracing::error!(registration_id = %registration_id, "agent identity insert reported an unexpected duplicate");
        return Err(AgentAuthError::server_error());
    }

    insert_agent_claim_attempt(
        &state.db,
        &NewAgentClaimAttempt {
            id: &new_claim_attempt_id(),
            identity_id: &registration_id,
            user_code: &user_code,
            user_code_expires_at: &to_sqlite_datetime(&user_code_expiry),
            email: Some(login_hint),
        },
    )
    .await?;

    let claim = claim_block(
        &user_code,
        &verification_uri(&state.config.agent_auth, &state.config.public_url),
        &user_code_expiry,
    );
    Ok(ok_json(&ServiceAuthResponse {
        registration_id,
        registration_type: RegistrationType::ServiceAuth.as_str(),
        claim_token,
        claim,
    }))
}

// ── identity_assertion ───────────────────────────────────────────────────────────

/// Claims read out of a verified ID-JAG. `sub` is required; `iss`, `aud`, and `exp` are validated
/// by `jsonwebtoken` and need not appear here.
#[derive(Debug, Deserialize)]
struct IdJagClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    auth_time: Option<u64>,
}

async fn handle_identity_assertion(
    state: &AppState,
    req: &AgentIdentityRequest,
) -> Result<Response, AgentAuthError> {
    // If the client names an assertion_type, it must be the ID-JAG type we support.
    if let Some(kind) = req.assertion_type.as_deref() {
        if kind != ID_JAG_ASSERTION_TYPE {
            return Err(AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("unsupported assertion_type: {kind:?}"),
            ));
        }
    }
    let assertion = req
        .assertion
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "identity_assertion requires a non-empty assertion",
            )
        })?;

    // Read the unverified `iss` to select a trusted issuer before doing any signature work.
    let iss = unverified_claim(assertion, "iss").ok_or_else(|| {
        AgentAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "assertion is malformed or missing an iss claim",
        )
    })?;
    let issuer_cfg = state
        .config
        .agent_auth
        .trusted_issuers
        .iter()
        .find(|t| t.issuer == iss)
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::FORBIDDEN,
                "issuer_not_enabled",
                "the assertion issuer is not on this server's trust list",
            )
        })?;

    let claims = verify_id_jag(assertion, issuer_cfg, &state.config.public_url)?;

    // Reject a stale authentication (`login_required`) so a long-lived ID-JAG can't be replayed
    // indefinitely against a session the user has since ended.
    if let Some(auth_time) = claims.auth_time {
        let now = Utc::now().timestamp().max(0) as u64;
        if now.saturating_sub(auth_time) > state.config.agent_auth.auth_time_max_age_secs {
            return Err(AgentAuthError::new(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "the asserted authentication is too old; re-authenticate",
            ));
        }
    }

    match get_agent_identity_by_issuer_subject(&state.db, &iss, &claims.sub).await? {
        Some(existing) => existing_identity_assertion(state, existing).await,
        None => new_identity_assertion(state, &iss, &claims).await,
    }
}

/// An `(iss, sub)` already registered: mint when confirmed, else re-issue the claim challenge.
async fn existing_identity_assertion(
    state: &AppState,
    existing: AgentIdentityRow,
) -> Result<Response, AgentAuthError> {
    match existing.status {
        AgentIdentityStatus::Claimed => {
            // Clamp the scopes stored at registration to the operator's *current* config, so
            // narrowing `[agent_auth] granted_scopes` narrows the minted assertion without
            // re-registration and the mint can never exceed the stored grant.
            let scopes = crate::auth::oauth_scopes::intersect_scope_tokens(
                &parse_scopes(&existing.scopes),
                &state.config.agent_auth.granted_scopes,
            );
            // A claimed `identity_assertion` registration always has a bound DID; a missing one is
            // a corrupt row, not a client error.
            let did = existing
                .did
                .as_deref()
                .ok_or_else(AgentAuthError::server_error)?;
            let minted = mint_identity_assertion(
                &state.oauth_signing_keypair,
                &state.config.public_url,
                state.config.agent_auth.assertion_ttl_secs,
                did,
                &existing.id,
                RegistrationType::IdentityAssertion.as_str(),
                &scopes,
            )?;
            set_agent_identity_assertion(
                &state.db,
                &existing.id,
                &minted.jwt,
                &minted.expires_sqlite,
            )
            .await?;
            Ok(ok_json(&IdentityAssertionResponse {
                registration_id: existing.id,
                registration_type: RegistrationType::IdentityAssertion.as_str(),
                identity_assertion: minted.jwt,
                assertion_expires: minted.expires_rfc3339,
                scopes,
            }))
        }
        AgentIdentityStatus::Active => {
            // Registered but not yet confirmed: return the claim challenge again. Reuse the stored
            // claim token; issue a fresh user code so an expired one doesn't strand the ceremony.
            let claim_token = existing
                .claim_token
                .clone()
                .ok_or_else(AgentAuthError::server_error)?;
            let user_code = generate_code();
            let user_code_expiry =
                Utc::now() + Duration::seconds(state.config.agent_auth.user_code_ttl_secs as i64);
            insert_agent_claim_attempt(
                &state.db,
                &NewAgentClaimAttempt {
                    id: &new_claim_attempt_id(),
                    identity_id: &existing.id,
                    user_code: &user_code,
                    user_code_expires_at: &to_sqlite_datetime(&user_code_expiry),
                    email: existing.email.as_deref(),
                },
            )
            .await?;
            let claim = claim_block(
                &user_code,
                &verification_uri(&state.config.agent_auth, &state.config.public_url),
                &user_code_expiry,
            );
            Err(AgentAuthError::interaction_required(claim, claim_token))
        }
        AgentIdentityStatus::Revoked => Err(AgentAuthError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "this agent identity has been revoked",
        )),
    }
}

/// A first-seen `(iss, sub)`: bind it to the local account matching the asserted email and start a
/// claim ceremony (`interaction_required`).
async fn new_identity_assertion(
    state: &AppState,
    iss: &str,
    claims: &IdJagClaims,
) -> Result<Response, AgentAuthError> {
    let email = claims
        .email
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AgentAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "assertion has no email claim to bind to a local account",
            )
        })?;
    let account = resolve_by_email(&state.db, email).await?.ok_or_else(|| {
        AgentAuthError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "no local account matches the asserted identity",
        )
    })?;

    let registration_id = new_registration_id();
    let claim_token = new_claim_token();
    let user_code = generate_code();
    let scopes_json = scopes_to_json(&state.config.agent_auth.granted_scopes);
    let claim_expiry =
        Utc::now() + Duration::seconds(state.config.agent_auth.claim_token_ttl_secs as i64);
    let user_code_expiry =
        Utc::now() + Duration::seconds(state.config.agent_auth.user_code_ttl_secs as i64);

    let outcome = insert_agent_identity(
        &state.db,
        &NewAgentIdentity {
            id: &registration_id,
            did: Some(&account.did),
            registration_type: RegistrationType::IdentityAssertion,
            issuer: Some(iss),
            subject: Some(&claims.sub),
            email: Some(email),
            scopes: &scopes_json,
            identity_assertion: None,
            assertion_expires_at: &to_sqlite_datetime(&claim_expiry),
            pre_claim_scopes: None,
            claim_token: Some(&claim_token),
            claim_token_expires_at: Some(&to_sqlite_datetime(&claim_expiry)),
        },
    )
    .await?;
    if outcome == InsertAgentIdentityOutcome::Duplicate {
        // A concurrent request registered the same `(iss, sub)` between our lookup and insert.
        // Retry the read path so the caller still gets a coherent interaction_required challenge.
        if let Some(existing) =
            get_agent_identity_by_issuer_subject(&state.db, iss, &claims.sub).await?
        {
            return existing_identity_assertion(state, existing).await;
        }
        return Err(AgentAuthError::server_error());
    }

    insert_agent_claim_attempt(
        &state.db,
        &NewAgentClaimAttempt {
            id: &new_claim_attempt_id(),
            identity_id: &registration_id,
            user_code: &user_code,
            user_code_expires_at: &to_sqlite_datetime(&user_code_expiry),
            email: Some(email),
        },
    )
    .await?;

    let claim = claim_block(
        &user_code,
        &verification_uri(&state.config.agent_auth, &state.config.public_url),
        &user_code_expiry,
    );
    Err(AgentAuthError::interaction_required(claim, claim_token))
}

// ── ID-JAG verification ──────────────────────────────────────────────────────────

/// Verify an ID-JAG's signature and standard claims against a trusted issuer.
///
/// Enforces the signature (issuer's configured key/alg), `iss`, `aud` (the issuer's configured
/// audience or this server's `public_url`), and `exp`.
fn verify_id_jag(
    assertion: &str,
    issuer: &TrustedIssuer,
    public_url: &str,
) -> Result<IdJagClaims, AgentAuthError> {
    let (key, alg) = decoding_key(issuer).ok_or_else(|| {
        tracing::error!(issuer = %issuer.issuer, "trusted issuer has an unusable public_key_pem/algorithm");
        AgentAuthError::server_error()
    })?;
    let expected_aud = issuer
        .audience
        .clone()
        .unwrap_or_else(|| public_url.trim_end_matches('/').to_string());

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&issuer.issuer]);
    validation.set_audience(&[&expected_aud]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    decode::<IdJagClaims>(assertion, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            AgentAuthError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_grant",
                format!("assertion verification failed: {e}"),
            )
        })
}

/// Build a `jsonwebtoken` decoding key + algorithm for a trusted issuer. `None` on an unusable PEM
/// or an algorithm outside the supported set (the latter is also rejected at config load).
fn decoding_key(issuer: &TrustedIssuer) -> Option<(DecodingKey, Algorithm)> {
    let pem = issuer.public_key_pem.as_bytes();
    match issuer.algorithm.as_str() {
        "ES256" => DecodingKey::from_ec_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::ES256)),
        "ES384" => DecodingKey::from_ec_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::ES384)),
        "RS256" => DecodingKey::from_rsa_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::RS256)),
        "RS384" => DecodingKey::from_rsa_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::RS384)),
        "RS512" => DecodingKey::from_rsa_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::RS512)),
        "EdDSA" => DecodingKey::from_ed_pem(pem)
            .ok()
            .map(|k| (k, Algorithm::EdDSA)),
        _ => None,
    }
}

/// Read a single top-level string claim out of a JWT *without* verifying its signature. Used only
/// to pick the trusted issuer before real verification runs.
fn unverified_claim(jwt: &str, key: &str) -> Option<String> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

// ── Small helpers ────────────────────────────────────────────────────────────────

fn ok_json<T: Serialize>(body: &T) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

fn new_registration_id() -> String {
    format!("reg_{}", Uuid::new_v4().simple())
}

/// An opaque, high-entropy claim token (`clm_` + 43-char base64url). Stored and looked up verbatim,
/// matching the `agent_identities.claim_token` query layer.
fn new_claim_token() -> String {
    format!("clm_{}", generate_token().plaintext)
}

fn parse_scopes(json_array: &str) -> Vec<String> {
    serde_json::from_str(json_array).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use base64::engine::general_purpose::STANDARD;
    use common::{AgentAuthConfig, TrustedIssuer};
    use jsonwebtoken::{EncodingKey, Header};
    use p256::pkcs8::spki::EncodePublicKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serde_json::json;
    use sqlx::SqlitePool;
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    const PUBLIC_URL: &str = "https://test.example.com";

    // ── key + JWT helpers ────────────────────────────────────────────────

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

    #[derive(serde::Serialize)]
    struct IdJagTestClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        iat: u64,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_time: Option<u64>,
    }

    fn make_id_jag(
        priv_pem: &str,
        iss: &str,
        sub: &str,
        aud: &str,
        email: Option<&str>,
        auth_time: Option<u64>,
    ) -> String {
        let now = Utc::now().timestamp().max(0) as u64;
        let claims = IdJagTestClaims {
            iss,
            sub,
            aud,
            iat: now,
            exp: now + 600,
            email,
            auth_time,
        };
        let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
    }

    // ── state + request helpers ──────────────────────────────────────────

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

    async fn post(state: AppState, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/identity")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn trusted(issuer: &str, public_key_pem: String) -> TrustedIssuer {
        TrustedIssuer {
            issuer: issuer.to_string(),
            audience: None,
            public_key_pem,
            algorithm: "ES256".to_string(),
        }
    }

    // ── dispatch / basic errors ──────────────────────────────────────────

    #[tokio::test]
    async fn missing_type_is_invalid_request() {
        let (status, body) = post(state_with(AgentAuthConfig::default()).await, json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn unknown_type_is_invalid_request() {
        let (status, body) = post(
            state_with(AgentAuthConfig::default()).await,
            json!({ "type": "carrier_pigeon" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn anonymous_disabled_by_default() {
        let (status, body) = post(
            state_with(AgentAuthConfig::default()).await,
            json!({ "type": "anonymous" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "anonymous_not_enabled");
    }

    #[tokio::test]
    async fn anonymous_enabled_registers_pre_claim_identity() {
        let cfg = AgentAuthConfig {
            anonymous_enabled: true,
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        let (status, body) = post(state.clone(), json!({ "type": "anonymous" })).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["registration_type"], "anonymous");
        let registration_id = body["registration_id"].as_str().unwrap();
        assert!(registration_id.starts_with("reg_"));
        assert!(body["claim_token"].as_str().unwrap().starts_with("clm_"));
        assert!(!body["assertion_expires"].as_str().unwrap().is_empty());
        // The pre-claim assertion is a JWT carrying the default pre-claim scope profile.
        let assertion = body["identity_assertion"].as_str().unwrap();
        assert_eq!(assertion.split('.').count(), 3, "assertion must be a JWT");
        assert_eq!(
            body["scopes"],
            json!(["atproto", "repo:*?action=create&action=update", "blob:*/*"])
        );

        // The identity was persisted ownerless (NULL did), active, with the assertion stored.
        let row: (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT did, status, identity_assertion FROM agent_identities WHERE id = ?",
        )
        .bind(registration_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row.0, None, "anonymous identity has no owning did");
        assert_eq!(row.1, "active");
        assert_eq!(row.2.as_deref(), Some(assertion));
    }

    #[tokio::test]
    async fn anonymous_pre_claim_assertion_cannot_be_exchanged_yet() {
        // The pre-claim identity is `active`, not `claimed`, so the jwt-bearer grant refuses to
        // exchange its assertion for an access token until a claim ceremony binds a DID.
        let cfg = AgentAuthConfig {
            anonymous_enabled: true,
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        let (_status, body) = post(state.clone(), json!({ "type": "anonymous" })).await;
        let assertion = body["identity_assertion"].as_str().unwrap().to_string();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={assertion}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "invalid_grant");
    }

    // ── service_auth ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn service_auth_disabled_by_default() {
        let (status, body) = post(
            state_with(AgentAuthConfig::default()).await,
            json!({ "type": "service_auth", "login_hint": "a@b.com" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "service_auth_not_enabled");
    }

    #[tokio::test]
    async fn service_auth_unknown_account_is_access_denied() {
        let cfg = AgentAuthConfig {
            service_auth_enabled: true,
            ..AgentAuthConfig::default()
        };
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "service_auth", "login_hint": "nobody@example.com" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "access_denied");
    }

    #[tokio::test]
    async fn service_auth_missing_login_hint_is_invalid_request() {
        let cfg = AgentAuthConfig {
            service_auth_enabled: true,
            ..AgentAuthConfig::default()
        };
        let (status, body) = post(state_with(cfg).await, json!({ "type": "service_auth" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn service_auth_starts_claim_ceremony() {
        let cfg = AgentAuthConfig {
            service_auth_enabled: true,
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        insert_account(
            &state.db,
            "did:plc:svcauth1111111111111",
            "agent@example.com",
        )
        .await;

        let (status, body) = post(
            state.clone(),
            json!({ "type": "service_auth", "login_hint": "agent@example.com" }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["registration_type"], "service_auth");
        assert!(body["registration_id"]
            .as_str()
            .unwrap()
            .starts_with("reg_"));
        assert!(body["claim_token"].as_str().unwrap().starts_with("clm_"));
        assert!(!body["claim"]["user_code"].as_str().unwrap().is_empty());
        assert_eq!(
            body["claim"]["verification_uri"],
            "https://test.example.com/agent/claim"
        );

        // A pending claim attempt and an identity row were persisted.
        let identities: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_identities WHERE did = ?")
                .bind("did:plc:svcauth1111111111111")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(identities, 1);
        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_claim_attempts")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(attempts, 1);
    }

    // ── identity_assertion ───────────────────────────────────────────────

    #[tokio::test]
    async fn identity_assertion_untrusted_issuer_is_refused() {
        let (_priv, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let (unknown_priv, _unknown_pub) = es256_keys();
        let jag = make_id_jag(
            &unknown_priv,
            "https://evil.example",
            "sub-1",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "issuer_not_enabled");
    }

    #[tokio::test]
    async fn identity_assertion_bad_signature_is_invalid_grant() {
        let (_priv, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        // Correct iss (so we reach verification) but signed by a different key.
        let (wrong_priv, _) = es256_keys();
        let jag = make_id_jag(
            &wrong_priv,
            "https://trusted.example",
            "sub-1",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn identity_assertion_stale_auth_time_is_login_required() {
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            auth_time_max_age_secs: 3600,
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let stale = (Utc::now().timestamp().max(0) as u64) - 7200;
        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-1",
            PUBLIC_URL,
            Some("agent@example.com"),
            Some(stale),
        );
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "login_required");
    }

    #[tokio::test]
    async fn identity_assertion_new_binding_requires_interaction() {
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        insert_account(
            &state.db,
            "did:plc:idassert11111111111",
            "agent@example.com",
        )
        .await;

        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-new",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state.clone(),
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "interaction_required");
        assert!(body["claim_token"].as_str().unwrap().starts_with("clm_"));
        assert!(!body["claim"]["user_code"].as_str().unwrap().is_empty());

        // The registration was persisted as active (awaiting confirmation) with the (iss, sub).
        let row: (String, String) = sqlx::query_as(
            "SELECT status, registration_type FROM agent_identities \
             WHERE issuer = ? AND subject = ?",
        )
        .bind("https://trusted.example")
        .bind("sub-new")
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row.0, "active");
        assert_eq!(row.1, "identity_assertion");
    }

    #[tokio::test]
    async fn identity_assertion_no_matching_account_is_access_denied() {
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-orphan",
            PUBLIC_URL,
            Some("nobody@example.com"),
            None,
        );
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "access_denied");
    }

    #[tokio::test]
    async fn identity_assertion_claimed_identity_mints_assertion() {
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        let did = "did:plc:claimed111111111111";
        insert_account(&state.db, did, "agent@example.com").await;
        // Pre-seed a confirmed (claimed) registration for this (iss, sub). The stored scopes match
        // the default granular profile so the config-clamp intersection is a no-op here.
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_seed', ?, 'identity_assertion', 'https://trusted.example', 'sub-known', \
                     'agent@example.com', \
                     '[\"atproto\",\"repo:*?action=create&action=update\",\"blob:*/*\"]', NULL, \
                     datetime('now', '+1 hour'), 'claimed', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-known",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state.clone(),
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["registration_id"], "reg_seed");
        assert_eq!(body["registration_type"], "identity_assertion");
        // Scopes are the config-clamped set, sorted by the intersection helper.
        assert_eq!(
            body["scopes"],
            json!(["atproto", "blob:*/*", "repo:*?action=create&action=update"])
        );
        let assertion = body["identity_assertion"].as_str().unwrap();
        assert_eq!(assertion.split('.').count(), 3, "assertion must be a JWT");

        // The freshly minted assertion was stored back on the identity.
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT identity_assertion FROM agent_identities WHERE id = 'reg_seed'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(stored.as_deref(), Some(assertion));
    }

    #[tokio::test]
    async fn identity_assertion_mint_is_clamped_to_current_config() {
        // Narrowing the operator's granted_scopes narrows the scopes minted for an
        // already-registered (claimed) identity, without re-registration.
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            // Operator has since narrowed the config to drop blob uploads.
            granted_scopes: vec![
                "atproto".to_string(),
                "repo:*?action=create&action=update".to_string(),
            ],
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        let did = "did:plc:clamped11111111111";
        insert_account(&state.db, did, "agent@example.com").await;
        // The registration was stored earlier with the broader default profile (incl. blob).
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_clamp', ?, 'identity_assertion', 'https://trusted.example', 'sub-clamp', \
                     'agent@example.com', \
                     '[\"atproto\",\"repo:*?action=create&action=update\",\"blob:*/*\"]', NULL, \
                     datetime('now', '+1 hour'), 'claimed', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-clamp",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state.clone(),
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        // blob:*/* was dropped because the current config no longer grants it.
        assert_eq!(
            body["scopes"],
            json!(["atproto", "repo:*?action=create&action=update"])
        );
    }

    #[tokio::test]
    async fn identity_assertion_mint_with_disjoint_config_yields_empty_scopes() {
        // Fail-closed edge case: when the current config shares no token with the registration's
        // stored scopes, the clamp yields an empty set — the agent's token is bounded to nothing
        // rather than falling back to a broader grant.
        let (priv_pem, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            // Disjoint from the stored `blob:*/*` scope below.
            granted_scopes: vec!["repo:*?action=create".to_string()],
            ..AgentAuthConfig::default()
        };
        let state = state_with(cfg).await;
        let did = "did:plc:disjoint111111111";
        insert_account(&state.db, did, "agent@example.com").await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_disjoint', ?, 'identity_assertion', 'https://trusted.example', \
                     'sub-disjoint', 'agent@example.com', '[\"blob:*/*\"]', NULL, \
                     datetime('now', '+1 hour'), 'claimed', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let jag = make_id_jag(
            &priv_pem,
            "https://trusted.example",
            "sub-disjoint",
            PUBLIC_URL,
            Some("agent@example.com"),
            None,
        );
        let (status, body) = post(
            state.clone(),
            json!({ "type": "identity_assertion", "assertion": jag }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scopes"], json!([]));
    }

    #[tokio::test]
    async fn identity_assertion_malformed_is_invalid_grant() {
        let (_priv, pub_pem) = es256_keys();
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
            ..AgentAuthConfig::default()
        };
        let (status, body) = post(
            state_with(cfg).await,
            json!({ "type": "identity_assertion", "assertion": "not-a-jwt" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }
}
