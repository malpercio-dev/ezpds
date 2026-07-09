// pattern: Imperative Shell
//
// End-to-end integration tests for the auth.md agent-authentication flows. The per-route modules
// (`agent_identity.rs`, `agent_claim.rs`, `oauth_token.rs`, `oauth_revoke.rs`, the two discovery
// endpoints) already unit-test each handler in isolation. This module instead drives the *whole
// journey* across endpoints through the real HTTP router — discovery → register → claim initiate →
// poll → confirm → token exchange → revoke — so a contract drift between two handlers (e.g. a
// `claim_token` minted by `/agent/identity` that the token endpoint no longer accepts, or a
// post-claim assertion that won't exchange) surfaces here even when every handler still passes its
// own unit tests.
//
// Two auth.md checklist items are intentionally NOT covered here because they don't map to shipped
// code: there is no Security Event Token (SET) endpoint yet (the AS metadata advertises
// `events_endpoint`/`events_supported` ahead of that work), and the claim ceremony is JSON-only
// (there is no HTML "claim page" route). Both are noted where relevant below.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use common::{AgentAuthConfig, TrustedIssuer};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::pkcs8::{spki::EncodePublicKey, EncodePrivateKey};
use rand_core::OsRng;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::app::{app, test_state, AppState};

const PUBLIC_URL: &str = "https://test.example.com";

// ── state helpers ────────────────────────────────────────────────────────────

/// `test_state()` with the agent-auth config swapped in (every flow is off by default).
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

/// A full-access HS256 access token for `did` — the credential the account owner presents to
/// confirm a claim (mirrors the shape `auth/extractors.rs` accepts).
fn owner_token(state: &AppState, did: &str) -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        sub: String,
        aud: String,
        exp: u64,
        scope: String,
    }
    let exp = (Utc::now().timestamp() + 3600) as u64;
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            sub: did.to_string(),
            aud: "did:plc:test".to_string(),
            exp,
            scope: "com.atproto.access".to_string(),
        },
        &EncodingKey::from_secret(&state.jwt_secret),
    )
    .unwrap()
}

// ── ID-JAG helpers (self-contained so `exp`/`auth_time` are controllable) ──────

/// A fresh ES256 keypair as (PKCS#8 private PEM, SPKI public PEM), via p256's built-in PEM encoders.
fn es256_keys() -> (String, String) {
    let sk = p256::SecretKey::random(&mut OsRng);
    let priv_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
    let pub_pem = sk
        .public_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    (priv_pem, pub_pem)
}

#[derive(serde::Serialize)]
struct JagClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
}

/// Sign an ID-JAG with explicit `iat`/`exp` (seconds since epoch) so callers can forge an expired
/// token — the per-route `make_id_jag` helper hardcodes `exp = now + 600` and can't.
fn make_jag(priv_pem: &str, iss: &str, sub: &str, email: &str, iat: i64, exp: i64) -> String {
    let claims = JagClaims {
        iss,
        sub,
        aud: PUBLIC_URL,
        iat,
        exp,
        email: Some(email),
    };
    let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
}

fn trusted(issuer: &str, public_key_pem: String) -> TrustedIssuer {
    TrustedIssuer {
        issuer: issuer.to_string(),
        audience: None,
        public_key_pem: Some(public_key_pem),
        jwks_url: None,
        algorithm: "ES256".to_string(),
    }
}

// ── request helpers ────────────────────────────────────────────────────────────

/// Drive a built request through the real router and decode the JSON response. Shared by the
/// verb-specific helpers so the send-and-decode flow (byte cap, fallback-to-`Null`) lives once.
async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = app(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get_json(state: AppState, uri: &str) -> (StatusCode, Value) {
    send(
        state,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
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
    send(state, builder.body(Body::from(body.to_string())).unwrap()).await
}

async fn post_form(state: AppState, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(state, request).await
}

/// jwt-bearer token exchange for a service-signed `identity_assertion`.
async fn exchange_assertion(state: AppState, assertion: &str) -> (StatusCode, Value) {
    post_form(
        state,
        "/oauth/token",
        &format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={assertion}"),
    )
    .await
}

/// Poll the claim grant for a `claim_token`.
async fn poll_claim(state: AppState, claim_token: &str) -> (StatusCode, Value) {
    post_form(
        state,
        "/oauth/token",
        &format!("grant_type=urn:workos:agent-auth:grant-type:claim&claim_token={claim_token}"),
    )
    .await
}

/// The claim-poll throttle marks a poll's instant and rejects the next poll within
/// `POLL_INTERVAL_SECS` with `slow_down`. Tests can't wait out a real 5s window, so we drop the
/// advisory mark to simulate the interval elapsing (the same shortcut the throttle unit test
/// deliberately avoids to prove the throttle fires).
fn reset_poll_throttle(state: &AppState) {
    state
        .poll_tracker
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
}

fn config_scopes() -> Vec<String> {
    AgentAuthConfig::default().granted_scopes
}

/// Register an `anonymous` identity and open its claim ceremony, returning the ceremony's
/// `claim_token` (the agent's polling credential) and `user_code` (the code the human confirms).
/// The flagship `anonymous_full_ceremony_*` test inlines these steps instead, because it polls and
/// asserts between them and needs the intermediate `registration_id`.
async fn register_and_initiate_anonymous_claim(state: &AppState) -> (String, String) {
    let (_s, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "anonymous" }),
        None,
    )
    .await;
    let claim_token = reg["claim_token"].as_str().unwrap().to_string();
    let (_is, ibody) = post_json(
        state.clone(),
        "/agent/identity/claim",
        json!({ "claim_token": claim_token }),
        None,
    )
    .await;
    let user_code = ibody["claim_attempt"]["user_code"]
        .as_str()
        .unwrap()
        .to_string();
    (claim_token, user_code)
}

// ── discovery round-trip ─────────────────────────────────────────────────────

/// The two discovery documents advertise agent endpoints; assert the advertised paths actually
/// route to a handler (per-endpoint unit tests only check the JSON, never that the URLs resolve).
#[tokio::test]
async fn discovery_advertises_endpoints_that_actually_route() {
    // PRM and AS metadata agree on the origin.
    let (prm_status, prm) =
        get_json(test_state().await, "/.well-known/oauth-protected-resource").await;
    assert_eq!(prm_status, StatusCode::OK);
    assert_eq!(prm["resource"], PUBLIC_URL);
    assert_eq!(prm["authorization_servers"][0], PUBLIC_URL);

    let (as_status, meta) = get_json(
        test_state().await,
        "/.well-known/oauth-authorization-server",
    )
    .await;
    assert_eq!(as_status, StatusCode::OK);

    // The agent-auth grants are advertised on the token endpoint.
    let grants = meta["grant_types_supported"].as_array().unwrap();
    assert!(grants
        .iter()
        .any(|g| g == "urn:ietf:params:oauth:grant-type:jwt-bearer"));
    assert!(grants
        .iter()
        .any(|g| g == "urn:workos:agent-auth:grant-type:claim"));

    // Strip the advertised origin to get the local path, then prove POSTing it reaches the real
    // handler (a well-formed auth.md `invalid_request`, NOT the router's 404/415).
    for field in ["identity_endpoint", "claim_endpoint"] {
        let url = meta["agent_auth"][field].as_str().unwrap();
        let path = url.strip_prefix(PUBLIC_URL).unwrap();
        let (status, body) = post_json(test_state().await, path, json!({}), None).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field} ({path}) must route to its handler"
        );
        assert_eq!(body["error"], "invalid_request", "{field} handler ran");
    }

    // `events_endpoint` (the SET receiver) is advertised ahead of its implementation, so it is
    // deliberately NOT round-tripped here — no handler serves it yet.
    assert_eq!(
        meta["agent_auth"]["events_endpoint"],
        format!("{PUBLIC_URL}/agent/event/notify")
    );
}

// ── anonymous journey: register → poll → initiate → confirm → poll → exchange ──

/// The full ownerless-agent ceremony end to end: an anonymous registration yields a `claim_token`
/// that polls `authorization_pending`, the ceremony is confirmed by an account owner, and the same
/// `claim_token` then collects a usable Bearer token whose assertion re-exchanges via jwt-bearer.
#[tokio::test]
async fn anonymous_full_ceremony_polls_pending_then_collects_token() {
    let state = state_with(AgentAuthConfig {
        anonymous_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:anonjourney1111111";
    insert_account(&state.db, owner, "owner@example.com").await;

    // 1. Register anonymously.
    let (status, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "anonymous" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let claim_token = reg["claim_token"].as_str().unwrap().to_string();
    let registration_id = reg["registration_id"].as_str().unwrap().to_string();

    // 2. Poll before the owner has confirmed (and before a user_code even exists) → pending.
    let (pstatus, pbody) = poll_claim(state.clone(), &claim_token).await;
    assert_eq!(pstatus, StatusCode::BAD_REQUEST);
    assert_eq!(pbody["error"], "authorization_pending");

    // 3. The agent starts the ceremony to surface a user_code for the human.
    let (istatus, ibody) = post_json(
        state.clone(),
        "/agent/identity/claim",
        json!({ "claim_token": claim_token }),
        None,
    )
    .await;
    assert_eq!(istatus, StatusCode::OK);
    let user_code = ibody["claim_attempt"]["user_code"]
        .as_str()
        .unwrap()
        .to_string();

    // 4. The owner confirms with their full-access token → the identity binds to them.
    let (cstatus, cbody) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(cstatus, StatusCode::OK);
    assert_eq!(cbody["status"], "claimed");
    assert_eq!(cbody["did"], owner);

    // 5. Poll again (simulating the advertised interval elapsing) → the token is issued.
    reset_poll_throttle(&state);
    let (tstatus, tbody) = poll_claim(state.clone(), &claim_token).await;
    assert_eq!(
        tstatus,
        StatusCode::OK,
        "claimed ceremony must yield a token"
    );
    assert_eq!(tbody["token_type"], "Bearer");
    assert_eq!(
        tbody["access_token"].as_str().unwrap().split('.').count(),
        3
    );
    // The granted scope is the operator's conservative default profile.
    let scope = tbody["scope"].as_str().unwrap();
    assert!(scope.contains("atproto"));
    assert!(scope.contains("blob:*/*"));

    // 6. The assertion returned alongside the token re-exchanges via jwt-bearer once the access
    //    token expires — proving the polled credential is a durable, exchangeable identity.
    let polled_assertion = tbody["identity_assertion"].as_str().unwrap().to_string();
    let (xstatus, xbody) = exchange_assertion(state.clone(), &polled_assertion).await;
    assert_eq!(xstatus, StatusCode::OK);
    assert_eq!(xbody["token_type"], "Bearer");

    // The persisted identity is claimed and bound to the owner.
    let row: (Option<String>, String) =
        sqlx::query_as("SELECT did, status FROM agent_identities WHERE id = ?")
            .bind(&registration_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(row.0.as_deref(), Some(owner));
    assert_eq!(row.1, "claimed");
}

// ── service_auth journey: register → confirm → exchange → revoke → re-exchange ─

/// A service_auth registration is confirmed by its owner, its assertion exchanges for a token, then
/// revoking the identity blocks any further exchange of the same assertion. `/oauth/revoke` only
/// revokes stateful OAuth refresh tokens — there is no route to revoke an agent identity yet (that
/// belongs to the later wallet agent-consent surface) — so the revoke leg flips the status
/// directly, exercising the token endpoint's terminal-refusal path end to end.
#[tokio::test]
async fn service_auth_journey_then_revoke_blocks_reexchange() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:svcjourney1111111";
    insert_account(&state.db, owner, "svc@example.com").await;

    // Register + confirm.
    let (_s, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "service_auth", "login_hint": "svc@example.com" }),
        None,
    )
    .await;
    let registration_id = reg["registration_id"].as_str().unwrap().to_string();
    let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();

    let (cstatus, _c) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(cstatus, StatusCode::OK);

    // The post-claim assertion the confirm stored is exchangeable.
    let assertion: String =
        sqlx::query_scalar("SELECT identity_assertion FROM agent_identities WHERE id = ?")
            .bind(&registration_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    let (x1, x1body) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(x1, StatusCode::OK, "confirmed identity must exchange");
    assert_eq!(x1body["token_type"], "Bearer");

    // Revoke the identity, then the SAME assertion is refused.
    sqlx::query("UPDATE agent_identities SET status = 'revoked' WHERE id = ?")
        .bind(&registration_id)
        .execute(&state.db)
        .await
        .unwrap();
    let (x2, x2body) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(x2, StatusCode::BAD_REQUEST);
    // The token endpoint maps a revoked identity to `access_denied` (the auth.md checklist's
    // "invalid_grant on re-exchange" predates the split between "unclaimed" (invalid_grant) and
    // "revoked" (access_denied); the shipped code distinguishes the two).
    assert_eq!(x2body["error"], "access_denied");
}

// ── identity_assertion journey: interaction → confirm → re-register → exchange ─

/// The trusted-issuer path end to end: a first-seen ID-JAG whose email matches a local account
/// requires interaction; after the owner confirms, re-presenting the same ID-JAG mints a
/// service-signed assertion that exchanges for a token.
#[tokio::test]
async fn identity_assertion_journey_interaction_confirm_reregister_exchange() {
    let (priv_pem, pub_pem) = es256_keys();
    let state = state_with(AgentAuthConfig {
        trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:idjagjourney111111";
    insert_account(&state.db, owner, "agent@example.com").await;

    let now = Utc::now().timestamp();
    let jag = make_jag(
        &priv_pem,
        "https://trusted.example",
        "sub-journey",
        "agent@example.com",
        now,
        now + 600,
    );

    // 1. First presentation → interaction_required with a claim challenge.
    let (s1, b1) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "identity_assertion", "assertion": jag }),
        None,
    )
    .await;
    assert_eq!(s1, StatusCode::UNAUTHORIZED);
    assert_eq!(b1["error"], "interaction_required");
    let user_code = b1["claim"]["user_code"].as_str().unwrap().to_string();

    // 2. Owner confirms.
    let (s2, _b2) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // 3. Re-presenting the same ID-JAG now mints a service-signed assertion.
    let (s3, b3) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "identity_assertion", "assertion": jag }),
        None,
    )
    .await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(b3["registration_type"], "identity_assertion");
    let minted = b3["identity_assertion"].as_str().unwrap().to_string();
    assert_eq!(minted.split('.').count(), 3);

    // 4. The minted assertion exchanges for a Bearer token bound to the owner.
    let (s4, b4) = exchange_assertion(state.clone(), &minted).await;
    assert_eq!(s4, StatusCode::OK);
    assert_eq!(b4["token_type"], "Bearer");
    assert_eq!(b4["access_token"].as_str().unwrap().split('.').count(), 3);
}

// ── discrete gaps ──────────────────────────────────────────────────────────────

/// A genuinely expired ID-JAG (`exp` in the past) fails signature/claim verification with
/// `invalid_grant` — distinct from a stale `auth_time` (which maps to `login_required`, covered in
/// `agent_identity.rs`). The per-route `make_id_jag` helper can't forge this (it hardcodes a future
/// `exp`), so it was previously untested.
#[tokio::test]
async fn expired_id_jag_is_invalid_grant() {
    let (priv_pem, pub_pem) = es256_keys();
    let state = state_with(AgentAuthConfig {
        trusted_issuers: vec![trusted("https://trusted.example", pub_pem)],
        ..AgentAuthConfig::default()
    })
    .await;
    insert_account(&state.db, "did:plc:expiredjag1111111", "agent@example.com").await;

    let now = Utc::now().timestamp();
    // Expired well beyond jsonwebtoken's default 60s leeway.
    let jag = make_jag(
        &priv_pem,
        "https://trusted.example",
        "sub-expired",
        "agent@example.com",
        now - 7200,
        now - 3600,
    );
    let (status, body) = post_json(
        state,
        "/agent/identity",
        json!({ "type": "identity_assertion", "assertion": jag }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_grant");
}

/// The claim-confirm endpoint rejects an expired `user_code` with `claim_expired`. Expiry was
/// covered on the initiate side and at the polling grant, but not on `/claim/confirm`.
#[tokio::test]
async fn confirm_with_expired_user_code_is_claim_expired() {
    let state = state_with(AgentAuthConfig {
        anonymous_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:expcode1111111111";
    insert_account(&state.db, owner, "owner@example.com").await;

    // Register anonymously and open a ceremony through the real endpoints...
    let (_claim_token, user_code) = register_and_initiate_anonymous_claim(&state).await;

    // ...then age the user_code past its expiry.
    sqlx::query(
        "UPDATE agent_claim_attempts SET user_code_expires_at = datetime('now', '-1 minute') \
         WHERE user_code = ?",
    )
    .bind(&user_code)
    .execute(&state.db)
    .await
    .unwrap();

    let (status, body) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "claim_expired");

    // Nothing was claimed.
    let claimed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_identities WHERE status = 'claimed'")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(claimed, 0);
}

/// A minted service assertion carries exactly the operator's configured granted scopes, and the
/// token issued for it echoes them — the discovery `scopes_supported` list and the actually-granted
/// agent scope set are deliberately different surfaces, so pin the granted set here.
#[tokio::test]
async fn granted_scopes_flow_from_config_through_to_the_issued_token() {
    let state = state_with(AgentAuthConfig {
        anonymous_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:scopeflow11111111";
    insert_account(&state.db, owner, "owner@example.com").await;

    let (claim_token, user_code) = register_and_initiate_anonymous_claim(&state).await;
    post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;

    reset_poll_throttle(&state);
    let (tstatus, tbody) = poll_claim(state.clone(), &claim_token).await;
    assert_eq!(tstatus, StatusCode::OK);

    // The token's scope claim is the config profile, space-joined (order-independent check).
    let token_scopes: Vec<&str> = tbody["scope"].as_str().unwrap().split(' ').collect();
    for expected in config_scopes() {
        assert!(
            token_scopes.contains(&expected.as_str()),
            "issued token must carry configured scope {expected:?}"
        );
    }
    // The conservative default never grants account/identity lifecycle control.
    assert!(!token_scopes.iter().any(|s| s.starts_with("account:")));
    assert!(!token_scopes.iter().any(|s| s.starts_with("identity:")));
}

// ── /v1/agents management API (the wallet's "My agents" surface) ───────────────

/// GET with a Bearer token — the management API is authenticated, unlike the discovery GETs.
async fn get_json_authed(state: AppState, uri: &str, token: &str) -> (StatusCode, Value) {
    send(
        state,
        Request::builder()
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// Register a `service_auth` agent for `email` and confirm it as `owner`, returning the
/// registration id.
async fn register_and_confirm_service_auth(state: &AppState, owner: &str, email: &str) -> String {
    let (_s, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "service_auth", "login_hint": email }),
        None,
    )
    .await;
    let registration_id = reg["registration_id"].as_str().unwrap().to_string();
    let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();
    let (cstatus, _c) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(state, owner)),
    )
    .await;
    assert_eq!(cstatus, StatusCode::OK, "confirm must succeed in setup");
    registration_id
}

/// The list is scoped to the authenticated DID, and a foreign registration id is a uniform 404
/// for both revoke and audit (no cross-account existence oracle).
#[tokio::test]
async fn management_api_isolates_accounts() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner_a = "did:plc:mgmtownera1111111";
    let owner_b = "did:plc:mgmtownerb1111111";
    insert_account(&state.db, owner_a, "mgmt-a@example.com").await;
    insert_account(&state.db, owner_b, "mgmt-b@example.com").await;
    let registration_id =
        register_and_confirm_service_auth(&state, owner_a, "mgmt-a@example.com").await;

    // Owner A sees exactly their agent, with the configured scopes and claimed status.
    let (astatus, abody) =
        get_json_authed(state.clone(), "/v1/agents", &owner_token(&state, owner_a)).await;
    assert_eq!(astatus, StatusCode::OK);
    let agents = abody["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["registrationId"], registration_id.as_str());
    assert_eq!(agents[0]["registrationType"], "service_auth");
    assert_eq!(agents[0]["status"], "claimed");
    assert!(!agents[0]["scopes"].as_array().unwrap().is_empty());
    assert!(
        agents[0].get("lastUsedAt").is_none(),
        "an agent that never exchanged a token has no lastUsedAt"
    );

    // Owner B sees an empty list and cannot revoke or audit A's registration.
    let (bstatus, bbody) =
        get_json_authed(state.clone(), "/v1/agents", &owner_token(&state, owner_b)).await;
    assert_eq!(bstatus, StatusCode::OK);
    assert_eq!(bbody["agents"].as_array().unwrap().len(), 0);

    let (rstatus, _r) = post_json(
        state.clone(),
        &format!("/v1/agents/{registration_id}/revoke"),
        json!({}),
        Some(&owner_token(&state, owner_b)),
    )
    .await;
    assert_eq!(rstatus, StatusCode::NOT_FOUND, "foreign revoke must 404");
    let (austatus, _au) = get_json_authed(
        state.clone(),
        &format!("/v1/agents/{registration_id}/audit"),
        &owner_token(&state, owner_b),
    )
    .await;
    assert_eq!(austatus, StatusCode::NOT_FOUND, "foreign audit must 404");
}

/// Revocation through the API immediately blocks the next token exchange, is idempotent, and
/// lands exactly one `revoked` audit event.
#[tokio::test]
async fn revoke_via_api_blocks_reexchange_and_audits_once() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:mgmtrevoke111111";
    insert_account(&state.db, owner, "mgmt-revoke@example.com").await;
    let registration_id =
        register_and_confirm_service_auth(&state, owner, "mgmt-revoke@example.com").await;

    let assertion: String =
        sqlx::query_scalar("SELECT identity_assertion FROM agent_identities WHERE id = ?")
            .bind(&registration_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    let (x1, _b1) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(x1, StatusCode::OK, "pre-revocation exchange must succeed");

    for round in 0..2 {
        let (rstatus, rbody) = post_json(
            state.clone(),
            &format!("/v1/agents/{registration_id}/revoke"),
            json!({}),
            Some(&owner_token(&state, owner)),
        )
        .await;
        assert_eq!(rstatus, StatusCode::OK, "revoke round {round} must be 200");
        assert_eq!(rbody["status"], "revoked");
    }

    let (x2, x2body) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(x2, StatusCode::BAD_REQUEST);
    assert_eq!(x2body["error"], "access_denied");

    // The list reflects revocation immediately, the trail shows a token exchange happened, and
    // the repeat revoke did not duplicate the `revoked` event.
    let (_ls, lbody) =
        get_json_authed(state.clone(), "/v1/agents", &owner_token(&state, owner)).await;
    assert_eq!(lbody["agents"][0]["status"], "revoked");
    assert!(lbody["agents"][0].get("lastUsedAt").is_some());

    let (_as, abody) = get_json_authed(
        state.clone(),
        &format!("/v1/agents/{registration_id}/audit"),
        &owner_token(&state, owner),
    )
    .await;
    let events = abody["events"].as_array().unwrap();
    let revoked = events
        .iter()
        .filter(|e| e["eventType"] == "revoked")
        .count();
    assert_eq!(revoked, 1, "idempotent revoke must audit exactly once");
}

/// register → claim initiated → confirmed → token exchanged → revoked appear in order,
/// attributed to this registration, and no event carries token material or the user code.
#[tokio::test]
async fn lifecycle_audit_trail_is_ordered_and_leak_free() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:mgmttrail1111111";
    insert_account(&state.db, owner, "mgmt-trail@example.com").await;

    let (_s, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "service_auth", "login_hint": "mgmt-trail@example.com" }),
        None,
    )
    .await;
    let registration_id = reg["registration_id"].as_str().unwrap().to_string();
    let claim_token = reg["claim_token"].as_str().unwrap().to_string();
    let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();
    let (cstatus, _c) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(cstatus, StatusCode::OK);
    let assertion: String =
        sqlx::query_scalar("SELECT identity_assertion FROM agent_identities WHERE id = ?")
            .bind(&registration_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    let (xstatus, _x) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(xstatus, StatusCode::OK);
    let (rstatus, _r) = post_json(
        state.clone(),
        &format!("/v1/agents/{registration_id}/revoke"),
        json!({}),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(rstatus, StatusCode::OK);

    let (astatus, abody) = get_json_authed(
        state.clone(),
        &format!("/v1/agents/{registration_id}/audit"),
        &owner_token(&state, owner),
    )
    .await;
    assert_eq!(astatus, StatusCode::OK);
    let events = abody["events"].as_array().unwrap();
    let types: Vec<&str> = events
        .iter()
        .map(|e| e["eventType"].as_str().unwrap())
        .collect();
    // Newest first.
    assert_eq!(
        types,
        vec![
            "revoked",
            "token_exchanged",
            "claim_confirmed",
            "claim_initiated",
            "registered"
        ]
    );

    // No secrets in the trail — not the user code, the claim token, or the assertion JWT.
    let rendered = abody.to_string();
    assert!(
        !rendered.contains(&user_code),
        "audit trail must not contain the user code"
    );
    assert!(
        !rendered.contains(&claim_token),
        "audit trail must not contain the claim token"
    );
    assert!(
        !rendered.contains(&assertion),
        "audit trail must not contain the identity assertion"
    );
}

/// An agent-derived token must not drive the management API — not even to read its own entry.
#[tokio::test]
async fn agent_tokens_cannot_use_management_api() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:mgmtagentself1111";
    insert_account(&state.db, owner, "mgmt-self@example.com").await;
    let registration_id =
        register_and_confirm_service_auth(&state, owner, "mgmt-self@example.com").await;
    let agent_token = crate::routes::test_utils::agent_jwt(
        &state.jwt_secret,
        owner,
        "com.atproto.access",
        &registration_id,
    );

    let (lstatus, _l) = get_json_authed(state.clone(), "/v1/agents", &agent_token).await;
    assert_eq!(lstatus, StatusCode::FORBIDDEN);
    let (rstatus, _r) = post_json(
        state.clone(),
        &format!("/v1/agents/{registration_id}/revoke"),
        json!({}),
        Some(&agent_token),
    )
    .await;
    assert_eq!(
        rstatus,
        StatusCode::FORBIDDEN,
        "an agent must not revoke itself"
    );
}

/// The wallet can preview exactly what confirming a code grants — type + scopes — before the
/// biometric gate; a foreign owner gets a uniform 404; the previewed scopes equal what
/// confirmation then stores.
#[tokio::test]
async fn claim_preview_shows_grant_before_confirm_and_isolates_owners() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:previewowner11111";
    let other = "did:plc:previewother11111";
    insert_account(&state.db, owner, "preview@example.com").await;
    insert_account(&state.db, other, "preview-other@example.com").await;

    let (_s, reg) = post_json(
        state.clone(),
        "/agent/identity",
        json!({ "type": "service_auth", "login_hint": "preview@example.com" }),
        None,
    )
    .await;
    let registration_id = reg["registration_id"].as_str().unwrap().to_string();
    let user_code = reg["claim"]["user_code"].as_str().unwrap().to_string();

    // The bound owner sees the grant; scopes match the operator profile confirmation will store.
    let (pstatus, pbody) = post_json(
        state.clone(),
        "/v1/agents/claim-preview",
        json!({ "userCode": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(pstatus, StatusCode::OK);
    assert_eq!(pbody["registrationId"], registration_id.as_str());
    assert_eq!(pbody["registrationType"], "service_auth");
    let previewed: Vec<&str> = pbody["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    for expected in config_scopes() {
        assert!(previewed.contains(&expected.as_str()));
    }

    // A different account cannot preview it, and a garbage code is the same uniform 404.
    let (fstatus, _f) = post_json(
        state.clone(),
        "/v1/agents/claim-preview",
        json!({ "userCode": user_code }),
        Some(&owner_token(&state, other)),
    )
    .await;
    assert_eq!(fstatus, StatusCode::NOT_FOUND);
    let (gstatus, _g) = post_json(
        state.clone(),
        "/v1/agents/claim-preview",
        json!({ "userCode": "000000" }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(gstatus, StatusCode::NOT_FOUND);

    // Preview is read-only: the ceremony still confirms afterwards.
    let (cstatus, _c) = post_json(
        state.clone(),
        "/agent/identity/claim/confirm",
        json!({ "user_code": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(cstatus, StatusCode::OK);

    // And a confirmed (no longer pending) code no longer previews.
    let (dstatus, _d) = post_json(
        state.clone(),
        "/v1/agents/claim-preview",
        json!({ "userCode": user_code }),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(dstatus, StatusCode::NOT_FOUND);
}

/// The audit endpoint's cursor pages the trail without skipping or duplicating: a full lifecycle
/// (5 events) read at `limit=2` yields three pages whose concatenation equals the single-page
/// read, and the short final page carries no cursor.
#[tokio::test]
async fn audit_cursor_pages_without_gaps_or_duplicates() {
    let state = state_with(AgentAuthConfig {
        service_auth_enabled: true,
        ..AgentAuthConfig::default()
    })
    .await;
    let owner = "did:plc:mgmtpaging111111";
    insert_account(&state.db, owner, "mgmt-paging@example.com").await;
    let registration_id =
        register_and_confirm_service_auth(&state, owner, "mgmt-paging@example.com").await;
    let assertion: String =
        sqlx::query_scalar("SELECT identity_assertion FROM agent_identities WHERE id = ?")
            .bind(&registration_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    let (xstatus, _x) = exchange_assertion(state.clone(), &assertion).await;
    assert_eq!(xstatus, StatusCode::OK);
    let (rstatus, _r) = post_json(
        state.clone(),
        &format!("/v1/agents/{registration_id}/revoke"),
        json!({}),
        Some(&owner_token(&state, owner)),
    )
    .await;
    assert_eq!(rstatus, StatusCode::OK);

    let (_fs, full) = get_json_authed(
        state.clone(),
        &format!("/v1/agents/{registration_id}/audit"),
        &owner_token(&state, owner),
    )
    .await;
    let all_ids: Vec<String> = full["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(all_ids.len(), 5, "full lifecycle should have 5 events");

    let mut paged_ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            Some(c) => format!("/v1/agents/{registration_id}/audit?limit=2&cursor={c}"),
            None => format!("/v1/agents/{registration_id}/audit?limit=2"),
        };
        let (pstatus, page) =
            get_json_authed(state.clone(), &uri, &owner_token(&state, owner)).await;
        assert_eq!(pstatus, StatusCode::OK);
        let events = page["events"].as_array().unwrap();
        paged_ids.extend(events.iter().map(|e| e["id"].as_str().unwrap().to_string()));
        match page["cursor"].as_str() {
            Some(c) => {
                assert_eq!(events.len(), 2, "a page carrying a cursor must be full");
                cursor = Some(c.to_string());
            }
            None => break,
        }
    }
    assert_eq!(
        paged_ids, all_ids,
        "paged reads must reproduce the single-page read exactly — no gaps, no duplicates"
    );
}
