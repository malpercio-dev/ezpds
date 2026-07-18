// pattern: Imperative Shell
//
// The wallet-confirmed half of OAuth consent (Phase A of the wallet-confirmed-OAuth-consent design
// plan). Three public routes plus a wallet preview, all keyed off the single-use
// `pending_oauth_authorizations` request the consent page
// (`oauth_authorize::get_authorization`) created:
//
//   GET  /oauth/authorize/consent-request  — wallet preview: client/origin/scope for a user_code
//   GET  /oauth/authorize/status           — browser poll (slow_down-throttled), returns {status}
//   POST /oauth/authorize/approve          — device-key-signed approve/deny of a request
//   POST /oauth/authorize/complete         — browser exchanges an approved request for the code
//
// Approval is proven with a canonical device-key envelope in the `sovereign_session` mold
// (`crypto::encode_oauth_consent_envelope`), verified against the account's **authoritative** PLC
// `rotationKeys` — never the cached DID doc. The envelope binds `request_id`, `client_id`, the
// decision, and a hash of the granted scope set, so an approval cannot be replayed onto a different
// request, flipped from a denial, or widened. Replay of the same envelope onto its own request is
// stopped by the single-use guarded status transition (the request_id binding + single-use row
// together subsume a nonce store). This module never imports another route handler.

use std::time::{Duration, Instant};

use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::{ApiError, ErrorCode, SOVEREIGN_TIMESTAMP_WINDOW_SECS};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::token::generate_token;
use crate::db::oauth::store_authorization_code;
use crate::db::pending_oauth_authorizations::{
    approve_pending_authorization, complete_pending_authorization, deny_pending_authorization,
    get_pending_by_request_id, get_pending_by_user_code, insert_oauth_consent_audit_event,
    OAuthConsentAuditEventType,
};
use crate::identity::plc::fetch_current_plc_state;
use crate::routes::oauth_templates::{build_code_redirect, error_page};

const SIGNATURE_BYTES: usize = 64;
const NONCE_BYTES: usize = 32;
/// Minimum spacing between accepted status polls for one request; a faster poll gets the
/// `slow_down` 429 the page's JS backs off on (the `claim_polling` discipline).
const STATUS_POLL_MIN_INTERVAL: Duration = Duration::from_secs(2);

// ── Shared helpers ──────────────────────────────────────────────────────────────

fn decode_canonical_base64url(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (decoded.len() == expected_len && URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

fn is_plc_did(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("did:plc:") else {
        return false;
    };
    suffix.len() == 24
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}

/// A request that is no longer approvable — absent, terminal, or lapsed — maps to one uniform
/// response so the caller can't probe request state beyond "pending or not".
fn not_approvable() -> ApiError {
    ApiError::new(
        ErrorCode::NotFound,
        "authorization request not found or expired",
    )
}

/// Signature / PLC / binding failures share one message so the surface reveals nothing about which
/// check failed.
fn approval_rejected() -> ApiError {
    ApiError::new(
        ErrorCode::AuthenticationRequired,
        "consent approval rejected",
    )
}

async fn active_local_account_exists(pool: &sqlx::SqlitePool, did: &str) -> Result<bool, ApiError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ? \
         AND deactivated_at IS NULL AND suspended_at IS NULL AND taken_down_at IS NULL)",
    )
    .bind(did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error checking local account for consent approval");
        ApiError::new(ErrorCode::InternalError, "failed to verify account")
    })
}

/// Reduce the wallet's requested granted-scope string to the tokens actually on offer: `atproto` is
/// always granted (never optional), and every other token is kept only if it was part of the
/// request's snapshotted `requested_scope`. This mirrors `oauth_authorize`'s reduction filter, so a
/// tampered/injected token that was never requested cannot add scope — only narrow it.
fn reduce_granted_scope(requested_scope: &str, wallet_granted: &str) -> String {
    let wallet: Vec<&str> = wallet_granted.split_whitespace().collect();
    requested_scope
        .split_whitespace()
        .filter(|t| *t == "atproto" || wallet.contains(t))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Preview ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentRequestQuery {
    /// Typed path: the human-entered `user_code`. Exactly one of `user_code` / `request_id`.
    user_code: Option<String>,
    /// Handoff path: the `request_id` carried by the "Open in Obsign" link.
    request_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRequestPreview {
    request_id: String,
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    origin: Option<String>,
    ip: Option<String>,
    requested_scope: Vec<String>,
    login_hint: Option<String>,
}

/// `GET /oauth/authorize/consent-request` — the wallet's preview of a pending request, resolved by
/// `user_code` (typed) or `request_id` (handoff). Returns 404 for anything not currently pending so
/// a guessed code reveals nothing.
pub async fn get_consent_request(
    State(state): State<AppState>,
    Query(query): Query<ConsentRequestQuery>,
) -> Result<Json<ConsentRequestPreview>, ApiError> {
    let pending = match (&query.user_code, &query.request_id) {
        (Some(code), None) => get_pending_by_user_code(&state.db, code).await?,
        (None, Some(request_id)) => get_pending_by_request_id(&state.db, request_id).await?,
        _ => {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "exactly one of userCode or requestId is required",
            ))
        }
    };
    let pending = pending.filter(|p| p.status == "pending" && !p.is_expired);
    let Some(p) = pending else {
        return Err(not_approvable());
    };
    Ok(Json(ConsentRequestPreview {
        request_id: p.request_id,
        client_id: p.client_id,
        client_name: p.client_name,
        redirect_uri: p.redirect_uri,
        origin: p.origin,
        ip: p.ip,
        requested_scope: p
            .requested_scope
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        login_hint: p.login_hint,
    }))
}

// ── Status poll ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StatusQuery {
    request_id: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
}

/// `GET /oauth/authorize/status?request_id=…` — the consent page's poll. Throttled per request with
/// the `slow_down` discipline (429 when polled faster than `STATUS_POLL_MIN_INTERVAL`), and reports
/// a derived `expired` for a lapsed or reclaimed request so the page stops.
pub async fn get_authorization_status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> Response {
    // slow_down throttle, reusing the shared poll tracker with a namespaced key so it can't collide
    // with agent claim-poll marks. A poll faster than the interval gets a 429 the page backs off on.
    {
        let key = format!("consent:{}", query.request_id);
        let mut tracker = state.poll_tracker.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = tracker.get(&key) {
            if last.elapsed() < STATUS_POLL_MIN_INTERVAL {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(StatusResponse {
                        status: "slow_down",
                    }),
                )
                    .into_response();
            }
        }
        tracker.insert(key, Instant::now());
    }

    let pending = match get_pending_by_request_id(&state.db, &query.request_id).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let status = match pending {
        // Absent (never created or reclaimed) reads as expired so the page stops polling.
        None => "expired",
        Some(p) if p.status == "pending" && p.is_expired => "expired",
        Some(p) => match p.status.as_str() {
            "pending" => "pending",
            "approved" => "approved",
            "denied" => "denied",
            "completed" => "completed",
            _ => "expired",
        },
    };
    Json(StatusResponse { status }).into_response()
}

// ── Approve / deny ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalRequest {
    did: String,
    signing_key: String,
    request_id: String,
    /// `"approve"` or `"deny"` — bound into the signed envelope so a captured denial cannot be
    /// replayed as an approval.
    decision: String,
    /// Space-joined granted-scope string the wallet chose (empty for a denial). Signed verbatim.
    #[serde(default)]
    granted_scope: String,
    timestamp: i64,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResponse {
    status: &'static str,
    did: String,
}

/// `POST /oauth/authorize/approve` — verify a device-key-signed approve/deny envelope against the
/// account's authoritative PLC rotation set and terminate the request accordingly.
pub async fn post_authorization_approve(
    State(state): State<AppState>,
    Json(request): Json<ApprovalRequest>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    // 1. Cheap syntactic gates before any DB or network work.
    let signature = decode_canonical_base64url(&request.signature, SIGNATURE_BYTES)
        .and_then(|bytes| <[u8; SIGNATURE_BYTES]>::try_from(bytes).ok())
        .ok_or_else(approval_rejected)?;
    if decode_canonical_base64url(&request.nonce, NONCE_BYTES).is_none() {
        return Err(approval_rejected());
    }
    if !is_plc_did(&request.did) {
        return Err(approval_rejected());
    }
    let approve = match request.decision.as_str() {
        crypto::OAUTH_CONSENT_DECISION_APPROVE => true,
        crypto::OAUTH_CONSENT_DECISION_DENY => false,
        _ => return Err(approval_rejected()),
    };
    let now = crate::time::unix_now_secs();
    if now.abs_diff(request.timestamp) > SOVEREIGN_TIMESTAMP_WINDOW_SECS as u64 {
        return Err(approval_rejected());
    }

    // 2. Load the pending request; it must be currently approvable.
    let pending = get_pending_by_request_id(&state.db, &request.request_id)
        .await?
        .filter(|p| p.status == "pending" && !p.is_expired)
        .ok_or_else(not_approvable)?;

    // 3. Account binding: a pre-bound login_hint must match the approving DID; otherwise the wallet
    //    binds its own DID here (like the agent claim confirm). Either way the DID must be a local
    //    active account so the authorization code can be issued against it.
    if let Some(hint) = pending.login_hint.as_deref() {
        if hint != request.did {
            return Err(approval_rejected());
        }
    }
    if !active_local_account_exists(&state.db, &request.did).await? {
        return Err(approval_rejected());
    }

    // 4. The granted scope the wallet signed over is the verbatim `granted_scope` string (empty for
    //    a denial); the stored set is that, reduced to what was actually requested.
    let signed_scope = if approve {
        request.granted_scope.as_str()
    } else {
        ""
    };
    let stored_scope = reduce_granted_scope(&pending.requested_scope, signed_scope);

    // 5. Verify the envelope signature, then confirm the signing key is in the account's
    //    authoritative current PLC rotation set (never the cached DID doc). Signature first, so an
    //    invalid signature never triggers the outbound PLC fetch.
    let server_did = state.config.resolve_server_did();
    let envelope = crypto::encode_oauth_consent_envelope(
        &server_did,
        &request.did,
        &request.signing_key,
        &request.request_id,
        &pending.client_id,
        &request.decision,
        signed_scope,
        request.timestamp,
        &request.nonce,
    );
    let signing_key = crypto::DidKeyUri(request.signing_key.clone());
    crypto::verify_did_key_signature(&signing_key, &envelope, &signature)
        .map_err(|_| approval_rejected())?;

    let plc = fetch_current_plc_state(
        &state.http_client,
        &state.config.plc_directory_url,
        &request.did,
    )
    .await?;
    if !plc.rotation_keys.iter().any(|k| k == &request.signing_key) {
        return Err(approval_rejected());
    }

    // 6. Terminate the request and audit it in one transaction. The guarded UPDATE is the single-use
    //    point: a replayed envelope lands on an already-terminal row and wins nothing.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin consent approval transaction");
        ApiError::new(ErrorCode::InternalError, "failed to record decision")
    })?;
    let won = if approve {
        approve_pending_authorization(&mut *tx, &request.request_id, &request.did, &stored_scope)
            .await?
    } else {
        deny_pending_authorization(&mut *tx, &request.request_id, &request.did).await?
    };
    if !won {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "authorization request already resolved",
        ));
    }
    let (event, detail) = if approve {
        (
            OAuthConsentAuditEventType::Approved,
            serde_json::json!({ "granted_scope": stored_scope }).to_string(),
        )
    } else {
        (
            OAuthConsentAuditEventType::Denied,
            serde_json::json!({}).to_string(),
        )
    };
    insert_oauth_consent_audit_event(
        &mut *tx,
        &uuid::Uuid::new_v4().to_string(),
        &request.request_id,
        Some(&request.did),
        &pending.client_id,
        event,
        Some(&detail),
    )
    .await?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit consent approval transaction");
        ApiError::new(ErrorCode::InternalError, "failed to record decision")
    })?;

    tracing::info!(
        account_did = %request.did,
        client_id = %pending.client_id,
        decision = %request.decision,
        plc_head = %plc.cid,
        "wallet-confirmed OAuth consent decision recorded"
    );
    Ok(Json(ApprovalResponse {
        status: if approve { "approved" } else { "denied" },
        did: request.did,
    }))
}

// ── Complete ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CompleteForm {
    request_id: String,
}

/// `POST /oauth/authorize/complete` — the browser exchanges an approved request for an
/// authorization code and is redirected back to the client. The guarded `approved → completed`
/// transition mints at most one code; a no-JS "I've approved — continue" button and the page's JS
/// poller both post here.
pub async fn post_authorization_complete(
    State(state): State<AppState>,
    Form(form): Form<CompleteForm>,
) -> Response {
    let issuer = state.config.public_url.trim_end_matches('/').to_string();

    let completed = match complete_pending_authorization(&state.db, &form.request_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            // Not in `approved` state: still pending, denied, expired, or already completed.
            return error_page(
                "Not Ready",
                "This authorization request has not been approved yet, or has already been used. \
                 Return to the app and start again if needed.",
            )
            .into_response();
        }
        Err(e) => return e.into_response(),
    };

    let token = generate_token();
    if let Err(e) = store_authorization_code(
        &state.db,
        &token.hash,
        &completed.client_id,
        &completed.account_did,
        &completed.code_challenge,
        &completed.code_challenge_method,
        &completed.redirect_uri,
        &completed.granted_scope,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store authorization code for wallet consent");
        return error_page(
            "Server Error",
            "Failed to issue the authorization code. Please try again.",
        )
        .into_response();
    }

    // Audit the completion (best-effort — the code is already issued and the redirect must proceed).
    if let Err(e) = insert_oauth_consent_audit_event(
        &state.db,
        &uuid::Uuid::new_v4().to_string(),
        &form.request_id,
        Some(&completed.account_did),
        &completed.client_id,
        OAuthConsentAuditEventType::Completed,
        Some(&serde_json::json!({ "granted_scope": completed.granted_scope }).to_string()),
    )
    .await
    {
        tracing::warn!(error = %e, "failed to audit wallet-consent completion");
    }

    build_code_redirect(
        &completed.redirect_uri,
        &token.plaintext,
        &completed.state,
        &issuer,
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use p256::ecdsa::{signature::Signer as _, Signature as P256Signature, SigningKey};
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method as wm_method, path as wm_path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, test_state_with_plc_url, AppState};
    use crate::db::oauth::register_oauth_client;
    use crate::db::pending_oauth_authorizations::NewPendingOAuthAuthorization;

    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";
    const CLIENT_METADATA: &str =
        r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"Test App"}"#;
    const REDIRECT_URI: &str = "https://app.example.com/callback";
    const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const REQUESTED_SCOPE: &str = "atproto transition:generic";

    struct TestKey {
        did: String,
        signing_key: SigningKey,
    }

    fn p256_key() -> TestKey {
        let generated = crypto::generate_p256_keypair().unwrap();
        let signing_key =
            SigningKey::from_bytes(generated.private_key_bytes.as_slice().into()).unwrap();
        TestKey {
            did: generated.key_id.0,
            signing_key,
        }
    }

    fn sign(key: &TestKey, message: &[u8]) -> String {
        let sig: P256Signature = key.signing_key.sign(message);
        URL_SAFE_NO_PAD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
    }

    async fn setup(plc: &MockServer) -> AppState {
        let state = test_state_with_plc_url(plc.uri()).await;
        register_oauth_client(&state.db, CLIENT_ID, CLIENT_METADATA)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'owner@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO handles (handle, did, created_at) VALUES ('owner.example.com', ?, datetime('now'))",
        )
        .bind(DID)
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    async fn seed_pending(state: &AppState, request_id: &str, login_hint: Option<&str>) {
        let new = NewPendingOAuthAuthorization {
            request_id,
            user_code: "TEST-CODE",
            client_id: CLIENT_ID,
            client_name: Some("Test App"),
            redirect_uri: REDIRECT_URI,
            code_challenge: "e3b0c44298fc1c149afb",
            code_challenge_method: "S256",
            state: "teststate",
            response_type: "code",
            requested_scope: REQUESTED_SCOPE,
            login_hint,
            origin: Some("https://app.example.com"),
            ip: Some("203.0.113.5"),
            user_agent: Some("test/1.0"),
            ttl_secs: 300,
        };
        crate::db::pending_oauth_authorizations::insert_pending_authorization(&state.db, &new)
            .await
            .unwrap();
    }

    async fn mount_audit_log(plc: &MockServer, rotation_keys: &[&str]) {
        let log = json!([{
            "did": DID,
            "cid": "bafy-head",
            "createdAt": "2026-07-18T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": rotation_keys,
                "verificationMethods": {},
                "alsoKnownAs": ["at://owner.example.com"],
                "services": {}
            }
        }]);
        Mock::given(wm_method("GET"))
            .and(wm_path(format!("/{DID}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(plc)
            .await;
    }

    fn now() -> i64 {
        crate::time::unix_now_secs()
    }

    fn approval_body(
        state: &AppState,
        key: &TestKey,
        request_id: &str,
        decision: &str,
        granted_scope: &str,
        timestamp: i64,
        nonce_fill: u8,
    ) -> Value {
        let nonce = URL_SAFE_NO_PAD.encode([nonce_fill; NONCE_BYTES]);
        let envelope = crypto::encode_oauth_consent_envelope(
            &state.config.resolve_server_did(),
            DID,
            &key.did,
            request_id,
            CLIENT_ID,
            decision,
            granted_scope,
            timestamp,
            &nonce,
        );
        json!({
            "did": DID,
            "signingKey": key.did,
            "requestId": request_id,
            "decision": decision,
            "grantedScope": granted_scope,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": sign(key, &envelope),
        })
    }

    async fn post_json(state: AppState, uri: &str, body: Value) -> axum::response::Response {
        app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn get(state: AppState, uri: &str) -> axum::response::Response {
        app(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // AC: a NULL-password account completes a full authorization-code login using only the wallet.
    #[tokio::test]
    async fn passwordless_account_completes_full_authorization_via_wallet() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_flow";
        seed_pending(&state, request_id, None).await;

        // Preview reflects the request.
        let preview = body_json(
            get(
                state.clone(),
                "/oauth/authorize/consent-request?user_code=TEST-CODE",
            )
            .await,
        )
        .await;
        assert_eq!(preview["clientName"], "Test App");
        assert_eq!(preview["requestId"], request_id);

        // Approve with a signed envelope granting the full requested scope.
        let resp = post_json(
            state.clone(),
            "/oauth/authorize/approve",
            approval_body(
                &state,
                &key,
                request_id,
                "approve",
                REQUESTED_SCOPE,
                now(),
                1,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["status"], "approved");

        // Status reflects approval.
        let status = body_json(
            get(
                state.clone(),
                &format!("/oauth/authorize/status?request_id={request_id}"),
            )
            .await,
        )
        .await;
        assert_eq!(status["status"], "approved");

        // Complete issues an authorization code and redirects back to the client.
        let complete = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/authorize/complete")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("request_id={request_id}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::SEE_OTHER);
        let location = complete
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with(REDIRECT_URI), "{location}");
        assert!(location.contains("code="));
        assert!(location.contains("state=teststate"));

        // An authorization code row now exists for this account.
        let codes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_authorization_codes WHERE did = ? AND client_id = ?",
        )
        .bind(DID)
        .bind(CLIENT_ID)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(codes, 1);
    }

    // AC: an approval cannot be replayed onto its request once it has resolved (single-use).
    #[tokio::test]
    async fn replayed_approval_is_rejected() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_replay";
        seed_pending(&state, request_id, None).await;
        let body = approval_body(
            &state,
            &key,
            request_id,
            "approve",
            REQUESTED_SCOPE,
            now(),
            2,
        );

        let first = post_json(state.clone(), "/oauth/authorize/approve", body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let replay = post_json(state.clone(), "/oauth/authorize/approve", body).await;
        // Second attempt no longer finds a pending request.
        assert_ne!(replay.status(), StatusCode::OK);
    }

    // AC: the binding covers the granted scope hash — a body granting a wider set than was signed
    // fails signature verification, so an approval cannot be widened.
    #[tokio::test]
    async fn approval_cannot_be_widened_beyond_the_signed_scope() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_widen";
        seed_pending(&state, request_id, None).await;

        // Sign over the base scope, then tamper the submitted grantedScope to a wider set.
        let mut body = approval_body(&state, &key, request_id, "approve", "atproto", now(), 3);
        body["grantedScope"] = json!(REQUESTED_SCOPE);
        let resp = post_json(state.clone(), "/oauth/authorize/approve", body).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // AC: denial terminates the request and is recorded.
    #[tokio::test]
    async fn denial_terminates_and_audits_the_request() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_deny";
        seed_pending(&state, request_id, None).await;

        let resp = post_json(
            state.clone(),
            "/oauth/authorize/approve",
            approval_body(&state, &key, request_id, "deny", "", now(), 4),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["status"], "denied");

        let status = body_json(
            get(
                state.clone(),
                &format!("/oauth/authorize/status?request_id={request_id}"),
            )
            .await,
        )
        .await;
        assert_eq!(status["status"], "denied");

        let (denied, completed): (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT COUNT(*) FROM oauth_consent_audit_events WHERE request_id = ? AND event_type = 'denied'), \
               (SELECT COUNT(*) FROM oauth_authorization_codes WHERE did = ?)",
        )
        .bind(request_id)
        .bind(DID)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(denied, 1);
        assert_eq!(
            completed, 0,
            "a denial must not issue an authorization code"
        );
    }

    // AC: a signing key absent from the account's authoritative PLC rotation set is rejected.
    #[tokio::test]
    async fn signing_key_outside_rotation_set_is_rejected() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let signer = p256_key();
        let other = p256_key();
        // The authoritative rotation set contains a different key.
        mount_audit_log(&plc, &[&other.did]).await;
        let request_id = "poauth_rot";
        seed_pending(&state, request_id, None).await;

        let resp = post_json(
            state.clone(),
            "/oauth/authorize/approve",
            approval_body(
                &state,
                &signer,
                request_id,
                "approve",
                REQUESTED_SCOPE,
                now(),
                5,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A login_hint pre-binds the account: a different approving DID is rejected.
    #[tokio::test]
    async fn login_hint_mismatch_is_rejected() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_hint";
        seed_pending(&state, request_id, Some("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")).await;

        let resp = post_json(
            state.clone(),
            "/oauth/authorize/approve",
            approval_body(
                &state,
                &key,
                request_id,
                "approve",
                REQUESTED_SCOPE,
                now(),
                6,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // AC: status polling is throttled (slow_down) when polled faster than the interval.
    #[tokio::test]
    async fn status_polling_is_throttled() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let request_id = "poauth_poll";
        seed_pending(&state, request_id, None).await;
        let uri = format!("/oauth/authorize/status?request_id={request_id}");

        let first = get(state.clone(), &uri).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = get(state.clone(), &uri).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // An expired pending request is not approvable and reports expired.
    #[tokio::test]
    async fn expired_request_is_not_approvable() {
        let plc = MockServer::start().await;
        let state = setup(&plc).await;
        let key = p256_key();
        mount_audit_log(&plc, &[&key.did]).await;
        let request_id = "poauth_expired";
        // Insert already-expired (negative TTL).
        let new = NewPendingOAuthAuthorization {
            request_id,
            user_code: "EXPI-RED0",
            client_id: CLIENT_ID,
            client_name: Some("Test App"),
            redirect_uri: REDIRECT_URI,
            code_challenge: "e3b0c44298fc1c149afb",
            code_challenge_method: "S256",
            state: "teststate",
            response_type: "code",
            requested_scope: REQUESTED_SCOPE,
            login_hint: None,
            origin: None,
            ip: None,
            user_agent: None,
            ttl_secs: -10,
        };
        crate::db::pending_oauth_authorizations::insert_pending_authorization(&state.db, &new)
            .await
            .unwrap();

        let status = body_json(
            get(
                state.clone(),
                &format!("/oauth/authorize/status?request_id={request_id}"),
            )
            .await,
        )
        .await;
        assert_eq!(status["status"], "expired");

        let resp = post_json(
            state.clone(),
            "/oauth/authorize/approve",
            approval_body(
                &state,
                &key,
                request_id,
                "approve",
                REQUESTED_SCOPE,
                now(),
                7,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
