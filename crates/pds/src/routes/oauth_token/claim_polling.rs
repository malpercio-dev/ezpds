// pattern: Imperative Shell
//
// The `urn:workos:agent-auth:grant-type:claim` grant (auth.md Step 4c): the machine-pollable half
// of the claim ceremony. An agent polls with its one-time `claim_token` while the account owner
// confirms out-of-band; the identity's lifecycle is the state machine, so this handler reads and
// reports (`authorization_pending`/`expired_token`/`access_denied`) or, once `claimed`, mints a
// plain Bearer access token plus the stored post-claim assertion for later re-exchange. No DPoP
// proof — the `claim_token` is itself the credential — and polling faster than the advertised
// interval yields `slow_down`.

use std::time::{Duration, Instant};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::SecondsFormat;
use serde::Serialize;

use super::{cleanup_expired_state, issue_access_token, TokenRequestForm};
use crate::app::AppState;
use crate::auth::agent_assertion::{parse_sqlite_datetime, POLL_INTERVAL_SECS};
use crate::auth::token::sha256_hex;
use crate::db::agent_auth::{
    get_agent_identity, get_agent_identity_by_claim_token, latest_agent_claim_attempt_for_identity,
    AgentIdentityRow, AgentIdentityStatus,
};
use crate::routes::oauth_errors::OAuthTokenError;

/// Successful claim-polling response body. Like the jwt-bearer response it carries a plain Bearer
/// access token and no refresh token, plus the post-claim `identity_assertion` the agent stores to
/// re-exchange (jwt-bearer grant) once this access token expires, and that assertion's expiry.
#[derive(Debug, Serialize)]
struct ClaimPollingResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    identity_assertion: String,
    assertion_expires: String,
}

/// `POST /oauth/token` with `grant_type=urn:workos:agent-auth:grant-type:claim`.
///
/// The machine-pollable half of the auth.md claim ceremony (spec Step 4c). A `service_auth` or
/// `anonymous` agent that started a ceremony (`POST /agent/identity/claim`) polls here with its
/// one-time `claim_token` while the account owner confirms out-of-band (`.../claim/confirm`). No
/// DPoP proof: the agent may hold no key yet, and the `claim_token` is itself the credential.
///
/// The identity's lifecycle *is* the state machine — the confirm endpoint already flipped it to
/// `claimed` and stored the post-claim assertion, so this handler only reads and reports:
///   - `active`, ceremony still pending → `authorization_pending`
///   - `active`, user_code / claim_token window lapsed → `expired_token`
///   - `claimed` → 200 with a fresh Bearer access token + the stored assertion
///   - `revoked` → `access_denied`
///
/// Polling faster than the advertised `interval` ([`POLL_INTERVAL_SECS`]) → `slow_down`.
pub(super) async fn handle_claim_polling(state: &AppState, form: TokenRequestForm) -> Response {
    cleanup_expired_state(state).await;

    let claim_token = match form.claim_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: claim_token")
                .into_response();
        }
    };

    // Pace polling to the advertised interval. Key on the token's SHA-256, never the raw secret; only
    // an *accepted* poll updates the mark, so a client that backs off for a full interval always
    // makes progress while one that keeps hammering keeps getting `slow_down`.
    let poll_key = sha256_hex(claim_token.as_bytes());
    {
        // A poisoned throttle map is non-fatal (it holds only advisory `Instant` marks), so recover
        // the guard rather than failing token issuance.
        let mut tracker = state
            .poll_tracker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(last) = tracker.get(&poll_key) {
            if last.elapsed() < Duration::from_secs(POLL_INTERVAL_SECS) {
                return OAuthTokenError::new(
                    "slow_down",
                    "polling faster than the permitted interval",
                )
                .into_response();
            }
        }
        tracker.insert(poll_key, Instant::now());
    }

    let identity = match get_agent_identity_by_claim_token(&state.db, claim_token).await {
        Ok(Some(identity)) => identity,
        // Unknown token — a grant credential that resolves to no registration.
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "unknown or expired claim token")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load agent identity for claim polling");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    match identity.status {
        // Turned off by its owner/operator — an explicit, terminal refusal.
        AgentIdentityStatus::Revoked => {
            OAuthTokenError::new("access_denied", "the agent identity has been revoked")
                .into_response()
        }
        // The owner confirmed the ceremony: collect the credential.
        AgentIdentityStatus::Claimed => claim_success(state, &identity).await,
        // Still awaiting the human confirmation gate — or the window has since lapsed.
        AgentIdentityStatus::Active => {
            let attempt = match latest_agent_claim_attempt_for_identity(&state.db, &identity.id)
                .await
            {
                Ok(attempt) => attempt,
                Err(e) => {
                    tracing::error!(error = %e, "failed to load claim attempt for polling");
                    return OAuthTokenError::new("server_error", "database error").into_response();
                }
            };

            // A pending, unexpired `user_code` — or a ceremony not yet started — is unambiguously
            // in-flight: confirm consumes the attempt atomically with the claim, so a still-pending
            // (or absent) attempt means the identity cannot have flipped to `claimed`. Keep polling.
            let claim_token_live = identity
                .claim_token_expires_at
                .as_deref()
                .map(|exp| parse_sqlite_datetime(exp) > chrono::Utc::now())
                .unwrap_or(true);
            let in_flight = attempt.as_ref().map(|a| a.is_pending()).unwrap_or(true);
            if claim_token_live && in_flight {
                return OAuthTokenError::new(
                    "authorization_pending",
                    "the claim has not been confirmed yet",
                )
                .into_response();
            }

            // The window looks lapsed — but the owner may have *just* confirmed, flipping the
            // identity `active → claimed` between our two non-atomic reads (the single-connection
            // pool releases the connection between the identity and attempt lookups). `claimed` is
            // terminal/monotonic, so a re-read of the authoritative status resolves a race with
            // confirm to success rather than a false `expired_token`.
            match get_agent_identity(&state.db, &identity.id).await {
                Ok(Some(fresh)) => match fresh.status {
                    AgentIdentityStatus::Claimed => claim_success(state, &fresh).await,
                    AgentIdentityStatus::Revoked => {
                        OAuthTokenError::new("access_denied", "the agent identity has been revoked")
                            .into_response()
                    }
                    AgentIdentityStatus::Active => {
                        OAuthTokenError::new("expired_token", "the claim window has expired")
                            .into_response()
                    }
                },
                Ok(None) => {
                    tracing::error!(registration_id = %identity.id, "agent identity vanished during claim polling");
                    OAuthTokenError::new("server_error", "database error").into_response()
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to re-read agent identity for claim polling");
                    OAuthTokenError::new("server_error", "database error").into_response()
                }
            }
        }
    }
}

/// Issue the post-claim credential for a `claimed` identity: a fresh Bearer access token carrying the
/// identity's granted scopes + `registration_id`, plus the stored post-claim assertion the agent
/// re-exchanges (jwt-bearer) once the token expires. A `claimed` identity always has a bound DID and
/// a stored assertion; a missing one is an internal inconsistency → `server_error`.
async fn claim_success(state: &AppState, identity: &AgentIdentityRow) -> Response {
    let (Some(did), Some(assertion)) = (
        identity.did.as_deref(),
        identity.identity_assertion.as_deref(),
    ) else {
        tracing::error!(registration_id = %identity.id, "claimed identity missing did or assertion");
        return OAuthTokenError::new("server_error", "claimed identity is inconsistent")
            .into_response();
    };

    // The token's `scope` must equal what a jwt-bearer exchange of this same assertion would carry:
    // the assertion's `scope` claim is `scopes.join(" ")`, and `identity.scopes` is the JSON of that
    // same list, so parse-and-join reproduces it exactly without re-decoding the JWT.
    let scope = match serde_json::from_str::<Vec<String>>(&identity.scopes) {
        Ok(scopes) => scopes.join(" "),
        Err(e) => {
            tracing::error!(registration_id = %identity.id, error = %e, "malformed stored agent scopes");
            return OAuthTokenError::new("server_error", "stored scopes are malformed")
                .into_response();
        }
    };

    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        did,
        &scope,
        None,
        Some(&identity.id),
        &state.config.public_url,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = crate::auth::agent_assertion::record_agent_audit(
        &state.db,
        &identity.id,
        Some(did),
        crate::db::agent_audit::AgentAuditEventType::TokenExchanged,
        serde_json::json!({ "grant": "claim", "scope": scope }),
    )
    .await
    {
        // Fail closed, mirroring the jwt-bearer path: the token was never returned to the caller.
        tracing::error!(error = %e, registration_id = %identity.id, "failed to record token-exchange audit event");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    let assertion_expires = parse_sqlite_datetime(&identity.assertion_expires_at)
        .to_rfc3339_opts(SecondsFormat::Millis, true);

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));

    (
        StatusCode::OK,
        headers,
        Json(ClaimPollingResponse {
            access_token,
            token_type: "Bearer",
            expires_in: 300,
            scope,
            identity_assertion: assertion.to_string(),
            assertion_expires,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use super::super::test_support::{json_body, mint_assertion, now_secs, post_token};
    use crate::app::{app, test_state, AppState};

    const CLAIM_GRANT: &str = "urn:workos:agent-auth:grant-type:claim";

    /// Seed an agent identity carrying a `claim_token` — the state the claim-polling grant reads.
    /// `did` is `Some` for a claimed/owned registration (an `accounts` row is inserted for the FK)
    /// or `None` for an ownerless anonymous one. `claim_token_expires_at`/`identity_assertion` are
    /// passed straight through so a test can seed a lapsed token or the stored post-claim assertion.
    #[allow(clippy::too_many_arguments)]
    async fn seed_claimable_identity(
        state: &AppState,
        registration_id: &str,
        did: Option<&str>,
        status: &str,
        claim_token: &str,
        claim_token_expires_sql: &str,
        scopes_json: &str,
        identity_assertion: Option<&str>,
    ) {
        if let Some(did) = did {
            sqlx::query(
                "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
                 VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
            )
            .bind(did)
            .bind(format!("{registration_id}@example.com"))
            .execute(&state.db)
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, claim_token, claim_token_expires_at, status, created_at, \
              updated_at) \
             VALUES (?, ?, 'anonymous', NULL, NULL, 'agent@example.com', ?, ?, \
                     datetime('now', '+1 hour'), ?, {claim_token_expires_sql}, ?, \
                     datetime('now'), datetime('now'))"
        ))
        .bind(registration_id)
        .bind(did)
        .bind(scopes_json)
        .bind(identity_assertion)
        .bind(claim_token)
        .bind(status)
        .execute(&state.db)
        .await
        .unwrap();
    }

    /// Seed a claim-ceremony attempt (`user_code`) for an identity. `expires_sql` is a SQLite
    /// datetime expression, so a test can seed a live (`+1 hour`) or lapsed (`-1 minute`) code.
    async fn seed_claim_attempt(
        state: &AppState,
        attempt_id: &str,
        identity_id: &str,
        user_code: &str,
        expires_sql: &str,
    ) {
        sqlx::query(&format!(
            "INSERT INTO agent_claim_attempts \
             (id, identity_id, user_code, user_code_expires_at, email, created_at) \
             VALUES (?, ?, ?, {expires_sql}, NULL, datetime('now'))"
        ))
        .bind(attempt_id)
        .bind(identity_id)
        .bind(user_code)
        .execute(&state.db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn claim_polling_missing_claim_token_returns_invalid_request() {
        let resp = app(test_state().await)
            .oneshot(post_token(&format!("grant_type={CLAIM_GRANT}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn claim_polling_unknown_claim_token_returns_invalid_grant() {
        let resp = app(test_state().await)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_nope"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn claim_polling_active_with_pending_attempt_returns_authorization_pending() {
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_pending",
            None,
            "active",
            "clm_pending",
            "datetime('now', '+1 hour')",
            r#"["repo:*"]"#,
            None,
        )
        .await;
        seed_claim_attempt(
            &state,
            "cla_pending",
            "reg_pending",
            "123456",
            "datetime('now', '+10 minutes')",
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_pending"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "authorization_pending");
    }

    #[tokio::test]
    async fn claim_polling_active_without_attempt_returns_authorization_pending() {
        // The agent has a claim_token but hasn't started the ceremony yet — nothing to expire.
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_nostart",
            None,
            "active",
            "clm_nostart",
            "datetime('now', '+1 hour')",
            r#"["repo:*"]"#,
            None,
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_nostart"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "authorization_pending");
    }

    #[tokio::test]
    async fn claim_polling_expired_claim_token_returns_expired_token() {
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_ctexpired",
            None,
            "active",
            "clm_ctexpired",
            "datetime('now', '-1 minute')",
            r#"["repo:*"]"#,
            None,
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_ctexpired"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "expired_token");
    }

    #[tokio::test]
    async fn claim_polling_expired_user_code_returns_expired_token() {
        // The claim_token is still live, but the latest user_code attempt lapsed.
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_ucexpired",
            None,
            "active",
            "clm_ucexpired",
            "datetime('now', '+1 hour')",
            r#"["repo:*"]"#,
            None,
        )
        .await;
        seed_claim_attempt(
            &state,
            "cla_ucexpired",
            "reg_ucexpired",
            "654321",
            "datetime('now', '-1 minute')",
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_ucexpired"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "expired_token");
    }

    #[tokio::test]
    async fn claim_polling_revoked_returns_access_denied() {
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_revoked",
            None,
            "revoked",
            "clm_revoked",
            "datetime('now', '+1 hour')",
            r#"["repo:*"]"#,
            None,
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_revoked"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "access_denied");
    }

    #[tokio::test]
    async fn claim_polling_claimed_returns_token_and_stored_assertion() {
        let state = test_state().await;
        let did = "did:plc:claimpoll000000000000";
        let assertion = mint_assertion(
            &state,
            did,
            "reg_claimed",
            "repo:* blob:*/*",
            now_secs() + 600,
        );
        seed_claimable_identity(
            &state,
            "reg_claimed",
            Some(did),
            "claimed",
            "clm_claimed",
            "datetime('now', '+1 hour')",
            r#"["repo:*","blob:*/*"]"#,
            Some(&assertion),
        )
        .await;

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_claimed"
            )))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a claimed identity yields a token"
        );
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
        );
        let json = json_body(resp).await;
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 300);
        // Scope is the stored JSON list rendered space-delimited — the jwt-bearer parity property.
        assert_eq!(json["scope"], "repo:* blob:*/*");
        // The stored post-claim assertion is handed back verbatim for later re-exchange.
        assert_eq!(json["identity_assertion"], assertion);
        assert!(
            json["assertion_expires"].as_str().unwrap().contains('T'),
            "assertion_expires is an RFC3339 timestamp"
        );
        assert!(
            json.get("refresh_token").is_none(),
            "the claim grant issues no refresh token"
        );
        // The access token is a well-formed 3-segment JWT.
        assert_eq!(json["access_token"].as_str().unwrap().split('.').count(), 3);
    }

    #[tokio::test]
    async fn claim_polling_faster_than_interval_returns_slow_down() {
        let state = test_state().await;
        seed_claimable_identity(
            &state,
            "reg_fast",
            None,
            "active",
            "clm_fast",
            "datetime('now', '+1 hour')",
            r#"["repo:*"]"#,
            None,
        )
        .await;
        let body = format!("grant_type={CLAIM_GRANT}&claim_token=clm_fast");

        // First poll is accepted (still pending) and records the poll mark on the shared tracker.
        let first = app(state.clone()).oneshot(post_token(&body)).await.unwrap();
        assert_eq!(json_body(first).await["error"], "authorization_pending");

        // An immediate second poll (same claim_token, well within the interval) is throttled.
        let second = app(state.clone()).oneshot(post_token(&body)).await.unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(second).await["error"], "slow_down");
    }
}
