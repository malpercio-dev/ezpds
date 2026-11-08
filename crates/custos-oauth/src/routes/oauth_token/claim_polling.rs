// pattern: Imperative Shell

//! The `urn:workos:agent-auth:grant-type:claim` grant (auth.md Step 4c): the machine-pollable
//! half of the claim ceremony. A `service_auth`/`anonymous` agent polls with its one-time
//! `claim_token` while the account owner confirms out-of-band — no DPoP proof, since the agent
//! may hold no key yet; the token is the credential.
//!
//! The identity's lifecycle is the state machine, so the handler reads it and reports it as
//! OAuth device-flow codes: `authorization_pending` (active, ceremony still pending),
//! `expired_token` (`claim_token`/`user_code` window lapsed — enforced in the `claimed` state
//! too, so the token has one lifetime), `access_denied` (`revoked`), or — once `claimed` —
//! **200** with a fresh Bearer token plus a post-claim `identity_assertion` minted on the spot
//! and its `assertion_expires`. That collecting poll is the claim token's one use: it retires
//! the token, so a later poll with it is `invalid_grant`. The assertion is minted from the row's
//! stored scopes and the token's scope derives from the same list, so the two agree
//! byte-for-byte, as they would across a jwt-bearer exchange.
//!
//! Polling faster than the advertised `interval`
//! (`auth/agent_assertion.rs::POLL_INTERVAL_SECS`, 5s) yields `slow_down`, throttled by the
//! in-memory `CoreState.poll_tracker` keyed by the `claim_token`'s SHA-256 — never the raw
//! secret — and pruned in `cleanup_expired_state`.

use std::time::{Duration, Instant};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use super::{cleanup_expired_state, issue_access_token, persist_assertion_mint, TokenRequestForm};
use crate::oauth_errors::{insert_no_store_headers, require, OAuthTokenError};
use custos_core::auth::agent_assertion::{
    mint_identity_assertion, parse_sqlite_datetime, POLL_INTERVAL_SECS,
};
use custos_core::auth::token::sha256_hex;
use custos_core::CoreState;
use custos_db::agent_auth::{
    get_agent_identity, get_agent_identity_by_claim_token, latest_agent_claim_attempt_for_identity,
    AgentIdentityRow, AgentIdentityStatus,
};

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
/// `claimed`, so this handler only reads and reports:
///   - `active`, ceremony still pending → `authorization_pending`
///   - `active`, user_code / claim_token window lapsed → `expired_token`
///   - `claimed`, claim_token window still open → 200 with a fresh Bearer access token + a
///     freshly minted assertion; the claim token is retired
///   - `revoked` → `access_denied`
///
/// Polling faster than the advertised `interval` ([`POLL_INTERVAL_SECS`]) → `slow_down`.
pub(super) async fn handle_claim_polling(state: &CoreState, form: TokenRequestForm) -> Response {
    cleanup_expired_state(state).await;

    let claim_token = match require(form.claim_token.as_deref(), "claim_token") {
        Ok(v) => v,
        Err(e) => return e.into_response(),
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
/// identity's granted scopes + `registration_id`, plus a post-claim assertion minted here, under the
/// claimed TTL, for the agent to re-exchange (jwt-bearer) once the token expires. The claim token
/// is spent by this collection. A `claimed` identity always has a bound DID; a missing one is an
/// internal inconsistency → `server_error`.
async fn claim_success(state: &CoreState, identity: &AgentIdentityRow) -> Response {
    let Some(did) = identity
        .did
        .as_deref()
        .and_then(|did| common::Did::parse(did).ok())
    else {
        tracing::error!(registration_id = %identity.id, "claimed identity missing or malformed did");
        return OAuthTokenError::new("server_error", "claimed identity is inconsistent")
            .into_response();
    };
    // The token's own window still bounds collection: a confirmed-but-uncollected registration
    // is otherwise a credential that never expires.
    let claim_token_lapsed = identity
        .claim_token_expires_at
        .as_deref()
        .is_some_and(|exp| parse_sqlite_datetime(exp) <= chrono::Utc::now());
    if claim_token_lapsed {
        return OAuthTokenError::new("expired_token", "the claim window has expired")
            .into_response();
    }

    // The assertion and the access token are minted from the same stored list, so the token's
    // `scope` equals the assertion's `scope` claim (`scopes.join(" ")`) exactly — what a jwt-bearer
    // exchange of this assertion would carry too.
    let scopes = match serde_json::from_str::<Vec<String>>(&identity.scopes) {
        Ok(scopes) => scopes,
        Err(e) => {
            tracing::error!(registration_id = %identity.id, error = %e, "malformed stored agent scopes");
            return OAuthTokenError::new("server_error", "stored scopes are malformed")
                .into_response();
        }
    };
    let scope = scopes.join(" ");
    let minted = match mint_identity_assertion(
        &state.oauth_signing_keypair,
        state.config.issuer(),
        state.config.agent_auth.claimed_assertion_ttl_secs,
        did.as_str(),
        &identity.id,
        identity.registration_type.as_str(),
        &scopes,
    ) {
        Ok(minted) => minted,
        Err(_) => {
            return OAuthTokenError::new("server_error", "assertion minting failed")
                .into_response();
        }
    };

    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        did.as_str(),
        &scope,
        None,
        Some(&identity.id),
        &state.config.public_url,
        super::AGENT_ACCESS_TOKEN_TTL_SECS,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = persist_assertion_mint(
        state,
        &identity.id,
        &did,
        &minted.expires_sqlite,
        true,
        serde_json::json!({ "grant": "claim", "scope": scope }),
    )
    .await
    {
        tracing::error!(error = %e, registration_id = %identity.id, "failed to persist claim-grant mint + audit event");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    let mut headers = axum::http::HeaderMap::new();
    insert_no_store_headers(&mut headers);

    (
        StatusCode::OK,
        headers,
        Json(ClaimPollingResponse {
            access_token,
            token_type: "Bearer",
            expires_in: super::AGENT_ACCESS_TOKEN_TTL_SECS,
            scope,
            identity_assertion: minted.jwt,
            assertion_expires: minted.expires_rfc3339,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    use super::super::test_support::{json_body, post_token};
    use crate::test_support::{test_app, test_state};
    use custos_core::auth::agent_assertion::parse_sqlite_datetime;
    use custos_core::auth::token::sha256_hex;
    use custos_core::CoreState;

    const CLAIM_GRANT: &str = "urn:workos:agent-auth:grant-type:claim";

    /// Builder for an agent identity carrying a `claim_token` — the state the claim-polling grant
    /// reads. Defaults to the shape most tests want (anonymous, `active`, a live claim-token
    /// window, the default granted scope); call the setters for the one or two fields a given
    /// test varies. The token is seeded as its SHA-256, the only form the table holds.
    struct ClaimableIdentity<'a> {
        registration_id: &'a str,
        claim_token: &'a str,
        did: Option<&'a str>,
        status: &'a str,
        claim_token_expires_sql: &'a str,
        scopes_json: &'a str,
    }

    impl<'a> ClaimableIdentity<'a> {
        fn new(registration_id: &'a str, claim_token: &'a str) -> Self {
            Self {
                registration_id,
                claim_token,
                did: None,
                status: "active",
                claim_token_expires_sql: "datetime('now', '+1 hour')",
                scopes_json: r#"["repo:*"]"#,
            }
        }

        /// A claimed/owned registration — inserts the `accounts` row the FK requires.
        fn did(mut self, did: &'a str) -> Self {
            self.did = Some(did);
            self
        }

        fn status(mut self, status: &'a str) -> Self {
            self.status = status;
            self
        }

        /// SQLite datetime expression for `claim_token_expires_at` (e.g. `"datetime('now',
        /// '-1 minute')"` for an already-lapsed window).
        fn claim_token_expires_sql(mut self, sql: &'a str) -> Self {
            self.claim_token_expires_sql = sql;
            self
        }

        fn scopes_json(mut self, scopes_json: &'a str) -> Self {
            self.scopes_json = scopes_json;
            self
        }

        async fn seed(self, state: &CoreState) {
            if let Some(did) = self.did {
                sqlx::query(
                    "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
                     VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
                )
                .bind(did)
                .bind(format!("{}@example.com", self.registration_id))
                .execute(&state.db)
                .await
                .unwrap();
            }
            sqlx::query(&format!(
                "INSERT INTO agent_identities \
                 (id, did, registration_type, issuer, subject, email, scopes, \
                  assertion_expires_at, claim_token_hash, claim_token_expires_at, status, \
                  created_at, updated_at) \
                 VALUES (?, ?, 'anonymous', NULL, NULL, 'agent@example.com', ?, \
                         datetime('now', '+1 hour'), ?, {}, ?, \
                         datetime('now'), datetime('now'))",
                self.claim_token_expires_sql
            ))
            .bind(self.registration_id)
            .bind(self.did)
            .bind(self.scopes_json)
            .bind(sha256_hex(self.claim_token.as_bytes()))
            .bind(self.status)
            .execute(&state.db)
            .await
            .unwrap();
        }
    }

    /// Seed a claim-ceremony attempt (`user_code`) for an identity. `expires_sql` is a SQLite
    /// datetime expression, so a test can seed a live (`+1 hour`) or lapsed (`-1 minute`) code.
    async fn seed_claim_attempt(
        state: &CoreState,
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
        let resp = test_app(test_state().await)
            .oneshot(post_token(&format!("grant_type={CLAIM_GRANT}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn claim_polling_unknown_claim_token_returns_invalid_grant() {
        let resp = test_app(test_state().await)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_nope"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_grant");
    }

    /// `seed identity with status/expiry X → poll → assert one error code`, parametrised over
    /// every non-success outcome the state machine reports.
    #[tokio::test]
    async fn claim_polling_error_cases() {
        struct Case<'a> {
            name: &'a str,
            identity: ClaimableIdentity<'a>,
            /// A live claim-ceremony `user_code` attempt to seed alongside the identity, if any
            /// — `(id, code, expires_sql)`.
            attempt: Option<(&'a str, &'a str, &'a str)>,
            expected_error: &'a str,
        }

        let cases = [
            Case {
                name: "active_with_pending_attempt",
                identity: ClaimableIdentity::new("reg_pending", "clm_pending"),
                attempt: Some(("cla_pending", "123456", "datetime('now', '+10 minutes')")),
                expected_error: "authorization_pending",
            },
            Case {
                // The agent has a claim_token but hasn't started the ceremony yet — nothing to
                // expire.
                name: "active_without_attempt",
                identity: ClaimableIdentity::new("reg_nostart", "clm_nostart"),
                attempt: None,
                expected_error: "authorization_pending",
            },
            Case {
                name: "expired_claim_token",
                identity: ClaimableIdentity::new("reg_ctexpired", "clm_ctexpired")
                    .claim_token_expires_sql("datetime('now', '-1 minute')"),
                attempt: None,
                expected_error: "expired_token",
            },
            Case {
                // The claim_token is still live, but the latest user_code attempt lapsed.
                name: "expired_user_code",
                identity: ClaimableIdentity::new("reg_ucexpired", "clm_ucexpired"),
                attempt: Some(("cla_ucexpired", "654321", "datetime('now', '-1 minute')")),
                expected_error: "expired_token",
            },
            Case {
                name: "revoked",
                identity: ClaimableIdentity::new("reg_revoked", "clm_revoked").status("revoked"),
                attempt: None,
                expected_error: "access_denied",
            },
            Case {
                // Confirmed, but never collected within the token's own window: the token has one
                // lifetime, so it does not become a credential that never expires.
                name: "claimed_after_claim_token_lapsed",
                identity: ClaimableIdentity::new("reg_lateclaim", "clm_lateclaim")
                    .did("did:plc:lateclaim00000000000")
                    .status("claimed")
                    .claim_token_expires_sql("datetime('now', '-1 minute')"),
                attempt: None,
                expected_error: "expired_token",
            },
        ];

        for case in cases {
            let state = test_state().await;
            let claim_token = case.identity.claim_token.to_string();
            let registration_id = case.identity.registration_id.to_string();
            case.identity.seed(&state).await;
            if let Some((attempt_id, user_code, expires_sql)) = case.attempt {
                seed_claim_attempt(&state, attempt_id, &registration_id, user_code, expires_sql)
                    .await;
            }

            let resp = test_app(state)
                .oneshot(post_token(&format!(
                    "grant_type={CLAIM_GRANT}&claim_token={claim_token}"
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case {}", case.name);
            assert_eq!(
                json_body(resp).await["error"],
                case.expected_error,
                "case {}",
                case.name
            );
        }
    }

    /// A claimed identity's poll mints the post-claim assertion on the spot — the table holds no
    /// copy to hand back — bound to the identity's DID, registration and stored grant, and records
    /// the fresh expiry on the row.
    #[tokio::test]
    async fn claim_polling_claimed_returns_token_and_freshly_minted_assertion() {
        let state = test_state().await;
        let did = "did:plc:claimpoll000000000000";
        ClaimableIdentity::new("reg_claimed", "clm_claimed")
            .did(did)
            .status("claimed")
            .scopes_json(r#"["repo:*","blob:*/*"]"#)
            .seed(&state)
            .await;

        let resp = test_app(state.clone())
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
        // The post-claim assertion is minted at poll time for this DID, registration and grant.
        let assertion = json["identity_assertion"].as_str().unwrap();
        let payload: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(assertion.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["sub"], did);
        assert_eq!(payload["registration_id"], "reg_claimed");
        assert_eq!(payload["scope"], "repo:* blob:*/*");
        assert!(
            payload["exp"].as_i64().unwrap() > custos_core::time::unix_now_secs() + 3600,
            "the collected assertion carries the claimed TTL, not the pre-claim one"
        );
        let expires = json["assertion_expires"].as_str().unwrap();
        assert!(
            expires.contains('T'),
            "assertion_expires is an RFC3339 timestamp"
        );
        let (stored_expiry,): (String,) =
            sqlx::query_as("SELECT assertion_expires_at FROM agent_identities WHERE id = ?")
                .bind("reg_claimed")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(
            parse_sqlite_datetime(&stored_expiry).timestamp(),
            payload["exp"].as_i64().unwrap(),
            "the row records the minted assertion's expiry"
        );

        // Collection spends the claim token: the same token is now unknown.
        state
            .poll_tracker
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        let resp = test_app(state)
            .oneshot(post_token(&format!(
                "grant_type={CLAIM_GRANT}&claim_token=clm_claimed"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(resp).await["error"],
            "invalid_grant",
            "a collected claim token is spent"
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
        ClaimableIdentity::new("reg_fast", "clm_fast")
            .seed(&state)
            .await;
        let body = format!("grant_type={CLAIM_GRANT}&claim_token=clm_fast");

        // First poll is accepted (still pending) and records the poll mark on the shared tracker.
        let first = test_app(state.clone())
            .oneshot(post_token(&body))
            .await
            .unwrap();
        assert_eq!(json_body(first).await["error"], "authorization_pending");

        // An immediate second poll (same claim_token, well within the interval) is throttled.
        let second = test_app(state.clone())
            .oneshot(post_token(&body))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(second).await["error"], "slow_down");
    }
}
