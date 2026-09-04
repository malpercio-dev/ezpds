// pattern: Imperative Shell

//! The `urn:ietf:params:oauth:grant-type:jwt-bearer` grant (RFC 7523 / auth.md Step 5): verify a
//! service-signed agent `identity_assertion` (self-signed under this server's OAuth key) and mint
//! a short-lived plain **Bearer** access token — no DPoP proof (the assertion is already
//! key-bound upstream) and no refresh token: the assertion itself is the durable credential.
//!
//! **Every successful exchange renews the assertion.** The response carries a freshly minted
//! `identity_assertion` (+ `assertion_expires`), scoped to the row's stored grant clamped to the
//! operator's *current* `[agent_auth] granted_scopes` and living
//! `[agent_auth] claimed_assertion_ttl_secs` from now, and the stored row is updated to match. An
//! agent that persists the returned assertion therefore keeps a sliding window: only a binding
//! dormant past a full claimed-assertion lifetime ever needs a new claim ceremony. The widened
//! exposure of a long-lived, self-renewing assertion is bounded by revocation, not expiry — a
//! revoked identity is refused at its next exchange below, exactly like a stolen OAuth refresh
//! token.
//!
//! The registration must be `claimed` with a DID matching the assertion `sub`. Both the
//! assertion verifier and this state gate name their specific cause in `error_description`
//! (expired / invalid / unclaimed / unknown registration / subject mismatch) so an autonomous
//! agent can self-diagnose: expired and unclaimed are the recoverable paths (re-register, or
//! complete the ceremony), revoked is terminal (`access_denied`), and a resource naming anything
//! but this server's origin → `invalid_target`. The RFC 7523 §3.1 error *codes* stay coarse —
//! the description is the machine-readable signal.
//!
//! The issued token carries the assertion's granular `scope` verbatim — no widening is possible,
//! because the grant accepts no requested `scope` — **and** its `registration_id` claim, which
//! marks the token agent-derived
//! (`auth/extractors.rs::AuthenticatedUser::{is_agent,require_not_agent}`) and ties it to the
//! `agent_identities` row for revocation and audit.
//!
//! **Revocation is bounded by the access-token TTL.** Flipping an identity to `revoked` blocks
//! the *next* exchange immediately, but an already-issued access token stays valid until it
//! expires (5 min); there is no live-token revocation list.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use super::{cleanup_expired_state, issue_access_token, TokenRequestForm};
use crate::app::AppState;
use crate::db::agent_auth::{get_agent_identity, AgentIdentityStatus};
use crate::routes::oauth_errors::OAuthTokenError;

/// Successful jwt-bearer response body. Unlike [`super::TokenResponse`], it carries no
/// `refresh_token`: the agent re-exchanges its `identity_assertion` (RFC 7523 §2.1) instead of
/// rotating a refresh token, and the issued token is a plain Bearer (no DPoP binding). The
/// `identity_assertion` + `assertion_expires` pair is the sliding renewal (field names match the
/// claim-polling response), which the agent should persist in place of the one it presented.
#[derive(Debug, Serialize)]
struct JwtBearerTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    identity_assertion: String,
    assertion_expires: String,
}

/// Claims read out of a service-signed `identity_assertion` (minted by `POST /agent/identity`).
/// `sub`, `scope`, and `registration_id` are all required — the assertion always carries them, and
/// their absence (e.g. an access token replayed as an assertion) fails deserialization → the caller
/// maps that to `invalid_grant`.
#[derive(Debug, Deserialize)]
struct AgentAssertionClaims {
    sub: String,
    scope: String,
    registration_id: String,
}

/// `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
///
/// Exchanges a service-signed agent `identity_assertion` for a short-lived Bearer access token
/// (auth.md spec Step 5 / RFC 7523). No DPoP proof is required — the assertion is already
/// key-bound by the registration ceremony that minted it — and no refresh token is issued: the
/// response instead carries a renewed `identity_assertion` for the agent to persist and
/// re-exchange (see the module doc).
pub(super) async fn handle_jwt_bearer(state: &AppState, form: TokenRequestForm) -> Response {
    // Prune stale nonces and expired tokens on every request, matching the other grant handlers.
    cleanup_expired_state(state).await;

    let assertion = match form.assertion.as_deref() {
        Some(a) if !a.is_empty() => a,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: assertion")
                .into_response();
        }
    };

    // RFC 8707: `resource` pins the token to a protected resource. ezpds is the sole resource it
    // serves (issuer == resource == public origin), so any other value is an unknown target.
    if let Some(resource) = form.resource.as_deref().filter(|r| !r.is_empty()) {
        let origin = state.config.issuer();
        if resource.trim_end_matches('/') != origin {
            return OAuthTokenError::new("invalid_target", "resource must be this server's origin")
                .into_response();
        }
    }

    let claims = match verify_agent_assertion(assertion, state) {
        Ok(claims) => claims,
        Err(e) => return e.into_response(),
    };

    // State gate (the assertion stays cryptographically valid until it expires, so identity state
    // is enforced here at exchange time, per RFC 7523 §3.1). Require exactly `Claimed`: that is the
    // only state for which the registration flow mints a service-signed assertion. A `Revoked`
    // identity was turned off by its owner/operator — an explicit `access_denied` closes the
    // credential. `Active` still owes the claim ceremony, and a missing/mismatched row can't be
    // trusted, so both → `invalid_grant`. Also require the stored
    // DID to match the assertion's `sub`, so the state lookup and the token subject resolve to the
    // same identity even if the issuance path ever drifts.
    //
    // Every `invalid_grant` here names its specific cause in `error_description`: an autonomous
    // agent deciding what to do next must be able to tell "my assertion lapsed — re-register" from
    // "this registration never existed / was never claimed" (both recoverable) from a forged or
    // replayed assertion (not recoverable). The RFC 7523 code stays coarse; the description is the
    // machine-readable signal.
    let identity = match get_agent_identity(&state.db, &claims.registration_id).await {
        Ok(Some(identity))
            if identity.status == AgentIdentityStatus::Claimed
                && identity.did.as_deref() == Some(claims.sub.as_str()) =>
        {
            identity
        }
        Ok(Some(identity)) if identity.status == AgentIdentityStatus::Revoked => {
            return OAuthTokenError::new("access_denied", "the agent identity has been revoked")
                .into_response();
        }
        Ok(Some(identity)) if identity.status == AgentIdentityStatus::Claimed => {
            // Claimed but the stored DID differs from the assertion `sub`: the two identity
            // graphs have drifted. Never mint a token across that seam.
            tracing::warn!(
                registration_id = %claims.registration_id,
                assertion_sub = %claims.sub,
                stored_did = ?identity.did,
                "jwt-bearer exchange: assertion subject does not match the registered identity"
            );
            return OAuthTokenError::new(
                "invalid_grant",
                "identity_assertion subject does not match the registered identity",
            )
            .into_response();
        }
        Ok(Some(_)) => {
            return OAuthTokenError::new(
                "invalid_grant",
                "agent identity has not been claimed yet; complete the claim ceremony first",
            )
            .into_response();
        }
        Ok(None) => {
            return OAuthTokenError::new(
                "invalid_grant",
                "unknown agent registration; re-register to obtain a new identity_assertion",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load agent identity for jwt-bearer exchange");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Sliding renewal: re-mint the assertion for the response, clamping the row's stored grant to
    // the operator's *current* `granted_scopes` (matching the re-mint paths in `agent_identity.rs`
    // and `agent_child.rs`, so narrowing the config narrows every renewal without re-registration).
    // The access token below still carries the *presented* assertion's scope verbatim.
    let renewed_scopes = crate::auth::oauth_scopes::intersect_scope_tokens(
        &serde_json::from_str::<Vec<String>>(&identity.scopes).unwrap_or_default(),
        &state.config.agent_auth.granted_scopes,
    );
    let renewed = match crate::auth::agent_assertion::mint_identity_assertion(
        &state.oauth_signing_keypair,
        state.config.issuer(),
        state.config.agent_auth.claimed_assertion_ttl_secs,
        &claims.sub,
        &claims.registration_id,
        identity.registration_type.as_str(),
        &renewed_scopes,
    ) {
        Ok(minted) => minted,
        Err(_) => {
            return OAuthTokenError::new("server_error", "assertion renewal failed")
                .into_response();
        }
    };

    // Issue a sender-unconstrained Bearer access token carrying the assertion's granted scope and
    // its `registration_id` (marking the token agent-derived for guard/audit purposes).
    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        &claims.sub,
        &claims.scope,
        None,
        Some(&claims.registration_id),
        &state.config.public_url,
        super::AGENT_ACCESS_TOKEN_TTL_SECS,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // The stored assertion update and the exchange's audit row commit together, and both fail
    // closed: a credential issuance (or renewal) the audit trail cannot account for must not
    // leave the building. The tokens above were never returned to the caller. Every read (and
    // both pure mints) ran before `begin()` — the single-connection pool cannot serve a
    // `&SqlitePool` read while a transaction holds the connection.
    let audit_result = async {
        let mut tx = state.db.begin().await?;
        crate::db::agent_auth::set_agent_identity_assertion(
            &mut *tx,
            &claims.registration_id,
            &renewed.jwt,
            &renewed.expires_sqlite,
        )
        .await?;
        let detail = serde_json::json!({
            "grant": "jwt_bearer",
            "scope": claims.scope,
            "assertion_renewed": true,
        })
        .to_string();
        crate::db::agent_audit::insert_agent_audit_event(
            &mut *tx,
            &uuid::Uuid::new_v4().to_string(),
            &claims.registration_id,
            Some(&claims.sub),
            crate::db::agent_audit::AgentAuditEventType::TokenExchanged,
            Some(&detail),
        )
        .await?;
        tx.commit().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    if let Err(e) = audit_result {
        tracing::error!(error = %e, registration_id = %claims.registration_id, "failed to persist jwt-bearer renewal + audit event");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));

    (
        StatusCode::OK,
        headers,
        Json(JwtBearerTokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: super::AGENT_ACCESS_TOKEN_TTL_SECS,
            scope: claims.scope,
            identity_assertion: renewed.jwt,
            assertion_expires: renewed.expires_rfc3339,
        }),
    )
        .into_response()
}

/// Verify a service-signed `identity_assertion`: ES256 signature under this server's own OAuth key
/// (the assertion is self-signed), plus `iss`/`aud` == this server's origin and an unexpired `exp`.
/// Both failure classes map to `invalid_grant` (RFC 7523 §3.1), but the `error_description`
/// separates an expired assertion (the routine, recoverable case — the agent should re-register)
/// from a signature/issuer/shape failure (forged, replayed, or foreign — never retry the same
/// credential): a sporadic agent whose assertion TTL lapsed must be able to self-diagnose from
/// the description alone instead of inferring expiry from a message shared with every other
/// rejection.
fn verify_agent_assertion(
    assertion: &str,
    state: &AppState,
) -> Result<AgentAssertionClaims, OAuthTokenError> {
    // Reuse the shared loader — the assertion is signed by the same OAuth key as access tokens.
    let decoding_key = crate::auth::jwt::oauth_es256_decoding_key(state)
        .map_err(|_| OAuthTokenError::new("server_error", "assertion verification unavailable"))?;

    let origin = state.config.issuer();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[origin]);
    validation.set_audience(&[origin]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
    validation.leeway = 0;

    jsonwebtoken::decode::<AgentAssertionClaims>(assertion, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::debug!(error = %e, error_kind = ?e.kind(), "agent identity_assertion verification failed");
            if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                OAuthTokenError::new(
                    "invalid_grant",
                    "identity_assertion has expired; re-register to obtain a new one",
                )
            } else {
                OAuthTokenError::new(
                    "invalid_grant",
                    "identity_assertion is invalid or not for this server",
                )
            }
        })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    use super::super::test_support::{json_body, mint_assertion, now_secs, post_token};
    use crate::app::{app, test_state, AppState};

    const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// Re-encode a JWT with its signature bytes corrupted — valid structure, wrong signature.
    fn tamper_signature(jwt: &str) -> String {
        let (rest, sig_b64) = jwt.rsplit_once('.').unwrap();
        let mut sig = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        sig[0] ^= 0xff;
        format!("{rest}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// Seed an account + an agent identity row with the given registration id and status.
    async fn seed_agent_identity(state: &AppState, registration_id: &str, did: &str, status: &str) {
        seed_agent_identity_with_scopes(
            state,
            registration_id,
            did,
            status,
            r#"["com.atproto.access"]"#,
        )
        .await;
    }

    /// [`seed_agent_identity`] with an explicit stored-scopes JSON array (the grant the sliding
    /// renewal re-clamps).
    async fn seed_agent_identity_with_scopes(
        state: &AppState,
        registration_id: &str,
        did: &str,
        status: &str,
        scopes_json: &str,
    ) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{registration_id}@example.com"))
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, issuer, subject, email, scopes, identity_assertion, \
              assertion_expires_at, status, created_at, updated_at) \
             VALUES (?, ?, 'identity_assertion', NULL, NULL, 'agent@example.com', \
                     ?, NULL, datetime('now', '+1 hour'), ?, \
                     datetime('now'), datetime('now'))",
        )
        .bind(registration_id)
        .bind(did)
        .bind(scopes_json)
        .bind(status)
        .execute(&state.db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn jwt_bearer_happy_path_returns_usable_bearer_token() {
        let state = test_state().await;
        let did = "did:plc:agentbearer0000000000";
        seed_agent_identity(&state, "reg_bearer", did, "claimed").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_bearer",
            "com.atproto.access",
            now_secs() + 600,
        );

        let body = format!("grant_type={JWT_BEARER}&assertion={assertion}");
        // No DPoP header — the jwt-bearer grant requires none.
        let resp = app(state.clone()).oneshot(post_token(&body)).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "valid assertion must return 200"
        );
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
        );
        assert!(
            !resp.headers().contains_key("DPoP-Nonce"),
            "jwt-bearer response must not carry a DPoP-Nonce header"
        );

        let json = json_body(resp).await;
        assert_eq!(
            json["token_type"], "Bearer",
            "token_type must be Bearer, not DPoP"
        );
        assert_eq!(json["expires_in"], 300);
        assert_eq!(json["scope"], "com.atproto.access");
        assert!(
            json.get("refresh_token").is_none(),
            "jwt-bearer issues no refresh token"
        );
        assert!(
            json["identity_assertion"].is_string(),
            "every exchange must return a renewed identity_assertion"
        );
        assert!(
            json["assertion_expires"].is_string(),
            "the renewed assertion must carry its expiry"
        );

        let at = json["access_token"].as_str().unwrap();
        let header_b64 = at.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["typ"], "at+jwt");

        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(
            payload["sub"], did,
            "access token sub must be the agent's DID"
        );
        assert!(
            payload.get("cnf").is_none(),
            "a Bearer token must carry no DPoP cnf binding"
        );

        // The load-bearing check: the issued token is accepted by the resource-server verifier.
        let claims = crate::auth::jwt::verify_access_token(at, &state).unwrap();
        assert_eq!(claims.sub, did);
        assert!(crate::auth::jwt::parse_scope(&claims.scope)
            .unwrap()
            .is_access());
    }

    #[tokio::test]
    async fn jwt_bearer_missing_assertion_returns_invalid_request() {
        let state = test_state().await;
        let resp = app(state)
            .oneshot(post_token(&format!("grant_type={JWT_BEARER}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn jwt_bearer_bad_signature_returns_invalid_grant() {
        let state = test_state().await;
        let did = "did:plc:agentbearer1111111111";
        seed_agent_identity(&state, "reg_badsig", did, "claimed").await;
        let assertion = tamper_signature(&mint_assertion(
            &state,
            did,
            "reg_badsig",
            "com.atproto.access",
            now_secs() + 600,
        ));

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
        // A tampered assertion is not an expired one: the description must say invalid, so the
        // agent does not loop on re-registration for what is actually a forgery or replay.
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("is invalid"),
            "tampered assertion must be described as invalid, got: {json}"
        );
    }

    #[tokio::test]
    async fn jwt_bearer_expired_assertion_returns_invalid_grant() {
        let state = test_state().await;
        let did = "did:plc:agentbearer2222222222";
        seed_agent_identity(&state, "reg_expired", did, "claimed").await;
        // exp in the past.
        let assertion = mint_assertion(
            &state,
            did,
            "reg_expired",
            "com.atproto.access",
            now_secs() - 60,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
        // The whole point of the split: an expired assertion is the routine, recoverable case,
        // and the description must say so — an agent acting sporadically hits this in every
        // action window and must be able to tell "re-register" from "revoked, stop".
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("has expired"),
            "expired assertion must be described as expired, got: {json}"
        );
    }

    /// A `claimed` row whose stored DID differs from the assertion `sub` gets its own
    /// description — the recoverable expiry/unclaimed paths must never absorb it.
    #[tokio::test]
    async fn jwt_bearer_subject_mismatch_names_the_mismatch() {
        let state = test_state().await;
        // The row is claimed, but for a different DID than the assertion names.
        seed_agent_identity(
            &state,
            "reg_mismatch",
            "did:plc:agentbearer5555555555",
            "claimed",
        )
        .await;
        let assertion = mint_assertion(
            &state,
            "did:plc:agentbearer6666666666",
            "reg_mismatch",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("does not match"),
            "subject mismatch must be described as a mismatch, got: {json}"
        );
    }

    /// An unclaimed (`active`) registration is not an unknown one: the description points the
    /// agent at the claim ceremony, not at re-registration.
    #[tokio::test]
    async fn jwt_bearer_unclaimed_registration_names_the_ceremony() {
        let state = test_state().await;
        let did = "did:plc:agentbearer7777777777";
        seed_agent_identity(&state, "reg_unclaimed", did, "active").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_unclaimed",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("claimed"),
            "unclaimed registration must be described as unclaimed, got: {json}"
        );
    }

    /// The sliding renewal: the returned `identity_assertion` is freshly minted with the claimed
    /// TTL, persisted on the row, and itself exchangeable — so an agent that persists it never
    /// needs a new claim ceremony while it keeps acting.
    #[tokio::test]
    async fn jwt_bearer_renewed_assertion_persists_and_round_trips() {
        let state = test_state().await;
        let did = "did:plc:agentrenewal000000000";
        // Stored scopes matching the default granted profile, so the clamp keeps them all.
        seed_agent_identity_with_scopes(
            &state,
            "reg_renewal",
            did,
            "claimed",
            r#"["atproto","repo:*?action=create&action=update","blob:*/*"]"#,
        )
        .await;
        let assertion = mint_assertion(&state, did, "reg_renewal", "atproto", now_secs() + 600);

        let resp = app(state.clone())
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_body(resp).await;
        let renewed = json["identity_assertion"].as_str().unwrap().to_string();

        // The renewal is persisted as the row's stored assertion.
        let stored: (Option<String>,) =
            sqlx::query_as("SELECT identity_assertion FROM agent_identities WHERE id = ?")
                .bind("reg_renewal")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stored.0.as_deref(), Some(renewed.as_str()));

        // The renewed assertion outlives the pre-claim TTL (claimed TTL is 30 days by default)
        // and carries the stored grant clamped to the operator's current config, sorted/deduped.
        let payload_b64 = renewed.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert!(
            payload["exp"].as_i64().unwrap() > now_secs() + 3600,
            "a renewed assertion must outlive the pre-claim TTL"
        );
        assert_eq!(
            payload["scope"], "atproto blob:*/* repo:*?action=create&action=update",
            "the renewal carries the stored grant, canonically ordered"
        );

        // The renewal itself exchanges — the sliding window closes the loop.
        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={renewed}"
            )))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a renewed assertion must be exchangeable in turn"
        );
    }

    /// Narrowing `[agent_auth] granted_scopes` narrows every renewal: a stored scope the operator
    /// no longer grants is dropped from the re-minted assertion without re-registration.
    #[tokio::test]
    async fn jwt_bearer_renewal_clamps_to_current_granted_scopes() {
        let state = test_state().await;
        let did = "did:plc:agentrenewclamp000000";
        // "account:email" is stored but absent from the default granted profile.
        seed_agent_identity_with_scopes(
            &state,
            "reg_renew_clamp",
            did,
            "claimed",
            r#"["atproto","account:email"]"#,
        )
        .await;
        let assertion = mint_assertion(&state, did, "reg_renew_clamp", "atproto", now_secs() + 600);

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_body(resp).await;
        let renewed = json["identity_assertion"].as_str().unwrap().to_string();
        let payload_b64 = renewed.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(
            payload["scope"], "atproto",
            "a scope the operator no longer grants must not survive renewal"
        );
    }

    #[tokio::test]
    async fn jwt_bearer_unknown_registration_returns_invalid_grant() {
        let state = test_state().await;
        let did = "did:plc:agentbearer3333333333";
        // Mint a validly-signed assertion but never persist the identity row.
        let assertion = mint_assertion(
            &state,
            did,
            "reg_missing",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn jwt_bearer_revoked_identity_returns_access_denied() {
        let state = test_state().await;
        let did = "did:plc:agentbearer4444444444";
        seed_agent_identity(&state, "reg_revoked", did, "revoked").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_revoked",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(resp).await["error"],
            "access_denied",
            "a revoked identity must be refused with access_denied"
        );
    }

    /// Drive the full jwt-bearer exchange and return the issued agent Bearer access token.
    async fn exchange_agent_token(state: &AppState, did: &str, registration_id: &str) -> String {
        seed_agent_identity(state, registration_id, did, "claimed").await;
        let assertion = mint_assertion(
            state,
            did,
            registration_id,
            // The conservative default agent profile: repo writes + blobs, no account/identity.
            "atproto repo:*?action=create&action=update blob:*/*",
            now_secs() + 600,
        );
        let resp = app(state.clone())
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        json_body(resp).await["access_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn bearer_post(uri: &str, token: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// A bounded agent token is refused (403) on the account-lifecycle and app-password-management
    /// surface — via the granular scope check (`deactivateAccount`) and the agent-token guard
    /// (`createAppPassword`), respectively.
    #[tokio::test]
    async fn agent_token_is_forbidden_on_account_and_app_password_routes() {
        let state = test_state().await;
        let did = "did:plc:agentbounded00000000";
        let at = exchange_agent_token(&state, did, "reg_bounded").await;

        // createAppPassword: rejected by the agent-token guard (require_not_agent).
        let resp = app(state.clone())
            .oneshot(bearer_post(
                "/xrpc/com.atproto.server.createAppPassword",
                &at,
                r#"{"name":"botpass"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an agent token must not create app passwords"
        );

        // deactivateAccount: rejected by the granular scope check (no account:status?action=manage).
        let resp = app(state)
            .oneshot(bearer_post(
                "/xrpc/com.atproto.server.deactivateAccount",
                &at,
                "{}",
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an agent token must not deactivate the account"
        );
    }

    #[tokio::test]
    async fn jwt_bearer_token_carries_registration_id_claim() {
        // An agent-derived access token carries `registration_id`; ordinary tokens do not.
        let state = test_state().await;
        let did = "did:plc:agentbearer9999999999";
        seed_agent_identity(&state, "reg_claim_present", did, "claimed").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_claim_present",
            "atproto repo:*?action=create&action=update",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let at = json_body(resp).await["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(
            payload["registration_id"], "reg_claim_present",
            "an agent-derived access token must carry its registration_id"
        );
    }

    #[tokio::test]
    async fn jwt_bearer_mismatched_resource_returns_invalid_target() {
        let state = test_state().await;
        let did = "did:plc:agentbearer5555555555";
        seed_agent_identity(&state, "reg_resource", did, "claimed").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_resource",
            "com.atproto.access",
            now_secs() + 600,
        );
        let body = format!(
            "grant_type={JWT_BEARER}&assertion={assertion}&resource=https%3A%2F%2Fother.example.com%2F"
        );

        let resp = app(state).oneshot(post_token(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_target");
    }

    #[tokio::test]
    async fn jwt_bearer_matching_resource_is_accepted() {
        let state = test_state().await;
        let did = "did:plc:agentbearer6666666666";
        seed_agent_identity(&state, "reg_okres", did, "claimed").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_okres",
            "com.atproto.access",
            now_secs() + 600,
        );
        // The server's own origin is a valid resource; a trailing slash is tolerated.
        let body = format!(
            "grant_type={JWT_BEARER}&assertion={assertion}&resource=https%3A%2F%2Ftest.example.com%2F"
        );

        let resp = app(state).oneshot(post_token(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn jwt_bearer_active_unclaimed_identity_returns_invalid_grant() {
        // An `active` identity still owes the claim ceremony; no service assertion is minted for it,
        // so even a validly-signed assertion must be refused until the identity is `claimed`.
        let state = test_state().await;
        let did = "did:plc:agentbearer8888888888";
        seed_agent_identity(&state, "reg_active", did, "active").await;
        let assertion = mint_assertion(
            &state,
            did,
            "reg_active",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(resp).await["error"],
            "invalid_grant",
            "an unclaimed (active) identity must not be able to exchange an assertion"
        );
    }

    #[tokio::test]
    async fn jwt_bearer_subject_did_mismatch_returns_invalid_grant() {
        // Defense-in-depth: the registration row's DID must match the assertion's `sub`. Seed the
        // identity under one DID but sign the assertion for a different one.
        let state = test_state().await;
        seed_agent_identity(
            &state,
            "reg_mismatch",
            "did:plc:agentbearer7777777777",
            "claimed",
        )
        .await;
        let assertion = mint_assertion(
            &state,
            "did:plc:someoneelse00000000",
            "reg_mismatch",
            "com.atproto.access",
            now_secs() + 600,
        );

        let resp = app(state)
            .oneshot(post_token(&format!(
                "grant_type={JWT_BEARER}&assertion={assertion}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(resp).await["error"],
            "invalid_grant",
            "an assertion sub that doesn't match the registration DID must be rejected"
        );
    }
}
