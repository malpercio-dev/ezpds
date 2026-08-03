// pattern: Imperative Shell
//
// The `refresh_token` grant (RFC 6749 §6 + DPoP RFC 9449): validate the DPoP proof, look up the
// stored refresh token, enforce the client_id match and the DPoP `jkt` binding (a NULL jkt predates
// binding enforcement and is rejected), then rotate — mark the old token superseded and mint a
// fresh DPoP-bound access token + new refresh token in the same session family, carrying the
// granted scope and the session's absolute expiry forward. A superseded token replayed within the
// short grace window is a concurrent duplicate refresh and still rotates; replayed later, it is a
// theft signal and the whole session family is revoked.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{
    cleanup_expired_state, issue_access_token, token_response_headers, TokenRequestForm,
    TokenResponse,
};
use crate::app::AppState;
use crate::auth::token::generate_token;
use crate::auth::{issue_nonce, validate_dpop_for_token_endpoint, DpopTokenEndpointError};
use crate::db::oauth::{
    delete_oauth_refresh_session, get_oauth_refresh_token, store_rotated_oauth_refresh_token,
    supersede_oauth_refresh_token,
};
use crate::routes::oauth_errors::OAuthTokenError;

pub(super) async fn handle_refresh_token(
    state: &AppState,
    headers: &HeaderMap,
    form: TokenRequestForm,
) -> Response {
    // Prune stale nonces and expired tokens on every request.
    cleanup_expired_state(state).await;

    // Required fields.
    let refresh_token_plaintext = match form.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: refresh_token")
                .into_response();
        }
    };
    let client_id = match form.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: client_id")
                .into_response();
        }
    };

    // Enforce the client's registered token_endpoint_auth_method (private_key_jwt clients
    // must present a valid client_assertion; public clients must not).
    if let Err(e) = super::client_auth::authenticate_token_client(
        state,
        &client_id,
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    )
    .await
    {
        return e.into_response();
    }
    // Reject multiple DPoP headers (RFC 9449 §11.1).
    if headers.get_all("DPoP").iter().count() > 1 {
        return OAuthTokenError::new(
            "invalid_dpop_proof",
            "multiple DPoP headers are not permitted",
        )
        .into_response();
    }

    // Validate DPoP proof — must be present, structurally valid, and carry a valid server nonce.
    let dpop_token = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => {
            return OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
                .into_response();
        }
    };

    let token_url = format!(
        "{}/oauth/token",
        state.config.public_url.trim_end_matches('/')
    );

    let jkt =
        match validate_dpop_for_token_endpoint(&dpop_token, "POST", &token_url, &state.dpop_nonces)
            .await
        {
            Ok(jkt) => jkt,
            Err(DpopTokenEndpointError::MissingHeader) => {
                return OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
                    .into_response();
            }
            Err(DpopTokenEndpointError::InvalidProof(msg)) => {
                return OAuthTokenError::new("invalid_dpop_proof", msg).into_response();
            }
            Err(DpopTokenEndpointError::UseNonce(fresh_nonce)) => {
                return OAuthTokenError::with_nonce(
                    "use_dpop_nonce",
                    "DPoP nonce required",
                    fresh_nonce,
                )
                .into_response();
            }
        };

    // Hash the presented refresh token for DB lookup.
    let token_hash = match URL_SAFE_NO_PAD.decode(refresh_token_plaintext.as_str()) {
        Ok(bytes) => crate::auth::token::sha256_hex(&bytes),
        Err(_) => {
            return OAuthTokenError::new("invalid_grant", "refresh token not found or expired")
                .into_response();
        }
    };

    // Retrieve the refresh token (without consuming yet).
    let stored = match get_oauth_refresh_token(&state.db, &token_hash).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "refresh token not found or expired")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to retrieve refresh token");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Verify client_id matches before consuming.
    if stored.client_id != client_id {
        return OAuthTokenError::new("invalid_grant", "client_id mismatch").into_response();
    }

    // DPoP binding check: tokens issued since V012 always carry jkt.
    // A NULL jkt means the token predates DPoP binding enforcement — reject it.
    match stored.jkt.as_deref() {
        None => {
            // Refresh tokens issued after V012 always have a jkt. A NULL jkt means
            // the token predates DPoP binding enforcement — reject rather than
            // silently accepting any key.
            return OAuthTokenError::new("invalid_grant", "refresh token not found or expired")
                .into_response();
        }
        Some(stored_jkt) => {
            use subtle::ConstantTimeEq;
            if !bool::from(stored_jkt.as_bytes().ct_eq(jkt.as_bytes())) {
                return OAuthTokenError::new("invalid_grant", "DPoP key mismatch").into_response();
            }
        }
    }

    // All validations passed. Rotation keeps superseded rows around instead of deleting
    // them, so a rotated-away token can be told apart from an unknown one:
    //
    // - current token → mark it superseded (its grace window starts now) and rotate;
    // - superseded within the grace window → a concurrent duplicate refresh (multi-tab,
    //   background+foreground race); rotate again off the family so both callers hold a
    //   live session, rather than stranding the race's loser with `invalid_grant`;
    // - superseded beyond the grace window → refresh-token reuse, the classic stolen-token
    //   signal: revoke the entire session family.
    match stored.superseded_within_grace {
        None => {
            match supersede_oauth_refresh_token(&state.db, &token_hash).await {
                // False = a concurrent request superseded it between our read and this
                // write — that is exactly the within-grace duplicate case; fall through.
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "failed to supersede refresh token");
                    return OAuthTokenError::new("server_error", "database error").into_response();
                }
            }
        }
        Some(true) => {}
        Some(false) => {
            tracing::warn!(
                did = %stored.did,
                client_id = %stored.client_id,
                "refresh token reuse beyond the concurrency grace window; revoking session family"
            );
            if let Err(e) = delete_oauth_refresh_session(&state.db, &stored.session_id).await {
                tracing::error!(error = %e, "failed to revoke refresh session after reuse");
                return OAuthTokenError::new("server_error", "database error").into_response();
            }
            return OAuthTokenError::new("invalid_grant", "refresh token not found or expired")
                .into_response();
        }
    }

    // Carry the granted granular scope forward across rotation — the rotated
    // session grants exactly what the original did. Refresh rows written before
    // granular scopes were persisted hold the fixed `com.atproto.refresh` string;
    // reusing that verbatim would mint an access token that resolves to
    // `AuthScope::Refresh` and fail every access-gated route, so coerce any scope
    // that isn't a valid atproto grant to the base `atproto` scope (full access
    // under the current session model).
    let granted_scope = if crate::auth::oauth_scopes::is_atproto_oauth_scope(&stored.scope) {
        stored.scope
    } else {
        "atproto".to_string()
    };

    // Issue new ES256 access token.
    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        &stored.did,
        &granted_scope,
        Some(&jkt),
        None,
        &state.config.public_url,
        super::ACCESS_TOKEN_TTL_SECS,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Generate and store the rotated refresh token: same session family, and the session's
    // absolute expiry carried forward verbatim — rotation never extends a session.
    let new_refresh = generate_token();
    if let Err(e) = store_rotated_oauth_refresh_token(
        &state.db,
        &new_refresh.hash,
        &stored.client_id,
        &stored.did,
        &granted_scope,
        &jkt,
        &stored.session_id,
        &stored.expires_at,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store rotated refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // Issue fresh DPoP nonce for the next request.
    let fresh_nonce = issue_nonce(&state.dpop_nonces).await;

    let response_headers = match token_response_headers(&fresh_nonce) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };

    (
        StatusCode::OK,
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: "DPoP",
            expires_in: super::ACCESS_TOKEN_TTL_SECS,
            refresh_token: new_refresh.plaintext,
            scope: granted_scope,
            sub: stored.did,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use tower::ServiceExt;

    use super::super::test_support::{
        dpop_thumbprint, json_body, make_dpop_proof, now_secs, post_token_with_dpop,
    };
    use crate::app::{app, test_state, AppState};
    use crate::auth::issue_nonce;
    use crate::auth::token::generate_token;
    use crate::db::oauth::{register_oauth_client, store_initial_oauth_refresh_token};

    /// Seed the DB with a client + account + fresh refresh token bound to `jkt`.
    ///
    /// Returns the base64url plaintext of the seeded refresh token.
    async fn seed_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        store_initial_oauth_refresh_token(
            &state.db,
            &token.hash,
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            "atproto transition:generic",
            jkt,
        )
        .await
        .unwrap();
        token.plaintext
    }

    /// Seed the DB with an already-expired refresh token (bypasses store_initial_oauth_refresh_token's +24h).
    ///
    /// Returns the base64url plaintext.
    async fn seed_expired_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
             VALUES (?, ?, ?, 'com.atproto.refresh', ?, datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .bind(jkt)
        .execute(&state.db)
        .await
        .unwrap();
        token.plaintext
    }

    /// Seed a valid refresh token holding the legacy fixed `com.atproto.refresh`
    /// scope (as written before granular scopes were persisted).
    async fn seed_legacy_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
             VALUES (?, ?, ?, 'com.atproto.refresh', ?, datetime('now', '+24 hours'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .bind(jkt)
        .execute(&state.db)
        .await
        .unwrap();
        token.plaintext
    }

    /// A legacy refresh row (scope `com.atproto.refresh`, written before granular
    /// scopes were persisted) must rotate into an *access-level* token: the access
    /// token's `scope` claim and the response `scope` are coerced to `atproto`
    /// rather than reused verbatim, which would resolve to `AuthScope::Refresh`.
    #[tokio::test]
    async fn refresh_token_legacy_scope_is_coerced_to_atproto() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_legacy_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = json_body(resp).await;
        assert_eq!(
            json["scope"], "atproto",
            "a legacy com.atproto.refresh scope must be coerced to the atproto access scope"
        );

        // The minted access token carries the coerced scope, so it resolves to an
        // access-level session rather than a refresh-only one.
        let at = json["access_token"].as_str().unwrap();
        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        assert_eq!(payload["scope"], "atproto");
    }

    #[tokio::test]
    async fn refresh_token_happy_path_returns_200_with_new_tokens() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "valid rotation must return 200"
        );
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response must include DPoP-Nonce header"
        );

        let json = json_body(resp).await;
        assert!(
            json["access_token"].is_string(),
            "access_token must be present"
        );
        assert_eq!(json["token_type"], "DPoP");
        assert_eq!(json["expires_in"], 900);
        assert!(
            json["refresh_token"].is_string(),
            "rotated refresh_token must be present"
        );
        assert_eq!(
            json["scope"], "atproto transition:generic",
            "the granted granular scope must be carried forward on rotation"
        );

        // AT Protocol OAuth requires `sub` (the account DID) on refresh responses too, not just
        // the initial exchange — a client re-verifies it on every rotation.
        assert_eq!(
            json["sub"], "did:plc:testaccount000000000000",
            "rotation response must return the account DID in sub"
        );

        // Rotated token must differ from the original and be the correct length.
        let new_rt = json["refresh_token"].as_str().unwrap();
        assert_eq!(new_rt.len(), 43, "rotated refresh_token must be 43 chars");
        assert_ne!(
            new_rt,
            plaintext.as_str(),
            "rotated refresh token must differ from original"
        );

        // Verify access token has correct iss and aud.
        let at = json["access_token"].as_str().unwrap();
        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        assert_eq!(
            payload["iss"], "https://test.example.com",
            "iss must be public_url"
        );
        assert_eq!(
            payload["aud"], "https://test.example.com",
            "aud must be public_url"
        );
    }

    /// A concurrent duplicate refresh (multi-tab, background+foreground race) presents the
    /// same token twice in quick succession. Within the reuse grace window the second use
    /// must succeed with its own fresh token pair — stranding the race's loser with
    /// `invalid_grant` is what silently logs mobile clients out.
    #[tokio::test]
    async fn refresh_token_second_use_within_grace_succeeds() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        // First use: succeeds. Clone state so the second request shares the same DB.
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce1),
            now_secs(),
        );
        let first_resp = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop1))
            .await
            .unwrap();
        assert_eq!(
            first_resp.status(),
            StatusCode::OK,
            "first use must succeed"
        );
        let first_json = json_body(first_resp).await;

        // Second use of the same original token, seconds later: still inside the grace
        // window, so it must succeed and mint its own distinct token pair.
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let resp2 = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop2))
            .await
            .unwrap();

        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "second use within the grace window must succeed (concurrent duplicate refresh)"
        );
        let json2 = json_body(resp2).await;
        assert!(json2["refresh_token"].is_string());
        assert_ne!(
            json2["refresh_token"], first_json["refresh_token"],
            "each duplicate refresh mints its own rotated token"
        );
    }

    /// A superseded token presented *after* the grace window is the stolen-token signal:
    /// the whole session family — including the current rotated token — must be revoked.
    #[tokio::test]
    async fn refresh_token_stale_reuse_revokes_session_family() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;

        // Rotate once so the seeded token becomes superseded and a successor exists.
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce1),
            now_secs(),
        );
        let first_resp = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop1))
            .await
            .unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        let successor = json_body(first_resp).await["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();

        // Age the supersession past the grace window (the handler compares against
        // `datetime('now', '-60 seconds')`).
        sqlx::query(
            "UPDATE oauth_tokens SET superseded_at = datetime('now', '-120 seconds') \
             WHERE superseded_at IS NOT NULL",
        )
        .execute(&state.db)
        .await
        .unwrap();

        // Replaying the superseded token now must fail AND revoke the successor too.
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let resp2 = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop2))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
        let json2 = json_body(resp2).await;
        assert_eq!(json2["error"], "invalid_grant");

        // The rotated successor is dead as well — the family is gone.
        let successor_body = format!(
            "grant_type=refresh_token\
             &refresh_token={successor}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );
        let nonce3 = issue_nonce(&state.dpop_nonces).await;
        let dpop3 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce3),
            now_secs(),
        );
        let resp3 = app(state)
            .oneshot(post_token_with_dpop(&successor_body, &dpop3))
            .await
            .unwrap();
        assert_eq!(
            resp3.status(),
            StatusCode::BAD_REQUEST,
            "stale reuse must revoke the whole session family, successor included"
        );
        let json3 = json_body(resp3).await;
        assert_eq!(json3["error"], "invalid_grant");
    }

    /// Rotation carries the session's absolute expiry forward — a rotated token never
    /// extends the session past what the initial grant set.
    #[tokio::test]
    async fn refresh_rotation_carries_absolute_expiry_forward() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let original_expiry: (String,) =
            sqlx::query_as("SELECT expires_at FROM oauth_tokens LIMIT 1")
                .fetch_one(&state.db)
                .await
                .unwrap();

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );
        let resp = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rotated_expiry: (String,) = sqlx::query_as(
            "SELECT expires_at FROM oauth_tokens WHERE superseded_at IS NULL LIMIT 1",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(
            rotated_expiry.0, original_expiry.0,
            "rotation must inherit the session's absolute expiry, not mint a fresh one"
        );
    }

    #[tokio::test]
    async fn refresh_token_expired_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_expired_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "expired refresh token must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn refresh_token_jkt_mismatch_returns_invalid_grant() {
        let state = test_state().await;
        let stored_key = SigningKey::random(&mut OsRng);
        let stored_jkt = dpop_thumbprint(&stored_key);

        // Seed token bound to stored_key's thumbprint.
        let plaintext = seed_refresh_token(&state, &stored_jkt).await;

        // Build proof with a DIFFERENT key — thumbprint will not match stored_jkt.
        let different_key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &different_key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "DPoP key mismatch must return invalid_grant"
        );
    }

    // ── C-1/C-2 ordering: token not consumed on validation failure ────────────

    #[tokio::test]
    async fn refresh_token_not_consumed_on_client_id_mismatch() {
        // Verifies that the refresh token is NOT deleted when client_id validation fails.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);
        let plaintext = seed_refresh_token(&state, &jkt).await;

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        // Attempt 1: wrong client_id — must fail.
        let bad_body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fwrong.example.com%2Fclient-metadata.json"
        );
        let bad_resp = app(state.clone())
            .oneshot(post_token_with_dpop(&bad_body, &dpop))
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
        let bad_json = json_body(bad_resp).await;
        assert_eq!(bad_json["error"], "invalid_grant");

        // Attempt 2: correct client_id — must succeed (token was not consumed above).
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let good_body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );
        let good_resp = app(state)
            .oneshot(post_token_with_dpop(&good_body, &dpop2))
            .await
            .unwrap();
        assert_eq!(
            good_resp.status(),
            StatusCode::OK,
            "refresh token must still be usable after a failed attempt with wrong client_id"
        );
    }

    // ── F3: NULL jkt rejected ─────────────────────────────────────────────────

    #[tokio::test]
    async fn refresh_token_with_null_jkt_returns_invalid_grant() {
        // Tokens issued before DPoP binding enforcement may have jkt = NULL.
        // These must be rejected rather than silently accepting any DPoP key.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        // Seed client and account (FK constraints required by oauth_tokens).
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        // Insert a refresh token with jkt = NULL directly (bypasses store_initial_oauth_refresh_token
        // which always sets jkt, simulating a pre-V012 row).
        let token = generate_token();
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
             VALUES (?, ?, ?, 'com.atproto.refresh', NULL, datetime('now', '+24 hours'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .execute(&state.db)
        .await
        .unwrap();

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json",
            token.plaintext
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "refresh token with NULL jkt must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn refresh_token_client_id_mismatch_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        // Wrong client_id — does not match stored "https://app.example.com/client-metadata.json".
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fother.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "client_id mismatch must return invalid_grant"
        );
    }
}
