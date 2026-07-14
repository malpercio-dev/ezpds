// pattern: Imperative Shell
//
// The `authorization_code` grant (RFC 6749 §4.1 + PKCE RFC 7636 + DPoP RFC 9449): validate the
// DPoP proof at the token endpoint, verify the PKCE S256 challenge and client_id/redirect_uri
// against the stored authorization code, consume the code, then mint a DPoP-bound access token +
// rotating refresh token.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use super::{
    cleanup_expired_state, issue_access_token, token_response_headers, TokenRequestForm,
    TokenResponse,
};
use crate::app::AppState;
use crate::auth::token::generate_token;
use crate::auth::{issue_nonce, validate_dpop_for_token_endpoint, DpopTokenEndpointError};
use crate::db::oauth::{
    delete_authorization_code, get_authorization_code, store_oauth_refresh_token,
};
use crate::routes::oauth_errors::OAuthTokenError;

/// Verify the PKCE S256 code challenge.
fn verify_pkce_s256(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    // Constant-time comparison to prevent timing oracle.
    subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), stored_challenge.as_bytes()).into()
}

pub(super) async fn handle_authorization_code(
    state: &AppState,
    headers: &HeaderMap,
    form: TokenRequestForm,
) -> Response {
    // Prune stale nonces and expired tokens on every request.
    cleanup_expired_state(state).await;

    // Required fields: code, redirect_uri, client_id, code_verifier.
    let code = match form.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: code")
                .into_response()
        }
    };
    let redirect_uri = match form.redirect_uri.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: redirect_uri")
                .into_response()
        }
    };
    let client_id = match form.client_id.as_deref() {
        Some(id) if !id.is_empty() => id,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: client_id")
                .into_response()
        }
    };
    let code_verifier = match form.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: code_verifier")
                .into_response()
        }
    };

    // RFC 7636 §4.1: 43–128 unreserved characters [A-Za-z0-9\-._~] (F7).
    {
        const CV_UNRESERVED: fn(u8) -> bool =
            |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        if code_verifier.len() < 43
            || code_verifier.len() > 128
            || !code_verifier.bytes().all(CV_UNRESERVED)
        {
            return OAuthTokenError::new(
                "invalid_grant",
                "code_verifier must be 43–128 unreserved characters [A-Za-z0-9-._~]",
            )
            .into_response();
        }
    }

    // Reject multiple DPoP headers (RFC 9449 §11.1).
    if headers.get_all("DPoP").iter().count() > 1 {
        return OAuthTokenError::new(
            "invalid_dpop_proof",
            "multiple DPoP headers are not permitted",
        )
        .into_response();
    }

    // Validate DPoP proof.
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

    // Hash the presented code for DB lookup.
    let code_hash = match URL_SAFE_NO_PAD.decode(code) {
        Ok(bytes) => crate::auth::token::sha256_hex(&bytes),
        Err(_) => {
            return OAuthTokenError::new("invalid_grant", "authorization code invalid or expired")
                .into_response();
        }
    };

    // Retrieve the authorization code (without consuming yet).
    let auth_code = match get_authorization_code(&state.db, &code_hash).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "authorization code invalid or expired")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to retrieve authorization code");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Verify client_id matches before consuming.
    if auth_code.client_id != client_id {
        return OAuthTokenError::new("invalid_grant", "client_id mismatch").into_response();
    }

    // Verify redirect_uri matches before consuming.
    if auth_code.redirect_uri != redirect_uri {
        return OAuthTokenError::new("invalid_grant", "redirect_uri mismatch").into_response();
    }

    // Enforce S256: reject plain (or any other method) in case it ever enters the DB.
    if auth_code.code_challenge_method != "S256" {
        return OAuthTokenError::new("invalid_request", "unsupported code_challenge_method")
            .into_response();
    }

    // Verify PKCE S256 challenge before consuming.
    if !verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        return OAuthTokenError::new(
            "invalid_grant",
            "code_verifier does not match code_challenge",
        )
        .into_response();
    }

    // All validations passed; now consume the code.
    if let Err(e) = delete_authorization_code(&state.db, &code_hash).await {
        tracing::error!(error = %e, "failed to delete authorization code");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // The access token carries the granular scope set granted at consent time verbatim —
    // `auth/oauth_scopes.rs` enforces it per route and `extractors.rs` reads the token's
    // scope claim on every authenticated request.
    let granted_scope = auth_code.scope;

    // Issue ES256 access token.
    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        &auth_code.did,
        &granted_scope,
        Some(&jkt),
        None,
        &state.config.public_url,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Generate and store refresh token, persisting the granted scope so rotation
    // carries it forward.
    let refresh = generate_token();
    if let Err(e) = store_oauth_refresh_token(
        &state.db,
        &refresh.hash,
        &auth_code.client_id,
        &auth_code.did,
        &granted_scope,
        &jkt,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // Issue a fresh DPoP nonce for the next request.
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
            expires_in: 300,
            refresh_token: refresh.plaintext,
            scope: granted_scope,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::super::test_support::{
        dpop_key_to_jwk, dpop_thumbprint, json_body, make_dpop_proof, now_secs, post_token,
        post_token_with_dpop,
    };
    use crate::app::{app, test_state, AppState};
    use crate::auth::issue_nonce;
    use crate::auth::token::generate_token;
    use crate::db::oauth::{register_oauth_client, store_authorization_code};

    /// Seed the DB with a test client + account + authorization code.
    async fn seed_auth_code(state: &AppState, code_hash: &str, code_challenge: &str) {
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

        store_authorization_code(
            &state.db,
            code_hash,
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            code_challenge,
            "S256",
            "https://app.example.com/callback",
            "atproto",
        )
        .await
        .unwrap();
    }

    // ── DPoP proof validation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_dpop_header_returns_invalid_dpop_proof() {
        let resp = app(test_state().await)
            .oneshot(post_token(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_wrong_htm_returns_invalid_dpop_proof() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "GET", // wrong — must be POST
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_dpop_proof",
            "wrong htm must return invalid_dpop_proof"
        );
    }

    #[tokio::test]
    async fn dpop_wrong_htu_returns_invalid_dpop_proof() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://wrong-url.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_stale_iat_returns_invalid_dpop_proof() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs() - 120, // 2 minutes ago — stale
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    // ── DPoP nonces ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn dpop_without_nonce_returns_use_dpop_nonce_with_header() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            None, // no nonce
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &dpop,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "use_dpop_nonce response must include DPoP-Nonce header"
        );
        let json = json_body(resp).await;
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    #[tokio::test]
    async fn dpop_with_unknown_nonce_returns_use_dpop_nonce() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some("fabricated-nonce-that-was-never-issued"),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    // ── authorization_code grant ──────────────────────────────────────────────

    #[tokio::test]
    async fn authorization_code_happy_path_returns_200_with_tokens() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        // Build PKCE S256 challenge.
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        // Raw code (43-char base64url) and its SHA-256 hex hash for DB storage.
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };

        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;

        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={code_verifier}"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "happy path must return 200");

        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response must include fresh DPoP-Nonce header"
        );

        let json = json_body(resp).await;

        assert!(
            json["access_token"].is_string(),
            "access_token must be present"
        );
        assert_eq!(json["token_type"], "DPoP", "token_type must be DPoP");
        assert_eq!(json["expires_in"], 300);
        assert!(
            json["refresh_token"].is_string(),
            "refresh_token must be present"
        );
        assert!(json["scope"].is_string(), "scope must be present");
        assert_eq!(
            json["scope"], "atproto",
            "the granted granular scope must be returned"
        );

        let rt = json["refresh_token"].as_str().unwrap();
        assert_eq!(rt.len(), 43, "refresh_token must be 43 chars");

        let at = json["access_token"].as_str().unwrap();
        let header_b64 = at.split('.').next().unwrap();
        let header_json = String::from_utf8(URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        assert_eq!(header["typ"], "at+jwt", "access token typ must be at+jwt");
        assert_eq!(header["alg"], "ES256", "access token alg must be ES256");

        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        let cnf_jkt = payload["cnf"]["jkt"].as_str().unwrap();
        let expected_jkt = dpop_thumbprint(&key);
        assert_eq!(
            cnf_jkt, expected_jkt,
            "cnf.jkt must match DPoP key thumbprint"
        );
        assert_eq!(
            payload["iss"], "https://test.example.com",
            "iss must be public_url"
        );
        assert_eq!(
            payload["aud"], "https://test.example.com",
            "aud must be public_url"
        );
    }

    #[tokio::test]
    async fn wrong_code_verifier_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        let code_verifier = "correctverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier=wrong-verifier"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "wrong code_verifier must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn consumed_code_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;

        let body = format!(
            "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier={code_verifier}"
        );

        // First use — should succeed.
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce1),
            now_secs(),
        );

        // Build the app twice using different oneshot calls on the same state.
        // Clone state so the DB pool is shared across both calls.
        let resp1 = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop1))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first use must succeed");

        // Second use — code was consumed.
        let state2 = state.clone();
        let nonce2 = issue_nonce(&state2.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let resp2 = app(state2)
            .oneshot(post_token_with_dpop(&body, &dpop2))
            .await
            .unwrap();
        let json2 = json_body(resp2).await;
        assert_eq!(
            json2["error"], "invalid_grant",
            "second use must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn client_id_mismatch_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fwrong-client.example.com%2F&code_verifier={code_verifier}"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "client_id mismatch must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn redirect_uri_mismatch_returns_invalid_grant() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fwrong.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier={code_verifier}"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "redirect_uri mismatch must return invalid_grant"
        );
    }

    // ── C-1/C-2 ordering: code not consumed on validation failure ─────────────

    #[tokio::test]
    async fn authorization_code_not_consumed_on_client_id_mismatch() {
        // Verifies that the auth code is NOT deleted when client_id validation fails —
        // i.e., the validate-before-consume ordering is in effect.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // 43-char S256 verifier
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let code = generate_token();
        seed_auth_code(&state, &code.hash, &challenge).await;

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
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fwrong.example.com%2Fclient-metadata.json\
             &code_verifier={verifier}",
            raw_code = code.plaintext
        );
        let bad_resp = app(state.clone())
            .oneshot(post_token_with_dpop(&bad_body, &dpop))
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
        let bad_json = json_body(bad_resp).await;
        assert_eq!(bad_json["error"], "invalid_grant");

        // Attempt 2: correct client_id — must succeed (code was not consumed above).
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let good_body = format!(
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={verifier}",
            raw_code = code.plaintext
        );
        let good_resp = app(state)
            .oneshot(post_token_with_dpop(&good_body, &dpop2))
            .await
            .unwrap();
        assert_eq!(
            good_resp.status(),
            StatusCode::OK,
            "code must still be usable after a failed attempt with wrong client_id"
        );
    }

    // ── C-5: multiple DPoP headers at token endpoint ──────────────────────────

    #[tokio::test]
    async fn multiple_dpop_headers_at_token_endpoint_returns_invalid_dpop_proof() {
        // The multiple-DPoP check fires after required field validation, so all required
        // fields must be present for the check to be reached.
        let state = test_state().await;
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", "first.proof.value")
            .header("DPoP", "second.proof.value")
            .body(Body::from(
                "grant_type=authorization_code\
                 &code=somerawcode\
                 &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
                 &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
                 &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ))
            .unwrap();
        let resp = app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    // ── F2: code_challenge_method = "plain" rejected ──────────────────────────

    #[tokio::test]
    async fn plain_code_challenge_method_returns_invalid_request() {
        // An auth code with code_challenge_method = "plain" must be rejected at the
        // token endpoint even if the PKCE check would otherwise pass.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

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

        // Seed an auth code with code_challenge_method = "plain" directly.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = generate_token();
        store_authorization_code(
            &state.db,
            &code.hash,
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            verifier, // for "plain", code_challenge == code_verifier
            "plain",
            "https://app.example.com/callback",
            "com.atproto.access",
        )
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
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={verifier}",
            raw_code = code.plaintext
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_request",
            "code_challenge_method=plain must return invalid_request (RFC 7636 §4.6)"
        );
    }

    // ── F7: code_verifier length validation ───────────────────────────────────

    #[tokio::test]
    async fn short_code_verifier_returns_invalid_grant() {
        // RFC 7636 §4.1 requires 43–128 characters. A verifier shorter than 43
        // chars must be rejected before the PKCE hash comparison.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let code = generate_token();
        seed_auth_code(&state, &code.hash, &challenge).await;

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );
        let body = format!(
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier=short", // < 43 chars
            raw_code = code.plaintext
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "code_verifier shorter than 43 chars must return invalid_grant"
        );
    }

    // ── F5: Cache-Control headers on token responses ──────────────────────────

    #[tokio::test]
    async fn authorization_code_success_response_has_cache_control_no_store() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let code = generate_token();
        seed_auth_code(&state, &code.hash, &challenge).await;

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );
        let body = format!(
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={verifier}",
            raw_code = code.plaintext
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "token response must include Cache-Control: no-store (RFC 6749 §5.1)"
        );
    }

    // ── transition:generic end-to-end: exchange → DPoP-authenticated service auth ──

    /// DPoP proof for a *resource* call: carries the `ath` (access token hash) claim
    /// resource endpoints require, unlike the token-endpoint proofs above.
    fn make_dpop_proof_with_ath(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        access_token: &str,
    ) -> String {
        let jwk = dpop_key_to_jwk(key);
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        let payload = serde_json::json!({
            "htm": htm, "htu": htu, "iat": now_secs(),
            "jti": Uuid::new_v4().to_string(), "ath": ath,
        });
        let hdr = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = key.sign(format!("{hdr}.{pay}").as_bytes());
        format!(
            "{hdr}.{pay}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
        )
    }

    #[tokio::test]
    async fn transition_generic_dpop_token_mints_service_auth_for_migration() {
        // The wallet's outbound-migration source flow, end to end: an authorization
        // code granted "atproto transition:generic" is exchanged for a DPoP-bound
        // access token, which then mints service auth for a foreign destination
        // (aud = the destination server DID, lxm = createAccount). transition:generic
        // is app-password-equivalent and must permit this (allows_rpc), exactly as
        // the reference PDS permits it — this is the first authenticated call the
        // migration orchestrator makes against its source PDS.
        let state = crate::routes::test_utils::state_with_master_key().await;
        let key = SigningKey::random(&mut OsRng);
        let did = "did:plc:migratesource00000000000";
        crate::routes::test_utils::seed_account_with_repo(&state.db, did).await;

        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();

        let code_verifier = "testcodeverifier1234567890abcdefghijklmnopqr";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "dGVzdGF1dGhvcml6YXRpb25jb2RlMTIzNDU2Nzg5MDEyMw";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        store_authorization_code(
            &state.db,
            &code_hash,
            "https://app.example.com/client-metadata.json",
            did,
            &code_challenge,
            "S256",
            "https://app.example.com/callback",
            "atproto transition:generic",
        )
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
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={code_verifier}"
        );
        let resp = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "token exchange must succeed");
        let json = json_body(resp).await;
        assert_eq!(
            json["scope"], "atproto transition:generic",
            "the granted scope must survive the exchange intact"
        );
        let access_token = json["access_token"].as_str().unwrap().to_string();

        // The orchestrator's first authenticated source call: mint service auth for
        // the destination's createAccount. RFC 9449 request shape (DPoP scheme + proof).
        let sa_path = "/xrpc/com.atproto.server.getServiceAuth";
        let htu = format!("{}{sa_path}", state.config.public_url);
        let proof = make_dpop_proof_with_ath(&key, "GET", &htu, &access_token);
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "{sa_path}?aud=did%3Aweb%3Adest.example.com&lxm=com.atproto.server.createAccount"
                    ))
                    .header("Authorization", format!("DPoP {access_token}"))
                    .header("DPoP", proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "transition:generic must permit service auth for the migration flow"
        );
        let json = json_body(resp).await;
        assert!(json["token"].is_string(), "must return a service-auth JWT");
    }
}
