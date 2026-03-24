pub mod dpop;
pub mod extractors;
pub mod jwt;
pub mod password;
pub mod rate_limit;
pub mod signing_key;

mod bearer;

// Re-export the public API so callers don't need to know the internal layout.
pub use dpop::{
    cleanup_expired_nonces, issue_nonce, new_nonce_store, validate_dpop_for_token_endpoint,
    DpopNonceStore, DpopTokenEndpointError,
};
// Foundational types: used once authenticated routes are wired up.
#[allow(unused_imports)]
pub use extractors::AuthenticatedUser;
#[allow(unused_imports)]
pub use jwt::{AuthScope, TokenType};
pub use signing_key::{load_or_create_oauth_signing_key, OAuthSigningKey};

// Test-only: make private helpers visible to the test module below (which uses `use super::*`).
#[cfg(test)]
pub(super) use bearer::extract_bearer_token;
#[cfg(test)]
pub(super) use dpop::{
    dpop_alg_from_str, jwk_thumbprint, validate_and_consume_nonce, validate_dpop,
};
#[cfg(test)]
pub(super) use jwt::{parse_scope, peek_jwt_typ, verify_access_token};

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::app::{test_state, AppState};

    // ── Test token helpers ────────────────────────────────────────────────────

    /// Claims struct for minting test JWTs.
    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        aud: String,
        exp: u64,
        scope: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cnf: Option<serde_json::Value>,
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mint a valid HS256 JWT using the given secret.
    fn mint_token(
        sub: &str,
        scope: &str,
        exp_offset_secs: i64,
        secret: &[u8; 32],
        cnf: Option<serde_json::Value>,
    ) -> String {
        let exp = (now_secs() as i64 + exp_offset_secs) as u64;
        let claims = TestClaims {
            sub: sub.to_owned(),
            aud: "did:plc:test".to_owned(),
            exp,
            scope: scope.to_owned(),
            cnf,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    // ── DPoP test helpers ─────────────────────────────────────────────────────

    /// Compute the JWK thumbprint for a P-256 signing key.
    fn dpop_key_thumbprint(key: &SigningKey) -> String {
        let jwk = dpop_key_to_jwk(key);
        jwk_thumbprint(&jwk).unwrap()
    }

    /// Build a minimal JWK Value from a P-256 signing key (public portion only).
    fn dpop_key_to_jwk(key: &SigningKey) -> serde_json::Value {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    /// Build a valid DPoP proof JWT signed with the given P-256 key using current time as `iat`.
    /// Includes the ath (access token hash) claim for use at resource endpoints.
    fn make_dpop_proof(key: &SigningKey, htm: &str, htu: &str) -> String {
        // Use a dummy access token for tests — the ath is computed from this.
        let dummy_access_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuZXhhbXBsZS5jb20iLCJqdGkiOiIxMjM0NTY3OC1hYmNkLWVmZ2gtaWprbCIsInN1YiI6ImRpZDpwbGM6YWxpY2UiLCJhdWQiOiJodHRwczovL3Rlc3QuZXhhbXBsZS5jb20iLCJpYXQiOjE2NzcwMDAwMDAsImV4cCI6MTY3NzAwMzAwMCwic2NvcGUiOiJjb20uYXRwcm90by5hY2Nlc3MiLCJjbmYiOnsianRrIjoiMTIzNDU2Nzg5MCJ9fQ.signature";
        make_dpop_proof_with_iat_and_ath(key, htm, htu, now_secs() as i64, dummy_access_token)
    }

    /// Build a DPoP proof JWT with an explicit `iat` — used to test freshness rejection.
    /// Does NOT include ath claim (for token endpoint tests where ath is not required).
    fn make_dpop_proof_with_iat(key: &SigningKey, htm: &str, htu: &str, iat: i64) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": uuid::Uuid::new_v4().to_string(),
        });

        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let signing_input = format!("{hdr_b64}.{pay_b64}");

        let sig: Signature = key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);

        format!("{hdr_b64}.{pay_b64}.{sig_b64}")
    }

    /// Build a DPoP proof JWT with explicit `iat` and `ath` claim (for resource endpoint testing).
    fn make_dpop_proof_with_iat_and_ath(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        iat: i64,
        access_token: &str,
    ) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let ath = {
            let hash = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        };
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": uuid::Uuid::new_v4().to_string(),
            "ath": ath,
        });

        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let signing_input = format!("{hdr_b64}.{pay_b64}");

        let sig: Signature = key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);

        format!("{hdr_b64}.{pay_b64}.{sig_b64}")
    }

    // ── Minimal test router ───────────────────────────────────────────────────

    fn protected_app(state: AppState) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|user: AuthenticatedUser| async move {
                    format!("did={} scope={:?}", user.did, user.scope)
                }),
            )
            .with_state(state)
    }

    async fn get_protected(app: Router, token: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().uri("/protected");
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Missing / malformed Authorization header ──────────────────────────────

    #[tokio::test]
    async fn missing_auth_header_returns_401_authentication_required() {
        let state = test_state().await;
        let resp = get_protected(protected_app(state), None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn bearer_prefix_missing_returns_401_authentication_required() {
        let state = test_state().await;
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Token abc123")
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    // ── Malformed / invalid token ─────────────────────────────────────────────

    #[tokio::test]
    async fn malformed_token_returns_401_invalid_token() {
        let state = test_state().await;
        let resp = get_protected(protected_app(state), Some("not.a.jwt")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn wrong_signature_returns_401_invalid_token() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &[0xFFu8; 32],
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── Expired token ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_token_returns_401_token_expired() {
        let state = test_state().await;
        let secret = state.jwt_secret;
        let token = mint_token("did:plc:user", "com.atproto.access", -1, &secret, None);
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
    }

    // ── Valid access tokens ───────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_access_token_extracts_did_and_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("did=did:plc:alice"));
        assert!(text.contains("scope=Access"));
    }

    #[tokio::test]
    async fn valid_refresh_token_extracts_refresh_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.refresh",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("scope=Refresh"));
    }

    #[tokio::test]
    async fn valid_app_pass_token_extracts_app_pass_scope() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.appPass",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("scope=AppPass"));
    }

    // ── Unknown scope ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_scope_returns_401_invalid_token() {
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.example.unknown",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── Audience validation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn token_with_wrong_audience_returns_401_when_server_did_configured() {
        use std::sync::Arc;
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.server_did = Some("did:plc:server".to_string());
        let state = AppState {
            config: Arc::new(config),
            ..base
        };

        // mint_token encodes aud = "did:plc:test" — wrong for did:plc:server
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — downgrade prevention (RFC 9449 §7.1) ──────────────────────────

    #[tokio::test]
    async fn dpop_bound_token_without_dpop_header_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);

        // Access token has cnf.jkt → DPoP-bound.
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // No DPoP header sent — must be rejected.
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_header_present_but_access_token_has_no_cnf_returns_401() {
        // Access token has no cnf claim at all. DPoP header is present with a valid
        // proof — must be rejected at the "access token missing DPoP binding" guard,
        // not earlier (the old test used "dummy.dpop.value" which failed at base64
        // decode and never reached the binding check).
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            None,
        );
        let dpop_proof = make_dpop_proof(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
        );
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_cnf_present_without_jkt_returns_401() {
        // Token with cnf:{} — cnf present but no jkt field. Must be rejected before
        // any DPoP proof is considered (guard added in round 2).
        let state = test_state().await;
        let token = mint_token(
            "did:plc:user",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({})), // cnf present but empty — no jkt
        );
        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — valid proof accepted ───────────────────────────────────────────

    #[tokio::test]
    async fn valid_dpop_bound_token_is_accepted() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);

        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // htu = public_url + path (matches how the extractor builds expected_htu)
        let htu = format!("{}/protected", state.config.public_url);
        // DPoP proof needs the ath (access token hash) claim for resource endpoint verification.
        let dpop_proof =
            make_dpop_proof_with_iat_and_ath(&dpop_key, "GET", &htu, now_secs() as i64, &token);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── DPoP — signature forgery rejected ────────────────────────────────────

    #[tokio::test]
    async fn dpop_proof_with_forged_signature_returns_401() {
        let state = test_state().await;
        // Attacker's key — different from the key that signed the access token.
        let attacker_key = SigningKey::random(&mut OsRng);
        let legit_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&legit_key);

        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // Proof is signed by attacker_key but claims legit_key's thumbprint in the header JWK.
        // The JWK in the proof header is attacker_key's public key → thumbprint mismatch.
        let htu = format!("{}/protected", state.config.public_url);
        let dpop_proof = make_dpop_proof(&attacker_key, "GET", &htu);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP — individual claim validation ───────────────────────────────────

    #[tokio::test]
    async fn dpop_wrong_htm_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        let htu = format!("{}/protected", state.config.public_url);
        // htm says POST but request is GET.
        let dpop_proof = make_dpop_proof(&dpop_key, "POST", &htu);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_wrong_htu_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // htu points to a different endpoint.
        let dpop_proof = make_dpop_proof(
            &dpop_key,
            "GET",
            &format!("{}/other-endpoint", state.config.public_url),
        );

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_wrong_typ_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );

        let jwk = dpop_key_to_jwk(&dpop_key);
        // Wrong typ — should be "dpop+jwt".
        let header = serde_json::json!({ "typ": "JWT", "alg": "ES256", "jwk": jwk });
        let payload = serde_json::json!({
            "htm": "GET",
            "htu": format!("{}/protected", state.config.public_url),
            "iat": now_secs() as i64,
            "jti": "test-jti",
        });
        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof = format!(
            "{hdr_b64}.{pay_b64}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
        );

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_empty_jti_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );

        let jwk = dpop_key_to_jwk(&dpop_key);
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        // Empty jti.
        let payload = serde_json::json!({
            "htm": "GET",
            "htu": format!("{}/protected", state.config.public_url),
            "iat": now_secs() as i64,
            "jti": "",
        });
        let hdr_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig: Signature = dpop_key.sign(format!("{hdr_b64}.{pay_b64}").as_bytes());
        let dpop_proof = format!(
            "{hdr_b64}.{pay_b64}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
        );

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_stale_proof_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // iat = now - 120: 120 s in the past — outside the ±60 s freshness window.
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            now_secs() as i64 - 120,
        );
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_future_dated_proof_returns_401() {
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        // iat = now + 120: 120 s in the future — also outside the ±60 s window.
        // This exercises the abs() branch (unsigned_abs() after widening).
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            now_secs() as i64 + 120,
        );
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn dpop_iat_at_i64_min_returns_401() {
        // i64::MIN is the specific iat value that motivated the i128 widening fix:
        // `now - i64::MIN` overflows in debug (panic → DoS) and wraps in release
        // (magnitude check bypass). The widened arithmetic must reject it as stale.
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        let dpop_proof = make_dpop_proof_with_iat(
            &dpop_key,
            "GET",
            &format!("{}/protected", state.config.public_url),
            i64::MIN,
        );
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", dpop_proof)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn multiple_dpop_headers_returns_401() {
        // RFC 9449 §11.1: multiple DPoP headers must be rejected.
        // A header-prepending proxy could inject a forged proof as the first value.
        let state = test_state().await;
        let dpop_key = SigningKey::random(&mut OsRng);
        let thumbprint = dpop_key_thumbprint(&dpop_key);
        let token = mint_token(
            "did:plc:alice",
            "com.atproto.access",
            3600,
            &state.jwt_secret,
            Some(serde_json::json!({ "jkt": thumbprint })),
        );
        let htu = format!("{}/protected", state.config.public_url);
        let proof1 = make_dpop_proof(&dpop_key, "GET", &htu);
        let proof2 = make_dpop_proof(&dpop_key, "GET", &htu);
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .header("DPoP", proof1)
            .header("DPoP", proof2)
            .body(Body::empty())
            .unwrap();
        let resp = protected_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── JWK thumbprint ────────────────────────────────────────────────────────

    #[test]
    fn rsa_jwk_thumbprint_matches_rfc7638_example() {
        // RFC 7638 §3.3 canonical example — RSA key with normative expected thumbprint.
        let jwk = serde_json::json!({
            "e": "AQAB",
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "use": "sig"  // extra member — must be excluded from canonical form
        });
        assert_eq!(
            jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn ec_jwk_thumbprint_produces_correct_format() {
        // EC (P-256) key from RFC 7517 Appendix A.2.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb.len(), 43, "thumbprint must be 43 base64url chars");
        assert!(
            thumb
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint must be base64url"
        );
        // Stable regression guard — verified against this implementation.
        assert_eq!(thumb, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
    }

    // ── DPoP nonce store tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn issued_nonce_validates_once() {
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;

        // First use: valid.
        assert!(
            validate_and_consume_nonce(&store, &nonce).await,
            "freshly issued nonce must validate"
        );

        // Second use: consumed — must fail (even though not expired).
        assert!(
            !validate_and_consume_nonce(&store, &nonce).await,
            "already-consumed nonce must not validate again"
        );
    }

    #[tokio::test]
    async fn unknown_nonce_is_rejected() {
        let store = new_nonce_store();
        assert!(
            !validate_and_consume_nonce(&store, "this-nonce-was-never-issued").await,
            "unknown nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        let store = new_nonce_store();
        // Manually insert a nonce that expired 1 second in the past.
        let nonce = "expired-nonce-test";
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert(nonce.to_string(), past);
        }

        assert!(
            !validate_and_consume_nonce(&store, nonce).await,
            "expired nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_nonces() {
        let store = new_nonce_store();

        // Insert one fresh nonce (not yet expired).
        let fresh_nonce = issue_nonce(&store).await;

        // Insert one already-expired nonce directly.
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert("stale-nonce".to_string(), past);
        }

        cleanup_expired_nonces(&store).await;

        let map = store.lock().await;
        assert!(
            map.contains_key(&fresh_nonce),
            "fresh nonce must survive cleanup"
        );
        assert!(
            !map.contains_key("stale-nonce"),
            "stale nonce must be pruned by cleanup"
        );
    }

    #[tokio::test]
    async fn issued_nonce_is_22_chars_base64url() {
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;
        assert_eq!(
            nonce.len(),
            22,
            "nonce must be 22 chars (16 bytes base64url no-pad)"
        );
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "nonce must be base64url charset"
        );
    }

    #[test]
    fn okp_jwk_thumbprint_produces_correct_format() {
        // Ed25519 (OKP) JWK — verifies OKP branch of jwk_thumbprint.
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"  // private — must be excluded
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb.len(), 43);
        assert!(thumb
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        // Stable regression guard.
        assert_eq!(thumb, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    // ── ES256 round-trip (F1) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn es256_at_jwt_accepted_at_resource_endpoint() {
        // Verifies the full dispatch path: peek_jwt_typ → verify_es256_access_token →
        // AuthenticatedUser. A token issued by the OAuth token endpoint (ES256, typ=at+jwt)
        // must be accepted at any endpoint that uses the AuthenticatedUser extractor.
        let state = test_state().await;

        // Issue an ES256 AT+JWT using the test state's signing key — no cnf.jkt so no
        // DPoP header is required; we are testing ES256 signature verification only.
        #[derive(Serialize)]
        struct Es256Claims {
            iss: String,
            jti: String,
            sub: String,
            aud: String,
            iat: u64,
            exp: u64,
            scope: String,
        }
        let now = now_secs() as u64;
        let claims = Es256Claims {
            iss: state.config.public_url.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            sub: "did:plc:alice".to_string(),
            aud: state.config.public_url.clone(),
            iat: now,
            exp: now + 300,
            scope: "com.atproto.access".to_string(),
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("at+jwt".to_string());
        let token = encode(&header, &claims, &state.oauth_signing_keypair.encoding_key).unwrap();

        let resp = get_protected(protected_app(state), Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("did=did:plc:alice"));
    }

    #[tokio::test]
    async fn es256_at_jwt_with_wrong_key_returns_401() {
        // A token signed by a different key (e.g. an attacker's P-256 key) must not
        // pass ES256 verification even if the typ header claims "at+jwt".
        let state = test_state().await;

        let attacker_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let attacker_pkcs8 = attacker_key.to_pkcs8_der().unwrap();

        #[derive(Serialize)]
        struct Es256Claims {
            iss: String,
            jti: String,
            sub: String,
            aud: String,
            iat: u64,
            exp: u64,
            scope: String,
        }
        let now = now_secs() as u64;
        let claims = Es256Claims {
            iss: state.config.public_url.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            sub: "did:plc:attacker".to_string(),
            aud: state.config.public_url.clone(),
            iat: now,
            exp: now + 300,
            scope: "com.atproto.access".to_string(),
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("at+jwt".to_string());
        let forged_token = encode(
            &header,
            &claims,
            &EncodingKey::from_ec_der(attacker_pkcs8.as_bytes()),
        )
        .unwrap();

        let resp = get_protected(protected_app(state), Some(&forged_token)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = json_body(resp).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }
}
