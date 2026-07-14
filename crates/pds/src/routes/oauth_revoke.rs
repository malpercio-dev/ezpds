// pattern: Imperative Shell
//
// Gathers: AppState (DB, DPoP nonce store), DPoP header, form body
// Processes: DPoP proof validation → refresh-token lookup (key- and client-bound) → delete
// Returns: 200 with an empty body on success or on an unknown/unauthorized token
//          (RFC 7009 §2.2 non-disclosure); JSON OAuthTokenError on a malformed or
//          unauthenticated request
//
// `POST /oauth/revoke` — OAuth 2.0 Token Revocation (RFC 7009).
//
// Only the stateful **refresh token** is revocable. Access tokens are self-contained
// 5-minute ES256 JWTs (`oauth_token.rs`) with no server-side store, so there is nothing to
// delete for one: an access-token `token` (or any unknown/expired value) is accepted as a
// no-op success, its lifetime already bounded by the 5-minute TTL — the same
// TTL-bounded-revocation property the jwt-bearer note in `oauth_token.rs` calls out.
//
// Authentication is DPoP proof-of-possession, mirroring the `refresh_token` grant: the
// caller must present a valid DPoP proof (RFC 9449) whose key thumbprint matches the one the
// refresh token is bound to. A party that merely observed the token string — but does not
// hold its key — can therefore neither use the token nor revoke it, closing the RFC 7009
// concern that revocation not become a denial-of-service oracle. This is the codebase's
// uniform posture: every other refresh-token operation already requires the bound DPoP key.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::app::AppState;
use crate::auth::{issue_nonce, validate_dpop_for_token_endpoint, DpopTokenEndpointError};
use crate::db::oauth::{
    cleanup_expired_refresh_tokens, delete_oauth_refresh_token, get_oauth_refresh_token,
};
use crate::routes::oauth_errors::OAuthTokenError;

/// Flat form body for `POST /oauth/revoke` (application/x-www-form-urlencoded, RFC 7009 §2.1).
///
/// `token` is the only required parameter. `token_type_hint` is accepted but not acted on:
/// this server has one revocable token store (refresh tokens), and an access-token value can
/// never collide with a stored refresh-token hash, so trying the refresh store unconditionally
/// is both correct and constant-work. `client_id` is the public client's identifier; when
/// present it must match the token's owning client for the revocation to take effect.
#[derive(Debug, Deserialize)]
pub struct RevokeRequestForm {
    pub token: Option<String>,
    // Accepted for RFC 7009 conformance but intentionally not read: the hint is advisory and a
    // server "MUST extend its search" across its token types anyway (§2.1), and this server has a
    // single revocable store, so honouring the hint could only wrongly skip a valid token.
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
}

/// `POST /oauth/revoke` — revoke a refresh token (RFC 7009).
pub async fn post_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeRequestForm>,
) -> Response {
    // `token` is the one required parameter (RFC 7009 §2.1).
    let token = match form.token.as_deref() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: token")
                .into_response();
        }
    };

    // Reject multiple DPoP headers (RFC 9449 §11.1).
    if headers.get_all("DPoP").iter().count() > 1 {
        return OAuthTokenError::new(
            "invalid_dpop_proof",
            "multiple DPoP headers are not permitted",
        )
        .into_response();
    }

    // Validate the DPoP proof — must be present, structurally valid, and carry a valid server
    // nonce. The `htu` is this endpoint's own URL so a proof minted for the token endpoint can't
    // be replayed here.
    let dpop_token = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => {
            return OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
                .into_response();
        }
    };

    let revoke_url = format!(
        "{}/oauth/revoke",
        state.config.public_url.trim_end_matches('/')
    );

    let jkt = match validate_dpop_for_token_endpoint(
        &dpop_token,
        "POST",
        &revoke_url,
        &state.dpop_nonces,
    )
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

    // Opportunistically prune expired refresh tokens, matching the token endpoint's hygiene.
    if let Err(e) = cleanup_expired_refresh_tokens(&state.db).await {
        tracing::warn!(error = %e, "failed to clean up expired refresh tokens during revocation");
    }

    // From here every outcome is a 200: RFC 7009 §2.2 makes revoking an unknown, expired, or
    // unauthorized token indistinguishable from revoking a live one, so the endpoint never
    // discloses whether a token existed.
    //
    // A `token` that isn't base64url can't be a stored refresh token (those are base64url of
    // random bytes) — e.g. an access-token JWT, whose dots fail to decode — so a decode failure
    // is simply "nothing to revoke".
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(token.as_str()) {
        let token_hash = crate::auth::token::sha256_hex(&bytes);
        match get_oauth_refresh_token(&state.db, &token_hash).await {
            Ok(Some(stored)) => {
                // Only the DPoP key the token is bound to may revoke it. `jkt` is compared in
                // constant time; a token with a NULL `jkt` (pre-DPoP-binding, not expected after
                // V012) can never match and is left to expire.
                let jkt_matches = match stored.jkt.as_deref() {
                    Some(stored_jkt) => bool::from(stored_jkt.as_bytes().ct_eq(jkt.as_bytes())),
                    None => false,
                };
                // If the caller names a `client_id`, it must be the token's owning client.
                let client_matches = match form.client_id.as_deref() {
                    Some(client_id) => client_id == stored.client_id,
                    None => true,
                };
                if jkt_matches && client_matches {
                    if let Err(e) = delete_oauth_refresh_token(&state.db, &token_hash).await {
                        tracing::error!(error = %e, "failed to delete refresh token during revocation");
                        return OAuthTokenError::new("server_error", "database error")
                            .into_response();
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "failed to look up refresh token during revocation");
                return OAuthTokenError::new("server_error", "database error").into_response();
            }
        }
    }

    // 200 with an empty body (RFC 7009 §2.2), a fresh DPoP nonce so the client can chain another
    // revocation without a challenge round-trip, and no-store so the response is never cached.
    let fresh_nonce = issue_nonce(&state.dpop_nonces).await;
    let mut response_headers = HeaderMap::new();
    if let Ok(hval) = axum::http::HeaderValue::from_str(&fresh_nonce) {
        response_headers.insert("DPoP-Nonce", hval);
    }
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response_headers.insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));
    (StatusCode::OK, response_headers, ()).into_response()
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

    use crate::app::{app, test_state, AppState};
    use crate::auth::issue_nonce;
    use crate::auth::token::generate_token;
    use crate::db::oauth::register_oauth_client;

    // ── DPoP proof test helpers (mirrors oauth_token.rs's test harness) ───────────

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn dpop_key_to_jwk(key: &SigningKey) -> serde_json::Value {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    fn dpop_thumbprint(key: &SigningKey) -> String {
        let jwk = dpop_key_to_jwk(key);
        // RFC 7638 requires lexicographic key order (crv, kty, x, y for EC). Do not reorder.
        let canonical = serde_json::to_string(&serde_json::json!({
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }))
        .unwrap();
        let hash = Sha256::digest(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    fn make_dpop_proof(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        iat: i64,
    ) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        let mut payload = serde_json::json!({ "htm": htm, "htu": htu, "iat": iat, "jti": Uuid::new_v4().to_string() });
        if let Some(n) = nonce {
            payload["nonce"] = serde_json::Value::String(n.to_string());
        }
        let hdr = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig_input = format!("{hdr}.{pay}");
        let sig: Signature = key.sign(sig_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);
        format!("{hdr}.{pay}.{sig_b64}")
    }

    const REVOKE_HTU: &str = "https://test.example.com/oauth/revoke";
    const TEST_CLIENT: &str = "https://app.example.com/client-metadata.json";
    const TEST_DID: &str = "did:plc:testaccount000000000000";

    /// Seed a client + account + a refresh token bound to `jkt`. Returns the token plaintext.
    async fn seed_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            TEST_CLIENT,
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'test@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(TEST_DID)
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        crate::db::oauth::store_oauth_refresh_token(
            &state.db,
            &token.hash,
            TEST_CLIENT,
            TEST_DID,
            "atproto",
            jkt,
        )
        .await
        .unwrap();
        token.plaintext
    }

    async fn refresh_token_exists(state: &AppState, plaintext: &str) -> bool {
        let bytes = URL_SAFE_NO_PAD.decode(plaintext).unwrap();
        let hash = crate::auth::token::sha256_hex(&bytes);
        let row: Option<(String,)> = sqlx::query_as("SELECT id FROM oauth_tokens WHERE id = ?")
            .bind(hash)
            .fetch_optional(&state.db)
            .await
            .unwrap();
        row.is_some()
    }

    fn post_revoke(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_revoke_with_dpop(body: &str, dpop: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Request shape / method routing ────────────────────────────────────────────

    #[tokio::test]
    async fn missing_token_returns_400_invalid_request() {
        // `token` is checked before DPoP, so this fails even with no proof.
        let resp = app(test_state().await)
            .oneshot(post_revoke("token_type_hint=refresh_token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn get_revoke_endpoint_returns_405() {
        let resp = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth/revoke")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // ── DPoP authentication ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_dpop_header_returns_invalid_dpop_proof() {
        let resp = app(test_state().await)
            .oneshot(post_revoke("token=sometoken"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_without_nonce_returns_use_dpop_nonce_with_header() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let dpop = make_dpop_proof(&key, "POST", REVOKE_HTU, None, now_secs());

        let resp = app(state)
            .oneshot(post_revoke_with_dpop("token=sometoken", &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "use_dpop_nonce response must include a DPoP-Nonce header"
        );
        assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");
    }

    #[tokio::test]
    async fn dpop_for_wrong_htu_returns_invalid_dpop_proof() {
        // A proof minted for the token endpoint must not be replayable at /oauth/revoke.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_revoke_with_dpop("token=sometoken", &dpop))
            .await
            .unwrap();

        assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");
    }

    // ── Revocation behaviour ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn revokes_bound_refresh_token() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);
        let plaintext = seed_refresh_token(&state, &jkt).await;
        assert!(refresh_token_exists(&state, &plaintext).await);

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce), now_secs());

        let resp = app(state.clone())
            .oneshot(post_revoke_with_dpop(
                &format!("token={plaintext}&client_id={TEST_CLIENT}"),
                &dpop,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "revocation must return 200");
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response should carry a fresh DPoP-Nonce"
        );
        assert!(
            !refresh_token_exists(&state, &plaintext).await,
            "the refresh token row must be gone after revocation"
        );
    }

    #[tokio::test]
    async fn revocation_is_idempotent() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);
        let plaintext = seed_refresh_token(&state, &jkt).await;

        // First revocation deletes the token.
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce1), now_secs());
        let resp1 = app(state.clone())
            .oneshot(post_revoke_with_dpop(&format!("token={plaintext}"), &dpop1))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second revocation of the now-unknown token still returns 200 (RFC 7009 §2.2).
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce2), now_secs());
        let resp2 = app(state)
            .oneshot(post_revoke_with_dpop(&format!("token={plaintext}"), &dpop2))
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "revoking an already-revoked token must still be 200"
        );
    }

    #[tokio::test]
    async fn unknown_token_returns_200() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce), now_secs());

        // A well-formed base64url token that was never issued — non-disclosure means 200.
        // Encoded from readable bytes at runtime so no opaque high-entropy literal (which a
        // secret scanner flags) sits in the source.
        let unknown_token = URL_SAFE_NO_PAD.encode(b"never-issued-refresh-token-value");
        let resp = app(state)
            .oneshot(post_revoke_with_dpop(
                &format!("token={unknown_token}"),
                &dpop,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_base64url_token_is_noop_200() {
        // An access-token JWT (carries dots) can't be a refresh-token hash — accepted as a no-op.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce), now_secs());

        let resp = app(state)
            .oneshot(post_revoke_with_dpop(
                "token=aaa.bbb.ccc&token_type_hint=access_token",
                &dpop,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_dpop_key_does_not_revoke() {
        // A caller who holds a valid DPoP key but not the one the token is bound to gets a
        // non-disclosing 200, yet the token must survive.
        let state = test_state().await;
        let bound_key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&bound_key);
        let plaintext = seed_refresh_token(&state, &jkt).await;

        let attacker_key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&attacker_key, "POST", REVOKE_HTU, Some(&nonce), now_secs());

        let resp = app(state.clone())
            .oneshot(post_revoke_with_dpop(&format!("token={plaintext}"), &dpop))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "must not disclose via status"
        );
        assert!(
            refresh_token_exists(&state, &plaintext).await,
            "a token bound to a different key must not be revoked"
        );
    }

    #[tokio::test]
    async fn mismatched_client_id_does_not_revoke() {
        // Right key, wrong client_id → the token is left intact.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);
        let plaintext = seed_refresh_token(&state, &jkt).await;

        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", REVOKE_HTU, Some(&nonce), now_secs());

        let resp = app(state.clone())
            .oneshot(post_revoke_with_dpop(
                &format!("token={plaintext}&client_id=https%3A%2F%2Fwrong.example.com%2F"),
                &dpop,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            refresh_token_exists(&state, &plaintext).await,
            "a client_id that isn't the token's owner must not revoke it"
        );
    }
}
