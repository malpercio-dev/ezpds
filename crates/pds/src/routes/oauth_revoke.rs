// pattern: Imperative Shell
//
// Gathers: AppState (DB, DPoP nonce store), DPoP header, form body
// Processes: DPoP proof validation → refresh-token lookup (key- and client-bound) → delete
// Returns: 200 with an empty body on success or on an unknown/unauthorized token
//          (RFC 7009 §2.2 non-disclosure); JSON OAuthTokenError on a malformed or
//          unauthenticated request

//! `POST /oauth/revoke` — OAuth 2.0 Token Revocation (RFC 7009), advertised as
//! `revocation_endpoint` in the AS metadata.
//!
//! Only the stateful **refresh token** (`oauth_tokens`) is revocable. Access tokens are
//! self-contained 5-minute ES256 JWTs (`oauth_token/`) with no server-side store, so there is
//! nothing to delete for one: an access-token `token` (or any unknown/expired value) is
//! accepted as a no-op success, its lifetime already bounded by the 5-minute TTL — the same
//! TTL-bounded-revocation property the jwt-bearer grant (`oauth_token/jwt_bearer.rs`) calls
//! out.
//!
//! Authentication is DPoP proof-of-possession, mirroring the `refresh_token` grant: the
//! caller must present a valid DPoP proof (RFC 9449) whose key thumbprint matches the one the
//! refresh token is bound to (and, when the caller names a `client_id`, that client must own
//! the token). A party that merely observed the token string — but does not hold its key —
//! can therefore neither use the token nor revoke it, closing the RFC 7009 concern that
//! revocation not become a denial-of-service oracle. This is the codebase's uniform posture:
//! every other refresh-token operation already requires the bound DPoP key.
//!
//! Every well-formed, DPoP-authenticated request returns **200 with an empty body** whether or
//! not a token matched (RFC 7009 §2.2 non-disclosure). Only a missing `token`
//! (`invalid_request`) or a missing/invalid DPoP proof (`invalid_dpop_proof`/`use_dpop_nonce`)
//! returns the `{error, error_description}` shape.

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
use crate::db::oauth::{
    cleanup_expired_refresh_tokens, delete_oauth_refresh_session, get_oauth_refresh_token,
};
use crate::routes::oauth_dpop::token_endpoint_dpop;
use crate::routes::oauth_errors::{insert_no_store_headers, require, OAuthTokenError};

/// Flat form body for `POST /oauth/revoke` (application/x-www-form-urlencoded, RFC 7009 §2.1).
///
/// `token` is the only required parameter. `client_id` is the public client's identifier;
/// when present it must match the token's owning client for the revocation to take effect.
/// The RFC 7009 §2.1 `token_type_hint` parameter is accepted (serde ignores unknown form
/// fields) and intentionally ignored: this server has one revocable token store (refresh
/// tokens), so trying it unconditionally is both correct and constant-work.
#[derive(Debug, Deserialize)]
pub struct RevokeRequestForm {
    pub token: Option<String>,
    pub client_id: Option<String>,
}

/// `POST /oauth/revoke` — revoke a refresh token (RFC 7009).
pub async fn post_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeRequestForm>,
) -> Response {
    // `token` is the one required parameter (RFC 7009 §2.1).
    let token = match require(form.token.as_deref(), "token") {
        Ok(v) => v.to_string(),
        Err(e) => return e.into_response(),
    };

    // The `htu` is this endpoint's own URL so a proof minted for the token endpoint can't be
    // replayed here.
    let revoke_url = format!("{}/oauth/revoke", state.config.issuer());
    let jkt = match token_endpoint_dpop(&state, &headers, &revoke_url) {
        Ok(jkt) => jkt,
        Err(e) => return e.into_response(),
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
                    // Revoking any refresh token ends the whole session family it belongs
                    // to (every rotation of the same grant) — revocation means "end this
                    // session", not "retire this one artifact".
                    if let Err(e) =
                        delete_oauth_refresh_session(&state.db, &stored.session_id).await
                    {
                        tracing::error!(error = %e, "failed to delete refresh session during revocation");
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
    let fresh_nonce = state.dpop_nonces.issue();
    let mut response_headers = HeaderMap::new();
    if let Ok(hval) = axum::http::HeaderValue::from_str(&fresh_nonce) {
        response_headers.insert("DPoP-Nonce", hval);
    }
    insert_no_store_headers(&mut response_headers);
    (StatusCode::OK, response_headers, ()).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::routes::test_utils;

    const REVOKE_HTU: &str = "https://test.example.com/oauth/revoke";
    const TEST_CLIENT: &str = "https://app.example.com/client-metadata.json";

    /// Seed a refresh token bound to `jkt` for the group's fixed test client/DID (see
    /// [`test_utils::seed_refresh_row`]). Returns the token plaintext.
    async fn seed_refresh_token(state: &AppState, jkt: &str) -> String {
        test_utils::seed_refresh_row(state, Some(jkt), "atproto", "datetime('now', '+24 hours')")
            .await
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
        let key = test_utils::DpopProofKey::generate();
        let dpop = key.proof_with("POST", REVOKE_HTU, None, None);

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
        let key = test_utils::DpopProofKey::generate();
        let dpop = test_utils::token_proof(&state, &key);

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
        let key = test_utils::DpopProofKey::generate();
        let jkt = key.thumbprint();
        let plaintext = seed_refresh_token(&state, &jkt).await;
        assert!(refresh_token_exists(&state, &plaintext).await);

        let nonce = state.dpop_nonces.issue();
        let dpop = key.proof_with("POST", REVOKE_HTU, Some(&nonce), None);

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

        // Revoking the now-unknown token again must still return 200 (RFC 7009 §2.2
        // non-disclosure) rather than surfacing that it was already gone.
        let nonce2 = state.dpop_nonces.issue();
        let dpop2 = key.proof_with("POST", REVOKE_HTU, Some(&nonce2), None);
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
        let key = test_utils::DpopProofKey::generate();
        let nonce = state.dpop_nonces.issue();
        let dpop = key.proof_with("POST", REVOKE_HTU, Some(&nonce), None);

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
        let key = test_utils::DpopProofKey::generate();
        let nonce = state.dpop_nonces.issue();
        let dpop = key.proof_with("POST", REVOKE_HTU, Some(&nonce), None);

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
        let bound_key = test_utils::DpopProofKey::generate();
        let jkt = bound_key.thumbprint();
        let plaintext = seed_refresh_token(&state, &jkt).await;

        let attacker_key = test_utils::DpopProofKey::generate();
        let nonce = state.dpop_nonces.issue();
        let dpop = attacker_key.proof_with("POST", REVOKE_HTU, Some(&nonce), None);

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
        let key = test_utils::DpopProofKey::generate();
        let jkt = key.thumbprint();
        let plaintext = seed_refresh_token(&state, &jkt).await;

        let nonce = state.dpop_nonces.issue();
        let dpop = key.proof_with("POST", REVOKE_HTU, Some(&nonce), None);

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
