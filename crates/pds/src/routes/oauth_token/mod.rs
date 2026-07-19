// pattern: Imperative Shell
//
// Gathers: AppState (signing key, nonce store, DB), DPoP header, form body
// Processes: DPoP validation → grant dispatch → token issuance
// Returns: JSON TokenResponse + DPoP-Nonce header on success;
//          JSON OAuthTokenError on all failure paths
//
// Grants: `authorization_code` and `refresh_token` (DPoP-bound, rotating refresh tokens) plus
// `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523) — the auth.md agent path that exchanges
// a service-signed `identity_assertion` for a short-lived Bearer access token, no DPoP, no refresh.
//
// One route module split across per-grant submodules: this file owns the request/response types,
// the shared token-issuance + cleanup helpers, and the `post_token` dispatcher; each grant's
// distinct logic and error surface lives in its own submodule (`authorization_code`, `refresh`,
// `jwt_bearer`, `claim_polling`). Route isolation is untouched — these are all one route module.

mod authorization_code;
mod claim_polling;
mod jwt_bearer;
mod refresh;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Form,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::agent_assertion::POLL_INTERVAL_SECS;
use crate::auth::cleanup_expired_nonces;
use crate::db::oauth::{cleanup_expired_auth_codes, cleanup_expired_refresh_tokens};
use crate::routes::oauth_errors::OAuthTokenError;

// ── Request / response types ──────────────────────────────────────────────────

/// Flat form body for `POST /oauth/token` (application/x-www-form-urlencoded).
///
/// All fields are `Option<String>` so that the handler can provide RFC 6749-compliant
/// error messages instead of Axum's default 422 rejection when fields are missing.
#[derive(Debug, Deserialize)]
pub struct TokenRequestForm {
    pub grant_type: Option<String>,
    // authorization_code grant
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    // refresh_token grant
    pub refresh_token: Option<String>,
    // jwt-bearer grant (RFC 7523): agent identity-assertion exchange
    pub assertion: Option<String>,
    pub resource: Option<String>,
    // claim-polling grant (urn:workos:agent-auth:grant-type:claim): the agent's one-time claim token
    pub claim_token: Option<String>,
}

/// Successful token endpoint response body (RFC 6749 §5.1 + AT Protocol OAuth profile).
///
/// The AT Protocol profile requires the Authorization Server to return the authenticated
/// account's DID in `sub` on both the initial `authorization_code` exchange and every
/// `refresh_token` response. atproto OAuth clients (e.g. indigo, which tangled.org runs)
/// read `sub` to bind the session to a DID and verify it matches the expected account; a
/// response without `sub` fails that check and the client aborts the login. Omitting it
/// is a plain RFC 6749 shape that breaks interop with every real atproto client.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
    /// The authenticated account's DID (AT Protocol OAuth: required in the token response).
    pub sub: String,
}

// ── Helper functions ────────────────────────────────────────────────────────────

/// Claims for an OAuth 2.0 AT+JWT access token (RFC 9068).
#[derive(Serialize)]
struct AccessTokenClaims {
    /// Issuer (RFC 9068 §2.2): the server's public URL.
    iss: String,
    /// Unique JWT identifier (RFC 7519).
    jti: String,
    /// Subject (RFC 9068 §2.2): the authenticated user's DID.
    sub: String,
    /// Audience (RFC 9068 §2.2): typically the server's URL; used for token binding validation.
    aud: String,
    /// Issued-at (Unix timestamp).
    iat: u64,
    /// Expiration (Unix timestamp).
    exp: u64,
    /// Scope string from the AT Protocol spec.
    scope: String,
    /// DPoP confirmation claim (RFC 9449 §4.3): binds the token to the client's keypair.
    /// Absent for sender-unconstrained Bearer tokens (the jwt-bearer grant), whose assertion
    /// is already key-bound upstream, so no DPoP proof is required at the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<CnfClaim>,
    /// Agent registration id — set only on tokens minted from an auth.md agent `identity_assertion`
    /// (the jwt-bearer grant). Carried through so `require_*` guards can recognise an agent-derived
    /// token and the audit path can attribute its actions; omitted entirely on all other grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_id: Option<String>,
}

#[derive(Serialize)]
struct CnfClaim {
    jkt: String,
}

/// Sign an ES256 `at+jwt` access token. `jkt` is the DPoP key thumbprint for a sender-constrained
/// token, or `None` for a plain Bearer token (jwt-bearer grant) that carries no `cnf` binding.
/// `registration_id` is set only for agent-derived tokens (jwt-bearer), marking them as such and
/// tying them to their `agent_identities` row; `None` for ordinary session/OAuth grants.
fn issue_access_token(
    signing_key: &crate::auth::OAuthSigningKey,
    did: &str,
    scope: &str,
    jkt: Option<&str>,
    registration_id: Option<&str>,
    public_url: &str,
) -> Result<String, OAuthTokenError> {
    use uuid::Uuid;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthTokenError::new("server_error", "system clock error"))?
        .as_secs();

    let claims = AccessTokenClaims {
        iss: public_url.to_string(),
        jti: Uuid::new_v4().to_string(),
        sub: did.to_string(),
        aud: public_url.to_string(),
        iat: now,
        exp: now + 300,
        scope: scope.to_string(),
        cnf: jkt.map(|jkt| CnfClaim {
            jkt: jkt.to_string(),
        }),
        registration_id: registration_id.map(str::to_string),
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(signing_key.key_id.clone());

    jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key).map_err(|e| {
        tracing::error!(error = %e, "failed to sign access token");
        OAuthTokenError::new("server_error", "token signing failed")
    })
}

/// Prune stale nonces and expired tokens. Run on every token request.
async fn cleanup_expired_state(state: &AppState) {
    cleanup_expired_nonces(&state.dpop_nonces).await;
    // Drop claim-poll marks older than the interval: once a mark is older than `POLL_INTERVAL_SECS`
    // it can no longer trigger `slow_down`, so keeping it only grows the map. Bounds memory to the
    // set of claim tokens polled within the last interval.
    let poll_window = Duration::from_secs(POLL_INTERVAL_SECS);
    state
        .poll_tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|_, last| last.elapsed() < poll_window);
    cleanup_expired_auth_codes(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to clean up expired auth codes");
        });
    cleanup_expired_refresh_tokens(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to clean up expired refresh tokens");
        });
}

/// Build the success-response headers for a token issuance: a fresh DPoP-Nonce
/// for the client's next request plus Cache-Control directives that prevent
/// caching of sensitive token responses (RFC 6749 §5.1).
fn token_response_headers(fresh_nonce: &str) -> Result<axum::http::HeaderMap, OAuthTokenError> {
    let mut response_headers = axum::http::HeaderMap::new();
    match axum::http::HeaderValue::from_str(fresh_nonce) {
        Ok(hval) => {
            response_headers.insert("DPoP-Nonce", hval);
        }
        Err(e) => {
            tracing::error!(nonce = ?fresh_nonce, error = %e, "failed to insert fresh DPoP-Nonce header, nonce format invalid");
            return Err(OAuthTokenError::new(
                "server_error",
                "failed to generate nonce header",
            ));
        }
    }
    // Add Cache-Control headers to prevent caching of sensitive token responses (RFC 6749 §5.1).
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response_headers.insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));
    Ok(response_headers)
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// `POST /oauth/token` — OAuth 2.0 token endpoint (RFC 6749 §3.2).
///
/// Dispatches to grant-specific handlers based on grant_type parameter.
pub async fn post_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequestForm>,
) -> Response {
    let grant_type = match form.grant_type.as_deref() {
        Some(g) => g,
        None => {
            return OAuthTokenError::new(
                "invalid_request",
                "missing required parameter: grant_type",
            )
            .into_response();
        }
    };

    match grant_type {
        "authorization_code" => {
            authorization_code::handle_authorization_code(&state, &headers, form).await
        }
        "refresh_token" => refresh::handle_refresh_token(&state, &headers, form).await,
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            jwt_bearer::handle_jwt_bearer(&state, form).await
        }
        "urn:workos:agent-auth:grant-type:claim" => {
            claim_polling::handle_claim_polling(&state, form).await
        }
        _ => OAuthTokenError::new(
            "unsupported_grant_type",
            "grant_type must be authorization_code, refresh_token, \
             urn:ietf:params:oauth:grant-type:jwt-bearer, or \
             urn:workos:agent-auth:grant-type:claim",
        )
        .into_response(),
    }
}

/// Shared `#[cfg(test)]` request builders, DPoP-proof minting, and body helpers used by every
/// grant's test module. The grant-specific seed helpers stay next to the tests that use them.
#[cfg(test)]
pub(crate) mod test_support {
    use axum::{body::Body, http::Request};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::app::AppState;

    pub(crate) fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    pub(crate) fn dpop_key_to_jwk(key: &SigningKey) -> serde_json::Value {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    pub(crate) fn dpop_thumbprint(key: &SigningKey) -> String {
        let jwk = dpop_key_to_jwk(key);
        // RFC 7638 requires keys to be in lexicographic order (crv, kty, x, y for EC keys).
        // Do NOT reorder these keys, or the thumbprint will differ silently.
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

    pub(crate) fn make_dpop_proof(
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

    pub(crate) fn post_token(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub(crate) fn post_token_with_dpop(body: &str, dpop: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub(crate) async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Mint a service-signed `identity_assertion` under the server's own OAuth key — exactly what
    /// `POST /agent/identity` returns for a claimed registration. Shared by the jwt-bearer and
    /// claim-polling test modules (the claim grant hands back an assertion of this same shape).
    pub(crate) fn mint_assertion(
        state: &AppState,
        did: &str,
        registration_id: &str,
        scope: &str,
        exp: i64,
    ) -> String {
        let origin = "https://test.example.com";
        let claims = serde_json::json!({
            "iss": origin,
            "sub": did,
            "aud": origin,
            "iat": now_secs(),
            "exp": exp,
            "jti": Uuid::new_v4().to_string(),
            "scope": scope,
            "registration_id": registration_id,
            "registration_type": "identity_assertion",
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(state.oauth_signing_keypair.key_id.clone());
        jsonwebtoken::encode(&header, &claims, &state.oauth_signing_keypair.encoding_key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::test_support::{json_body, post_token};
    use crate::app::{app, test_state};

    // ── Grant-type dispatch tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_grant_type_returns_400_unsupported() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=client_credentials"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn missing_grant_type_returns_400_invalid_request() {
        let resp = app(test_state().await)
            .oneshot(post_token("code=abc123"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn error_response_content_type_is_json() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=bad"))
            .await
            .unwrap();
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/json"));
    }

    #[tokio::test]
    async fn error_response_has_error_and_error_description_fields() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=bad"))
            .await
            .unwrap();
        let json = json_body(resp).await;
        assert!(json["error"].is_string());
        assert!(json["error_description"].is_string());
    }

    #[tokio::test]
    async fn get_token_endpoint_returns_405() {
        // Method routing (no AC)
        let resp = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth/token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
