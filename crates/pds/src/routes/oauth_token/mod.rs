// pattern: Imperative Shell
//
// Gathers: AppState (signing key, nonce store, DB), DPoP header, form body
// Processes: DPoP validation → grant dispatch → token issuance
// Returns: JSON TokenResponse + DPoP-Nonce header on success;
//          JSON OAuthTokenError on all failure paths

//! `POST /oauth/token` — one route module split across per-grant submodules: this file owns the
//! request/response types, the shared token-issuance + `cleanup_expired_state` helpers, and the
//! `post_token` grant dispatcher; each grant's distinct logic, error surface, and tests live in
//! its own submodule. Still a single route module, so the no-routes-importing-routes rule is
//! untouched.
//!
//! Grants:
//!
//! - `authorization_code` + `refresh_token` — DPoP-bound, rotating refresh tokens
//!   (`authorization_code.rs`, `refresh.rs`)
//! - `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523) — exchanges a service-signed
//!   agent `identity_assertion` for a short-lived Bearer access token (`jwt_bearer.rs`)
//! - `urn:workos:agent-auth:grant-type:claim` (auth.md Step 4c) — the machine-pollable half of
//!   the agent claim ceremony (`claim_polling.rs`)

mod authorization_code;
mod claim_polling;
mod client_auth;
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
    // private_key_jwt client authentication (RFC 7523), enforced per the client's
    // registered token_endpoint_auth_method
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
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

/// Agent-flow (jwt-bearer / claim-polling) access-token lifetime. Deliberately shorter than
/// the OAuth lifetime and deliberately not configurable: agent tokens are minted headlessly,
/// with no consent leg and no human to notice a session behaving oddly.
pub(super) const AGENT_ACCESS_TOKEN_TTL_SECS: u64 = 300;

/// Sign an ES256 `at+jwt` access token. `jkt` is the DPoP key thumbprint for a sender-constrained
/// token, or `None` for a plain Bearer token (jwt-bearer grant) that carries no `cnf` binding.
/// `registration_id` is set only for agent-derived tokens (jwt-bearer), marking them as such and
/// tying them to their `agent_identities` row; `None` for ordinary session/OAuth grants.
/// `ttl_secs` is the token's lifetime — [`crate::app::AppState`]'s configured
/// `oauth.access_token_ttl_secs` for OAuth grants, [`AGENT_ACCESS_TOKEN_TTL_SECS`] for agent ones.
fn issue_access_token(
    signing_key: &crate::auth::OAuthSigningKey,
    did: &str,
    scope: &str,
    jkt: Option<&str>,
    registration_id: Option<&str>,
    public_url: &str,
    ttl_secs: u64,
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
        exp: now + ttl_secs,
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

/// Prune expired tokens and stale poll marks. Run on every token request.
async fn cleanup_expired_state(state: &AppState) {
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
    use uuid::Uuid;

    use crate::app::AppState;

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
            "iat": crate::time::unix_now_secs(),
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
    async fn error_response_has_error_and_error_description_fields() {
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
