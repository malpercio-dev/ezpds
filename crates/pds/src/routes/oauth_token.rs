// pattern: Imperative Shell
//
// Gathers: AppState (signing key, nonce store, DB), DPoP header, form body
// Processes: DPoP validation → grant dispatch → token issuance
// Returns: JSON TokenResponse + DPoP-Nonce header on success;
//          JSON OAuthTokenError on all failure paths

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::auth::{
    cleanup_expired_nonces, issue_nonce, validate_dpop_for_token_endpoint, DpopTokenEndpointError,
};
use crate::db::oauth::{
    cleanup_expired_auth_codes, cleanup_expired_refresh_tokens, delete_authorization_code,
    delete_oauth_refresh_token, get_authorization_code, get_oauth_refresh_token,
    store_oauth_refresh_token,
};
use crate::token::generate_token;

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
}

/// Successful token endpoint response body (RFC 6749 §5.1).
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

/// OAuth 2.0 error response body (RFC 6749 §5.2).
///
/// All token endpoint errors use this format, distinct from the codebase's
/// `ApiError` envelope (`{ "error": { "code": "...", "message": "..." } }`).
pub struct OAuthTokenError {
    pub error: &'static str,
    pub error_description: &'static str,
    /// Optional DPoP-Nonce value to include in the response header.
    /// Required for `use_dpop_nonce` errors so the client can retry.
    pub dpop_nonce: Option<String>,
}

impl OAuthTokenError {
    pub fn new(error: &'static str, error_description: &'static str) -> Self {
        Self {
            error,
            error_description,
            dpop_nonce: None,
        }
    }

    pub fn with_nonce(error: &'static str, error_description: &'static str, nonce: String) -> Self {
        Self {
            error,
            error_description,
            dpop_nonce: Some(nonce),
        }
    }
}

impl IntoResponse for OAuthTokenError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.error_description,
        });
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        if let Some(nonce) = self.dpop_nonce {
            match axum::http::HeaderValue::from_str(&nonce) {
                Ok(hval) => {
                    headers.insert("DPoP-Nonce", hval);
                }
                Err(e) => {
                    // This should never happen: nonces are base64url ASCII, always valid
                    // header values. If it does happen, returning use_dpop_nonce without
                    // the nonce header leaves the client with no retry path (RFC 9449 §7.1).
                    // Return server_error instead.
                    tracing::error!(nonce = ?nonce, error = %e, "nonce string cannot be encoded as HTTP header value; this is a server bug");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            axum::http::HeaderValue::from_static("application/json"),
                        )],
                        Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "internal server error",
                        })),
                    )
                        .into_response();
                }
            }
        }

        // RFC 6749 §5.2: most errors are 400, but server_error is 500.
        let status = if self.error == "server_error" {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, headers, Json(body)).into_response()
    }
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
    cnf: CnfClaim,
}

#[derive(Serialize)]
struct CnfClaim {
    jkt: String,
}

fn issue_access_token(
    signing_key: &crate::auth::OAuthSigningKey,
    did: &str,
    scope: &str,
    jkt: &str,
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
        cnf: CnfClaim {
            jkt: jkt.to_string(),
        },
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(signing_key.key_id.clone());

    jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key).map_err(|e| {
        tracing::error!(error = %e, "failed to sign access token");
        OAuthTokenError::new("server_error", "token signing failed")
    })
}

/// Verify the PKCE S256 code challenge.
fn verify_pkce_s256(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    // Constant-time comparison to prevent timing oracle.
    subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), stored_challenge.as_bytes()).into()
}

/// Prune stale nonces and expired tokens. Run on every token request.
async fn cleanup_expired_state(state: &AppState) {
    cleanup_expired_nonces(&state.dpop_nonces).await;
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
        "authorization_code" => handle_authorization_code(&state, &headers, form).await,
        "refresh_token" => handle_refresh_token(&state, &headers, form).await,
        _ => OAuthTokenError::new(
            "unsupported_grant_type",
            "grant_type must be authorization_code or refresh_token",
        )
        .into_response(),
    }
}

async fn handle_authorization_code(
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
        Ok(bytes) => crate::token::sha256_hex(&bytes),
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

    // The access token carries the granular scope set granted at consent time,
    // recording exactly what the client was granted. Per-request enforcement is a
    // later change; today any granted atproto scope is treated as full access.
    let granted_scope = auth_code.scope;

    // Issue ES256 access token.
    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        &auth_code.did,
        &granted_scope,
        &jkt,
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

async fn handle_refresh_token(
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
        Ok(bytes) => crate::token::sha256_hex(&bytes),
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

    // All validations passed; now consume the token.
    if let Err(e) = delete_oauth_refresh_token(&state.db, &token_hash).await {
        tracing::error!(error = %e, "failed to delete refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
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
        &jkt,
        &state.config.public_url,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Generate and store new refresh token (rotation: old token already deleted above).
    let new_refresh = generate_token();
    if let Err(e) = store_oauth_refresh_token(
        &state.db,
        &new_refresh.hash,
        &stored.client_id,
        &stored.did,
        &granted_scope,
        &jkt,
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
            expires_in: 300,
            refresh_token: new_refresh.plaintext,
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

    use crate::app::{app, test_state, AppState};
    use crate::auth::issue_nonce;
    use crate::db::oauth::{
        register_oauth_client, store_authorization_code, store_oauth_refresh_token,
    };
    use crate::token::generate_token;

    // ── DPoP proof test helpers ───────────────────────────────────────────────

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

    fn post_token(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_token_with_dpop(body: &str, dpop: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Phase 4 tests (retained) ──────────────────────────────────────────────

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

    // ── refresh_token grant ───────────────────────────────────────────────────

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
        store_oauth_refresh_token(
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

    /// Seed the DB with an already-expired refresh token (bypasses store_oauth_refresh_token's +24h).
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
        assert_eq!(json["expires_in"], 300);
        assert!(
            json["refresh_token"].is_string(),
            "rotated refresh_token must be present"
        );
        assert_eq!(
            json["scope"], "atproto transition:generic",
            "the granted granular scope must be carried forward on rotation"
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

    #[tokio::test]
    async fn refresh_token_second_use_returns_invalid_grant() {
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

        // Second use of the same original token: must return invalid_grant.
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
            StatusCode::BAD_REQUEST,
            "second use must return 400"
        );
        let json = json_body(resp2).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "second use of consumed token must return invalid_grant"
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

        // Insert a refresh token with jkt = NULL directly (bypasses store_oauth_refresh_token
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
        crate::db::oauth::store_authorization_code(
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
