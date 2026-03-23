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
use crate::db::oauth::store_oauth_refresh_token;
use crate::routes::token::generate_token;

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
    #[allow(dead_code)]
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
            "application/json".parse().unwrap(),
        );
        if let Some(nonce) = self.dpop_nonce {
            headers.insert("DPoP-Nonce", nonce.parse().unwrap());
        }
        (StatusCode::BAD_REQUEST, headers, Json(body)).into_response()
    }
}

// ── Helper functions ────────────────────────────────────────────────────────────

/// Claims for an OAuth 2.0 AT+JWT access token (RFC 9068).
#[derive(Serialize)]
struct AccessTokenClaims {
    sub: String,
    iat: u64,
    exp: u64,
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
) -> Result<String, OAuthTokenError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthTokenError::new("server_error", "system clock error"))?
        .as_secs();

    let claims = AccessTokenClaims {
        sub: did.to_string(),
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
        "refresh_token" => {
            // Implemented in Phase 6.
            OAuthTokenError::new("invalid_grant", "refresh_token grant not yet implemented")
                .into_response()
        }
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
    // Prune stale nonces on every request.
    cleanup_expired_nonces(&state.dpop_nonces).await;

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
    let code_hash = crate::routes::token::sha256_hex(
        &URL_SAFE_NO_PAD
            .decode(code)
            .unwrap_or_else(|_| code.as_bytes().to_vec()),
    );

    // Atomically consume the authorization code.
    let auth_code = match crate::db::oauth::consume_authorization_code(&state.db, &code_hash).await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "authorization code invalid or expired")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume authorization code");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Verify client_id matches.
    if auth_code.client_id != client_id {
        return OAuthTokenError::new("invalid_grant", "client_id mismatch").into_response();
    }

    // Verify redirect_uri matches.
    if auth_code.redirect_uri != redirect_uri {
        return OAuthTokenError::new("invalid_grant", "redirect_uri mismatch").into_response();
    }

    // Verify PKCE S256 challenge.
    if !verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        return OAuthTokenError::new(
            "invalid_grant",
            "code_verifier does not match code_challenge",
        )
        .into_response();
    }

    // Issue ES256 access token.
    let access_token = match issue_access_token(
        &state.oauth_signing_keypair,
        &auth_code.did,
        &auth_code.scope,
        &jkt,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Generate and store refresh token.
    let refresh = generate_token();
    if let Err(e) = store_oauth_refresh_token(
        &state.db,
        &refresh.hash,
        &auth_code.client_id,
        &auth_code.did,
        &jkt,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // Issue a fresh DPoP nonce for the next request.
    let fresh_nonce = issue_nonce(&state.dpop_nonces).await;

    let mut response_headers = axum::http::HeaderMap::new();
    response_headers.insert("DPoP-Nonce", fresh_nonce.parse().unwrap());

    (
        StatusCode::OK,
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: "DPoP",
            expires_in: 300,
            refresh_token: refresh.plaintext,
            scope: auth_code.scope,
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
    use crate::db::oauth::{register_oauth_client, store_authorization_code};

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
        // AC5.2
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
        // AC5.3
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
        // AC5.4
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
        // AC5.1
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

    // ── AC2 — DPoP proof validation ───────────────────────────────────────────

    #[tokio::test]
    async fn missing_dpop_header_returns_invalid_dpop_proof() {
        // AC2.3
        let resp = app(test_state().await)
            .oneshot(post_token(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_wrong_htm_returns_invalid_dpop_proof() {
        // AC2.4
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
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
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
        // AC2.5
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
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_stale_iat_returns_invalid_dpop_proof() {
        // AC2.6
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
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    // ── AC3 — DPoP nonces ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn dpop_without_nonce_returns_use_dpop_nonce_with_header() {
        // AC3.2
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
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
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
        // AC3.4
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
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    // ── AC1 — authorization_code grant ───────────────────────────────────────

    #[tokio::test]
    async fn authorization_code_happy_path_returns_200_with_tokens() {
        // AC1.1, AC1.2, AC1.3, AC2.1, AC2.2, AC3.5, AC6.3
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

        // AC3.5 — DPoP-Nonce header in success response.
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response must include fresh DPoP-Nonce header"
        );

        let json = json_body(resp).await;

        // AC1.1 — TokenResponse fields.
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

        // AC1.3 — refresh token is 43-char base64url.
        let rt = json["refresh_token"].as_str().unwrap();
        assert_eq!(rt.len(), 43, "refresh_token must be 43 chars (AC1.3)");

        // AC1.2 + AC6.3 — access token is ES256 JWT with typ=at+jwt.
        let at = json["access_token"].as_str().unwrap();
        let header_b64 = at.split('.').next().unwrap();
        let header_json = String::from_utf8(URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        assert_eq!(
            header["typ"], "at+jwt",
            "access token typ must be at+jwt (AC1.2)"
        );
        assert_eq!(
            header["alg"], "ES256",
            "access token alg must be ES256 (AC6.3)"
        );

        // AC2.2 — cnf.jkt in access token matches DPoP key thumbprint.
        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        let cnf_jkt = payload["cnf"]["jkt"].as_str().unwrap();
        let expected_jkt = dpop_thumbprint(&key);
        assert_eq!(
            cnf_jkt, expected_jkt,
            "cnf.jkt must match DPoP key thumbprint (AC2.2)"
        );
    }

    #[tokio::test]
    async fn wrong_code_verifier_returns_invalid_grant() {
        // AC1.4
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
            "wrong code_verifier must return invalid_grant (AC1.4)"
        );
    }

    #[tokio::test]
    async fn consumed_code_returns_invalid_grant() {
        // AC1.6
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
            "second use must return invalid_grant (AC1.6)"
        );
    }

    #[tokio::test]
    async fn client_id_mismatch_returns_invalid_grant() {
        // AC1.7
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
            "client_id mismatch must return invalid_grant (AC1.7)"
        );
    }

    #[tokio::test]
    async fn redirect_uri_mismatch_returns_invalid_grant() {
        // AC1.8
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
            "redirect_uri mismatch must return invalid_grant (AC1.8)"
        );
    }
}
