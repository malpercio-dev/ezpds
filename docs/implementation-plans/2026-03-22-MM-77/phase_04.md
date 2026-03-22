# OAuth Token Endpoint — Phase 4: Token Endpoint Routing and Request Parsing

**Goal:** Register `POST /oauth/token`, parse the form body into typed grant variants, and return correct RFC 6749 errors for malformed requests. Full grant logic is added in Phases 5 and 6.

**Architecture:** New route handler file `routes/oauth_token.rs` with `TokenRequestForm`, `TokenResponse`, `OAuthTokenError`, and a stub `post_token` handler. The handler only validates `grant_type` in this phase — returning `unsupported_grant_type` or `invalid_request` as appropriate. Registered in `app.rs`. Two Bruno files for manual testing.

**Tech Stack:** `axum::extract::Form` (URL-encoded body), `serde::Deserialize`, `axum::http::StatusCode`, `serde_json::json!`.

**Scope:** Phase 4 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

### MM-77.AC5: Error response format
- **MM-77.AC5.2:** Unknown `grant_type` → 400 `unsupported_grant_type`
- **MM-77.AC5.3:** Missing required params → 400 `invalid_request` (tested here for missing `grant_type`)
- **MM-77.AC5.4:** No HTML in error responses

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Create the oauth_token route handler file

**Files:**
- Create: `crates/relay/src/routes/oauth_token.rs`

**Step 1: Create the file**

Create `crates/relay/src/routes/oauth_token.rs` with this content:

```rust
// pattern: Imperative Shell
//
// Gathers: AppState (signing key, nonce store, DB), DPoP header, form body
// Processes: DPoP validation → grant dispatch → token issuance
// Returns: JSON TokenResponse + DPoP-Nonce header on success;
//          JSON OAuthTokenError on all failure paths

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

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

    pub fn with_nonce(
        error: &'static str,
        error_description: &'static str,
        nonce: String,
    ) -> Self {
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

// ── Handler ───────────────────────────────────────────────────────────────────

/// `POST /oauth/token` — OAuth 2.0 token endpoint (RFC 6749 §3.2).
///
/// Phase 4 stub: validates grant_type, returns correct errors for unknown or
/// missing grant_type. Full grant logic is added in Phases 5 and 6.
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
            // Implemented in Phase 5.
            OAuthTokenError::new("invalid_grant", "authorization_code grant not yet implemented")
                .into_response()
        }
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
```

**Step 2: Register the module in `routes/mod.rs`**

In `crates/relay/src/routes/mod.rs`, add after the existing `pub mod oauth_authorize;` line:

```rust
pub mod oauth_token;
```

**Step 3: Register the route in `app.rs`**

In `crates/relay/src/app.rs`, add these imports after the existing OAuth route imports:

```rust
use crate::routes::oauth_token::post_token;
```

In the `app()` function's `Router::new()` chain, add after the `/oauth/authorize` route:

```rust
        .route("/oauth/token", post(post_token))
```

**Step 4: Compile**

```bash
cargo build -p relay
```

Expected: compiles without errors.

**Step 5: Commit**

```bash
git add crates/relay/src/routes/oauth_token.rs \
        crates/relay/src/routes/mod.rs \
        crates/relay/src/app.rs
git commit -m "feat(relay): POST /oauth/token stub — route, types, error format"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Tests for Phase 4 (error format + grant_type dispatch)

**Verifies:** MM-77.AC5.2, MM-77.AC5.3, MM-77.AC5.4

**Files:**
- Modify: `crates/relay/src/routes/oauth_token.rs` (add `#[cfg(test)]` block)

**Step 1: Add tests to `oauth_token.rs`**

Append this block at the end of `routes/oauth_token.rs`:

```rust
#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    fn post_token(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // AC5.2 — unknown grant_type
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

    // AC5.3 — missing grant_type
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

    // AC5.4 — errors must be JSON, not HTML
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
        assert!(ct.contains("application/json"), "content-type must be application/json");
    }

    // AC5.1 partial — errors have expected field shape
    #[tokio::test]
    async fn error_response_has_error_and_error_description_fields() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=bad"))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert!(json["error"].is_string(), "error field must be a string");
        assert!(
            json["error_description"].is_string(),
            "error_description field must be a string"
        );
    }

    // GET to /oauth/token should return 405 Method Not Allowed.
    #[tokio::test]
    async fn get_token_endpoint_returns_405() {
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
```

**Step 2: Run tests**

```bash
cargo test -p relay routes::oauth_token
```

Expected: all 5 tests pass.

**Step 3: Commit**

```bash
git add crates/relay/src/routes/oauth_token.rs
git commit -m "test(relay): POST /oauth/token Phase 4 — error format and grant_type tests"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Bruno collection entries

**Files:**
- Create: `bruno/oauth_token_authorization_code.bru` (seq 15)
- Create: `bruno/oauth_token_refresh.bru` (seq 16)

**Step 1: Create `bruno/oauth_token_authorization_code.bru`**

```
meta {
  name: OAuth Token — Authorization Code Exchange
  type: http
  seq: 15
}

post {
  url: {{baseUrl}}/oauth/token
  body: formUrlEncoded
  auth: none
}

headers {
  DPoP: {{dpopProof}}
}

body:form-urlencoded {
  grant_type: authorization_code
  code: {{authCode}}
  redirect_uri: https://app.example.com/callback
  client_id: https://app.example.com/client-metadata.json
  code_verifier: {{codeVerifier}}
}

vars:pre-request {
  dpopProof: <replace-with-dpop-proof-jwt>
  authCode: <replace-with-authorization-code>
  codeVerifier: <replace-with-pkce-code-verifier>
}
```

**Step 2: Create `bruno/oauth_token_refresh.bru`**

```
meta {
  name: OAuth Token — Refresh Token Rotation
  type: http
  seq: 16
}

post {
  url: {{baseUrl}}/oauth/token
  body: formUrlEncoded
  auth: none
}

headers {
  DPoP: {{dpopProof}}
}

body:form-urlencoded {
  grant_type: refresh_token
  refresh_token: {{refreshToken}}
  client_id: https://app.example.com/client-metadata.json
}

vars:pre-request {
  dpopProof: <replace-with-dpop-proof-jwt>
  refreshToken: <replace-with-refresh-token>
}
```

**Step 3: Commit**

```bash
git add bruno/oauth_token_authorization_code.bru bruno/oauth_token_refresh.bru
git commit -m "docs(bruno): add oauth/token authorization_code and refresh_token entries (seq 15, 16)"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
