# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Implement the authenticated HTTP client (`OAuthClient`) that wraps all requests with DPoP proofs, handles lazy token refresh, and retries once on `use_dpop_nonce`.

**Architecture:** `OAuthClient` owns a `reqwest::Client`, a `DPoPKeypair`, a `base_url: String`, and an `Arc<Mutex<OAuthSession>>`. Before every request it calls `maybe_refresh_token()` — checks if the access token expires within 60 seconds (lazy, on-demand refresh), computes `ath = base64url(sha256(access_token))`, builds a fresh DPoP proof with nonce and ath, and attaches the `Authorization` + `DPoP` headers. On `use_dpop_nonce` 400, it updates `session.dpop_nonce`, rebuilds the proof, and retries once. Created as a separate file `oauth_client.rs`.

> **Design clarification (lazy vs. background refresh):** The design DoD says "background token refresh before the 5-min TTL expires." AC6.1 is more precise: "When `expires_at < now + 60s`, a new token is fetched via refresh grant *before the next request proceeds*." The implementation satisfies AC6.1 with on-demand/lazy refresh (checked per-request in `maybe_refresh_token()`), which makes the refresh transparent to the caller — the spirit of "background" in the DoD. A proactive timer task is not implemented; the 60-second window ensures the relay's 5-minute token is always refreshed before it expires as long as the app is actively making requests.

**Tech Stack:** `reqwest 0.12`, `p256 = "0.13"`, `sha2 = "0.10"`, `base64 = "0.21"`, `tokio = "1"`

**Scope:** 7 phases from original design (phase 6 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC4: Tokens stored securely and loaded on restart
- **MM-149.AC4.2 Success:** On app restart with valid Keychain tokens, `AppState.oauth_session` is populated without re-running the OAuth flow (setup() logic — implemented here, exercised in Phase 7)

### MM-149.AC5: Authenticated requests carry DPoP proofs
- **MM-149.AC5.1 Success:** Every `OAuthClient` request includes `Authorization: DPoP {token}` and a `DPoP` header with a fresh proof
- **MM-149.AC5.2 Success:** `use_dpop_nonce` 400 from server triggers exactly one retry with the provided nonce; second consecutive failure returns an error
- **MM-149.AC5.3 Failure:** Request after token is deliberately cleared returns an auth error, not a panic

### MM-149.AC6: Token refresh works transparently
- **MM-149.AC6.1 Success:** When `expires_at < now + 60s`, a new token is fetched via refresh grant before the next request proceeds
- **MM-149.AC6.2 Success:** Refresh grant POST includes a fresh DPoP proof without `ath`
- **MM-149.AC6.3 Failure:** If refresh fails (e.g. relay returns `invalid_grant`), the error surfaces to the caller — no silent swallow

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Create oauth_client.rs

**Verifies:** MM-149.AC5.1, MM-149.AC5.2, MM-149.AC5.3, MM-149.AC6.1, MM-149.AC6.2, MM-149.AC6.3

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/oauth_client.rs`

Key design decisions:
- `OAuthClient` stores a `DPoPKeypair` to avoid repeated Keychain lookups per request
- `session: Arc<Mutex<OAuthSession>>` is mutable — refresh updates the session in place and persists to Keychain
- `prepare_request()` is the central method: lazy refresh + ath + proof + headers
- `execute_with_retry()` handles the `use_dpop_nonce` loop — retries exactly once
- Token refresh requires `DPoP` proof WITHOUT `ath` (no access token in hand at that point)

**Step 1: Create the file**

```rust
// pattern: Imperative Shell
//
// Gathers: session state (access_token, refresh_token, expiry, nonce), request params
// Processes: lazy refresh → DPoP proof → header attachment → nonce retry
// Returns: reqwest::Response or OAuthError

use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{Client, Response};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::oauth::{DPoPKeypair, OAuthError, OAuthSession};

/// Authenticated HTTP client.
///
/// Wraps every request with:
/// - `Authorization: DPoP {access_token}` header
/// - `DPoP: {proof}` header containing a fresh ES256 JWT with `ath` claim
///
/// Transparently refreshes the access token when it has less than 60 seconds remaining.
/// Retries once on `use_dpop_nonce` 400 responses.
pub struct OAuthClient {
    inner: Client,
    dpop: DPoPKeypair,
    session: Arc<Mutex<OAuthSession>>,
    base_url: String,
}

impl OAuthClient {
    /// Construct from an existing session.
    ///
    /// Loads the DPoP keypair from Keychain (same key used in the original flow).
    ///
    /// `Client::new()` inherits the TLS backend configured at the crate level via Cargo features
    /// (`default-features = false, features = ["rustls-tls"]` in Cargo.toml). No builder
    /// configuration is needed — the feature flags apply crate-wide, not per-client-instance.
    pub fn new(session: Arc<Mutex<OAuthSession>>) -> Result<Self, OAuthError> {
        let dpop = DPoPKeypair::get_or_create()?;
        Ok(Self {
            inner: Client::new(),
            dpop,
            session,
            base_url: crate::http::RelayClient::base_url(),
        })
    }

    /// GET `{base_url}/{path}` with DPoP authentication.
    pub async fn get(&self, path: &str) -> Result<Response, OAuthError> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        self.execute_with_retry(reqwest::Method::GET, &url, None::<&()>).await
    }

    /// POST `{base_url}/{path}` with JSON body and DPoP authentication.
    pub async fn post<B: Serialize + Sync>(&self, path: &str, body: &B) -> Result<Response, OAuthError> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        self.execute_with_retry(reqwest::Method::POST, &url, Some(body)).await
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Build and send a request with DPoP headers, retrying once on `use_dpop_nonce`.
    async fn execute_with_retry<B: Serialize + Sync>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<Response, OAuthError> {
        // Lazy refresh before reading the access token.
        self.maybe_refresh_token().await?;

        let nonce_opt = {
            let s = self.session.lock().unwrap();
            s.dpop_nonce.clone()
        };

        let resp = self.send_with_dpop(&method, url, body, nonce_opt.as_deref()).await?;

        // On use_dpop_nonce, extract the server nonce, update session, retry once.
        if resp.status().as_u16() == 400 {
            // Peek at the error body to check for use_dpop_nonce.
            let maybe_nonce = resp.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            if let Some(fresh_nonce) = maybe_nonce {
                {
                    let mut s = self.session.lock().unwrap();
                    s.dpop_nonce = Some(fresh_nonce.clone());
                }
                tracing::debug!(nonce = %fresh_nonce, "retrying request with server DPoP nonce");
                // Do NOT re-check expiry on the retry — avoid double-refresh.
                return self.send_with_dpop(&method, url, body, Some(&fresh_nonce)).await;
            }
        }

        Ok(resp)
    }

    /// Send a single request with `Authorization: DPoP` and `DPoP: {proof}` headers.
    async fn send_with_dpop<B: Serialize + Sync>(
        &self,
        method: &reqwest::Method,
        url: &str,
        body: Option<&B>,
        nonce: Option<&str>,
    ) -> Result<Response, OAuthError> {
        let (access_token, ath) = {
            let s = self.session.lock().unwrap();
            let ath = DPoPKeypair::compute_ath(&s.access_token);
            (s.access_token.clone(), ath)
        };

        let proof = self.dpop.make_proof(
            method.as_str(),
            url,
            nonce,
            Some(&ath),
        )?;

        let mut builder = match method {
            m if *m == reqwest::Method::GET => self.inner.get(url),
            m if *m == reqwest::Method::POST => self.inner.post(url),
            _ => return Err(OAuthError::NotAuthenticated),
        };

        builder = builder
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof);

        if let (Some(b), m) = (body, method) {
            if *m == reqwest::Method::POST {
                builder = builder.json(b);
            }
        }

        builder.send().await.map_err(|e| {
            tracing::error!(error = %e, "OAuthClient request network error");
            OAuthError::NotAuthenticated
        })
    }

    /// Refresh the access token if it expires within the next 60 seconds.
    async fn maybe_refresh_token(&self) -> Result<(), OAuthError> {
        let should_refresh = {
            let s = self.session.lock().unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            s.expires_at < now + 60
        };

        if should_refresh {
            self.refresh_token().await?;
        }
        Ok(())
    }

    /// POST `/oauth/token` with `grant_type=refresh_token` — no `ath` claim in DPoP proof.
    ///
    /// Updates `self.session` with the new tokens and persists to Keychain.
    /// Surfaces all errors to the caller — no silent swallowing (MM-149.AC6.3).
    pub async fn refresh_token(&self) -> Result<(), OAuthError> {
        let (refresh_token, nonce_opt) = {
            let s = self.session.lock().unwrap();
            (s.refresh_token.clone(), s.dpop_nonce.clone())
        };

        let token_htu = format!("{}/oauth/token", self.base_url);
        let proof = self.dpop.make_proof("POST", &token_htu, nonce_opt.as_deref(), None)?;

        let resp = self.inner
            .post(&token_htu)
            .header("DPoP", &proof)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
                ("client_id", "dev.malpercio.identitywallet"),
            ])
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "token refresh network error");
                OAuthError::TokenRefreshFailed
            })?;

        // On use_dpop_nonce from the refresh endpoint, retry once with the nonce.
        if resp.status().as_u16() == 400 {
            let retry_nonce = resp.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            if let Some(nonce_val) = retry_nonce {
                let proof2 = self.dpop.make_proof("POST", &token_htu, Some(&nonce_val), None)?;
                let resp2 = self.inner
                    .post(&token_htu)
                    .header("DPoP", &proof2)
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", refresh_token.as_str()),
                        ("client_id", "dev.malpercio.identitywallet"),
                    ])
                    .send()
                    .await
                    .map_err(|_| OAuthError::TokenRefreshFailed)?;

                if resp2.status().as_u16() == 200 {
                    return self.apply_token_response(resp2).await;
                }
                let body = resp2.text().await.unwrap_or_default();
                tracing::error!(body = %body, "token refresh failed after nonce retry");
                return Err(OAuthError::TokenRefreshFailed);
            }
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(body = %body, "token refresh 400 without nonce header");
            return Err(OAuthError::TokenRefreshFailed);
        }

        if resp.status().as_u16() != 200 {
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(body = %body, "token refresh failed");
            return Err(OAuthError::TokenRefreshFailed);
        }

        self.apply_token_response(resp).await
    }

    /// Construct with a custom base URL and pre-built keypair (test use only).
    #[cfg(test)]
    pub fn new_for_test(
        keypair: DPoPKeypair,
        session: Arc<Mutex<OAuthSession>>,
        base_url: String,
    ) -> Self {
        Self {
            inner: Client::new(),
            dpop: keypair,
            session,
            base_url,
        }
    }

    /// Deserialize a 200 token response and update session + Keychain.
    async fn apply_token_response(&self, resp: Response) -> Result<(), OAuthError> {
        // Capture the DPoP-Nonce header before consuming the response body.
        let new_nonce = resp.headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let token_resp: crate::http::TokenResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "token refresh response deserialization failed");
            OAuthError::TokenRefreshFailed
        })?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + token_resp.expires_in;

        crate::keychain::store_oauth_tokens(&token_resp.access_token, &token_resp.refresh_token)
            .map_err(|_| OAuthError::KeychainError)?;

        let mut s = self.session.lock().unwrap();
        s.access_token = token_resp.access_token;
        s.refresh_token = token_resp.refresh_token;
        s.expires_at = expires_at;
        s.dpop_nonce = new_nonce;

        tracing::info!("access token refreshed");
        Ok(())
    }
}
```

**Step 2: Add `pub mod oauth_client;` to lib.rs**

Find the module declarations at the top of `apps/identity-wallet/src-tauri/src/lib.rs` (lines 1-4) and add:

```rust
pub mod oauth_client;
```

So the module list reads:
```rust
pub mod device_key;
pub mod http;
pub mod keychain;
pub mod oauth;
pub mod oauth_client;
```

**Step 3: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors. If there are Serialize/Sync bound issues with the `body: Option<&B>` generic, simplify by removing the generic and accepting `Option<&serde_json::Value>` instead, or split `get()` and `post()` implementations without sharing `execute_with_retry()`.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Write tests for OAuthClient

**Verifies:** MM-149.AC5.1 (DPoP headers on requests), MM-149.AC5.2 (nonce retry, exactly 2 requests), MM-149.AC5.3 (cleared session, no panic), MM-149.AC6.1 (lazy refresh fires when near expiry), MM-149.AC6.2 (refresh DPoP proof has no ath), MM-149.AC6.3 (invalid_grant returns error)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs` (add `#[cfg(test)]` module)

These tests use `httpmock` to capture outgoing headers and verify behavior without a live relay. They call `OAuthClient::new_for_test(keypair, session, server.base_url())` which was added in Task 1. The DPoP keypair is created via `DPoPKeypair::get_or_create()` — in `#[cfg(test)]` builds, `keychain.rs` redirects all Keychain operations to an in-memory test store, so no real macOS Keychain access occurs during tests.

**Step 1: Add httpmock dev-dependency**

In `apps/identity-wallet/src-tauri/Cargo.toml`, add:

```toml
[dev-dependencies]
httpmock = "0.7"
```

**Step 2: Add test helper function (token response body)**

The mock token endpoint needs to return a valid token response JSON. Define this once in the test module for reuse:

```rust
fn token_response_body() -> serde_json::Value {
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 300;
    serde_json::json!({
        "access_token": "new_access_token",
        "token_type": "DPoP",
        "expires_in": 300,
        "refresh_token": "new_refresh_token",
        "scope": "atproto",
        "expires_at": expires_at
    })
}
```

**Step 3: Add test module to oauth_client.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use httpmock::prelude::*;

    fn make_session(access: &str, refresh: &str, expires_in_secs: u64) -> Arc<Mutex<OAuthSession>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Arc::new(Mutex::new(OAuthSession {
            access_token: access.to_string(),
            refresh_token: refresh.to_string(),
            expires_at: now + expires_in_secs,
            dpop_nonce: None,
        }))
    }

    fn token_response_body() -> serde_json::Value {
        serde_json::json!({
            "access_token": "new_access_token",
            "token_type": "DPoP",
            "expires_in": 300,
            "refresh_token": "new_refresh_token",
            "scope": "atproto"
        })
    }

    #[tokio::test]
    async fn dpop_and_authorization_headers_present_on_get() {
        // MM-149.AC5.1: Every request carries Authorization: DPoP {token} and DPoP: {proof}
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_access_token", "my_refresh_token", 300);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        let resp = client.get("/resource").await.expect("GET must succeed");
        assert_eq!(resp.status().as_u16(), 200);

        // Verify the mock server received the expected headers.
        let request = mock.calls()[0].request.clone();
        let auth = request.headers.get("authorization").expect("Authorization header must be present");
        assert!(auth.starts_with("DPoP "), "Authorization must use DPoP scheme, got: {auth}");
        assert_eq!(&auth[5..], "my_access_token", "Authorization must include the access token");

        let dpop = request.headers.get("dpop").expect("DPoP header must be present");
        let parts: Vec<&str> = dpop.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "DPoP proof must be a three-part JWT, got: {dpop}");
    }

    #[tokio::test]
    async fn nonce_retry_sends_exactly_two_requests() {
        // MM-149.AC5.2: use_dpop_nonce 400 triggers one retry; second success returns response
        let server = MockServer::start();

        // First request: 400 with DPoP-Nonce header
        let mock1 = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(400)
                .header("DPoP-Nonce", "test-server-nonce");
        });

        // Second request (retry with nonce): 200 success
        let mock2 = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_access_token", "my_refresh_token", 300);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        let resp = client.get("/resource").await.expect("GET must succeed after retry");
        assert_eq!(resp.status().as_u16(), 200);

        // Verify exactly 2 requests hit the server.
        assert_eq!(mock1.calls().len(), 1, "first request must hit once");
        assert_eq!(mock2.calls().len(), 1, "retry request must hit once");

        // Verify the retry carried the nonce in the DPoP proof.
        let retry_dpop = mock2.calls()[0].request.headers.get("dpop")
            .expect("retry must have DPoP header");
        let (_, claims_b64, _) = {
            let parts: Vec<&str> = retry_dpop.splitn(3, '.').collect();
            (parts[0], parts[1], parts[2])
        };
        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).expect("valid base64url");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("valid JSON");
        assert_eq!(
            claims["nonce"].as_str(),
            Some("test-server-nonce"),
            "retry DPoP proof must carry the server nonce"
        );
    }

    #[tokio::test]
    async fn empty_access_token_does_not_panic() {
        // MM-149.AC5.3: Cleared session (empty access_token) must not panic
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(401);
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("", "my_refresh_token", 300);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        // Should return a response (401) without panicking — the auth error comes from the server.
        let resp = client.get("/resource").await.expect("must not panic");
        assert_eq!(resp.status().as_u16(), 401, "empty token produces a server-side auth error");
    }

    #[tokio::test]
    async fn lazy_refresh_fires_when_expiry_near() {
        // MM-149.AC6.1: expires_at < now + 60 triggers refresh before the request
        let server = MockServer::start();

        // Refresh endpoint returns new tokens.
        let refresh_mock = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).json_body(token_response_body());
        });

        // Resource endpoint (called after refresh).
        let resource_mock = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        // Token expires in 30 seconds — below the 60-second refresh threshold.
        let session = make_session("old_access_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session.clone(), server.base_url());

        client.get("/resource").await.expect("request must succeed");

        // Verify refresh was called before the resource request.
        assert_eq!(refresh_mock.calls().len(), 1, "refresh must be called once");
        assert_eq!(resource_mock.calls().len(), 1, "resource must be called once");

        // Verify session was updated with the new token.
        let updated = session.lock().unwrap();
        assert_eq!(updated.access_token, "new_access_token", "session must have new token");
    }

    #[tokio::test]
    async fn refresh_dpop_proof_has_no_ath_claim() {
        // MM-149.AC6.2: Refresh grant DPoP proof must not include ath (no access token in hand)
        let server = MockServer::start();

        let refresh_mock = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).json_body(token_response_body());
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        // Session near expiry to trigger refresh.
        let session = make_session("old_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        client.refresh_token().await.expect("refresh must succeed");

        let request = refresh_mock.calls()[0].request.clone();
        let dpop_header = request.headers.get("dpop").expect("DPoP header must be present");

        // Decode the DPoP claims and verify no ath field.
        let parts: Vec<&str> = dpop_header.splitn(3, '.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("valid base64url claims");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("valid JSON");
        assert!(
            claims["ath"].is_null(),
            "refresh DPoP proof must not include ath, got: {:?}",
            claims["ath"]
        );
    }

    #[tokio::test]
    async fn refresh_invalid_grant_returns_token_refresh_failed() {
        // MM-149.AC6.3: Relay returns invalid_grant → Err(TokenRefreshFailed), not silent swallow
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400)
                .json_body(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "refresh token expired"
                }));
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        let result = client.refresh_token().await;
        assert!(
            matches!(result, Err(OAuthError::TokenRefreshFailed)),
            "invalid_grant must surface as TokenRefreshFailed, got: {:?}",
            result
        );
    }
}
```

**Step 4: Run the tests**

```bash
cargo test -p identity-wallet oauth_client
```

Expected: all 6 tests pass.

**Step 5: Run all tests**

```bash
cargo test -p identity-wallet
```

Expected: all tests pass.

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Commit

**Step 1: Commit Phase 6 changes**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git add apps/identity-wallet/src-tauri/src/lib.rs
git add apps/identity-wallet/src-tauri/src/oauth_client.rs
git commit -m "feat(identity-wallet): OAuthClient with DPoP proofs, lazy refresh, nonce retry (MM-149 phase 6)"
```

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
