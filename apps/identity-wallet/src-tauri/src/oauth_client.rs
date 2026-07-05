// pattern: Imperative Shell
//
// Gathers: session state (access_token, refresh_token, expiry, nonce), request params
// Processes: lazy refresh → DPoP proof → header attachment → nonce retry
// Returns: reqwest::Response or OAuthError

use std::sync::{Arc, Mutex};

use reqwest::{Client, Response};
use serde::Serialize;

use crate::oauth::{DPoPKeypair, OAuthError, OAuthSession};

/// Extract the `exp` claim from a JWT's payload.
///
/// Splits the token on `.`, base64url-decodes the payload segment, and parses it as JSON.
/// Returns `None` on any failure (malformed token, missing exp, unparseable JSON, etc.).
fn jwt_exp_claim(token: &str) -> Option<u64> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_u64()
}

/// How this client authenticates its XRPC requests.
///
/// `Dpop` is the wallet's normal OAuth mode (DPoP-bound access token + proof header,
/// refresh via `/oauth/token`). `Bearer` is the legacy session mode used ONLY for the
/// migrated (deactivated) destination account, whose credentials are the plain
/// `accessJwt`/`refreshJwt` that migration-mode `createAccount` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Dpop,
    Bearer,
}

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
    auth_mode: AuthMode,
}

impl OAuthClient {
    /// Construct from an existing session.
    ///
    /// Loads the DPoP keypair from Keychain (same key used in the original flow).
    ///
    /// `Client::new()` inherits the TLS backend configured at the crate level via Cargo features
    /// (`default-features = false, features = ["rustls-tls"]` in Cargo.toml). No builder
    /// configuration is needed — the feature flags apply crate-wide, not per-client-instance.
    pub fn new(session: Arc<Mutex<OAuthSession>>, base_url: String) -> Result<Self, OAuthError> {
        let dpop = DPoPKeypair::get_or_create()?;
        Ok(Self {
            inner: Client::new(),
            dpop,
            session,
            base_url,
            auth_mode: AuthMode::Dpop,
        })
    }

    /// Build a Bearer-session client for a migrated destination account. `access_jwt` /
    /// `refresh_jwt` are the legacy tokens returned by migration-mode `createAccount`.
    /// `expires_at` is derived from the access token's `exp` claim so proactive refresh works.
    pub fn new_bearer(access_jwt: String, refresh_jwt: String, base_url: String)
        -> Result<Self, OAuthError>
    {
        let expires_at = jwt_exp_claim(&access_jwt).unwrap_or(0);
        let session = OAuthSession {
            access_token: access_jwt,
            refresh_token: refresh_jwt,
            expires_at,
            dpop_nonce: None,
        };
        Ok(Self {
            inner: Client::new(),
            dpop: DPoPKeypair::get_or_create()?,
            session: Arc::new(Mutex::new(session)),
            base_url,
            auth_mode: AuthMode::Bearer,
        })
    }

    /// GET `{base_url}/{path}` with DPoP authentication.
    pub async fn get(&self, path: &str) -> Result<Response, OAuthError> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        self.execute_with_retry(reqwest::Method::GET, &url, None::<&()>)
            .await
    }

    /// POST `{base_url}/{path}` with JSON body and DPoP authentication.
    pub async fn post<B: Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Response, OAuthError> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        self.execute_with_retry(reqwest::Method::POST, &url, Some(body))
            .await
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

        let resp = self
            .send_with_dpop(&method, url, body, nonce_opt.as_deref())
            .await?;

        // Bearer mode: send once, no retry on use_dpop_nonce (Bearer servers don't use nonces).
        if self.auth_mode == AuthMode::Bearer {
            return Ok(resp);
        }

        // On use_dpop_nonce, extract the server nonce from the DPoP-Nonce header,
        // update session, and retry once.
        if resp.status().as_u16() == 400 {
            // Extract nonce header BEFORE consuming the body.
            let maybe_nonce = resp
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            // Now consume the body to check the error type.
            let error_body = resp.text().await.unwrap_or_default();

            // Parse the error response to check for use_dpop_nonce.
            let is_use_dpop_nonce = {
                serde_json::from_str::<serde_json::Value>(&error_body)
                    .ok()
                    .and_then(|v| v.get("error")?.as_str().map(|e| e == "use_dpop_nonce"))
                    .unwrap_or(false)
            };

            if is_use_dpop_nonce {
                if let Some(fresh_nonce) = maybe_nonce {
                    {
                        let mut s = self.session.lock().unwrap();
                        s.dpop_nonce = Some(fresh_nonce.clone());
                    }
                    tracing::debug!(nonce = %fresh_nonce, "retrying request with server DPoP nonce");
                    // Do NOT re-check expiry on the retry — avoid double-refresh.
                    return self
                        .send_with_dpop(&method, url, body, Some(&fresh_nonce))
                        .await;
                } else {
                    // use_dpop_nonce but no nonce header — this is an error.
                    tracing::error!("use_dpop_nonce response missing DPoP-Nonce header");
                    return Err(OAuthError::NotAuthenticated);
                }
            } else {
                // Not use_dpop_nonce — the body has been consumed, so we can't return it.
                // Treat as auth failure since the request cannot proceed.
                tracing::error!(body = %error_body, "400 response without use_dpop_nonce error");
                return Err(OAuthError::NotAuthenticated);
            }
        }

        Ok(resp)
    }

    /// Send a single request with appropriate authentication headers.
    ///
    /// For DPoP mode: `Authorization: DPoP {token}` + `DPoP: {proof}`.
    /// For Bearer mode: `Authorization: Bearer {token}` with no DPoP header.
    async fn send_with_dpop<B: Serialize + Sync>(
        &self,
        method: &reqwest::Method,
        url: &str,
        body: Option<&B>,
        nonce: Option<&str>,
    ) -> Result<Response, OAuthError> {
        let access_token = {
            let s = self.session.lock().unwrap();
            s.access_token.clone()
        };

        let mut builder = match method {
            m if *m == reqwest::Method::GET => self.inner.get(url),
            m if *m == reqwest::Method::POST => self.inner.post(url),
            _ => return Err(OAuthError::NotAuthenticated),
        };

        // Branch on auth mode for header construction.
        match self.auth_mode {
            AuthMode::Bearer => {
                // Bearer mode: only Authorization header, no DPoP proof.
                builder = builder
                    .header("Authorization", format!("Bearer {access_token}"));
            }
            AuthMode::Dpop => {
                // DPoP mode: Authorization + DPoP proof with ath claim.
                let ath = DPoPKeypair::compute_ath(&access_token);
                let proof = self
                    .dpop
                    .make_proof(method.as_str(), url, nonce, Some(&ath))?;
                builder = builder
                    .header("Authorization", format!("DPoP {access_token}"))
                    .header("DPoP", &proof);
            }
        }

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
                .map_err(|_| OAuthError::TokenRefreshFailed)?
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
    /// Surfaces all errors to the caller — no silent swallowing.
    pub async fn refresh_token(&self) -> Result<(), OAuthError> {
        let (refresh_token, nonce_opt) = {
            let s = self.session.lock().unwrap();
            (s.refresh_token.clone(), s.dpop_nonce.clone())
        };

        let token_htu = format!("{}/oauth/token", self.base_url);
        let proof = self
            .dpop
            .make_proof("POST", &token_htu, nonce_opt.as_deref(), None)?;

        let resp = self
            .inner
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
            let retry_nonce = resp
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            if let Some(nonce_val) = retry_nonce {
                let proof2 = self
                    .dpop
                    .make_proof("POST", &token_htu, Some(&nonce_val), None)?;
                let resp2 = self
                    .inner
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

                // Check for invalid_grant after nonce retry.
                if resp2.status().as_u16() == 400 {
                    let body = resp2.text().await.unwrap_or_default();
                    if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
                        if err.get("error").and_then(|e| e.as_str()) == Some("invalid_grant") {
                            tracing::error!("refresh token invalid after nonce retry");
                            return Err(OAuthError::InvalidGrant);
                        }
                    }
                    tracing::error!(body = %body, "token refresh failed after nonce retry");
                    return Err(OAuthError::TokenRefreshFailed);
                }

                tracing::error!("token refresh failed after nonce retry");
                return Err(OAuthError::TokenRefreshFailed);
            }

            // No nonce header, check the error body for invalid_grant.
            let body = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
                if err.get("error").and_then(|e| e.as_str()) == Some("invalid_grant") {
                    tracing::error!("refresh token invalid");
                    return Err(OAuthError::InvalidGrant);
                }
            }
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
            auth_mode: AuthMode::Dpop,
        }
    }

    /// Deserialize a 200 token response and update session + Keychain.
    async fn apply_token_response(&self, resp: Response) -> Result<(), OAuthError> {
        // Capture the DPoP-Nonce header before consuming the response body.
        let new_nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let token_resp: crate::http::TokenResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "token refresh response deserialization failed");
            OAuthError::TokenRefreshFailed
        })?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| OAuthError::TokenRefreshFailed)?
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

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Create a Bearer-mode test JWT with a specific exp claim.
    fn make_bearer_jwt(exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, exp).as_bytes());
        // Dummy signature; jwt_exp_claim never verifies it
        let sig = "dummy_signature";
        format!("{}.{}.{}", header, payload, sig)
    }

    /// Create a Bearer-mode OAuthClient for testing.
    async fn make_bearer_client(access: &str, refresh: &str, base_url: &str) -> OAuthClient {
        OAuthClient::new_bearer(access.to_string(), refresh.to_string(), base_url.to_string())
            .expect("new_bearer must succeed")
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

    /// Decode a DPoP proof JWT from the request's DPoP header and return the payload.
    /// Returns None if the header is absent or malformed.
    fn decode_dpop_payload(req: &HttpMockRequest) -> Option<serde_json::Value> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let val = req
            .headers_vec()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("dpop"))
            .map(|(_, v)| v.as_str())?;
        let parts: Vec<&str> = val.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts.get(1)?).ok()?;
        serde_json::from_slice(&payload_bytes).ok()
    }

    /// `when.is_true()` predicate: DPoP proof must NOT contain an `ath` claim.
    /// Used for refresh-grant requests where no access token is available yet.
    fn dpop_has_no_ath(req: &HttpMockRequest) -> bool {
        decode_dpop_payload(req)
            .map(|p| p.get("ath").is_none())
            .unwrap_or(false)
    }

    /// `when.is_true()` predicate: DPoP proof must NOT contain a `nonce` claim.
    /// Used to match the first (pre-challenge) request in a nonce-retry scenario.
    fn dpop_has_no_nonce(req: &HttpMockRequest) -> bool {
        decode_dpop_payload(req)
            .map(|p| p.get("nonce").is_none())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn dpop_and_authorization_headers_present_on_get() {
        // Verifies: Every request carries Authorization: DPoP {token} and DPoP: {proof}
        // If either header is missing or wrong, the mock won't match -> 404 -> assertion fails.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/resource")
                .header("Authorization", "DPoP my_access_token")
                .header_exists("DPoP");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_access_token", "my_refresh_token", 300);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        let resp = client.get("/resource").await.expect("GET must succeed");
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn nonce_retry_sends_exactly_two_requests() {
        // use_dpop_nonce 400 triggers exactly one retry; the retry carries the server nonce.
        // Wire-level verification via two mocks (httpmock FIFO: first registered wins):
        //   Mock1 (specific): first request has NO nonce in DPoP proof → 400+DPoP-Nonce
        //   Mock2 (general):  retry has nonce in proof → Mock1 won't match → Mock2 serves
        //
        // If the retry proof omits the nonce, Mock1 matches again → Mock1.hits() would
        // be 2 and Mock2.hits() would be 0, causing the assertion below to fail.
        let server = MockServer::start();

        let mock_challenge = server.mock(|when, then| {
            when.method(GET)
                .path("/resource")
                .is_true(dpop_has_no_nonce);
            then.status(400)
                .header("DPoP-Nonce", "test-server-nonce")
                .json_body(serde_json::json!({"error": "use_dpop_nonce"}));
        });
        let mock_retry = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_access_token", "my_refresh_token", 300);
        let client = OAuthClient::new_for_test(keypair, session.clone(), server.base_url());

        let resp = client
            .get("/resource")
            .await
            .expect("must not error on retry path");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "retry must succeed with the nonce"
        );

        assert_eq!(
            mock_challenge.hits(),
            1,
            "initial request must hit the nonce-challenge mock"
        );
        assert_eq!(
            mock_retry.hits(),
            1,
            "retry must hit the success mock (nonce in proof)"
        );

        // The server-provided nonce must be stored in session after receiving a nonce challenge.
        assert_eq!(
            session.lock().unwrap().dpop_nonce.as_deref(),
            Some("test-server-nonce"),
            "server nonce must be stored in session after 400+nonce response"
        );
    }

    #[tokio::test]
    async fn empty_access_token_does_not_panic() {
        // Verifies: Cleared session (empty access_token) must not panic
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
        assert_eq!(
            resp.status().as_u16(),
            401,
            "empty token produces a server-side auth error"
        );
    }

    #[tokio::test]
    async fn lazy_refresh_fires_when_expiry_near() {
        // Verifies: expires_at < now + 60 triggers refresh before the request
        let server = MockServer::start();

        // Refresh endpoint returns new tokens.
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).json_body(token_response_body());
        });

        // Resource endpoint (called after refresh).
        server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(200).body("ok");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        // Token expires in 30 seconds — below the 60-second refresh threshold.
        let session = make_session("old_access_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session.clone(), server.base_url());

        client.get("/resource").await.expect("request must succeed");

        // Verify session was updated with the new token.
        let updated = session.lock().unwrap();
        assert_eq!(
            updated.access_token, "new_access_token",
            "session must have new token"
        );
    }

    #[tokio::test]
    async fn refresh_dpop_proof_has_no_ath_claim() {
        // Verifies: Refresh grant DPoP proof must not include ath (RFC 9449 §4.3).
        // Wire-level check: mock only responds 200 if the DPoP header has NO ath claim.
        // If refresh_token() sends a proof with ath, the mock won't match → test fails.
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST)
                .path("/oauth/token")
                .is_true(dpop_has_no_ath);
            then.status(200).json_body(token_response_body());
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("old_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        client.refresh_token().await.expect("refresh must succeed");
    }

    #[tokio::test]
    async fn refresh_invalid_grant_returns_invalid_grant() {
        // Verifies: PDS returns invalid_grant → Err(InvalidGrant), not TokenRefreshFailed
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "refresh token expired"
            }));
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        let session = make_session("my_token", "my_refresh_token", 30);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        let result = client.refresh_token().await;
        assert!(
            matches!(result, Err(OAuthError::InvalidGrant)),
            "invalid_grant must surface as InvalidGrant, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn refresh_token_nonce_retry_sends_exactly_two_requests() {
        // Verifies: refresh_token() retries exactly once when the token endpoint returns
        // 400 with a DPoP-Nonce header. The retry itself also gets 400 (no success mock
        // available in a single-response httpmock setup), so the function returns
        // TokenRefreshFailed — but the nonce retry path is proven by hits() == 2.
        let server = MockServer::start();

        let token_mock = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).header("DPoP-Nonce", "server-nonce");
        });

        let keypair = DPoPKeypair::get_or_create().expect("keypair must exist");
        // expires_in_secs = 0 → expires_at = now; satisfies the < now + 60 check,
        // but we're calling refresh_token() directly to test it in isolation.
        let session = make_session("access_token", "refresh_token_value", 0);
        let client = OAuthClient::new_for_test(keypair, session, server.base_url());

        // Both the initial request and the nonce retry get 400 → TokenRefreshFailed.
        let result = client.refresh_token().await;
        assert!(
            matches!(result, Err(OAuthError::TokenRefreshFailed)),
            "expected TokenRefreshFailed, got: {:?}",
            result
        );

        // Exactly 2 requests: initial attempt + one nonce retry.
        assert_eq!(
            token_mock.hits(),
            2,
            "must make exactly 2 requests: initial + nonce retry"
        );
    }

    /// `when.is_true()` predicate: request must NOT have a `DPoP` header.
    fn request_has_no_dpop_header(req: &HttpMockRequest) -> bool {
        req.headers_vec()
            .iter()
            .all(|(k, _)| !k.eq_ignore_ascii_case("dpop"))
    }

    #[tokio::test]
    async fn bearer_mode_sends_authorization_bearer_header() {
        // Verifies: Bearer-mode client sends Authorization: Bearer {token} and no DPoP header.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/resource")
                .header("Authorization", "Bearer my_bearer_token")
                .is_true(request_has_no_dpop_header);
            then.status(200).body("ok");
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_exp = now + 3600;
        let access_jwt = make_bearer_jwt(future_exp);
        let client = make_bearer_client(&access_jwt, "my_refresh_token", &server.base_url()).await;

        let resp = client.get("/resource").await.expect("GET must succeed");
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn bearer_mode_does_not_retry_on_use_dpop_nonce() {
        // Verifies: Bearer mode sends once, does not retry on 400 with DPoP-Nonce.
        // This is a clarity/safety measure — Bearer servers never return use_dpop_nonce.
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(GET).path("/resource");
            then.status(400)
                .header("DPoP-Nonce", "server-nonce")
                .json_body(serde_json::json!({"error": "use_dpop_nonce"}));
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_exp = now + 3600;
        let access_jwt = make_bearer_jwt(future_exp);
        let client = make_bearer_client(&access_jwt, "my_refresh_token", &server.base_url()).await;

        let resp = client.get("/resource").await.expect("GET must not error");
        assert_eq!(resp.status().as_u16(), 400, "should return the 400 without retry");
        assert_eq!(mock.hits(), 1, "must send exactly one request (no retry)");
    }

    #[tokio::test]
    async fn bearer_mode_derives_expires_at_from_jwt_exp() {
        // Verifies: new_bearer derives expires_at from the access JWT's exp claim.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt_exp = now + 7200; // 2 hours in future
        let access_jwt = make_bearer_jwt(jwt_exp);

        let client = OAuthClient::new_bearer(
            access_jwt,
            "refresh_token".to_string(),
            "http://localhost".to_string(),
        )
        .expect("new_bearer must succeed");

        let session = client.session.lock().unwrap();
        assert_eq!(
            session.expires_at, jwt_exp,
            "expires_at must match the JWT exp claim"
        );
    }

    #[tokio::test]
    async fn bearer_mode_falls_back_to_zero_on_invalid_jwt() {
        // Verifies: new_bearer falls back to expires_at=0 if jwt_exp_claim fails.
        let access_jwt = "invalid.jwt.token".to_string();

        let client = OAuthClient::new_bearer(
            access_jwt,
            "refresh_token".to_string(),
            "http://localhost".to_string(),
        )
        .expect("new_bearer must succeed");

        let session = client.session.lock().unwrap();
        assert_eq!(
            session.expires_at, 0,
            "expires_at must default to 0 on invalid JWT"
        );
    }
}
