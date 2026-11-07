// pattern: Imperative Shell

//! [`OAuthClient`]: the authenticated XRPC HTTP client for a plain `accessJwt`/`refreshJwt`
//! session (a password or sovereign login, a migration destination account). Gathers session
//! state (access/refresh token, expiry) and request params; runs lazy refresh → header
//! attachment; returns `reqwest::Response` or [`OAuthError`].
//!
//! Every request carries `Authorization: Bearer {access_jwt}`. Expiry is derived from the
//! access JWT's `exp` claim, and refresh goes through `com.atproto.server.refreshSession`
//! with the new pair held in memory only; durable per-DID storage belongs to the caller.
//!
//! **Lazy refresh.** The token is refreshed before a request whenever it has under 60
//! seconds remaining, so callers never see a routinely-expired token. A client built with an
//! empty refresh token (a one-shot service-auth JWT) never refreshes.
//!
//! A non-2xx response, including a 400, is handed back as an intact `reqwest::Response` so the
//! caller's status classifier surfaces the server's real status and body.
//!
//! **Breadcrumbs are injected**, not hardcoded: this crate has no Tauri/Keychain dependency, so
//! a caller supplies a [`TransportObserver`] (defaulted to a no-op for `new_bearer`'s common
//! 3-arg form — see [`OAuthClient::new_bearer_with_observer`] for callers that want real
//! breadcrumbs).
//!
//! Request methods: `get`, `post`/`put` (JSON), `post_no_body` (zero bytes and no
//! `Content-Type` — for no-input XRPC procedures like `requestPlcOperationSignature`/
//! `activateAccount`, whose lexicons define no input and where a spec-strict PDS rejects any
//! body), and `post_bytes` (raw byte body — CAR repo import and blob upload).

use std::sync::Mutex;

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};

use crate::error::{NoopObserver, TransportObserver};

/// Error type for all OAuth-related operations.
///
/// Variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }` to match the existing
/// error pattern (`CreateAccountError`, `DeviceKeyError`, etc.).
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum OAuthError {
    #[error("PAR request failed")]
    ParFailed,
    #[error("Token exchange failed")]
    TokenExchangeFailed,
    #[error("Token refresh failed")]
    TokenRefreshFailed,
    #[error("Refresh token has been revoked or is invalid")]
    InvalidGrant,
    #[error("Not authenticated")]
    NotAuthenticated,
}

/// The token pair a client carries.
struct Tokens {
    access_token: String,
    refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    expires_at: u64,
}

/// Token refresh response from `com.atproto.server.refreshSession`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
}

/// Extract the `exp` claim from a JWT's payload.
///
/// Splits the token on `.`, base64url-decodes the payload segment, and parses it as JSON.
/// Returns `None` on any failure (malformed token, missing exp, unparseable JSON, etc.).
fn jwt_exp_claim(token: &str) -> Option<u64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let payload_bytes = crate::base64url::b64url_decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_u64()
}

/// Authenticated HTTP client for a Bearer session.
///
/// Wraps every request with `Authorization: Bearer {access_jwt}` and transparently refreshes
/// the access token when it has less than 60 seconds remaining.
pub struct OAuthClient {
    inner: Client,
    session: Mutex<Tokens>,
    base_url: String,
    observer: std::sync::Arc<dyn TransportObserver>,
}

impl OAuthClient {
    /// Build a Bearer-session client for a plain `accessJwt`/`refreshJwt` session (a migration
    /// destination account, a sovereign/password login, …). `expires_at` is derived from the
    /// access token's `exp` claim so proactive refresh works. Records no diagnostics breadcrumbs
    /// on transport failure — use [`Self::new_bearer_with_observer`] for that.
    ///
    /// `Client::new()` inherits the TLS backend configured at the crate level via Cargo features
    /// (`default-features = false, features = ["rustls-tls"]`); the flags apply crate-wide.
    pub fn new_bearer(
        access_jwt: String,
        refresh_jwt: String,
        base_url: String,
    ) -> Result<Self, OAuthError> {
        Self::new_bearer_with_observer(
            access_jwt,
            refresh_jwt,
            base_url,
            std::sync::Arc::new(NoopObserver),
        )
    }

    /// [`Self::new_bearer`], recording transport-failure breadcrumbs into `observer`.
    pub fn new_bearer_with_observer(
        access_jwt: String,
        refresh_jwt: String,
        base_url: String,
        observer: std::sync::Arc<dyn TransportObserver>,
    ) -> Result<Self, OAuthError> {
        let expires_at = jwt_exp_claim(&access_jwt).unwrap_or(0);
        Ok(Self {
            inner: Client::new(),
            session: Mutex::new(Tokens {
                access_token: access_jwt,
                refresh_token: refresh_jwt,
                expires_at,
            }),
            base_url,
            observer,
        })
    }

    /// Snapshot the current session token pair (access, refresh).
    ///
    /// Reads the live session state, so a pair rotated by a transparent refresh is returned
    /// rather than the construction-time snapshot. Used by the migration finalize path to
    /// persist the destination Bearer session for a did:web identity, which has no PLC
    /// rotation keys to mint a sovereign session with.
    pub fn session_tokens(&self) -> (String, String) {
        let session = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (session.access_token.clone(), session.refresh_token.clone())
    }

    fn access_token(&self) -> String {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .access_token
            .clone()
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    /// GET `{base_url}/{path}`.
    pub async fn get(&self, path: &str) -> Result<Response, OAuthError> {
        self.send(reqwest::Method::GET, path, |b| b).await
    }

    /// POST `{base_url}/{path}` with a JSON body.
    pub async fn post<B: Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Response, OAuthError> {
        self.send(reqwest::Method::POST, path, |b| b.json(body))
            .await
    }

    /// PUT `{base_url}/{path}` with a JSON body.
    ///
    /// Used for idempotent owner writes like `PUT /v1/recovery/escrow-share` (deposit or
    /// replace the account's escrow Share 2), where the resource is the account's single
    /// escrow slot rather than a new collection member.
    pub async fn put<B: Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Response, OAuthError> {
        self.send(reqwest::Method::PUT, path, |b| b.json(body))
            .await
    }

    /// POST `{base_url}/{path}` with NO request body and no `Content-Type` header.
    ///
    /// For no-input XRPC procedures (`requestPlcOperationSignature`, `activateAccount`):
    /// their lexicons define no input, and a spec-strict PDS (bsky.social) rejects any
    /// body with `InvalidRequest: A request body was provided when none was expected`.
    pub async fn post_no_body(&self, path: &str) -> Result<Response, OAuthError> {
        self.send(reqwest::Method::POST, path, |b| b).await
    }

    /// POST `{base_url}/{path}` with a raw byte body and caller-chosen Content-Type.
    ///
    /// Used for binary uploads like `importRepo` (CAR format) and `uploadBlob` (arbitrary MIME type).
    pub async fn post_bytes(
        &self,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Response, OAuthError> {
        self.send(reqwest::Method::POST, path, |b| {
            b.header("Content-Type", content_type).body(body)
        })
        .await
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Refresh if due, then send one request with the Bearer header. `attach` adds the body.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        attach: impl FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<Response, OAuthError> {
        self.maybe_refresh_token().await?;

        let url = self.url(path);
        let builder = self
            .inner
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.access_token()));

        attach(builder).send().await.map_err(|e| {
            // Strip the request URL from the error before it is logged: a reqwest error's
            // `Display` embeds the full URL (host + query), which can carry a DID or other
            // account material. The redacted host is recorded separately below.
            let e = e.without_url();
            tracing::error!(error = %e, "OAuthClient request network error");
            // Record a redacted breadcrumb (host + transport category only), so a genuine
            // connect/timeout/read failure leaves a trace in the diagnostics log.
            self.observer
                .record_transport("oauthRequest", Some(&url), &e);
            OAuthError::NotAuthenticated
        })
    }

    /// Refresh the access token if it expires within the next 60 seconds.
    async fn maybe_refresh_token(&self) -> Result<(), OAuthError> {
        let should_refresh = {
            let s = self
                .session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A one-shot client (e.g. carrying a service-auth JWT) is built with an empty
            // refresh token — it cannot refresh, so never attempt it (a refresh with an empty
            // Bearer would fail and abort the in-flight request).
            if s.refresh_token.is_empty() {
                false
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| OAuthError::TokenRefreshFailed)?
                    .as_secs();
                s.expires_at < now + 60
            }
        };

        if should_refresh {
            self.refresh_token().await?;
        }
        Ok(())
    }

    /// Refresh the access token via `POST /xrpc/com.atproto.server.refreshSession` with the
    /// refresh JWT as the Bearer. Updates the session **in memory only**. Surfaces all errors
    /// to the caller — no silent swallowing.
    pub async fn refresh_token(&self) -> Result<(), OAuthError> {
        let refresh_token = {
            let s = self
                .session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.refresh_token.clone()
        };

        let url = format!("{}/xrpc/com.atproto.server.refreshSession", self.base_url);
        let resp = self
            .inner
            .post(&url)
            .header("Authorization", format!("Bearer {refresh_token}"))
            .send()
            .await
            .map_err(|e| {
                self.observer
                    .record_transport("oauthBearerRefresh", Some(&url), &e);
                let e = e.without_url();
                tracing::error!(error = %e, "Bearer token refresh network error");
                OAuthError::TokenRefreshFailed
            })?;

        if resp.status().as_u16() == 400 {
            let body = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
                if err.get("error").and_then(|e| e.as_str()) == Some("invalid_grant") {
                    tracing::error!("Bearer refresh token invalid");
                    return Err(OAuthError::InvalidGrant);
                }
            }
            tracing::error!(body = %body, "Bearer token refresh failed");
            return Err(OAuthError::TokenRefreshFailed);
        }

        if resp.status().as_u16() != 200 {
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(body = %body, "Bearer token refresh failed");
            return Err(OAuthError::TokenRefreshFailed);
        }

        let token_resp: RefreshSessionResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "Bearer token refresh response deserialization failed");
            OAuthError::TokenRefreshFailed
        })?;

        let expires_at = jwt_exp_claim(&token_resp.access_jwt).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        let mut s = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.access_token = token_resp.access_jwt;
        s.refresh_token = token_resp.refresh_jwt;
        s.expires_at = expires_at;

        tracing::info!("Bearer access token refreshed (in-memory only)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    /// Create a Bearer-mode test JWT with a specific exp claim.
    fn make_bearer_jwt(exp: u64) -> String {
        use crate::base64url::b64url_encode;
        let header = b64url_encode(r#"{"alg":"ES256"}"#);
        let payload = b64url_encode(format!(r#"{{"exp":{}}}"#, exp).as_bytes());
        // Dummy signature; jwt_exp_claim never verifies it
        let sig = "dummy_signature";
        format!("{}.{}.{}", header, payload, sig)
    }

    /// Create a Bearer-mode OAuthClient for testing.
    async fn make_bearer_client(access: &str, refresh: &str, base_url: &str) -> OAuthClient {
        OAuthClient::new_bearer(
            access.to_string(),
            refresh.to_string(),
            base_url.to_string(),
        )
        .expect("new_bearer must succeed")
    }

    /// `when.is_true()` predicate: request must NOT have a `DPoP` header.
    fn request_has_no_dpop_header(req: &HttpMockRequest) -> bool {
        req.headers_vec()
            .iter()
            .all(|(k, _)| !k.eq_ignore_ascii_case("dpop"))
    }

    #[tokio::test]
    async fn put_reaches_server_with_body_in_bearer_mode() {
        // Regression: `send` once matched only GET/POST, so every PUT returned
        // `NotAuthenticated` before any network call — breaking the escrow-share deposit
        // (`PUT /v1/recovery/escrow-share`), which then surfaced as a bogus "network error".
        let server = MockServer::start();
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let access_jwt = make_bearer_jwt(far_future);
        let mock = server.mock(|when, then| {
            when.method(PUT)
                .path("/v1/recovery/escrow-share")
                .header("Authorization", format!("Bearer {access_jwt}"))
                .json_body(serde_json::json!({ "share": "share-two" }));
            then.status(200).body("ok");
        });

        let client = make_bearer_client(&access_jwt, "bearer_refresh", &server.base_url()).await;
        let resp = client
            .put(
                "/v1/recovery/escrow-share",
                &serde_json::json!({ "share": "share-two" }),
            )
            .await
            .expect("PUT must reach the server, not fail before sending");
        assert_eq!(resp.status().as_u16(), 200);
        mock.assert();
    }

    #[tokio::test]
    async fn bearer_mode_sends_authorization_bearer_header() {
        // Verifies: Bearer-mode client sends Authorization: Bearer {token} and no DPoP header.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_exp = now + 3600;
        let access_jwt = make_bearer_jwt(future_exp);
        // The access token IS the JWT, so the Authorization header is `Bearer {jwt}`.
        let expected_auth = format!("Bearer {access_jwt}");

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/resource")
                .header("Authorization", expected_auth.as_str())
                .is_true(request_has_no_dpop_header);
            then.status(200).body("ok");
        });

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
        assert_eq!(
            resp.status().as_u16(),
            400,
            "should return the 400 without retry"
        );
        assert_eq!(mock.calls(), 1, "must send exactly one request (no retry)");
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

    #[tokio::test]
    async fn bearer_refresh_hits_refresh_session_not_oauth_token() {
        // Verifies: Bearer client refresh uses POST /xrpc/com.atproto.server.refreshSession, not /oauth/token.
        // Also verifies: refresh updates session in memory only.
        let server = MockServer::start();

        // Mock the refreshSession endpoint.
        let refresh_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/xrpc/com.atproto.server.refreshSession")
                .header("Authorization", "Bearer old_refresh_token");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": "new_access_jwt",
                "refreshJwt": "new_refresh_jwt"
            }));
        });

        // Mock /oauth/token — should NOT be called (0 hits expected).
        let oauth_mock = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200);
        });

        // Create a Bearer client with an expired token (expires_at = 0 forces refresh).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_jwt = make_bearer_jwt(now - 100); // Already expired
        let client =
            make_bearer_client(&expired_jwt, "old_refresh_token", &server.base_url()).await;

        // Issue a request — should trigger lazy refresh.
        let resp_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/resource")
                .header("Authorization", "Bearer new_access_jwt")
                .is_true(request_has_no_dpop_header);
            then.status(200).body("ok");
        });

        let resp = client.get("/resource").await.expect("GET must succeed");
        assert_eq!(resp.status().as_u16(), 200);

        // Verify refreshSession was called exactly once.
        assert_eq!(
            refresh_mock.calls(),
            1,
            "POST /xrpc/com.atproto.server.refreshSession must be called exactly once"
        );

        // Verify /oauth/token was NOT called.
        assert_eq!(
            oauth_mock.calls(),
            0,
            "POST /oauth/token must NOT be called for Bearer mode"
        );

        // Verify the follow-up request used the new access token.
        assert_eq!(
            resp_mock.calls(),
            1,
            "follow-up request must carry the new access token"
        );

        // Verify session was updated in memory with the new tokens.
        let session = client.session.lock().unwrap();
        assert_eq!(
            session.access_token, "new_access_jwt",
            "session access token must be updated"
        );
        assert_eq!(
            session.refresh_token, "new_refresh_jwt",
            "session refresh token must be updated"
        );
    }

    #[tokio::test]
    async fn bearer_refresh_invalid_grant_returns_invalid_grant() {
        // Verifies: Bearer refresh 400 with invalid_grant maps to InvalidGrant, not TokenRefreshFailed.
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST)
                .path("/xrpc/com.atproto.server.refreshSession");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "refresh token expired"
            }));
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_jwt = make_bearer_jwt(now - 100);
        let client =
            make_bearer_client(&expired_jwt, "old_refresh_token", &server.base_url()).await;

        let result = client.refresh_token().await;
        assert!(
            matches!(result, Err(OAuthError::InvalidGrant)),
            "Bearer refresh invalid_grant must surface as InvalidGrant, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn post_bytes_bearer_sends_correct_headers_and_body() {
        // Verifies: Bearer client post_bytes sends Authorization: Bearer, Content-Type, no DPoP header, and the exact byte body.
        let expected_bytes = b"fake CAR data blob here";

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_exp = now + 3600;
        let access_jwt = make_bearer_jwt(future_exp);
        // The access token IS the JWT, so the Authorization header is `Bearer {jwt}`.
        let expected_auth = format!("Bearer {access_jwt}");

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/xrpc/com.atproto.repo.importRepo")
                .header("Authorization", expected_auth.as_str())
                .header("Content-Type", "application/vnd.ipld.car")
                .is_true(request_has_no_dpop_header)
                // Exact full-body match (httpmock's `When::body`); the payload is ASCII.
                .body(std::str::from_utf8(expected_bytes).unwrap());
            then.status(200).json_body(serde_json::json!({
                "uri": "at://did:plc:abc/com.atproto.repo.blob/hash"
            }));
        });

        let client = make_bearer_client(&access_jwt, "my_refresh_token", &server.base_url()).await;

        let resp = client
            .post_bytes(
                "/xrpc/com.atproto.repo.importRepo",
                "application/vnd.ipld.car",
                expected_bytes.to_vec(),
            )
            .await
            .expect("post_bytes must succeed");

        assert_eq!(resp.status().as_u16(), 200, "post_bytes must return 200");
    }
}
