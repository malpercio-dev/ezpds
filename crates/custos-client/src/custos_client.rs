// pattern: Imperative Shell

//! [`CustosClient`]: the HTTP client for *one* configured PDS — plain JSON/Bearer requests
//! plus the OAuth PAR/token-exchange pair. Unlike [`crate::oauth_client::OAuthClient`], this
//! client carries no session state; it is the pre-session client an app uses to talk to
//! whichever single PDS instance it has configured (discovery/auth/XRPC against *arbitrary*
//! PDS endpoints is the caller's job, e.g. identity-wallet's `pds_client.rs`).
//!
//! `par`/`token_exchange` take `client_id`/`redirect_uri` as parameters rather than deriving
//! them internally — an app's OAuth client identity names the app itself, so it stays out of
//! this Tauri-free crate (see this crate's AGENTS.md Boundaries).
//!
//! Diagnostics breadcrumbs are injected via [`crate::error::TransportObserver`], same as
//! [`crate::oauth_client::OAuthClient`].

use std::sync::Arc;

use reqwest::{Client, Response};
use serde::Serialize;

use crate::error::TransportObserver;
use crate::oauth_client::OAuthError;

/// Successful response from `POST /oauth/par` (RFC 9126 §2.2).
#[derive(Debug, serde::Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u32,
}

/// Error response from `POST /oauth/token` (RFC 6749 §5.2).
#[derive(Debug, serde::Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// Parameters for [`CustosClient::par`], grouped to keep the method to one argument (zero
/// production callers today — the retired create-flow OAuth login — so this is the natural
/// moment to avoid an eight-argument signature rather than `#[allow]`ing it).
pub struct ParRequest<'a> {
    pub code_challenge: &'a str,
    pub state: &'a str,
    pub dpop_proof: &'a str,
    /// The JWK thumbprint of the DPoP key; included as a form field for servers that support
    /// PAR-level DPoP key binding (the PDS ignores it, but it is spec-correct to send it).
    pub dpop_jkt: &'a str,
    pub login_hint: Option<&'a str>,
    /// The caller's OAuth client identity — this crate never hardcodes an app's own.
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
}

/// HTTP client for one configured PDS.
pub struct CustosClient {
    client: Client,
    base_url: String,
    observer: Arc<dyn TransportObserver>,
}

impl CustosClient {
    fn record_transport(&self, op: &str, url: &str, error: &reqwest::Error) {
        self.observer.record_transport(op, Some(url), error);
    }

    /// Create a `CustosClient` for `base_url` (no trailing slash), recording transport
    /// breadcrumbs into `observer`.
    pub fn new_with_url(base_url: String, observer: Arc<dyn TransportObserver>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            observer,
        }
    }

    /// POST JSON to `path` (relative, e.g. `"/v1/accounts/mobile"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|error| {
                self.record_transport("custosPost", &url, &error);
                error.without_url()
            })
    }

    /// GET `path` (relative, e.g. `"/v1/PDS/keys"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn get(&self, path: &str) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await.map_err(|error| {
            self.record_transport("custosGet", &url, &error);
            error.without_url()
        })
    }

    /// GET `path` with a Bearer token in the Authorization header.
    ///
    /// Used for authenticated PDS GETs (e.g. `GET /v1/repo-signing-key`, which is
    /// scoped to the caller's pending session).
    pub async fn get_with_bearer(
        &self,
        path: &str,
        bearer_token: &str,
    ) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .get(&url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .map_err(|error| {
                self.record_transport("custosGetAuthenticated", &url, &error);
                error.without_url()
            })
    }

    /// POST JSON to `path` with a Bearer token in the Authorization header.
    ///
    /// Used for authenticated PDS endpoints (e.g. `POST /v1/dids` which
    /// requires the pending session token).
    pub async fn post_with_bearer<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        bearer_token: &str,
    ) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .bearer_auth(bearer_token)
            .json(body)
            .send()
            .await
            .map_err(|error| {
                self.record_transport("custosPostAuthenticated", &url, &error);
                error.without_url()
            })
    }

    /// POST `/oauth/par` — push the authorization request parameters to the PDS.
    ///
    /// Sends the required PKCE and OAuth parameters as `application/x-www-form-urlencoded`.
    /// Includes a `DPoP` proof header per RFC 9449 §6.
    pub async fn par(&self, request: ParRequest<'_>) -> Result<ParResponse, OAuthError> {
        let url = format!("{}/oauth/par", self.base_url);

        let hint_owned;
        let mut fields = vec![
            ("client_id", request.client_id),
            ("redirect_uri", request.redirect_uri),
            ("code_challenge", request.code_challenge),
            ("code_challenge_method", "S256"),
            ("state", request.state),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("dpop_jkt", request.dpop_jkt),
        ];

        if let Some(hint) = request.login_hint {
            hint_owned = hint.to_string();
            fields.push(("login_hint", &hint_owned));
        }

        let resp = self
            .client
            .post(&url)
            .header("DPoP", request.dpop_proof)
            .form(&fields)
            .send()
            .await
            .map_err(|e| {
                self.record_transport("oauthPar", &url, &e);
                let e = e.without_url();
                tracing::error!(error = %e, "PAR request network error");
                OAuthError::ParFailed
            })?;

        let status = resp.status();
        if status.as_u16() != 201 {
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(status = %status, body = %body, "PAR request failed");
            return Err(OAuthError::ParFailed);
        }

        resp.json::<ParResponse>().await.map_err(|e| {
            tracing::error!(error = %e, "PAR response deserialization failed");
            OAuthError::ParFailed
        })
    }

    /// POST `/oauth/token` — exchange an authorization code for tokens.
    ///
    /// Sends the authorization code, PKCE verifier, and DPoP proof. Returns the token
    /// response body on 200, or an error. The caller is responsible for reading the
    /// `DPoP-Nonce` response header if the server returns one (the full `reqwest::Response`
    /// is returned for this) and for deserializing a 200 body as
    /// [`crate::oauth_client::TokenResponse`]. `client_id`/`redirect_uri` are the caller's
    /// OAuth client identity.
    pub async fn token_exchange(
        &self,
        code: &str,
        pkce_verifier: &str,
        dpop_proof: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<reqwest::Response, OAuthError> {
        let url = format!("{}/oauth/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("DPoP", dpop_proof)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", client_id),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| {
                self.record_transport("oauthTokenExchange", &url, &e);
                let e = e.without_url();
                tracing::error!(error = %e, "token exchange network error");
                OAuthError::TokenExchangeFailed
            })?;
        Ok(resp)
    }

    /// Returns the base URL for this PDS client instance.
    pub fn base_url_str(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NoopObserver;

    #[tokio::test]
    async fn network_error_is_url_redacted() {
        let client =
            CustosClient::new_with_url("http://127.0.0.1:1".to_string(), Arc::new(NoopObserver));
        let error = client
            .post(
                "/v1/accounts/mobile?claim=diagnostic-secret",
                &serde_json::json!({"email": "secret@example.com"}),
            )
            .await
            .unwrap_err();
        let displayed_error = error.to_string();
        assert!(!displayed_error.contains("diagnostic-secret"));
        assert!(!displayed_error.contains("/v1/accounts/mobile"));
    }
}
