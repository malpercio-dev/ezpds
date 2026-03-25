//! Relay HTTP client for identity-wallet.
//!
//! All relay API calls go through `RelayClient`. The base URL is
//! compile-time configured: `http://localhost:8080` in debug builds,
//! `https://relay.ezpds.com` in release builds.

use reqwest::{Client, Response};
use serde::Serialize;

use crate::oauth::OAuthError;

#[cfg(debug_assertions)]
const RELAY_BASE_URL: &str = "http://localhost:8080";
#[cfg(not(debug_assertions))]
const RELAY_BASE_URL: &str = "https://relay.ezpds.com";

/// Successful response from `POST /oauth/par` (RFC 9126 §2.2).
#[derive(Debug, serde::Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u32,
}

/// Successful response from `POST /oauth/token` (RFC 6749 §5.1).
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

/// Error response from `POST /oauth/token` (RFC 6749 §5.2).
#[derive(Debug, serde::Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// HTTP client for relay API requests.
pub struct RelayClient {
    client: Client,
    base_url: &'static str,
}

impl RelayClient {
    /// Create a new `RelayClient` with the compile-time base URL.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: RELAY_BASE_URL,
        }
    }

    /// POST JSON to `path` (relative, e.g. `"/v1/accounts/mobile"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.post(&url).json(body).send().await
    }

    /// GET `path` (relative, e.g. `"/v1/relay/keys"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn get(&self, path: &str) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await
    }

    /// POST JSON to `path` with a Bearer token in the Authorization header.
    ///
    /// Used for authenticated relay endpoints (e.g. `POST /v1/dids` which
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
    }

    /// POST `/oauth/par` — push the authorization request parameters to the relay.
    ///
    /// Sends the required PKCE and OAuth parameters as `application/x-www-form-urlencoded`.
    /// Includes a `DPoP` proof header per RFC 9449 §6.
    ///
    /// `dpop_jkt` is the JWK thumbprint of the DPoP key; included as a form field for
    /// servers that support PAR-level DPoP key binding (the relay currently ignores it,
    /// but it is spec-correct to send it).
    pub async fn par(
        &self,
        code_challenge: &str,
        state_param: &str,
        dpop_proof: &str,
        dpop_jkt: &str,
        login_hint: Option<&str>,
    ) -> Result<ParResponse, OAuthError> {
        let url = format!("{}/oauth/par", self.base_url);

        let hint_owned;
        let mut fields = vec![
            ("client_id", "dev.malpercio.identitywallet"),
            (
                "redirect_uri",
                "dev.malpercio.identitywallet:/oauth/callback",
            ),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
            ("state", state_param),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("dpop_jkt", dpop_jkt),
        ];

        if let Some(hint) = login_hint {
            hint_owned = hint.to_string();
            fields.push(("login_hint", &hint_owned));
        }

        let resp = self
            .client
            .post(&url)
            .header("DPoP", dpop_proof)
            .form(&fields)
            .send()
            .await
            .map_err(|e| {
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
    /// Sends the authorization code, PKCE verifier, and DPoP proof.
    /// Returns the token response body on 200, or an error.
    /// The caller is responsible for reading the `DPoP-Nonce` response header
    /// if the server returns one (the full `reqwest::Response` is returned for this).
    pub async fn token_exchange(
        &self,
        code: &str,
        pkce_verifier: &str,
        dpop_proof: &str,
    ) -> Result<reqwest::Response, OAuthError> {
        let url = format!("{}/oauth/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("DPoP", dpop_proof)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                (
                    "redirect_uri",
                    "dev.malpercio.identitywallet:/oauth/callback",
                ),
                ("client_id", "dev.malpercio.identitywallet"),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "token exchange network error");
                OAuthError::TokenExchangeFailed
            })?;
        Ok(resp)
    }

    /// Returns the compile-time base URL for this relay client instance.
    ///
    /// Used as the `service_endpoint` parameter in DID ceremony genesis op construction.
    pub const fn base_url() -> &'static str {
        RELAY_BASE_URL
    }
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}
