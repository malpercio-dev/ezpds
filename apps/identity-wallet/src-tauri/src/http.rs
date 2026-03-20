//! Relay HTTP client for identity-wallet.
//!
//! All relay API calls go through `RelayClient`. The base URL is
//! compile-time configured: `http://localhost:8080` in debug builds,
//! `https://relay.ezpds.com` in release builds.

use reqwest::{Client, Response};
use serde::Serialize;

#[cfg(debug_assertions)]
const RELAY_BASE_URL: &str = "http://localhost:8080";
#[cfg(not(debug_assertions))]
const RELAY_BASE_URL: &str = "https://relay.ezpds.com";

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
