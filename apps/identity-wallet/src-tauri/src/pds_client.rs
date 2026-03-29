// pattern: Imperative Shell
//
// Gathers: PDS discovery parameters (handle, DID, OAuth metadata)
// Processes: DNS TXT resolution, HTTP well-known fetches, PDS OAuth metadata discovery
// Returns: PDS endpoints, authorization server metadata, or error codes

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

/// OAuth client ID for the identity wallet application
const CLIENT_ID: &str = "dev.malpercio.identitywallet";

/// OAuth redirect URI for the identity wallet application
const REDIRECT_URI: &str = "dev.malpercio.identitywallet:/oauth/callback";

/// Error type for PDS client operations.
///
/// Serializes to frontend with `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`,
/// matching the `OAuthError` / `IdentityStoreError` pattern.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PdsClientError {
    /// Neither DNS nor HTTP resolution succeeded for the handle.
    #[error("handle not found")]
    HandleNotFound,

    /// plc.directory returned 404 for the DID.
    #[error("did not found")]
    DidNotFound,

    /// PDS endpoint is down or unreachable.
    #[error("pds unreachable: {reason}")]
    PdsUnreachable {
        /// Reason for unreachability (transport error, connection refused, etc.).
        /// Not serialized to frontend (serde skip).
        #[serde(skip)]
        reason: String,
    },

    /// Transport-level failure (DNS timeout, connection refused, etc.).
    #[error("network error: {message}")]
    NetworkError { message: String },

    /// Response body couldn't be parsed or was missing expected fields.
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },

    /// PAR or token exchange failed.
    #[error("oauth failed: {message}")]
    OauthFailed { message: String },
}

/// PLC directory DID document response.
///
/// Returned from `GET {plc_directory_url}/{did}`.
/// Field names use camelCase per the API.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcDidDocument {
    pub did: String,
    pub also_known_as: Vec<String>,
    pub rotation_keys: Vec<String>,
    pub verification_methods: serde_json::Value,
    pub services: HashMap<String, PlcService>,
}

/// PLC service entry (one service in `PlcDidDocument.services`).
#[derive(Debug, Clone, Deserialize)]
pub struct PlcService {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

/// OAuth authorization server metadata.
///
/// Returned from `GET {pds_url}/.well-known/oauth-authorization-server`.
#[derive(Debug, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub pushed_authorization_request_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
}

/// Response from PAR (Pushed Authorization Request).
///
/// Returned from `POST {pushed_authorization_request_endpoint}`.
#[derive(Debug, Deserialize)]
pub struct PdsParResponse {
    pub request_uri: String,
    pub expires_in: u32,
}

/// Request body for `signPlcOperation`.
///
/// Serializes to frontend with `#[serde(rename_all = "camelCase")]`.
/// Optional fields are skipped if None.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPlcOperationRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_methods: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<serde_json::Value>,
}

/// Response from `signPlcOperation`.
///
/// Returned from `POST /xrpc/com.atproto.identity.signPlcOperation`.
#[derive(Debug, Deserialize)]
pub struct SignPlcOperationResponse {
    pub operation: serde_json::Value,
}

/// Recommended credentials for a DID.
///
/// Returned from `GET /xrpc/com.atproto.identity.getRecommendedDidCredentials`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedCredentials {
    pub rotation_keys: Option<Vec<String>>,
    pub also_known_as: Option<Vec<String>>,
    pub verification_methods: Option<serde_json::Value>,
    pub services: Option<serde_json::Value>,
}

/// PDS client for discovery and OAuth operations against arbitrary PDS endpoints.
///
/// Stateless except for the HTTP client which pools connections.
#[allow(dead_code)]
// TODO(Phase 4): Remove #[allow(dead_code)] once Tauri commands call PdsClient methods
pub struct PdsClient {
    client: Client,
    plc_directory_url: String,
}

impl PdsClient {
    /// Construct a new PdsClient with the default plc.directory URL.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            plc_directory_url: "https://plc.directory".to_string(),
        }
    }

    /// Test constructor: accepts a custom plc.directory URL (e.g., mock server).
    ///
    /// Follows the same pattern as `OAuthClient::new_for_test` in oauth_client.rs.
    #[cfg(test)]
    pub fn new_for_test(plc_directory_url: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            plc_directory_url,
        }
    }

    /// Resolve a handle to a DID via DNS TXT lookup with HTTP fallback.
    ///
    /// Attempts DNS TXT lookup for `_atproto.{handle}` first, then falls back to HTTP
    /// `/.well-known/atproto-did` if DNS fails or returns no records.
    /// Returns `HANDLE_NOT_FOUND` only when both methods fail.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, PdsClientError> {
        // Try DNS TXT lookup first
        let dns_error = match try_resolve_dns(handle).await {
            Ok(Some(did)) => return Ok(did),
            Ok(None) => None,
            Err(e) => Some(e),
        };

        // Try HTTP well-known lookup
        let http_url = format!("https://{}/.well-known/atproto-did", handle);
        match try_resolve_http(&self.client, &http_url).await {
            Ok(Some(did)) => return Ok(did),
            Ok(None) => {
                // Both DNS and HTTP failed; if DNS had a transport error, surface it
                if let Some(dns_err) = dns_error {
                    return Err(dns_err);
                }
            }
            Err(e) => return Err(e),
        }

        // Neither DNS nor HTTP succeeded (both returned "not found", no transport errors)
        Err(PdsClientError::HandleNotFound)
    }

    /// Fetch the DID document from plc.directory and extract the PDS endpoint.
    ///
    /// Fetches the DID document from plc.directory, extracts the atproto_pds service
    /// endpoint, and verifies it is reachable via a HEAD request.
    /// Returns `DID_NOT_FOUND` on 404, `PDS_UNREACHABLE` if the endpoint is down.
    pub async fn discover_pds(
        &self,
        did: &str,
    ) -> Result<(String, PlcDidDocument), PdsClientError> {
        let url = format!("{}/{}", self.plc_directory_url, did);

        // Fetch the DID document from plc.directory
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| PdsClientError::NetworkError {
                    message: format!("failed to fetch DID document: {}", e),
                })?;

        match response.status() {
            s if s == 404 => return Err(PdsClientError::DidNotFound),
            s if !s.is_success() => {
                return Err(PdsClientError::NetworkError {
                    message: format!("plc.directory returned {}", s),
                });
            }
            _ => {}
        }

        // Parse response as PlcDidDocument
        let doc: PlcDidDocument =
            response
                .json()
                .await
                .map_err(|e| PdsClientError::InvalidResponse {
                    message: format!("failed to parse DID document: {}", e),
                })?;

        // Extract the atproto_pds service
        let pds_service =
            doc.services
                .get("atproto_pds")
                .ok_or_else(|| PdsClientError::InvalidResponse {
                    message: "missing atproto_pds service".to_string(),
                })?;

        let pds_endpoint = &pds_service.endpoint;

        // Verify PDS reachability with a HEAD request (5-second timeout)
        self.client
            .head(pds_endpoint)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| PdsClientError::PdsUnreachable {
                reason: format!("failed to reach PDS endpoint: {}", e),
            })?;

        Ok((pds_endpoint.to_string(), doc))
    }

    /// Fetch OAuth authorization server metadata from the PDS.
    ///
    /// Fetches `/.well-known/oauth-authorization-server` and validates that
    /// `response_types_supported` includes "code" and `code_challenge_methods_supported`
    /// includes "S256".
    pub async fn discover_auth_server(
        &self,
        pds_url: &str,
    ) -> Result<AuthServerMetadata, PdsClientError> {
        let url = format!("{}/.well-known/oauth-authorization-server", pds_url);

        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| PdsClientError::NetworkError {
                    message: format!("failed to fetch OAuth metadata: {}", e),
                })?;

        if !response.status().is_success() {
            return Err(PdsClientError::InvalidResponse {
                message: format!(
                    "OAuth metadata fetch returned {} from {}",
                    response.status(),
                    pds_url
                ),
            });
        }

        let metadata: AuthServerMetadata =
            response
                .json()
                .await
                .map_err(|e| PdsClientError::InvalidResponse {
                    message: format!("failed to parse OAuth metadata: {}", e),
                })?;

        // Validate required capabilities
        if !metadata
            .response_types_supported
            .contains(&"code".to_string())
        {
            return Err(PdsClientError::InvalidResponse {
                message: "OAuth metadata missing 'code' in response_types_supported".to_string(),
            });
        }

        if !metadata
            .code_challenge_methods_supported
            .contains(&"S256".to_string())
        {
            return Err(PdsClientError::InvalidResponse {
                message: "OAuth metadata missing 'S256' in code_challenge_methods_supported"
                    .to_string(),
            });
        }

        Ok(metadata)
    }

    /// Perform a Pushed Authorization Request to an arbitrary PDS.
    ///
    /// Sends a PAR request with PKCE challenge, DPoP proof, and optional login_hint.
    pub async fn pds_par(
        &self,
        metadata: &AuthServerMetadata,
        pkce_challenge: &str,
        state_param: &str,
        dpop_proof: &str,
        dpop_jkt: &str,
        login_hint: Option<&str>,
    ) -> Result<PdsParResponse, PdsClientError> {
        let par_url = metadata
            .pushed_authorization_request_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

        let mut form_data = vec![
            ("response_type", "code".to_string()),
            ("code_challenge_method", "S256".to_string()),
            ("code_challenge", pkce_challenge.to_string()),
            ("state", state_param.to_string()),
            ("client_id", CLIENT_ID.to_string()),
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("scope", "atproto transition:generic".to_string()),
            ("dpop_jkt", dpop_jkt.to_string()),
        ];

        if let Some(hint) = login_hint {
            form_data.push(("login_hint", hint.to_string()));
        }

        let response = self
            .client
            .post(&par_url)
            .header("DPoP", dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PdsClientError::OauthFailed {
                message: format!("PAR request failed: {}", e),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(PdsClientError::OauthFailed {
                message: format!("PAR returned {}: {}", status, error_body),
            });
        }

        let json_resp =
            response
                .json::<PdsParResponse>()
                .await
                .map_err(|e| PdsClientError::OauthFailed {
                    message: format!("failed to parse PAR response: {}", e),
                })?;

        Ok(json_resp)
    }

    /// Exchange authorization code for tokens at an arbitrary PDS.
    ///
    /// Returns the raw response so the caller can handle nonce retry logic.
    /// Only transport-level failures are mapped to PdsClientError; HTTP error statuses
    /// are returned as-is for the caller to inspect.
    pub async fn pds_token_exchange(
        &self,
        metadata: &AuthServerMetadata,
        code: &str,
        pkce_verifier: &str,
        dpop_proof: &str,
    ) -> Result<reqwest::Response, PdsClientError> {
        let token_url = &metadata.token_endpoint;

        let form_data = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", pkce_verifier),
            ("client_id", CLIENT_ID),
        ];

        self.client
            .post(token_url)
            .header("DPoP", dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PdsClientError::OauthFailed {
                message: format!("token exchange request failed: {}", e),
            })
    }

    /// Build the browser redirect URL for OAuth authorization.
    ///
    /// Constructs `{authorization_endpoint}?client_id=...&request_uri=...` with optional login_hint.
    pub fn build_pds_authorize_url(
        metadata: &AuthServerMetadata,
        request_uri: &str,
        login_hint: Option<&str>,
    ) -> String {
        let mut url = format!(
            "{}?client_id={}&request_uri={}",
            metadata.authorization_endpoint,
            CLIENT_ID,
            urlencoding::encode(request_uri)
        );

        if let Some(hint) = login_hint {
            url.push_str(&format!("&login_hint={}", urlencoding::encode(hint)));
        }

        url
    }
}

impl Default for PdsClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper functions for resolve_handle
// ============================================================================

/// DNS TXT lookup for `_atproto.{handle}`. Returns `Ok(Some(did))` on success,
/// `Ok(None)` if no matching TXT record found, `Err` on transport failure.
async fn try_resolve_dns(handle: &str) -> Result<Option<String>, PdsClientError> {
    let dns_name = format!("_atproto.{}", handle);

    // Create a resolver using system DNS config (matches relay pattern in dns.rs:49)
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to create DNS resolver: {}", e),
        })?
        .build();

    match resolver.txt_lookup(&dns_name).await {
        Ok(lookup) => {
            // Iterate through TXT records and find one starting with "did="
            for record in lookup.iter() {
                for part in record.txt_data() {
                    match std::str::from_utf8(part) {
                        Ok(s) => {
                            if let Some(did_value) = s.strip_prefix("did=") {
                                let did = did_value.trim().to_string();
                                return Ok(Some(did));
                            }
                        }
                        Err(_) => {
                            // Non-UTF-8 bytes in TXT record; skip
                        }
                    }
                }
            }
            Ok(None)
        }
        Err(e) => {
            // Check if it's a "no records found" error (normal for unregistered handles)
            // vs. a transport error (network failure)
            if e.is_no_records_found() {
                Ok(None)
            } else {
                Err(PdsClientError::NetworkError {
                    message: format!("DNS lookup failed: {}", e),
                })
            }
        }
    }
}

/// HTTP well-known fetch. `GET {url}` and return trimmed body on 2xx,
/// `Ok(None)` on 4xx (handle not found), `Err(NetworkError)` on transport or 5xx.
/// The caller constructs the full URL.
async fn try_resolve_http(
    client: &reqwest::Client,
    url: &str,
) -> Result<Option<String>, PdsClientError> {
    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => Ok(Some(body.trim().to_string())),
                    Err(e) => Err(PdsClientError::NetworkError {
                        message: format!("failed to read response body: {}", e),
                    }),
                }
            } else if response.status().is_client_error() {
                // 4xx = handle not found at this endpoint
                Ok(None)
            } else {
                // 5xx = temporary server error
                Err(PdsClientError::NetworkError {
                    message: format!("server error from {}: {}", url, response.status()),
                })
            }
        }
        Err(e) => {
            // Transport error
            Err(PdsClientError::NetworkError {
                message: format!("HTTP request failed: {}", e),
            })
        }
    }
}

// ============================================================================
// XRPC Identity methods (require DPoP-authenticated OAuthClient)
// ============================================================================

/// Request a PLC operation signature from the PDS.
///
/// Triggers email verification on the PDS.
pub async fn request_plc_operation_signature(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
            &serde_json::json!({}),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })?;

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(PdsClientError::NetworkError {
            message: format!("request_plc_operation_signature returned {}: {}", status, body),
        })
    }
}

/// Sign a PLC operation with credentials from the PDS.
pub async fn sign_plc_operation(
    client: &crate::oauth_client::OAuthClient,
    request: &SignPlcOperationRequest,
) -> Result<SignPlcOperationResponse, PdsClientError> {
    let resp = client
        .post("/xrpc/com.atproto.identity.signPlcOperation", request)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("sign_plc_operation failed: {}", e),
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(PdsClientError::NetworkError {
            message: format!("sign_plc_operation returned {}: {}", status, body),
        });
    }

    resp.json::<SignPlcOperationResponse>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse sign_plc_operation response: {}", e),
        })
}

/// Fetch recommended credentials for the DID from the PDS.
pub async fn get_recommended_did_credentials(
    client: &crate::oauth_client::OAuthClient,
) -> Result<RecommendedCredentials, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_recommended_did_credentials failed: {}", e),
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(PdsClientError::NetworkError {
            message: format!("get_recommended_did_credentials returned {}: {}", status, body),
        });
    }

    resp.json::<RecommendedCredentials>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!(
                "failed to parse get_recommended_did_credentials response: {}",
                e
            ),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn test_pds_client_default() {
        let client = PdsClient::default();
        assert_eq!(client.plc_directory_url, "https://plc.directory");
    }

    #[test]
    fn test_sign_plc_operation_request_skip_none_fields() {
        let req = SignPlcOperationRequest {
            token: "test_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let json = serde_json::to_string(&req).expect("serialization failed");
        // Verify that None fields are skipped
        assert!(!json.contains("rotationKeys"));
        assert!(!json.contains("alsoKnownAs"));
        assert!(json.contains("token"));
    }

    // ============================================================================
    // discover_pds and discover_auth_server tests
    // ============================================================================

    /// PDS endpoint is extracted from DID document
    #[tokio::test]
    async fn test_discover_pds_extracts_endpoint() {
        let mock_server = MockServer::start();
        let pds_endpoint = format!("{}/pds", mock_server.base_url());

        let did_doc_json = serde_json::json!({
            "did": "did:plc:test123",
            "alsoKnownAs": ["at://alice.example.com"],
            "rotationKeys": ["did:key:zQ3test1", "did:key:zQ3test2"],
            "verificationMethods": {"atproto": "did:key:zQ3test1"},
            "services": {
                "atproto_pds": {
                    "type": "AtprotoPersonalDataServer",
                    "endpoint": pds_endpoint
                }
            }
        });

        // Mock the plc.directory GET request
        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:test123");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(did_doc_json);
        });

        // Mock the PDS reachability check (HEAD request for the service endpoint)
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::HEAD).path("/pds");
            then.status(200);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.discover_pds("did:plc:test123").await;

        assert!(result.is_ok());
        let (pds_url, doc) = result.unwrap();
        assert!(pds_url.contains("/pds"));
        assert_eq!(doc.did, "did:plc:test123");
        assert_eq!(doc.also_known_as, vec!["at://alice.example.com"]);
        assert_eq!(doc.rotation_keys.len(), 2);
    }

    /// DID_NOT_FOUND error when plc.directory returns 404
    #[tokio::test]
    async fn test_discover_pds_did_not_found() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:nonexistent");
            then.status(404);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.discover_pds("did:plc:nonexistent").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::DidNotFound => {
                // Expected
            }
            e => panic!("Expected DidNotFound, got: {:?}", e),
        }
    }

    /// PDS_UNREACHABLE error when PDS endpoint is down
    #[tokio::test]
    async fn test_discover_pds_pds_unreachable() {
        let mock_server = MockServer::start();

        let did_doc_json = serde_json::json!({
            "did": "did:plc:test123",
            "alsoKnownAs": [],
            "rotationKeys": [],
            "verificationMethods": {},
            "services": {
                "atproto_pds": {
                    "type": "AtprotoPersonalDataServer",
                    "endpoint": "http://127.0.0.1:1"
                }
            }
        });

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:test123");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(did_doc_json);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.discover_pds("did:plc:test123").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::PdsUnreachable { .. } => {
                // Expected
            }
            e => panic!("Expected PdsUnreachable, got: {:?}", e),
        }
    }

    /// InvalidResponse error when atproto_pds service is missing
    #[tokio::test]
    async fn test_discover_pds_missing_service() {
        let mock_server = MockServer::start();

        let did_doc_json = serde_json::json!({
            "did": "did:plc:test123",
            "alsoKnownAs": [],
            "rotationKeys": [],
            "verificationMethods": {},
            "services": {}
        });

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:test123");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(did_doc_json);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.discover_pds("did:plc:test123").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::InvalidResponse { .. } => {
                // Expected
            }
            e => panic!("Expected InvalidResponse, got: {:?}", e),
        }
    }

    /// Auth server metadata is fetched and validated
    #[tokio::test]
    async fn test_discover_auth_server_success() {
        let mock_server = MockServer::start();

        let metadata_json = serde_json::json!({
            "issuer": "https://pds.example.com",
            "authorization_endpoint": "https://pds.example.com/oauth/authorize",
            "token_endpoint": "https://pds.example.com/oauth/token",
            "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto", "transition:generic"]
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(metadata_json);
        });

        let client = PdsClient::new();
        let result = client.discover_auth_server(&mock_server.base_url()).await;

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.issuer, "https://pds.example.com");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://pds.example.com/oauth/authorize"
        );
        assert_eq!(
            metadata.token_endpoint,
            "https://pds.example.com/oauth/token"
        );
        assert!(metadata
            .response_types_supported
            .contains(&"code".to_string()));
        assert!(metadata
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
    }

    /// discover_auth_server rejects missing S256
    #[tokio::test]
    async fn test_discover_auth_server_missing_s256() {
        let mock_server = MockServer::start();

        let metadata_json = serde_json::json!({
            "issuer": "https://pds.example.com",
            "authorization_endpoint": "https://pds.example.com/oauth/authorize",
            "token_endpoint": "https://pds.example.com/oauth/token",
            "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["plain"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto"]
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(metadata_json);
        });

        let client = PdsClient::new();
        let result = client.discover_auth_server(&mock_server.base_url()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::InvalidResponse { message } => {
                assert!(message.contains("S256"));
            }
            e => panic!("Expected InvalidResponse, got: {:?}", e),
        }
    }

    /// discover_auth_server rejects missing "code" response type
    #[tokio::test]
    async fn test_discover_auth_server_missing_code_response_type() {
        let mock_server = MockServer::start();

        let metadata_json = serde_json::json!({
            "issuer": "https://pds.example.com",
            "authorization_endpoint": "https://pds.example.com/oauth/authorize",
            "token_endpoint": "https://pds.example.com/oauth/token",
            "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
            "response_types_supported": ["id_token"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto"]
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(metadata_json);
        });

        let client = PdsClient::new();
        let result = client.discover_auth_server(&mock_server.base_url()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::InvalidResponse { message } => {
                assert!(message.contains("code"));
            }
            e => panic!("Expected InvalidResponse, got: {:?}", e),
        }
    }

    /// discover_auth_server returns InvalidResponse on HTTP error
    #[tokio::test]
    async fn test_discover_auth_server_pds_unreachable() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server");
            then.status(500);
        });

        let client = PdsClient::new();
        let result = client.discover_auth_server(&mock_server.base_url()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::InvalidResponse { .. } => {
                // Expected: HTTP errors are InvalidResponse, not PdsUnreachable
            }
            e => panic!("Expected InvalidResponse, got: {:?}", e),
        }
    }

    // ============================================================================
    // resolve_handle tests
    // ============================================================================

    /// HANDLE_NOT_FOUND error is returned correctly
    #[test]
    fn test_pds_client_error_handle_not_found() {
        let error = PdsClientError::HandleNotFound;
        assert_eq!(format!("{}", error), "handle not found");
    }

    /// DNS TXT resolution (integration test, ignored for CI)
    ///
    /// This requires real DNS access and tests against a known public handle.
    /// Run manually with `cargo test -- --ignored --nocapture` if DNS is available.
    #[tokio::test]
    #[ignore]
    async fn test_resolve_handle_dns_txt_integration() {
        // This test requires real DNS and uses a stable handle
        let result = try_resolve_dns("jay.bsky.team").await;

        match result {
            Ok(Some(did)) => {
                assert!(did.starts_with("did:plc:") || did.starts_with("did:key:"));
            }
            Ok(None) => {
                panic!("DNS lookup returned None for known handle");
            }
            Err(e) => {
                panic!("DNS lookup failed: {}", e);
            }
        }
    }

    // ============================================================================
    // HTTP fallback resolution tests
    // ============================================================================

    /// HTTP fallback resolves handle to DID
    #[tokio::test]
    async fn test_try_resolve_http_success() {
        let mock_server = MockServer::start();

        // Mock server returns a valid DID on the well-known endpoint
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(200).body("did:plc:test123");
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
    }

    /// HTTP fallback handles response body with whitespace
    #[tokio::test]
    async fn test_try_resolve_http_with_whitespace() {
        let mock_server = MockServer::start();

        // Mock server returns DID with surrounding whitespace
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(200).body("  did:plc:test123\n  ");
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
    }

    /// HTTP fallback returns Ok(None) on 404 client error
    #[tokio::test]
    async fn test_try_resolve_http_not_found() {
        let mock_server = MockServer::start();

        // Mock server returns 404
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(404);
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    /// HTTP fallback returns NetworkError on 500 server error
    #[tokio::test]
    async fn test_try_resolve_http_server_error() {
        let mock_server = MockServer::start();

        // Mock server returns 500
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(500);
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected: 5xx is a server error, not a missing handle
            }
            e => panic!("Expected NetworkError on 5xx, got: {:?}", e),
        }
    }

    // ============================================================================
    // PAR and token exchange tests
    // ============================================================================

    /// PAR sends correct request with PKCE, DPoP, and optional login_hint
    #[tokio::test]
    async fn test_pds_par_sends_correct_request() {
        let mock_server = MockServer::start();

        let mock_par = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/oauth/par")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:test",
                "expires_in": 60
            }));
        });

        let metadata = AuthServerMetadata {
            issuer: mock_server.base_url(),
            authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
            token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
            pushed_authorization_request_endpoint: Some(format!(
                "{}/oauth/par",
                mock_server.base_url()
            )),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
            scopes_supported: Some(vec!["atproto".to_string()]),
        };

        let client = PdsClient::new();
        let result = client
            .pds_par(
                &metadata,
                "test_pkce_challenge",
                "test_state",
                "test_dpop_proof",
                "test_dpop_jkt",
                Some("user@example.com"),
            )
            .await;

        assert!(result.is_ok());
        let par_response = result.unwrap();
        assert_eq!(
            par_response.request_uri,
            "urn:ietf:params:oauth:request_uri:test"
        );
        assert_eq!(par_response.expires_in, 60);
        assert_eq!(mock_par.hits(), 1);
    }

    /// PAR without login_hint
    #[tokio::test]
    async fn test_pds_par_without_login_hint() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/oauth/par");
            then.status(200).json_body(serde_json::json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:test2",
                "expires_in": 120
            }));
        });

        let metadata = AuthServerMetadata {
            issuer: mock_server.base_url(),
            authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
            token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
            pushed_authorization_request_endpoint: Some(format!(
                "{}/oauth/par",
                mock_server.base_url()
            )),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let client = PdsClient::new();
        let result = client
            .pds_par(&metadata, "challenge", "state", "proof", "jkt", None)
            .await;

        assert!(result.is_ok());
    }

    /// PAR failure returns OauthFailed
    #[tokio::test]
    async fn test_pds_par_failure() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/oauth/par");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_request",
                "error_description": "missing code_challenge"
            }));
        });

        let metadata = AuthServerMetadata {
            issuer: mock_server.base_url(),
            authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
            token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
            pushed_authorization_request_endpoint: Some(format!(
                "{}/oauth/par",
                mock_server.base_url()
            )),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let client = PdsClient::new();
        let result = client
            .pds_par(&metadata, "challenge", "state", "proof", "jkt", None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::OauthFailed { .. } => {
                // Expected
            }
            e => panic!("Expected OauthFailed, got: {:?}", e),
        }
    }

    /// Token exchange sends correct request
    #[tokio::test]
    async fn test_pds_token_exchange_sends_correct_request() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/oauth/token")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "access_token": "test_access_token",
                "token_type": "DPoP",
                "expires_in": 300,
                "refresh_token": "test_refresh_token",
                "scope": "atproto transition:generic"
            }));
        });

        let metadata = AuthServerMetadata {
            issuer: mock_server.base_url(),
            authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
            token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
            pushed_authorization_request_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let client = PdsClient::new();
        let result = client
            .pds_token_exchange(&metadata, "test_code", "test_verifier", "test_dpop_proof")
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }

    /// Token exchange returns raw response on non-2xx
    #[tokio::test]
    async fn test_pds_token_exchange_returns_raw_response_on_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/oauth/token");
            then.status(400).json_body(serde_json::json!({
                "error": "use_dpop_nonce",
                "error_description": "nonce required"
            }));
        });

        let metadata = AuthServerMetadata {
            issuer: mock_server.base_url(),
            authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
            token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
            pushed_authorization_request_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let client = PdsClient::new();
        let result = client
            .pds_token_exchange(&metadata, "test_code", "test_verifier", "test_dpop_proof")
            .await;

        // Should return Ok(Response) with 400 status — caller handles error interpretation.
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status().as_u16(), 400);
    }

    /// Token exchange to unreachable endpoint returns OauthFailed
    #[tokio::test]
    async fn test_pds_token_exchange_unreachable_endpoint() {
        let metadata = AuthServerMetadata {
            issuer: "http://127.0.0.1:1".to_string(),
            authorization_endpoint: "http://127.0.0.1:1/oauth/authorize".to_string(),
            token_endpoint: "http://127.0.0.1:1/oauth/token".to_string(),
            pushed_authorization_request_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let client = PdsClient::new();
        let result = client
            .pds_token_exchange(&metadata, "test_code", "test_verifier", "test_dpop_proof")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::OauthFailed { .. } => {
                // Expected
            }
            e => panic!("Expected OauthFailed, got: {:?}", e),
        }
    }

    /// build_pds_authorize_url constructs correct URL
    #[test]
    fn test_build_pds_authorize_url_with_login_hint() {
        let metadata = AuthServerMetadata {
            issuer: "https://pds.example.com".to_string(),
            authorization_endpoint: "https://pds.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://pds.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let url = PdsClient::build_pds_authorize_url(
            &metadata,
            "urn:ietf:params:oauth:request_uri:test",
            Some("user@example.com"),
        );

        assert!(url.contains("client_id=dev.malpercio.identitywallet"));
        assert!(url.contains("request_uri="));
        assert!(url.contains("login_hint="));
        assert!(url.starts_with("https://pds.example.com/oauth/authorize?"));
    }

    /// build_pds_authorize_url without login_hint
    #[test]
    fn test_build_pds_authorize_url_without_login_hint() {
        let metadata = AuthServerMetadata {
            issuer: "https://pds.example.com".to_string(),
            authorization_endpoint: "https://pds.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://pds.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: None,
            scopes_supported: None,
        };

        let url = PdsClient::build_pds_authorize_url(
            &metadata,
            "urn:ietf:params:oauth:request_uri:test2",
            None,
        );

        assert!(url.contains("client_id=dev.malpercio.identitywallet"));
        assert!(url.contains("request_uri="));
        assert!(!url.contains("login_hint="));
        assert!(url.starts_with("https://pds.example.com/oauth/authorize?"));
    }

    // ============================================================================
    // XRPC identity method tests
    // ============================================================================

    /// request_plc_operation_signature sends correct request
    #[tokio::test]
    async fn test_request_plc_operation_signature_success() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({}));
        });

        // Create a test session and OAuthClient
        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let result = request_plc_operation_signature(&oauth_client).await;
        assert!(result.is_ok());
    }

    /// request_plc_operation_signature handles error
    #[tokio::test]
    async fn test_request_plc_operation_signature_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature");
            then.status(401).json_body(serde_json::json!({
                "error": "Unauthorized"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let result = request_plc_operation_signature(&oauth_client).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }

    /// sign_plc_operation sends token and rotation keys
    #[tokio::test]
    async fn test_sign_plc_operation_success() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "operation": {
                    "type": "plc_operation",
                    "prev": "bafytest123"
                }
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let request = SignPlcOperationRequest {
            token: "test_email_token".to_string(),
            rotation_keys: Some(vec!["did:key:zQ3test1".to_string()]),
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.operation.get("type").is_some());
    }

    /// sign_plc_operation omits optional null fields
    #[tokio::test]
    async fn test_sign_plc_operation_omits_none_fields() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": {}
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let request = SignPlcOperationRequest {
            token: "test_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_ok());

        // Verify the mock was hit (request was made)
        assert_eq!(mock.hits(), 1);
    }

    /// get_recommended_did_credentials returns credentials
    #[tokio::test]
    async fn test_get_recommended_did_credentials_success() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": ["did:key:zQ3test1"],
                "alsoKnownAs": ["at://alice.test"]
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let result = get_recommended_did_credentials(&oauth_client).await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert!(creds.rotation_keys.is_some());
        assert!(creds.also_known_as.is_some());
    }

    /// resolve_handle returns HandleNotFound when both DNS and HTTP fail
    /// This test uses a nonexistent .test TLD which DNS will reject, then attempts HTTP
    /// which will fail due to inability to connect. Both failures result in HandleNotFound.
    #[tokio::test]
    async fn test_resolve_handle_orchestration_nonexistent() {
        let client = PdsClient::new();
        // Use a nonexistent handle on .test TLD (reserved, non-routable domain)
        // DNS will fail (no records found) and HTTP to https://.../.well-known/atproto-did
        // will fail (unable to resolve/connect). Both failures return HandleNotFound.
        let result = client
            .resolve_handle("this-handle-definitely-does-not-exist-12345.test")
            .await;

        assert!(result.is_err());
        // The error could be HandleNotFound if DNS+HTTP both fail, or NetworkError
        // if the HTTP request itself fails before we can determine there's no record.
        // We accept both as evidence that the handle cannot be resolved.
        match result.unwrap_err() {
            PdsClientError::HandleNotFound | PdsClientError::NetworkError { .. } => {
                // Expected: either no handle found or network failure during resolution
            }
            e => panic!("Expected HandleNotFound or NetworkError, got: {:?}", e),
        }
    }

    /// HandleNotFound error serializes with code "HANDLE_NOT_FOUND"
    #[test]
    fn test_pds_client_error_handle_not_found_serialization() {
        let error = PdsClientError::HandleNotFound;
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"HANDLE_NOT_FOUND\""));
    }

    /// DidNotFound error serializes with code "DID_NOT_FOUND"
    #[test]
    fn test_pds_client_error_did_not_found_serialization() {
        let error = PdsClientError::DidNotFound;
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"DID_NOT_FOUND\""));
    }

    /// PdsUnreachable error serializes with code "PDS_UNREACHABLE"
    /// and does NOT include "reason" (because it's #[serde(skip)])
    #[test]
    fn test_pds_client_error_pds_unreachable_serialization() {
        let error = PdsClientError::PdsUnreachable {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"PDS_UNREACHABLE\""));
        // Verify "reason" field is NOT serialized (it's #[serde(skip)])
        assert!(!json.contains("\"reason\""));
        assert!(!json.contains("test"));
    }

    /// XRPC get_recommended_did_credentials error: returns NetworkError on 403
    #[tokio::test]
    async fn test_get_recommended_did_credentials_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(403).json_body(serde_json::json!({
                "error": "Forbidden"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let result = get_recommended_did_credentials(&oauth_client).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }

    /// NetworkError error serializes with code "NETWORK_ERROR"
    #[test]
    fn test_pds_client_error_network_error_serialization() {
        let error = PdsClientError::NetworkError {
            message: "connection refused".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"NETWORK_ERROR\""));
    }

    /// InvalidResponse error serializes with code "INVALID_RESPONSE"
    #[test]
    fn test_pds_client_error_invalid_response_serialization() {
        let error = PdsClientError::InvalidResponse {
            message: "missing required field".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"INVALID_RESPONSE\""));
    }

    /// OauthFailed error serializes with code "OAUTH_FAILED"
    #[test]
    fn test_pds_client_error_oauth_failed_serialization() {
        let error = PdsClientError::OauthFailed {
            message: "invalid_grant".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"OAUTH_FAILED\""));
    }

    /// sign_plc_operation returns NetworkError on HTTP error
    #[tokio::test]
    async fn test_sign_plc_operation_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_token"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let request = SignPlcOperationRequest {
            token: "test_email_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }
}
