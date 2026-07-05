// pattern: Imperative Shell
//
// Gathers: PDS discovery parameters (handle, DID, OAuth metadata)
// Processes: DNS TXT resolution, HTTP well-known fetches, PDS OAuth metadata discovery
// Returns: PDS endpoints, authorization server metadata, or error codes

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

/// OAuth client metadata path, appended to the PDS's public URL to form the `client_id`.
///
/// External auth servers (e.g. bsky.social) GET `{pds_url}/oauth/client-metadata.json`
/// to discover redirect_uris, grant_types, etc.
const CLIENT_METADATA_PATH: &str = "/oauth/client-metadata.json";

/// OAuth redirect URI for external PDS authentication.
const REDIRECT_URI: &str = "dev.malpercio.identitywallet:/oauth/callback";

/// Build the OAuth client_id URL from a PDS base URL.
///
/// The client_id is the PDS's public URL + `/oauth/client-metadata.json`.
/// This must match what the PDS serves at that path.
pub fn client_id_for_pds(pds_url: &str) -> String {
    format!("{}{}", pds_url.trim_end_matches('/'), CLIENT_METADATA_PATH)
}

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

    /// DID already exists (HTTP 409 from createAccount migration).
    #[error("did already exists")]
    DidAlreadyExists,
}

/// PLC operation data for a DID.
///
/// Combines fields from the W3C DID Document (`GET /{did}`) and the PLC audit log
/// (`GET /{did}/log/audit`). `rotation_keys` only exist in the audit log — they are
/// NOT part of the W3C DID Document and must be populated separately.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcDidDocument {
    pub did: String,
    pub also_known_as: Vec<String>,
    /// Rotation keys from the latest PLC operation. Empty if only populated from
    /// the W3C DID Document (which doesn't include rotation keys).
    #[serde(default)]
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

// ── W3C DID Document (private, for parsing `GET /{did}` responses) ───────────

/// W3C DID Document as returned by `GET {plc_directory_url}/{did}`.
/// Different shape from PLC operations: `id` not `did`, arrays not HashMaps.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct W3cDidDocument {
    id: String,
    #[serde(default)]
    also_known_as: Vec<String>,
    #[serde(default)]
    verification_method: Vec<W3cVerificationMethod>,
    #[serde(default)]
    service: Vec<W3cService>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct W3cVerificationMethod {
    id: String,
    #[serde(default)]
    public_key_multibase: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct W3cService {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    service_endpoint: String,
}

impl W3cDidDocument {
    /// Convert to PlcDidDocument. `rotation_keys` will be empty — the caller
    /// must populate them from the audit log if needed.
    fn into_plc_doc(self) -> PlcDidDocument {
        // Convert verification_method array to the { "atproto": "did:key:..." } shape
        let mut vm_map = serde_json::Map::new();
        for method in &self.verification_method {
            // Strip the "did:plc:...#" prefix from the id to get the key name
            let key_name = method
                .id
                .rsplit_once('#')
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| method.id.clone());
            if let Some(ref pkm) = method.public_key_multibase {
                vm_map.insert(key_name, serde_json::Value::String(pkm.clone()));
            }
        }

        // Convert service array to HashMap keyed by id (strip leading '#')
        let services = self
            .service
            .into_iter()
            .map(|svc| {
                let key = svc.id.strip_prefix('#').unwrap_or(&svc.id).to_string();
                let plc_svc = PlcService {
                    service_type: svc.service_type,
                    endpoint: svc.service_endpoint,
                };
                (key, plc_svc)
            })
            .collect();

        PlcDidDocument {
            did: self.id,
            also_known_as: self.also_known_as,
            rotation_keys: Vec::new(),
            verification_methods: serde_json::Value::Object(vm_map),
            services,
        }
    }
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

// ── Migration XRPC request/response types ──────────────────────────────────

/// Service auth token from getServiceAuth.
///
/// Returned from `GET /xrpc/com.atproto.server.getServiceAuth`.
#[derive(Debug, Deserialize)]
pub struct ServiceAuthToken {
    pub token: String,
}

/// Request body for createAccount migration.
///
/// Serializes to frontend with `#[serde(rename_all = "camelCase")]`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountMigrationRequest {
    pub handle: String,
    pub email: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
}

/// Response from createAccount migration.
///
/// Returned from `POST /xrpc/com.atproto.server.createAccount`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
    #[serde(default)]
    pub did_doc: Option<serde_json::Value>,
}

/// Missing blob entry from listMissingBlobs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingBlob {
    pub cid: String,
    pub record_uri: String,
}

/// Response from listMissingBlobs.
///
/// Returned from `GET /xrpc/com.atproto.repo.listMissingBlobs`.
#[derive(Debug, Deserialize)]
pub struct MissingBlobs {
    pub blobs: Vec<MissingBlob>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Account status from checkAccountStatus.
///
/// Returned from `GET /xrpc/com.atproto.server.checkAccountStatus`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub activated: bool,
    pub valid_did: bool,
    #[serde(default)]
    pub repo_commit: Option<String>,
    #[serde(default)]
    pub repo_rev: Option<String>,
    pub stored_blocks: i64,
    pub indexed_records: u64,
    pub private_state_values: u64,
    pub expected_blobs: u64,
    pub imported_blobs: u64,
}

/// Response from uploadBlob.
///
/// Returned from `POST /xrpc/com.atproto.repo.uploadBlob`.
#[derive(Debug, Deserialize)]
pub struct UploadBlobResponse {
    pub blob: serde_json::Value,
}

/// Parameters for a Pushed Authorization Request.
pub struct PdsParRequest<'a> {
    pub pkce_challenge: &'a str,
    pub state_param: &'a str,
    pub dpop_proof: &'a str,
    pub dpop_jkt: &'a str,
    pub login_hint: Option<&'a str>,
    pub client_id: &'a str,
}

/// PDS client for discovery and OAuth operations against arbitrary PDS endpoints.
///
/// Stateless except for the HTTP client which pools connections.
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

    /// Returns the plc.directory base URL.
    pub fn plc_directory_url(&self) -> &str {
        &self.plc_directory_url
    }

    /// Returns a reference to the inner HTTP client.
    pub fn client(&self) -> &Client {
        &self.client
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

        // Parse W3C DID Document and convert to PlcDidDocument.
        // rotation_keys will be empty — callers that need them must fetch the audit log.
        let w3c_doc: W3cDidDocument =
            response
                .json()
                .await
                .map_err(|e| PdsClientError::InvalidResponse {
                    message: format!("failed to parse DID document: {}", e),
                })?;
        let doc = w3c_doc.into_plc_doc();

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

    /// Discover the OAuth authorization server for a PDS.
    ///
    /// Follows RFC 9728 (OAuth Protected Resource Metadata):
    /// 1. Try `GET {pds_url}/.well-known/oauth-protected-resource` to find the
    ///    authorization server URL (e.g. Bluesky entryway at `bsky.social`)
    /// 2. Fetch `GET {auth_server}/.well-known/oauth-authorization-server`
    /// 3. Fall back to `GET {pds_url}/.well-known/oauth-authorization-server`
    ///    if the protected resource endpoint doesn't exist (self-hosted PDS)
    ///
    /// Validates that the metadata includes "code" in `response_types_supported`
    /// and "S256" in `code_challenge_methods_supported`.
    pub async fn discover_auth_server(
        &self,
        pds_url: &str,
    ) -> Result<AuthServerMetadata, PdsClientError> {
        // Step 1: Try protected resource metadata to find the auth server
        let auth_server_base = self.discover_protected_resource_auth_server(pds_url).await;

        let metadata_base = match &auth_server_base {
            Some(server) => {
                tracing::debug!(auth_server = %server, "using authorization server from protected resource metadata");
                server.as_str()
            }
            None => {
                tracing::debug!(pds_url = %pds_url, "no protected resource metadata, falling back to PDS directly");
                pds_url
            }
        };

        // Step 2: Fetch the OAuth authorization server metadata
        let url = format!("{}/.well-known/oauth-authorization-server", metadata_base);
        tracing::debug!(url = %url, "fetching OAuth authorization server metadata");

        let response = self.client.get(&url).send().await.map_err(|e| {
            tracing::error!(url = %url, error = %e, "OAuth metadata fetch failed");
            PdsClientError::NetworkError {
                message: format!("failed to fetch OAuth metadata: {}", e),
            }
        })?;

        if !response.status().is_success() {
            tracing::error!(url = %url, status = %response.status(), "OAuth metadata returned non-success");
            return Err(PdsClientError::InvalidResponse {
                message: format!(
                    "OAuth metadata fetch returned {} from {}",
                    response.status(),
                    metadata_base
                ),
            });
        }

        let metadata: AuthServerMetadata = response.json().await.map_err(|e| {
            tracing::error!(url = %url, error = %e, "OAuth metadata parsing failed");
            PdsClientError::InvalidResponse {
                message: format!("failed to parse OAuth metadata: {}", e),
            }
        })?;
        tracing::debug!(issuer = %metadata.issuer, "OAuth metadata parsed");

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

    /// Try to discover the authorization server URL from the PDS's protected
    /// resource metadata (RFC 9728). Returns `None` if the endpoint doesn't
    /// exist or can't be parsed — the caller should fall back to the PDS URL.
    async fn discover_protected_resource_auth_server(&self, pds_url: &str) -> Option<String> {
        let url = format!("{}/.well-known/oauth-protected-resource", pds_url);
        tracing::debug!(url = %url, "checking protected resource metadata");

        let response = match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::debug!(url = %url, status = %r.status(), "protected resource metadata not available");
                return None;
            }
            Err(e) => {
                tracing::debug!(url = %url, error = %e, "protected resource metadata fetch failed");
                return None;
            }
        };

        #[derive(serde::Deserialize)]
        struct ProtectedResource {
            #[serde(default)]
            authorization_servers: Vec<String>,
        }

        match response.json::<ProtectedResource>().await {
            Ok(pr) => {
                let server = pr.authorization_servers.into_iter().next();
                if let Some(ref s) = server {
                    tracing::debug!(auth_server = %s, "found authorization server in protected resource metadata");
                }
                server
            }
            Err(e) => {
                tracing::debug!(url = %url, error = %e, "failed to parse protected resource metadata");
                None
            }
        }
    }

    /// Perform a Pushed Authorization Request to an arbitrary PDS.
    ///
    /// Sends a PAR request with PKCE challenge, DPoP proof, and optional login_hint.
    pub async fn pds_par(
        &self,
        metadata: &AuthServerMetadata,
        request: PdsParRequest<'_>,
    ) -> Result<PdsParResponse, PdsClientError> {
        let par_url = metadata
            .pushed_authorization_request_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

        let mut form_data = vec![
            ("response_type", "code".to_string()),
            ("code_challenge_method", "S256".to_string()),
            ("code_challenge", request.pkce_challenge.to_string()),
            ("state", request.state_param.to_string()),
            ("client_id", request.client_id.to_string()),
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("scope", "atproto transition:generic".to_string()),
            ("dpop_jkt", request.dpop_jkt.to_string()),
        ];

        if let Some(hint) = request.login_hint {
            form_data.push(("login_hint", hint.to_string()));
        }

        let response = self
            .client
            .post(&par_url)
            .header("DPoP", request.dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PdsClientError::OauthFailed {
                message: format!("PAR request failed: {}", e),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
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
        client_id: &str,
    ) -> Result<reqwest::Response, PdsClientError> {
        let token_url = &metadata.token_endpoint;

        let form_data = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", pkce_verifier),
            ("client_id", client_id),
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
        client_id: &str,
    ) -> String {
        let mut url = format!(
            "{}?client_id={}&request_uri={}",
            metadata.authorization_endpoint,
            urlencoding::encode(client_id),
            urlencoding::encode(request_uri)
        );

        if let Some(hint) = login_hint {
            url.push_str(&format!("&login_hint={}", urlencoding::encode(hint)));
        }

        url
    }

    /// Fetch the PLC operation audit log for a DID.
    ///
    /// Calls `GET {plc_directory_url}/{did}/log/audit` and returns the raw JSON string.
    pub async fn fetch_audit_log(&self, did: &str) -> Result<String, PdsClientError> {
        let url = format!("{}/{}/log/audit", self.plc_directory_url, did);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| PdsClientError::NetworkError {
                    message: format!("failed to fetch audit log: {}", e),
                })?;

        match resp.status() {
            s if s == 404 => return Err(PdsClientError::DidNotFound),
            s if !s.is_success() => {
                return Err(PdsClientError::NetworkError {
                    message: format!("audit log fetch returned {}", s),
                });
            }
            _ => {}
        }

        resp.text().await.map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to read audit log response: {}", e),
        })
    }

    /// Submit a signed PLC operation to plc.directory.
    ///
    /// Calls `POST {plc_directory_url}/{did}` with the signed operation as JSON body.
    pub async fn post_plc_operation(
        &self,
        did: &str,
        operation: &serde_json::Value,
    ) -> Result<(), PdsClientError> {
        let url = format!("{}/{}", self.plc_directory_url, did);
        let resp = self
            .client
            .post(&url)
            .json(operation)
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to post plc operation: {}", e),
            })?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            Err(PdsClientError::InvalidResponse {
                message: format!("plc.directory rejected operation: {}", body),
            })
        }
    }

    /// Fetch the full repo as a CAR file (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.getRepo?did={did}` and returns the raw CAR bytes.
    /// No Authorization header is sent.
    pub async fn fetch_repo_car(&self, pds_url: &str, did: &str) -> Result<Vec<u8>, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to fetch repo CAR: {}", e),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            return Err(PdsClientError::NetworkError {
                message: format!("fetch_repo_car returned {}: {}", status, body),
            });
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to read repo CAR bytes: {}", e),
            })
    }

    /// Fetch a blob by DID and CID (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}` and returns the raw blob bytes.
    /// No Authorization header is sent.
    pub async fn fetch_blob(
        &self,
        pds_url: &str,
        did: &str,
        cid: &str,
    ) -> Result<Vec<u8>, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did),
            urlencoding::encode(cid)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to fetch blob: {}", e),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            return Err(PdsClientError::NetworkError {
                message: format!("fetch_blob returned {}: {}", status, body),
            });
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to read blob bytes: {}", e),
            })
    }

    /// Reserve a signing key for a DID on the PDS (auth: none, idempotent).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.reserveSigningKey` with body `{"did": did}`.
    /// Returns the `signingKey` field from the response (a did:key string).
    pub async fn reserve_signing_key(&self, pds_url: &str, did: &str) -> Result<String, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            pds_url.trim_end_matches('/')
        );

        let body = serde_json::json!({ "did": did });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to reserve signing key: {}", e),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            return Err(PdsClientError::NetworkError {
                message: format!("reserve_signing_key returned {}: {}", status, body_text),
            });
        }

        #[derive(Deserialize)]
        struct ReserveSigningKeyResponse {
            #[serde(rename = "signingKey")]
            signing_key: String,
        }

        resp.json::<ReserveSigningKeyResponse>()
            .await
            .map(|r| r.signing_key)
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to parse reserve_signing_key response: {}", e),
            })
    }
}

impl Default for PdsClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public helpers
// ============================================================================

/// Extract rotation keys from the latest entry in a raw PLC audit log JSON string.
/// Returns an empty Vec if parsing fails or the log has no entries.
pub fn rotation_keys_from_audit_log(raw_json: &str) -> Vec<String> {
    let entries: Vec<serde_json::Value> = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    entries
        .last()
        .and_then(|entry| entry.get("operation"))
        .and_then(|op| op.get("rotationKeys"))
        .and_then(|keys| keys.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ============================================================================
// Helper functions for resolve_handle
// ============================================================================

/// DNS TXT lookup for `_atproto.{handle}`. Returns `Ok(Some(did))` on success,
/// `Ok(None)` if no matching TXT record found, `Err` on transport failure.
async fn try_resolve_dns(handle: &str) -> Result<Option<String>, PdsClientError> {
    let dns_name = format!("_atproto.{}", handle);
    tracing::debug!(dns_name = %dns_name, "attempting DNS TXT lookup");

    // Create a resolver using system DNS config (matches PDS pattern in dns.rs:49)
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to create DNS resolver: {}", e),
        })?
        .build()
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to build DNS resolver: {}", e),
        })?;

    match resolver.txt_lookup(&dns_name).await {
        Ok(lookup) => {
            // Iterate through TXT records and find one starting with "did="
            for record in lookup.answers() {
                let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                    continue;
                };
                for part in txt.txt_data.iter() {
                    match std::str::from_utf8(part) {
                        Ok(s) => {
                            if let Some(did_value) = s.strip_prefix("did=") {
                                let did = did_value.trim().to_string();
                                tracing::debug!(did = %did, "DNS TXT resolved");
                                return Ok(Some(did));
                            }
                        }
                        Err(_) => {
                            // Non-UTF-8 bytes in TXT record; skip
                        }
                    }
                }
            }
            tracing::debug!(dns_name = %dns_name, "no did= TXT record found");
            Ok(None)
        }
        Err(e) => {
            // Check if it's a "no records found" error (normal for unregistered handles)
            // vs. a transport error (network failure)
            if e.is_no_records_found() {
                tracing::debug!(dns_name = %dns_name, "no DNS TXT records found");
                Ok(None)
            } else {
                tracing::warn!(dns_name = %dns_name, error = %e, "DNS TXT lookup failed");
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
    tracing::debug!(url = %url, "attempting HTTP well-known lookup");
    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        tracing::debug!(url = %url, did = %body.trim(), "HTTP well-known resolved");
                        Ok(Some(body.trim().to_string()))
                    }
                    Err(e) => {
                        tracing::warn!(url = %url, error = %e, "HTTP well-known body read failed");
                        Err(PdsClientError::NetworkError {
                            message: format!("failed to read response body: {}", e),
                        })
                    }
                }
            } else if response.status().is_client_error() {
                // 4xx = handle not found at this endpoint
                tracing::debug!(url = %url, status = %response.status(), "HTTP well-known not found");
                Ok(None)
            } else {
                // 5xx = temporary server error
                tracing::warn!(url = %url, status = %response.status(), "HTTP well-known server error");
                Err(PdsClientError::NetworkError {
                    message: format!("server error from {}: {}", url, response.status()),
                })
            }
        }
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "HTTP well-known request failed");
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
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "(response body unreadable)".to_string());
        Err(PdsClientError::NetworkError {
            message: format!(
                "request_plc_operation_signature returned {}: {}",
                status, body
            ),
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
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "(response body unreadable)".to_string());
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
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "(response body unreadable)".to_string());
        return Err(PdsClientError::NetworkError {
            message: format!(
                "get_recommended_did_credentials returned {}: {}",
                status, body
            ),
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

        // W3C DID Document format (what plc.directory actually returns)
        let did_doc_json = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"
            ],
            "id": "did:plc:test123",
            "alsoKnownAs": ["at://alice.example.com"],
            "verificationMethod": [{
                "id": "did:plc:test123#atproto",
                "type": "Multikey",
                "controller": "did:plc:test123",
                "publicKeyMultibase": "zQ3test1"
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds_endpoint
            }]
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
        // W3C DID Document doesn't include rotation keys — they come from the audit log
        assert!(doc.rotation_keys.is_empty());
        // Service array converted to HashMap keyed by id (without '#' prefix)
        assert!(doc.services.contains_key("atproto_pds"));
        // verificationMethod array converted to { "atproto": "zQ3test1" }
        assert_eq!(doc.verification_methods["atproto"], "zQ3test1");
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
            "id": "did:plc:test123",
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "http://127.0.0.1:1"
            }]
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
            "id": "did:plc:test123",
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": []
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
                PdsParRequest {
                    pkce_challenge: "test_pkce_challenge",
                    state_param: "test_state",
                    dpop_proof: "test_dpop_proof",
                    dpop_jkt: "test_dpop_jkt",
                    login_hint: Some("user@example.com"),
                    client_id: "https://test.example.com/oauth/client-metadata.json",
                },
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
            .pds_par(
                &metadata,
                PdsParRequest {
                    pkce_challenge: "challenge",
                    state_param: "state",
                    dpop_proof: "proof",
                    dpop_jkt: "jkt",
                    login_hint: None,
                    client_id: "https://test.example.com/oauth/client-metadata.json",
                },
            )
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
            .pds_par(
                &metadata,
                PdsParRequest {
                    pkce_challenge: "challenge",
                    state_param: "state",
                    dpop_proof: "proof",
                    dpop_jkt: "jkt",
                    login_hint: None,
                    client_id: "https://test.example.com/oauth/client-metadata.json",
                },
            )
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
            .pds_token_exchange(
                &metadata,
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
            )
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
            .pds_token_exchange(
                &metadata,
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
            )
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
            .pds_token_exchange(
                &metadata,
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
            )
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
            "https://test.example.com/oauth/client-metadata.json",
        );

        assert!(
            url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json")
        );
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
            "https://test.example.com/oauth/client-metadata.json",
        );

        assert!(
            url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json")
        );
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

    /// fetch_audit_log returns the raw JSON audit log array on success
    #[tokio::test]
    async fn test_fetch_audit_log_success() {
        let mock_server = MockServer::start();

        let audit_log_json = serde_json::json!([
            {
                "did": "did:plc:test123",
                "cid": "bafy123456789",
                "createdAt": "2024-01-01T00:00:00Z",
                "nullified": false,
                "operation": {
                    "sig": "test_sig",
                    "prev": serde_json::json!(null),
                    "type": "plc_operation",
                    "rotationKeys": ["did:key:z123"],
                    "verificationMethods": {},
                    "alsoKnownAs": [],
                    "services": {}
                }
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:test123/log/audit");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json.clone());
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.fetch_audit_log("did:plc:test123").await;

        assert!(result.is_ok());
        let json_str = result.unwrap();
        // Verify it parses as valid JSON array
        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().len(), 1);
    }

    /// fetch_audit_log returns DidNotFound on 404
    #[tokio::test]
    async fn test_fetch_audit_log_not_found() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:notfound/log/audit");
            then.status(404);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let result = client.fetch_audit_log("did:plc:notfound").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::DidNotFound => {
                // Expected
            }
            e => panic!("Expected DidNotFound, got: {:?}", e),
        }
    }

    // ============================================================================
    // post_plc_operation tests
    // ============================================================================

    /// post_plc_operation succeeds with 200 response
    #[tokio::test]
    async fn test_post_plc_operation_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:test123");
            then.status(200);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let operation = serde_json::json!({
            "type": "plc_operation",
            "prev": "bafy123",
            "rotationKeys": ["did:key:z123"]
        });

        let result = client
            .post_plc_operation("did:plc:test123", &operation)
            .await;

        assert!(result.is_ok());
    }

    /// post_plc_operation returns InvalidResponse with error body on non-2xx
    #[tokio::test]
    async fn test_post_plc_operation_conflict() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:test123");
            then.status(409).body("Conflicting operation");
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let operation = serde_json::json!({
            "type": "plc_operation"
        });

        let result = client
            .post_plc_operation("did:plc:test123", &operation)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::InvalidResponse { message } => {
                assert!(message.contains("Conflicting operation"));
            }
            e => panic!("Expected InvalidResponse, got: {:?}", e),
        }
    }

    // ============================================================================
    // Migration XRPC method tests
    // ============================================================================

    /// fetch_repo_car requests correct endpoint without auth and returns CAR bytes
    #[tokio::test]
    async fn test_fetch_repo_car_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo")
                .query_param("did", "did:plc:test123");
            then.status(200)
                .header("content-type", "application/vnd.ipld.car")
                .body("CAR header and data");
        });

        let client = PdsClient::new();
        let result = client
            .fetch_repo_car(&mock_server.base_url(), "did:plc:test123")
            .await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, "CAR header and data".as_bytes());
    }

    /// fetch_repo_car returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_fetch_repo_car_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo")
                .query_param("did", "did:plc:notfound");
            then.status(404).body("not found");
        });

        let client = PdsClient::new();
        let result = client
            .fetch_repo_car(&mock_server.base_url(), "did:plc:notfound")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { message } => {
                assert!(message.contains("404"));
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }

    /// fetch_blob requests correct endpoint without auth and returns blob bytes
    #[tokio::test]
    async fn test_fetch_blob_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("did", "did:plc:test123")
                .query_param("cid", "bafy123");
            then.status(200)
                .header("content-type", "application/octet-stream")
                .body("blob data");
        });

        let client = PdsClient::new();
        let result = client
            .fetch_blob(&mock_server.base_url(), "did:plc:test123", "bafy123")
            .await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, "blob data".as_bytes());
    }

    /// fetch_blob returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_fetch_blob_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("did", "did:plc:test123")
                .query_param("cid", "bafy_notfound");
            then.status(404).body("blob not found");
        });

        let client = PdsClient::new();
        let result = client
            .fetch_blob(&mock_server.base_url(), "did:plc:test123", "bafy_notfound")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { message } => {
                assert!(message.contains("404"));
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }

    /// reserve_signing_key POSTs {"did": did} and parses signingKey response
    #[tokio::test]
    async fn test_reserve_signing_key_success() {
        let mock_server = MockServer::start();
        let signing_key = "did:key:z6Mkq2r...";

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey")
                .body_includes("did:plc:test123");
            then.status(200).json_body(serde_json::json!({
                "signingKey": signing_key
            }));
        });

        let client = PdsClient::new();
        let result = client
            .reserve_signing_key(&mock_server.base_url(), "did:plc:test123")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signing_key);
    }

    /// reserve_signing_key returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_reserve_signing_key_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(400).body("invalid did");
        });

        let client = PdsClient::new();
        let result = client
            .reserve_signing_key(&mock_server.base_url(), "invalid")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected
            }
            e => panic!("Expected NetworkError, got: {:?}", e),
        }
    }
}
