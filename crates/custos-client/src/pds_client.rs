// pattern: Imperative Shell

//! [`PdsClient`]: discovery, auth, and XRPC against *arbitrary* PDS endpoints and
//! plc.directory — every server an app learns about at runtime, as opposed to the one
//! configured server ([`crate::CustosClient`]). Stateless: wraps a `reqwest::Client`
//! (connection pooling) plus the plc.directory base URL (default `https://plc.directory`).
//!
//! `PdsClient` methods, grouped:
//! - **Discovery**: `resolve_handle` (DNS TXT `_atproto.{handle}`, then HTTP
//!   `/.well-known/atproto-did`; `HandleNotFound` only when both fail), `discover_pds`
//!   (DID doc → `atproto_pds` endpoint, HEAD reachability check), `discover_auth_server`
//!   (validates `code` + `S256` support).
//! - **OAuth against a discovered AS**: `pds_par`, `pds_token_exchange` (returns the raw
//!   `reqwest::Response` so the caller runs the nonce retry), `build_pds_authorize_url`.
//!   `PdsParRequest` carries the caller's `client_id`/`redirect_uri` — this crate never
//!   hardcodes an app's OAuth identity.
//! - **plc.directory**: `fetch_audit_log`, `fetch_plc_data_document`,
//!   `post_plc_operation`, and the free helper `rotation_keys_from_audit_log`.
//! - **Per-server calls**: `describe_server` (pre-migration probe for `did`/domains; every
//!   success also reports the optional `custos` extension to a [`DescribeServerObserver`]),
//!   `create_session` (password source login — 401 → `InvalidCredentials`, or
//!   `AuthFactorTokenRequired` for email 2FA), `fetch_repo_car`,
//!   `fetch_blob`/`fetch_blob_with_type`, `list_blobs`, `reserve_signing_key`,
//!   `delete_account`.
//!
//! **Status classification.** Every call routes non-2xx responses through
//! [`crate::error::classify_xrpc_response`]: `429` → `RateLimited { retry_after }`, `401` →
//! `Unauthorized`, anything else → `XrpcError { status, error, message }`.
//! [`PdsClientError::NetworkError`] is transport-only — a server that answered is never
//! reported as a connectivity failure. Diagnostics breadcrumbs are injected via
//! [`TransportObserver`], same as [`crate::OAuthClient`]/[`crate::CustosClient`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{classify_xrpc_response, error_code_is, xrpc_json, xrpc_ok};
use crate::{NoopObserver, PdsClientError, TransportObserver};

/// Reports the `custos` capability extension observed on a `describeServer` response, so an
/// app can warm its own per-host capability cache without this crate knowing that cache's
/// shape. `NoopDescribeServerObserver` is the default for callers with nothing to record.
pub trait DescribeServerObserver: Send + Sync {
    fn record_custos_capabilities(&self, pds_url: &str, custos: Option<&CustosExtension>);
}

/// A [`DescribeServerObserver`] that records nothing.
pub struct NoopDescribeServerObserver;

impl DescribeServerObserver for NoopDescribeServerObserver {
    fn record_custos_capabilities(&self, _pds_url: &str, _custos: Option<&CustosExtension>) {}
}

/// Render a failed PAR response as the authorization server's own words.
///
/// A PAR rejection body is an RFC 6749 §5.2 `{error, error_description}` JSON object;
/// extracting it is what makes a policy rejection (e.g. `invalid_redirect_uri`)
/// diagnosable in the UI instead of an opaque status line. Falls back to the raw
/// status + body when the body isn't that shape.
fn par_rejection_message(status: reqwest::StatusCode, body: &str) -> String {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        let code = json.get("error").and_then(|v| v.as_str());
        let description = json.get("error_description").and_then(|v| v.as_str());
        match (code, description) {
            (Some(c), Some(d)) => return format!("{c}: {d}"),
            (Some(c), None) => return c.to_string(),
            _ => {}
        }
    }
    format!("PAR returned {status}: {body}")
}

/// Whether a PDS URL is safe to send an account password to: HTTPS, or a loopback host over HTTP
/// (localhost/127.0.0.1/::1) for local development and the test harness. Anything else — including
/// an unparseable URL — is refused, so the password never crosses a plaintext link.
fn pds_url_is_password_safe(pds_url: &str) -> bool {
    match url::Url::parse(pds_url) {
        Ok(url) => match url.scheme() {
            "https" => true,
            "http" => matches!(
                url.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
            ),
            _ => false,
        },
        Err(_) => false,
    }
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

        // Convert service array to HashMap keyed by the id's fragment. Like the
        // verification-method ids above, service ids come in both W3C forms:
        // plc.directory serves the bare fragment ("#atproto_pds") while a did:web
        // document typically carries the absolute form ("did:web:host#atproto_pds").
        let services = self
            .service
            .into_iter()
            .map(|svc| {
                let key = svc
                    .id
                    .rsplit_once('#')
                    .map(|(_, name)| name.to_string())
                    .unwrap_or_else(|| svc.id.clone());
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

/// Response from `com.atproto.server.createSession` (legacy password login).
///
/// The `accessJwt`/`refreshJwt` are the full-session credentials the claim flow needs to drive
/// PLC operations (`requestPlcOperationSignature`/`signPlcOperation`) — operations no OAuth
/// `transition:generic` token can authorize. They feed straight into `OAuthClient::new_bearer`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub did: String,
    #[serde(default)]
    pub handle: Option<String>,
}

/// Response from describeServer.
///
/// Returned from `GET /xrpc/com.atproto.server.describeServer`. This is the public,
/// unauthenticated server description endpoint used to discover the server's DID and
/// available user domains (for destination reachability probes), and — on a Custos
/// host — the capabilities an app may feature-gate on.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerResponse {
    pub did: String,
    #[serde(default)]
    pub available_user_domains: Vec<String>,
    /// Custos's off-lexicon capability extension. **Absent on every other
    /// implementation** — the reference PDS and rsky-pds return strictly the lexicon
    /// fields, millipds adds only a top-level `version` — so this must stay optional and
    /// its absence must mean "no Custos capabilities", never an error.
    #[serde(default)]
    pub custos: Option<CustosExtension>,
}

/// The `custos` object of a describeServer response: what the host is, and what it offers.
///
/// Both members are tolerant by design. `version` is informational only (never parsed for
/// comparison — a client gates on named capabilities, not on version arithmetic), and an
/// unrecognized capability name is simply one this build does not use, not an error.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CustosExtension {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// A device-key-signed authorization to permanently delete an account — the credential a
/// key-sovereign account presents to `deleteAccount` in place of a password it may never have had.
///
/// The bytes signed are the caller's own envelope encoding; the server verifies them against
/// the identity's authoritative current rotation set. Travels inside the request body's
/// off-lexicon `custos.proof` object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountProof {
    pub signing_key: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

/// Which first factor a deletion request carries alongside the emailed confirmation code.
pub enum DeleteCredential {
    /// The account password — the standard lexicon field, the only option on a host that does
    /// not advertise `walletAccountDelete`.
    Password(String),
    /// A device-key-signed proof of ownership.
    Proof(DeleteAccountProof),
}

impl DeleteCredential {
    /// What goes in the body's required `password` field: the password itself, or the empty
    /// string when a proof is carrying the request instead.
    fn password_field(&self) -> &str {
        match self {
            Self::Password(password) => password,
            Self::Proof(_) => "",
        }
    }
}

/// One page of a DID's blob CIDs from the public sync listing.
///
/// Returned from `GET /xrpc/com.atproto.sync.listBlobs` (auth: none). Used by an app's
/// blob-backup sync pass to enumerate the account's blobs on its hosting PDS.
#[derive(Debug, Deserialize)]
pub struct ListedBlobs {
    pub cids: Vec<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Parameters for a Pushed Authorization Request. `client_id`/`redirect_uri` are the caller's
/// OAuth client identity — this crate never hardcodes an app's own.
pub struct PdsParRequest<'a> {
    pub pkce_challenge: &'a str,
    pub state_param: &'a str,
    pub dpop_proof: &'a str,
    pub dpop_jkt: &'a str,
    pub login_hint: Option<&'a str>,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
}

/// Parameters for [`PdsClient::pds_token_exchange`], grouped for the same reason as
/// [`PdsParRequest`]: two adjacent `&str` positional arguments (`client_id`/`redirect_uri`)
/// would compile if transposed and silently break OAuth.
pub struct PdsTokenExchangeRequest<'a> {
    pub code: &'a str,
    pub pkce_verifier: &'a str,
    pub dpop_proof: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
}

fn default_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// PDS client for discovery and OAuth operations against arbitrary PDS endpoints.
///
/// Stateless except for the HTTP client which pools connections.
pub struct PdsClient {
    client: Client,
    plc_directory_url: String,
    observer: Arc<dyn TransportObserver>,
    describe_observer: Arc<dyn DescribeServerObserver>,
}

impl PdsClient {
    /// Construct a new PdsClient with the default plc.directory URL and no-op observers.
    /// Use [`Self::new_with_observers`] to wire real diagnostics/capability reporting.
    pub fn new() -> Self {
        Self::new_for_test("https://plc.directory".to_string())
    }

    /// Construct with a custom plc.directory URL (e.g. a mock server) and no-op observers.
    ///
    /// Despite the name, **not** `#[cfg(test)]`: a dependent crate's test build cannot see a
    /// dependency's `#[cfg(test)]` items, so this stays a plain constructor (harmless in
    /// production — it is exactly [`Self::new`] with a configurable plc.directory URL).
    pub fn new_for_test(plc_directory_url: String) -> Self {
        Self {
            client: default_client(),
            plc_directory_url,
            observer: Arc::new(NoopObserver),
            describe_observer: Arc::new(NoopDescribeServerObserver),
        }
    }

    /// Construct with real diagnostics/capability observers and the default plc.directory URL.
    /// Use [`Self::with_plc_directory_url`] to also override the URL (e.g. a test that wants
    /// both a mock plc.directory and real observer wiring).
    pub fn new_with_observers(
        observer: Arc<dyn TransportObserver>,
        describe_observer: Arc<dyn DescribeServerObserver>,
    ) -> Self {
        Self {
            client: default_client(),
            plc_directory_url: "https://plc.directory".to_string(),
            observer,
            describe_observer,
        }
    }

    /// Override the plc.directory base URL (e.g. a mock server), keeping the observers.
    pub fn with_plc_directory_url(mut self, plc_directory_url: String) -> Self {
        self.plc_directory_url = plc_directory_url;
        self
    }

    /// Returns the plc.directory base URL.
    pub fn plc_directory_url(&self) -> &str {
        &self.plc_directory_url
    }

    /// Returns a reference to the inner HTTP client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn note_transport_failure(&self, op: &str, url: Option<&str>, e: &reqwest::Error) {
        self.observer.record_transport(op, url, e);
    }

    /// Resolve a handle to a DID via DNS TXT lookup with HTTP fallback.
    ///
    /// Attempts DNS TXT lookup for `_atproto.{handle}` first, then falls back to HTTP
    /// `/.well-known/atproto-did` if DNS fails or returns no records.
    /// Returns `HANDLE_NOT_FOUND` only when both methods fail.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, PdsClientError> {
        // Try DNS TXT lookup first
        let dns_error = match try_resolve_dns(handle, self.observer.as_ref()).await {
            Ok(Some(did)) => return Ok(did),
            Ok(None) => None,
            Err(e) => Some(e),
        };

        // Try HTTP well-known lookup
        let http_url = format!("https://{}/.well-known/atproto-did", handle);
        match try_resolve_http(&self.client, &http_url, self.observer.as_ref()).await {
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
        // A did:web document lives at the domain itself, not plc.directory. Hostname-form
        // identifiers only (the shape apps compose): a colon would smuggle a port or
        // path segment into the URL, so those shapes are refused rather than misresolved.
        let url = if let Some(host) = did.strip_prefix("did:web:") {
            if host.is_empty() || host.contains([':', '/', '@']) {
                return Err(PdsClientError::InvalidResponse {
                    message: "unsupported did:web identifier".to_string(),
                });
            }
            format!("https://{}/.well-known/did.json", host.to_ascii_lowercase())
        } else {
            format!("{}/{}", self.plc_directory_url, did)
        };

        // Fetch the DID document from plc.directory
        let response = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("discover_pds", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch DID document: {}", e),
            }
        })?;

        if response.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }

        // Parse W3C DID Document and convert to PlcDidDocument. Status-classified like the
        // other plc.directory reads: a throttle or outage verdict is preserved for callers
        // instead of flattening to a transport error. rotation_keys will be empty —
        // callers that need them must fetch the audit log.
        let w3c_doc: W3cDidDocument =
            xrpc_json("discover_pds", response, self.observer.as_ref()).await?;
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
            .map_err(|e| {
                self.note_transport_failure("discover_pds", Some(pds_endpoint), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to reach PDS endpoint: {}", e),
                }
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
            self.note_transport_failure("discover_auth_server", Some(&url), &e);
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

    /// Fetch the server description from a PDS.
    ///
    /// Gets `GET {pds_url}/xrpc/com.atproto.server.describeServer` (public, no auth).
    /// This is used as a destination reachability probe and to obtain the destination
    /// server's DID for service-auth requests.
    /// Maps connection failure / non-2xx to `PdsClientError::PdsUnreachable`.
    pub async fn describe_server(
        &self,
        pds_url: &str,
    ) -> Result<DescribeServerResponse, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.describeServer",
            pds_url.trim_end_matches('/')
        );

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("describeServer", Some(&url), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to reach PDS: {}", e),
                }
            })?;

        if !response.status().is_success() {
            return Err(PdsClientError::PdsUnreachable {
                reason: format!("describeServer returned {}", response.status()),
            });
        }

        let described = response
            .json::<DescribeServerResponse>()
            .await
            .map_err(|e| {
                self.note_transport_failure("describeServer", Some(&url), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to parse describeServer response: {}", e),
                }
            })?;

        // Warm the caller's per-host capability cache from every describeServer call,
        // wherever it was made from. The probe and the cache are then the same fetch
        // rather than a second round trip.
        self.describe_observer
            .record_custos_capabilities(pds_url, described.custos.as_ref());

        Ok(described)
    }

    /// Create a full password session against a PDS (`com.atproto.server.createSession`).
    ///
    /// This is the source-PDS login for the claim (inbound-migration) flow. Unlike OAuth,
    /// a password `createSession` yields a **full-access** session (`com.atproto.access`), the
    /// only credential class that can drive PLC operations on a spec-strict PDS like bsky.social.
    /// The `identifier` is a handle, DID, or email; the `password` must be the account's
    /// real password (an app password is a lesser scope and is rejected the same way).
    ///
    /// The password is used for this single request and never persisted — the caller keeps only
    /// the returned JWTs (in an in-memory Bearer `OAuthClient`).
    ///
    /// `auth_factor_token` carries the email one-time code for accounts with 2FA enabled. Pass
    /// `None` on the first attempt; a 2FA account then answers with `AuthFactorTokenRequired`
    /// ([`PdsClientError::AuthFactorTokenRequired`]) and emails a code — retry with that code as
    /// `Some`. Any other 401 maps to [`PdsClientError::InvalidCredentials`] ("wrong password").
    pub async fn create_session(
        &self,
        pds_url: &str,
        identifier: &str,
        password: &str,
        auth_factor_token: Option<&str>,
    ) -> Result<CreateSessionResponse, PdsClientError> {
        // Never send the account password over a plaintext link. `pds_url` comes from the DID
        // document, so a misconfigured or hostile `http://` endpoint must be refused here.
        if !pds_url_is_password_safe(pds_url) {
            tracing::error!(pds_url = %pds_url, "refusing to send password to a non-HTTPS PDS");
            return Err(PdsClientError::InsecurePdsUrl {
                url: pds_url.to_string(),
            });
        }

        let url = format!(
            "{}/xrpc/com.atproto.server.createSession",
            pds_url.trim_end_matches('/')
        );

        let mut request_body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });
        if let Some(token) = auth_factor_token {
            request_body["authFactorToken"] = serde_json::Value::String(token.to_string());
        }

        let response = self
            .client
            .post(&url)
            .timeout(Duration::from_secs(30))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("createSession", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("createSession request failed: {}", e),
                }
            })?;

        let status = response.status();
        if status.as_u16() == 401 {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            // An account with email 2FA answers a token-less attempt with `AuthFactorTokenRequired`
            // (and emails a code) — distinct from a wrong password, so the UI can prompt for the
            // code instead of blaming the password.
            if error_code_is(&body, "AuthFactorTokenRequired") {
                return Err(PdsClientError::AuthFactorTokenRequired);
            }
            return Err(PdsClientError::InvalidCredentials { message: body });
        }
        if !status.is_success() {
            // 401 is already handled above (wrong password / 2FA). Anything else — a 429 rate
            // limit, a 400 validation error — is classified so its real reason survives.
            return Err(
                classify_xrpc_response("createSession", response, self.observer.as_ref()).await,
            );
        }

        response.json::<CreateSessionResponse>().await.map_err(|e| {
            PdsClientError::InvalidResponse {
                message: format!("failed to parse createSession response: {}", e),
            }
        })
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
            ("redirect_uri", request.redirect_uri.to_string()),
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
            .map_err(|e| {
                self.note_transport_failure("pds_par", Some(&par_url), &e);
                PdsClientError::NetworkError {
                    message: format!("PAR request failed: {}", e),
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            // Surface the AS's own OAuth error — a PAR rejection (e.g. bsky.social's
            // invalid_redirect_uri) must reach the caller as more than a status code.
            return Err(PdsClientError::OauthFailed {
                message: par_rejection_message(status, &error_body),
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
        request: PdsTokenExchangeRequest<'_>,
    ) -> Result<reqwest::Response, PdsClientError> {
        let token_url = &metadata.token_endpoint;

        let form_data = vec![
            ("grant_type", "authorization_code"),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("code_verifier", request.pkce_verifier),
            ("client_id", request.client_id),
        ];

        self.client
            .post(token_url)
            .header("DPoP", request.dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("pds_token_exchange", Some(token_url), &e);
                PdsClientError::OauthFailed {
                    message: format!("token exchange request failed: {}", e),
                }
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
        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("fetch_audit_log", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch audit log: {}", e),
            }
        })?;

        if resp.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }
        // A non-2xx is plc.directory's verdict (429 throttle, 5xx outage), not a
        // connectivity problem — classify by status so callers can say which it was.
        let resp = xrpc_ok("fetch_audit_log", resp, self.observer.as_ref()).await?;

        resp.text().await.map_err(|e| {
            self.note_transport_failure("fetch_audit_log", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to read audit log response: {}", e),
            }
        })
    }

    /// Fetch the PLC *data* document for a DID.
    ///
    /// Calls `GET {plc_directory_url}/{did}/data` — the PLC-native shape
    /// (`did, alsoKnownAs, rotationKeys, verificationMethods, services`). The W3C
    /// document (`GET /{did}`) carries no `rotationKeys` and must never be cached in its place.
    pub async fn fetch_plc_data_document(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, PdsClientError> {
        let url = format!("{}/{}/data", self.plc_directory_url, did);
        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("fetch_plc_data_document", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch PLC data document: {}", e),
            }
        })?;

        if resp.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }
        // Same status-classification as `fetch_audit_log`: a 429/5xx from plc.directory
        // must not read as "check your connection".
        let resp = xrpc_ok("fetch_plc_data_document", resp, self.observer.as_ref()).await?;

        resp.json().await.map_err(|e| {
            self.note_transport_failure("fetch_plc_data_document", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to parse PLC data document: {}", e),
            }
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
            .map_err(|e| {
                self.note_transport_failure("post_plc_operation", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to post plc operation: {}", e),
                }
            })?;

        if resp.status().is_success() {
            Ok(())
        } else if resp.status().as_u16() == 429 {
            // A throttle is not a rejection of the operation — surface it as the retryable
            // condition it is, with the server's pacing hint.
            Err(classify_xrpc_response("post_plc_operation", resp, self.observer.as_ref()).await)
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
    pub async fn fetch_repo_car(
        &self,
        pds_url: &str,
        did: &str,
    ) -> Result<Vec<u8>, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );

        // A full repo CAR can be large; override the shared 30s client timeout so a slow bulk
        // download doesn't fail mid-stream.
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("getRepo", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to fetch repo CAR: {}", e),
                }
            })?;

        let resp = xrpc_ok("getRepo", resp, self.observer.as_ref()).await?;

        resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
            self.note_transport_failure("getRepo", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to read repo CAR bytes: {}", e),
            }
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
        self.fetch_blob_with_type(pds_url, did, cid)
            .await
            .map(|(bytes, _)| bytes)
    }

    /// Fetch a blob by DID and CID, also returning the server's `Content-Type` (auth: none).
    ///
    /// Same call as [`fetch_blob`](Self::fetch_blob), but preserves the response's
    /// `Content-Type` header — the only place the blob's MIME type is available on the
    /// public sync surface (`listBlobs` yields bare CIDs). A blob-backup manifest can record
    /// it so a later `uploadBlob` restore replays the original type.
    pub async fn fetch_blob_with_type(
        &self,
        pds_url: &str,
        did: &str,
        cid: &str,
    ) -> Result<(Vec<u8>, Option<String>), PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did),
            urlencoding::encode(cid)
        );

        // Blobs (images/video) can be large; override the shared 30s client timeout for the download.
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("getBlob", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to fetch blob: {}", e),
                }
            })?;

        let resp = xrpc_ok("getBlob", resp, self.observer.as_ref()).await?;

        // Capture the header before the body read consumes the response.
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        resp.bytes()
            .await
            .map(|b| (b.to_vec(), content_type))
            .map_err(|e| {
                self.note_transport_failure("getBlob", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to read blob bytes: {}", e),
                }
            })
    }

    /// List a DID's blob CIDs on its PDS, one page (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.listBlobs?did={did}&cursor={cursor}`.
    /// This is the source-side listing a blob-backup sync pass paginates (distinct from the
    /// authenticated destination-side `listMissingBlobs` a migration drain uses); the
    /// response is bare CIDs plus an optional cursor.
    pub async fn list_blobs(
        &self,
        pds_url: &str,
        did: &str,
        cursor: Option<&str>,
    ) -> Result<ListedBlobs, PdsClientError> {
        let mut url = format!(
            "{}/xrpc/com.atproto.sync.listBlobs?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );
        if let Some(cur) = cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(cur)));
        }

        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("listBlobs", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to list blobs: {}", e),
            }
        })?;

        xrpc_json("listBlobs", resp, self.observer.as_ref()).await
    }

    /// Reserve a signing key on the PDS (auth: none, idempotent per DID).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.reserveSigningKey` with body `{"did": did}`,
    /// or an empty body when `did` is `None`. Returns the `signingKey` field from the response (a
    /// did:key string).
    ///
    /// `None` is the *anonymous* reservation, for a key that has to exist before the DID it will
    /// belong to does: a child-account mint has to name a repo-signing key inside the genesis op
    /// whose hash becomes the child's DID. Anonymous reservations are rate-limited per IP and are
    /// not idempotent — each call yields a fresh key.
    pub async fn reserve_signing_key(
        &self,
        pds_url: &str,
        did: Option<&str>,
    ) -> Result<String, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            pds_url.trim_end_matches('/')
        );

        let body = match did {
            Some(did) => serde_json::json!({ "did": did }),
            None => serde_json::json!({}),
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("reserveSigningKey", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to reserve signing key: {}", e),
                }
            })?;

        let resp = xrpc_ok("reserveSigningKey", resp, self.observer.as_ref()).await?;

        #[derive(Deserialize)]
        struct ReserveSigningKeyResponse {
            #[serde(rename = "signingKey")]
            signing_key: String,
        }

        resp.json::<ReserveSigningKeyResponse>()
            .await
            .map(|r| r.signing_key)
            .map_err(|e| {
                self.note_transport_failure("reserveSigningKey", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to parse reserve_signing_key response: {}", e),
                }
            })
    }

    /// Permanently delete an account on its PDS (auth: none — the credentials are in the body).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.deleteAccount` with `{ did, password, token }`,
    /// where `token` is the single-use code minted by `requestAccountDelete` and emailed to the
    /// account. Not session-authed, so no `OAuthClient` is needed — but a credential travels in
    /// the body either way, so the endpoint is refused over a non-HTTPS URL (loopback excepted),
    /// same guard as the password `createSession` path.
    ///
    /// `credential` selects the first factor. [`DeleteCredential::Proof`] additionally sends the
    /// off-lexicon `custos.proof` object, and sends `password` as the empty string — the vendored
    /// lexicon marks the field required, so it stays on the wire even for an account that has no
    /// password. Only a host advertising `walletAccountDelete` reads it.
    pub async fn delete_account(
        &self,
        pds_url: &str,
        did: &str,
        credential: &DeleteCredential,
        token: &str,
    ) -> Result<(), PdsClientError> {
        if !pds_url_is_password_safe(pds_url) {
            return Err(PdsClientError::InsecurePdsUrl {
                url: pds_url.to_string(),
            });
        }

        let url = format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            pds_url.trim_end_matches('/')
        );
        let mut body = serde_json::json!({
            "did": did,
            "password": credential.password_field(),
            "token": token,
        });
        if let DeleteCredential::Proof(proof) = credential {
            body["custos"] = serde_json::json!({ "proof": proof });
        }
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("deleteAccount", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("delete_account failed: {}", e),
                }
            })?;

        xrpc_ok("deleteAccount", resp, self.observer.as_ref())
            .await
            .map(|_| ())
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
///
/// `pub` (not just crate-private) so a caller's own handle-resolution pre-flight (e.g. a
/// change-handle DNS check) can report this vantage separately from the hosting PDS's own
/// resolution.
pub async fn try_resolve_dns(
    handle: &str,
    observer: &dyn TransportObserver,
) -> Result<Option<String>, PdsClientError> {
    let dns_name = format!("_atproto.{}", handle);
    tracing::debug!(dns_name = %dns_name, "attempting DNS TXT lookup");

    // Create a resolver using system DNS config (matches the PDS's own resolver setup).
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
                // Host is omitted: the DNS name embeds the handle, which the diagnostics log
                // must never capture. The fixed `"dns"` category is enough to show the class.
                observer.record_transport_category("resolve_handle_dns", None, "dns");
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
    observer: &dyn TransportObserver,
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
                        // Host omitted: the well-known URL's host IS the handle domain.
                        observer.record_transport("resolve_handle_http", None, &e);
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
            // Host omitted: the well-known URL's host IS the handle domain.
            observer.record_transport("resolve_handle_http", None, &e);
            Err(PdsClientError::NetworkError {
                message: format!("HTTP request failed: {}", e),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NoopObserver;
    use httpmock::prelude::*;

    /// A failed PAR surfaces the AS's own error/error_description; non-OAuth bodies
    /// fall back to the raw status + body.
    #[test]
    fn par_rejection_message_extracts_oauth_error() {
        let status = reqwest::StatusCode::BAD_REQUEST;
        assert_eq!(
            par_rejection_message(
                status,
                r#"{"error":"invalid_redirect_uri","error_description":"scheme mismatch"}"#
            ),
            "invalid_redirect_uri: scheme mismatch"
        );
        assert_eq!(
            par_rejection_message(status, r#"{"error":"invalid_request"}"#),
            "invalid_request"
        );
        assert_eq!(
            par_rejection_message(status, "<html>gateway error</html>"),
            "PAR returned 400 Bad Request: <html>gateway error</html>"
        );
    }

    // A did:web document carries absolute-form ids ("did:web:host#atproto_pds"), unlike
    // plc.directory's bare fragments ("#atproto_pds"). Both must key the services map by
    // the fragment alone, or `discover_pds` reports "missing atproto_pds service" for a
    // perfectly valid did:web document.
    #[test]
    fn test_into_plc_doc_keys_services_by_fragment_for_absolute_ids() {
        let did = "did:web:rehearsal.example";
        let w3c_doc: W3cDidDocument = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": ["at://rehearsal.example"],
            "verificationMethod": [
                {
                    "id": format!("{did}#device"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": "zDnaDevice"
                },
                {
                    "id": format!("{did}#atproto"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": "zDnaRepo"
                }
            ],
            "service": [{
                "id": format!("{did}#atproto_pds"),
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example"
            }]
        }))
        .expect("document deserializes");

        let doc = w3c_doc.into_plc_doc();
        let pds = doc
            .services
            .get("atproto_pds")
            .expect("service keyed by fragment, not the absolute id");
        assert_eq!(pds.endpoint, "https://pds.example");
        assert_eq!(doc.verification_methods["atproto"], "zDnaRepo");
        assert_eq!(doc.verification_methods["device"], "zDnaDevice");
    }

    // ============================================================================
    // HTTP fallback resolution tests
    // ============================================================================

    /// HTTP fallback resolves handle to DID
    #[tokio::test]
    async fn test_try_resolve_http_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(200).body("did:plc:test123");
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url, &NoopObserver).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
    }

    /// HTTP fallback handles response body with whitespace
    #[tokio::test]
    async fn test_try_resolve_http_with_whitespace() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(200).body("  did:plc:test123\n  ");
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url, &NoopObserver).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
    }

    /// HTTP fallback returns Ok(None) on 404 client error
    #[tokio::test]
    async fn test_try_resolve_http_not_found() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(404);
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url, &NoopObserver).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    /// HTTP fallback returns NetworkError on 500 server error
    #[tokio::test]
    async fn test_try_resolve_http_server_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/.well-known/atproto-did");
            then.status(500);
        });

        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
        let result = try_resolve_http(&client, &url, &NoopObserver).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::NetworkError { .. } => {
                // Expected: 5xx is a server error, not a missing handle
            }
            e => panic!("Expected NetworkError on 5xx, got: {:?}", e),
        }
    }

    /// `PdsClient::new_for_test`'s default field values.
    #[test]
    fn test_pds_client_default() {
        let client = PdsClient::default();
        assert_eq!(client.plc_directory_url(), "https://plc.directory");
    }
}
