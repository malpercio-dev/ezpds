// pattern: Imperative Shell

//! [`PdsClient`]: discovery, auth, and XRPC against *arbitrary* PDS endpoints and
//! plc.directory — every server an app learns about at runtime, as opposed to the one
//! configured server ([`crate::CustosClient`]). Stateless: wraps a `reqwest::Client`
//! (connection pooling) plus the plc.directory base URL (default `https://plc.directory`).
//!
//! `PdsClient` methods, grouped (one submodule per group; shared types stay here):
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
//!   `AuthFactorTokenRequired` for email 2FA), `refresh_session` (rotate a Bearer pair;
//!   no sub/aud validation — see `sovereign_session::refresh_bearer_session`),
//!   `fetch_repo_car`,
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

/// Whether it is safe to send credentials (an account password, a Bearer token) to `pds_url`:
/// HTTPS, or a loopback host over HTTP (localhost/127.0.0.1/::1) for local development and the
/// test harness. Anything else — including an unparseable URL — is refused, so a credential never
/// crosses a plaintext link.
pub fn pds_url_is_secure(pds_url: &str) -> bool {
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

/// `com.atproto.sync.getLatestCommit` output.
#[derive(Debug, Clone, Deserialize)]
pub struct LatestCommit {
    pub cid: String,
    pub rev: String,
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
    // The browser's fetch client has no client-wide timeout; the per-request ones below still apply.
    #[cfg(target_arch = "wasm32")]
    {
        Client::new()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new())
    }
}

/// PDS client for discovery and OAuth operations against arbitrary PDS endpoints.
///
/// Stateless except for the HTTP client which pools connections; a clone shares the pool.
#[derive(Clone)]
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
}

impl Default for PdsClient {
    fn default() -> Self {
        Self::new()
    }
}

// ── Methods, one module per concern (the groups in the module doc above) ────

mod discovery;
mod oauth;
mod plc;
mod server;

pub use discovery::*;
pub use plc::*;

#[cfg(test)]
mod tests;
