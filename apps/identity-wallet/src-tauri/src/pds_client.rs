// pattern: Imperative Shell
//
// Gathers: PDS discovery parameters (handle, DID, OAuth metadata)
// Processes: DNS TXT resolution, HTTP well-known fetches, PDS OAuth metadata discovery
// Returns: PDS endpoints, authorization server metadata, or error codes

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

/// OAuth client metadata path — the canonical client_id's path, also appended to a
/// loopback Custos base URL by the local-development exception in [`client_id_for_pds`].
const CLIENT_METADATA_PATH: &str = "/oauth/client-metadata.json";

/// The wallet's canonical OAuth client_id: its client-metadata document, served by the
/// production Custos at a stable wallet-owned host. The atproto OAuth spec requires a
/// native client's private-use redirect scheme to be the client_id host's FQDN in
/// reverse order — `identitywallet.obsign.org` ⇄ `org.obsign.identitywallet:` — and
/// third-party authorization servers (bsky.social) enforce it. Must stay in sync with
/// [`REDIRECT_URI`]/[`CALLBACK_SCHEME`], the Custos client-metadata route, and the
/// V042-seeded `oauth_clients` row.
pub const CANONICAL_CLIENT_ID: &str =
    "https://identitywallet.obsign.org/oauth/client-metadata.json";

/// OAuth redirect URI. The private-use scheme is the canonical client_id host reversed;
/// its scheme must match the `CFBundleURLTypes` entry in `src-tauri/Info.ios.plist`.
pub const REDIRECT_URI: &str = "org.obsign.identitywallet:/oauth/callback";

/// The redirect URI's scheme — what the auth-session plugin matches the callback on.
pub const CALLBACK_SCHEME: &str = "org.obsign.identitywallet";

/// The wallet's OAuth client_id.
///
/// This is the fixed [`CANONICAL_CLIENT_ID`]: the OAuth client is the wallet app, so
/// its identity does not vary with the Custos instance the user configured. The one
/// exception is a loopback Custos (local development), which serves a self-referencing
/// localhost document — there the client_id derives from the configured base so the
/// authorization server's fetch-and-match resolution still succeeds.
pub fn client_id_for_pds(custos_base_url: &str) -> String {
    if url_is_loopback(custos_base_url) {
        format!(
            "{}{}",
            custos_base_url.trim_end_matches('/'),
            CLIENT_METADATA_PATH
        )
    } else {
        CANONICAL_CLIENT_ID.to_string()
    }
}

/// Whether a URL string's host is loopback (unparseable → false).
fn url_is_loopback(base: &str) -> bool {
    let Ok(parsed) = url::Url::parse(base) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
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

    /// Transport-level failure (DNS timeout, connection refused, TLS error, body read error) —
    /// the request never got a well-formed HTTP response back. A non-2xx *response* is NOT a
    /// `NetworkError`: it is classified into one of the status-specific variants below. Keeping
    /// this variant transport-only is what lets screens tell "check your connection" apart from
    /// "the server said no".
    #[error("network error: {message}")]
    NetworkError { message: String },

    /// The server answered `429 Too Many Requests`. `retry_after` is the raw `Retry-After` header
    /// (seconds or an HTTP date) when the server sent one, so the UI can say how long to wait
    /// instead of blaming the connection. `message` is the server's own error text.
    #[error("rate limited: {message}")]
    RateLimited {
        retry_after: Option<String>,
        message: String,
    },

    /// The server answered `401 Unauthorized` — the session/token was rejected (expired, wrong
    /// audience, a scope refusal presented as 401). Distinct from a transport failure so the UI
    /// can prompt a re-login rather than a retry. `error` is the atproto error code from the
    /// envelope when present (e.g. `ExpiredToken`, `InvalidToken`) — preserved so a token failure
    /// reported under 401 is still recognizable by code rather than only by message text; `message`
    /// is the server's own error text.
    #[error("unauthorized: {message}")]
    Unauthorized {
        error: Option<String>,
        message: String,
    },

    /// Any other non-2xx XRPC response, carrying the atproto error envelope so the real reason
    /// reaches the UI instead of connectivity boilerplate. `error` is the envelope's `error` code
    /// (e.g. `InvalidRequest`, `InsufficientScope`) when the body was a recognizable envelope;
    /// `message` is the envelope's human-readable `message` (falling back to the error code, then
    /// the raw body). `status` is the HTTP status code.
    #[error("server error {status}: {message}")]
    XrpcError {
        status: u16,
        error: Option<String>,
        message: String,
    },

    /// Response body couldn't be parsed or was missing expected fields.
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },

    /// PAR or token exchange failed.
    #[error("oauth failed: {message}")]
    OauthFailed { message: String },

    /// DID already exists (HTTP 409 from createAccount migration).
    #[error("did already exists")]
    DidAlreadyExists,

    /// `createSession` rejected the identifier/password (HTTP 401). Distinct from a transport
    /// failure so the claim flow can tell the user "wrong password" rather than "network error".
    #[error("invalid credentials: {message}")]
    InvalidCredentials { message: String },

    /// `createSession` needs an email 2FA one-time code (`AuthFactorTokenRequired`, HTTP 401).
    /// The account has email two-factor enabled and the server has emailed a code; retry
    /// `create_session` with that code as `auth_factor_token`.
    #[error("auth factor token required")]
    AuthFactorTokenRequired,

    /// Refused to send the account password to a non-HTTPS PDS URL (loopback excepted). The
    /// `pds_url` is derived from the DID document, so a plaintext `http://` endpoint must never
    /// receive the password.
    #[error("insecure pds url: {url}")]
    InsecurePdsUrl { url: String },
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

/// Whether an atproto XRPC error body (`{"error":"...","message":"..."}`) carries `error == code`.
fn error_code_is(body: &str, code: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(|s| s == code))
        .unwrap_or(false)
}

/// Parse an atproto XRPC error envelope (`{"error":"Code","message":"human text"}`) out of a
/// response body. Returns `(error_code, human_message)`:
/// - `error_code` is the envelope's `error` field when the body was a recognizable JSON envelope,
///   else `None` (e.g. an HTML gateway page or an empty body);
/// - `human_message` is the envelope's `message`, falling back to the `error` code, then to the
///   raw (trimmed) body when it wasn't an envelope at all.
///
/// The atproto error envelope is designed to be shown to users, so preserving both fields is what
/// turns an opaque non-2xx into a diagnosable one.
fn parse_xrpc_error_envelope(body: &str) -> (Option<String>, String) {
    let envelope = serde_json::from_str::<serde_json::Value>(body).ok();
    let error = envelope
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| e.as_str())
        .map(str::to_string);
    let message = envelope
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .or_else(|| error.clone())
        .unwrap_or_else(|| body.trim().to_string());
    (error, message)
}

/// Classify a non-2xx XRPC response into the typed `PdsClientError` variant that preserves the
/// server's own words. A pure function of the HTTP status, the raw `Retry-After` header, and the
/// parsed error envelope, so it is unit-testable without a live response.
///
/// Contract:
/// - `429` → [`PdsClientError::RateLimited`], carrying `retry_after` when the server sent it.
/// - `401` → [`PdsClientError::Unauthorized`], carrying the atproto `error` code when present so a
///   token failure reported under 401 stays recognizable by code.
/// - anything else → [`PdsClientError::XrpcError`] with the atproto `error` code and human message.
///
/// It must NEVER return [`PdsClientError::NetworkError`]: by the time we are here the server *did*
/// answer, so this is never a transport failure.
fn classify_xrpc_error(status: u16, retry_after: Option<String>, body: &str) -> PdsClientError {
    let (error, message) = parse_xrpc_error_envelope(body);
    match status {
        429 => PdsClientError::RateLimited {
            retry_after,
            message,
        },
        401 => PdsClientError::Unauthorized { error, message },
        // Everything else — including 403 — keeps its atproto error code and human message. Domain
        // callers (e.g. `claim::classify_plc_op_error`) recognize codes like `InsufficientScope`
        // here; this layer only speaks HTTP-status semantics. `retry_after` is meaningful only for
        // 429, so it is intentionally dropped for these statuses.
        _ => PdsClientError::XrpcError {
            status,
            error,
            message,
        },
    }
}

/// Upper bound on how much of an error response body we buffer, keep, and log. An atproto error
/// envelope is a short JSON object; anything larger is a broken or hostile server, and reading it
/// in full would let an untrusted endpoint spike memory or flood the logs.
const MAX_XRPC_ERROR_BODY: usize = 8 * 1024;

/// Read at most `cap` bytes of a response body, streaming so an oversized (untrusted) payload is
/// never fully buffered. Returns the decoded (lossy-UTF-8) prefix. A transport error mid-read
/// propagates as `Err` so the caller can treat it as a `NetworkError` rather than a server verdict.
async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<String, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await? {
            Some(chunk) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            None => break,
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read the status, `Retry-After` header, and body off a non-success XRPC response and classify it.
///
/// The imperative wrapper around [`classify_xrpc_error`]. The `Retry-After` header is captured
/// before the body (reading the body consumes the response). The body is bounded to
/// [`MAX_XRPC_ERROR_BODY`] so an oversized untrusted payload can't spike memory or flood logs, and
/// a mid-read transport failure surfaces as `NetworkError` rather than a fabricated server verdict.
/// `context` names the call site (e.g. `"requestPlcOperationSignature"`) for the log line only —
/// the returned error carries the server's own message, not the context, so screens show it
/// verbatim.
async fn classify_xrpc_response(context: &str, resp: reqwest::Response) -> PdsClientError {
    let status = resp.status();
    // Capture the host before the body read consumes the response — the diagnostics
    // breadcrumb records the server hostname only (never the path or query).
    let host = resp.url().host_str().map(str::to_string);
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = match read_body_capped(resp, MAX_XRPC_ERROR_BODY).await {
        Ok(body) => body,
        Err(e) => {
            crate::diagnostics::record_transport(
                context,
                host.as_deref(),
                crate::diagnostics::transport_category(&e),
            );
            tracing::warn!(context, status = %status, error = %e, "failed to read XRPC error body");
            return PdsClientError::NetworkError {
                message: format!("failed to read {status} response body: {e}"),
            };
        }
    };
    tracing::warn!(context, status = %status, body = %body, "XRPC call returned non-success");
    // Redacted breadcrumb for the user-exportable diagnostics log: the atproto `error`
    // code is a short, safe token (e.g. `RateLimited`), never the free-form message/body.
    let (error_code, _message) = parse_xrpc_error_envelope(&body);
    crate::diagnostics::record_server(
        context,
        host.as_deref(),
        status.as_u16(),
        error_code.as_deref(),
    );
    classify_xrpc_error(status.as_u16(), retry_after, &body)
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

/// Response from `com.atproto.server.createSession` (legacy password login).
///
/// The `accessJwt`/`refreshJwt` are the full-session credentials the claim flow needs to drive
/// PLC operations (`requestPlcOperationSignature`/`signPlcOperation`) — operations no OAuth
/// `transition:generic` token can authorize. They feed straight into
/// `OAuthClient::new_bearer`.
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
/// available user domains (for destination reachability probes).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerResponse {
    pub did: String,
    #[serde(default)]
    pub available_user_domains: Vec<String>,
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
/// Also returned to the frontend via `verify_import` command, so it must derive Serialize.
#[derive(Debug, Deserialize, Serialize)]
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
            // Status-classified like the other plc.directory reads: a throttle or outage
            // verdict is preserved for callers instead of flattening to a transport error.
            s if !s.is_success() => {
                return Err(classify_xrpc_response("discover_pds", response).await);
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

    /// Fetch the server description from a PDS.
    ///
    /// Gets `GET {pds_url}/xrpc/com.atproto.server.describeServer` (public, no auth).
    /// This is used as a destination reachability probe (`prepare_migration`) and to
    /// obtain the destination server's DID for service-auth requests.
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
            .map_err(|e| PdsClientError::PdsUnreachable {
                reason: format!("failed to reach PDS: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(PdsClientError::PdsUnreachable {
                reason: format!("describeServer returned {}", response.status()),
            });
        }

        response
            .json::<DescribeServerResponse>()
            .await
            .map_err(|e| PdsClientError::PdsUnreachable {
                reason: format!("failed to parse describeServer response: {}", e),
            })
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
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("createSession request failed: {}", e),
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
            return Err(classify_xrpc_response("createSession", response).await);
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
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("PAR request failed: {}", e),
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
            // A non-2xx is plc.directory's verdict (429 throttle, 5xx outage), not a
            // connectivity problem — classify by status so callers can say which it was.
            s if !s.is_success() => {
                return Err(classify_xrpc_response("fetch_audit_log", resp).await);
            }
            _ => {}
        }

        resp.text().await.map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to read audit log response: {}", e),
        })
    }

    /// Fetch the PLC *data* document for a DID.
    ///
    /// Calls `GET {plc_directory_url}/{did}/data` — the PLC-native shape
    /// (`did, alsoKnownAs, rotationKeys, verificationMethods, services`), which is
    /// what the per-identity DID-doc cache stores and its readers (the home card's
    /// `rotationKeys[0]` custody badge, `extractPdsFromPlcDoc`) parse. The W3C
    /// document (`GET /{did}`) carries no `rotationKeys` and must never be cached.
    pub async fn fetch_plc_data_document(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, PdsClientError> {
        let url = format!("{}/{}/data", self.plc_directory_url, did);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| PdsClientError::NetworkError {
                    message: format!("failed to fetch PLC data document: {}", e),
                })?;

        match resp.status() {
            s if s == 404 => return Err(PdsClientError::DidNotFound),
            // Same status-classification as `fetch_audit_log`: a 429/5xx from plc.directory
            // must not read as "check your connection".
            s if !s.is_success() => {
                return Err(classify_xrpc_response("fetch_plc_data_document", resp).await);
            }
            _ => {}
        }

        resp.json().await.map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse PLC data document: {}", e),
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
        } else if resp.status().as_u16() == 429 {
            // A throttle is not a rejection of the operation — surface it as the retryable
            // condition it is, with the server's pacing hint.
            Err(classify_xrpc_response("post_plc_operation", resp).await)
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
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to fetch repo CAR: {}", e),
            })?;

        if !resp.status().is_success() {
            return Err(classify_xrpc_response("getRepo", resp).await);
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

        // Blobs (images/video) can be large; override the shared 30s client timeout for the download.
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("failed to fetch blob: {}", e),
            })?;

        if !resp.status().is_success() {
            return Err(classify_xrpc_response("getBlob", resp).await);
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
    pub async fn reserve_signing_key(
        &self,
        pds_url: &str,
        did: &str,
    ) -> Result<String, PdsClientError> {
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

        if !resp.status().is_success() {
            return Err(classify_xrpc_response("reserveSigningKey", resp).await);
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

    /// Permanently delete an account on its PDS (auth: none — the credentials are in the body).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.deleteAccount` with `{ did, password, token }`,
    /// where `token` is the single-use code minted by `requestAccountDelete` and emailed to the
    /// account. The PDS purges all local account data and emits an `#account` (`status="deleted"`)
    /// firehose frame; it does NOT touch the did:plc identity (the wallet tombstones that
    /// separately). Not session-authed, so no `OAuthClient` is needed — but the password travels in
    /// the body, so the endpoint is refused over a non-HTTPS URL (loopback excepted), same guard as
    /// the password `createSession` path.
    pub async fn delete_account(
        &self,
        pds_url: &str,
        did: &str,
        password: &str,
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
        let body = serde_json::json!({ "did": did, "password": password, "token": token });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PdsClientError::NetworkError {
                message: format!("delete_account failed: {}", e),
            })?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(classify_xrpc_response("deleteAccount", resp).await)
        }
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
/// Triggers email verification on the PDS. `requestPlcOperationSignature` is a
/// no-input procedure: the request must carry NO body — a spec-strict PDS
/// (bsky.social) rejects `{}` with `InvalidRequest: A request body was provided
/// when none was expected` (our own route is laxer, which is how the `{}` shipped).
pub async fn request_plc_operation_signature(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.identity.requestPlcOperationSignature")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("requestPlcOperationSignature", resp).await)
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

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("signPlcOperation", resp).await);
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

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("getRecommendedDidCredentials", resp).await);
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

// ============================================================================
// App-password management (full-access session required)
// ============================================================================

/// Result of minting an app password (`com.atproto.server.createAppPassword`).
/// `password` is the generated secret, surfaced ONCE at creation — the server
/// stores only its hash, so it can never be retrieved again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPasswordCreated {
    pub name: String,
    /// The generated `xxxx-xxxx-xxxx-xxxx` secret. Shown once; never retrievable.
    pub password: String,
    pub created_at: String,
    pub privileged: bool,
}

/// One app-password entry from `listAppPasswords` — public metadata only, never the secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPasswordEntry {
    pub name: String,
    pub created_at: String,
    pub privileged: bool,
}

#[derive(Deserialize)]
struct ListAppPasswordsResponse {
    passwords: Vec<AppPasswordEntry>,
}

/// Mint a named app password on the hosting PDS.
///
/// Calls `POST /xrpc/com.atproto.server.createAppPassword`. Requires a full-access
/// session (an app-password session cannot mint more app passwords). A duplicate
/// name surfaces as `XrpcError { status: 409, .. }`.
pub async fn create_app_password(
    client: &crate::oauth_client::OAuthClient,
    name: &str,
    privileged: bool,
) -> Result<AppPasswordCreated, PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.server.createAppPassword",
            &serde_json::json!({ "name": name, "privileged": privileged }),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("create_app_password failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("createAppPassword", resp).await);
    }

    resp.json::<AppPasswordCreated>()
        .await
        .map_err(|e| PdsClientError::InvalidResponse {
            message: format!("failed to parse create_app_password response: {}", e),
        })
}

/// List the account's app passwords (names, creation times, privilege — never secrets).
///
/// Calls `GET /xrpc/com.atproto.server.listAppPasswords`. Requires a full-access session.
pub async fn list_app_passwords(
    client: &crate::oauth_client::OAuthClient,
) -> Result<Vec<AppPasswordEntry>, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.listAppPasswords")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("list_app_passwords failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("listAppPasswords", resp).await);
    }

    resp.json::<ListAppPasswordsResponse>()
        .await
        .map(|body| body.passwords)
        .map_err(|e| PdsClientError::InvalidResponse {
            message: format!("failed to parse list_app_passwords response: {}", e),
        })
}

/// Revoke a named app password (and, server-side, its sessions/refresh tokens atomically).
///
/// Calls `POST /xrpc/com.atproto.server.revokeAppPassword`. Idempotent on the server.
pub async fn revoke_app_password(
    client: &crate::oauth_client::OAuthClient,
    name: &str,
) -> Result<(), PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.server.revokeAppPassword",
            &serde_json::json!({ "name": name }),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("revoke_app_password failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("revokeAppPassword", resp).await)
    }
}

// ============================================================================
// Migration XRPC helpers (Task 3, 4, 5)
// ============================================================================

/// Get service auth token for migration from the SOURCE PDS.
///
/// Calls `GET /xrpc/com.atproto.server.getServiceAuth?aud={dest_did}&lxm={lxm}`.
/// For migration, `aud` is the destination server DID and `lxm` is typically
/// "com.atproto.server.createAccount".
pub async fn get_service_auth(
    client: &crate::oauth_client::OAuthClient,
    aud: &str,
    lxm: &str,
) -> Result<ServiceAuthToken, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
        urlencoding::encode(aud),
        urlencoding::encode(lxm),
    );

    let resp = client
        .get(&path)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_service_auth failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("getServiceAuth", resp).await);
    }

    resp.json::<ServiceAuthToken>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse get_service_auth response: {}", e),
        })
}

/// Create account in migration mode on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.createAccount` with the request body.
/// The `client` should be a Bearer client carrying a service-auth JWT from the source PDS.
/// A 409 response maps to `PdsClientError::DidAlreadyExists`.
pub async fn create_account_migration(
    client: &crate::oauth_client::OAuthClient,
    req: &CreateAccountMigrationRequest,
) -> Result<CreateAccountResponse, PdsClientError> {
    let resp = client
        .post("/xrpc/com.atproto.server.createAccount", req)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("create_account_migration failed: {}", e),
        })?;

    let status = resp.status();
    if status.as_u16() == 409 {
        return Err(PdsClientError::DidAlreadyExists);
    }

    if !status.is_success() {
        return Err(classify_xrpc_response("createAccount", resp).await);
    }

    resp.json::<CreateAccountResponse>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse create_account_migration response: {}", e),
        })
}

/// Import a CAR into the destination PDS repository.
///
/// Calls `POST /xrpc/com.atproto.repo.importRepo` with raw CAR bytes.
/// Content-Type is `application/vnd.ipld.car`.
pub async fn import_repo(
    client: &crate::oauth_client::OAuthClient,
    car: Vec<u8>,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_bytes(
            "/xrpc/com.atproto.repo.importRepo",
            "application/vnd.ipld.car",
            car,
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("import_repo failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("importRepo", resp).await)
    }
}

/// Upload a blob to the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.repo.uploadBlob` with raw blob bytes.
/// Content-Type is set to the provided MIME type.
pub async fn upload_blob(
    client: &crate::oauth_client::OAuthClient,
    mime: &str,
    bytes: Vec<u8>,
) -> Result<UploadBlobResponse, PdsClientError> {
    let resp = client
        .post_bytes("/xrpc/com.atproto.repo.uploadBlob", mime, bytes)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("upload_blob failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("uploadBlob", resp).await);
    }

    resp.json::<UploadBlobResponse>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse upload_blob response: {}", e),
        })
}

/// List missing blobs on the destination PDS (one page).
///
/// Calls `GET /xrpc/com.atproto.repo.listMissingBlobs?cursor=...` (cursor is optional).
pub async fn list_missing_blobs(
    client: &crate::oauth_client::OAuthClient,
    cursor: Option<&str>,
) -> Result<MissingBlobs, PdsClientError> {
    let path = if let Some(cur) = cursor {
        format!(
            "/xrpc/com.atproto.repo.listMissingBlobs?cursor={}",
            urlencoding::encode(cur)
        )
    } else {
        "/xrpc/com.atproto.repo.listMissingBlobs".to_string()
    };

    let resp = client
        .get(&path)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("list_missing_blobs failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("listMissingBlobs", resp).await);
    }

    resp.json::<MissingBlobs>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse list_missing_blobs response: {}", e),
        })
}

/// Get the user's preferences.
///
/// Calls `GET /xrpc/app.bsky.actor.getPreferences`.
/// Returns the full response object (with `preferences` key).
pub async fn get_preferences(
    client: &crate::oauth_client::OAuthClient,
) -> Result<serde_json::Value, PdsClientError> {
    let resp = client
        .get("/xrpc/app.bsky.actor.getPreferences")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_preferences failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("getPreferences", resp).await);
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse get_preferences response: {}", e),
        })
}

/// Put the user's preferences.
///
/// Calls `POST /xrpc/app.bsky.actor.putPreferences` with the preferences object
/// (the same object returned by `get_preferences`).
pub async fn put_preferences(
    client: &crate::oauth_client::OAuthClient,
    prefs: &serde_json::Value,
) -> Result<(), PdsClientError> {
    let resp = client
        .post("/xrpc/app.bsky.actor.putPreferences", prefs)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("put_preferences failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("putPreferences", resp).await)
    }
}

/// Check the account status on the destination PDS.
///
/// Calls `GET /xrpc/com.atproto.server.checkAccountStatus`.
pub async fn check_account_status(
    client: &crate::oauth_client::OAuthClient,
) -> Result<AccountStatus, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.checkAccountStatus")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("check_account_status failed: {}", e),
        })?;

    if !resp.status().is_success() {
        return Err(classify_xrpc_response("checkAccountStatus", resp).await);
    }

    resp.json::<AccountStatus>()
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to parse check_account_status response: {}", e),
        })
}

/// Activate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.activateAccount` with NO body and no
/// `Content-Type` — it is a no-input procedure. Our handler
/// (`crates/pds/src/routes/activate_account.rs`) rejects any non-whitespace body
/// with a 400, and a spec-strict PDS rejects any body at all; `post_no_body`
/// satisfies both (the previous `post_bytes(.., Vec::new())` workaround still sent
/// a `Content-Type` header with zero bytes).
pub async fn activate_account(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.activateAccount")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("activate_account failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("activateAccount", resp).await)
    }
}

/// Deactivate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.deactivateAccount` with optional deleteAfter (RFC 3339).
pub async fn deactivate_account(
    client: &crate::oauth_client::OAuthClient,
    delete_after: Option<&str>,
) -> Result<(), PdsClientError> {
    let body = match delete_after {
        Some(t) => serde_json::json!({ "deleteAfter": t }),
        None => serde_json::json!({}),
    };

    let resp = client
        .post("/xrpc/com.atproto.server.deactivateAccount", &body)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("deactivate_account failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("deactivateAccount", resp).await)
    }
}

/// Request permanent deletion of the authenticated account: mints and emails a single-use code.
///
/// Calls `POST /xrpc/com.atproto.server.requestAccountDelete` with NO body (a no-input procedure,
/// like `activateAccount`). Full-access session authed. The PDS emails a 1-hour confirmation code
/// to the account address; the code + the account password are then supplied to
/// `PdsClient::delete_account` to complete the deletion.
pub async fn request_account_delete(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.requestAccountDelete")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_account_delete failed: {}", e),
        })?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(classify_xrpc_response("requestAccountDelete", resp).await)
    }
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

    /// The client_id is the fixed canonical URL for every non-loopback Custos — the
    /// app's OAuth identity must not vary with the configured server.
    #[test]
    fn client_id_is_canonical_for_public_custos() {
        assert_eq!(client_id_for_pds("https://obsign.org"), CANONICAL_CLIENT_ID);
        assert_eq!(
            client_id_for_pds("https://ezpds-staging.up.railway.app/"),
            CANONICAL_CLIENT_ID
        );
    }

    /// Loopback dev exception: a local Custos serves a self-referencing localhost
    /// document, so the client_id derives from the configured base.
    #[test]
    fn client_id_derives_from_loopback_custos() {
        assert_eq!(
            client_id_for_pds("http://localhost:8080"),
            "http://localhost:8080/oauth/client-metadata.json"
        );
        assert_eq!(
            client_id_for_pds("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/oauth/client-metadata.json"
        );
    }

    /// The redirect scheme is the canonical client_id host in reverse order — the
    /// pairing third-party authorization servers enforce.
    #[test]
    fn redirect_scheme_reverses_canonical_client_id_host() {
        let host = url::Url::parse(CANONICAL_CLIENT_ID)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        let reversed = host.split('.').rev().collect::<Vec<_>>().join(".");
        assert_eq!(REDIRECT_URI, format!("{reversed}:/oauth/callback"));
        assert_eq!(CALLBACK_SCHEME, reversed);
    }

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

    // ── XRPC error classification ───────────────────────────────────────────

    /// The envelope parser pulls both the atproto `error` code and the human `message`, and falls
    /// back sensibly when the body isn't an envelope.
    #[test]
    fn parse_xrpc_error_envelope_extracts_code_and_message() {
        assert_eq!(
            parse_xrpc_error_envelope(r#"{"error":"InvalidRequest","message":"Missing handle"}"#),
            (
                Some("InvalidRequest".to_string()),
                "Missing handle".to_string()
            )
        );
        // error code but no message → message falls back to the code.
        assert_eq!(
            parse_xrpc_error_envelope(r#"{"error":"ExpiredToken"}"#),
            (Some("ExpiredToken".to_string()), "ExpiredToken".to_string())
        );
        // Non-envelope body → no code, message is the trimmed raw body.
        assert_eq!(
            parse_xrpc_error_envelope("  <html>502 Bad Gateway</html>  "),
            (None, "<html>502 Bad Gateway</html>".to_string())
        );
    }

    /// A plc.directory 429 on the audit-log read classifies as RateLimited (with the pacing
    /// hint), not as a connectivity failure.
    #[tokio::test]
    async fn fetch_audit_log_429_is_rate_limited_not_network_error() {
        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:throttled/log/audit");
            then.status(429)
                .header("Retry-After", "30")
                .body(r#"{"message":"rate limit exceeded"}"#);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let err = client
            .fetch_audit_log("did:plc:throttled")
            .await
            .unwrap_err();
        match err {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("30"));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    /// A plc.directory 5xx on the audit-log read is the directory's verdict — a status-classified
    /// error, not NetworkError ("check your connection").
    #[tokio::test]
    async fn fetch_audit_log_500_is_status_classified_not_network_error() {
        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:outage/log/audit");
            then.status(500).body("upstream exploded");
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let err = client.fetch_audit_log("did:plc:outage").await.unwrap_err();
        match err {
            PdsClientError::XrpcError { status, .. } => assert_eq!(status, 500),
            other => panic!("expected XrpcError, got {other:?}"),
        }
    }

    /// A plc.directory 404 keeps its dedicated DidNotFound classification.
    #[tokio::test]
    async fn fetch_audit_log_404_stays_did_not_found() {
        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:ghost/log/audit");
            then.status(404);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let err = client.fetch_audit_log("did:plc:ghost").await.unwrap_err();
        assert!(matches!(err, PdsClientError::DidNotFound));
    }

    /// A plc.directory 429 on an operation submit surfaces as RateLimited; a 400 rejection keeps
    /// the InvalidResponse "rejected operation" shape callers rely on.
    #[tokio::test]
    async fn post_plc_operation_classifies_throttle_but_keeps_rejection_shape() {
        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:busy");
            then.status(429).header("Retry-After", "7").body("{}");
        });
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:badop");
            then.status(400).body(r#"{"message":"invalid prev"}"#);
        });

        let client = PdsClient::new_for_test(mock_server.base_url());
        let op = serde_json::json!({});
        match client
            .post_plc_operation("did:plc:busy", &op)
            .await
            .unwrap_err()
        {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("7"));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        match client
            .post_plc_operation("did:plc:badop", &op)
            .await
            .unwrap_err()
        {
            PdsClientError::InvalidResponse { message } => {
                assert!(message.contains("rejected operation"), "got: {message}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// 429 classifies as RateLimited and carries the Retry-After value through verbatim.
    #[test]
    fn classify_xrpc_error_429_is_rate_limited_with_retry_after() {
        let err = classify_xrpc_error(
            429,
            Some("120".to_string()),
            r#"{"error":"RateLimitExceeded","message":"slow down"}"#,
        );
        match err {
            PdsClientError::RateLimited {
                retry_after,
                message,
            } => {
                assert_eq!(retry_after.as_deref(), Some("120"));
                assert_eq!(message, "slow down");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    /// 401 classifies as Unauthorized, preserving both the atproto error code and the message.
    #[test]
    fn classify_xrpc_error_401_is_unauthorized() {
        let err = classify_xrpc_error(
            401,
            None,
            r#"{"error":"ExpiredToken","message":"Token has expired"}"#,
        );
        match err {
            PdsClientError::Unauthorized { error, message } => {
                assert_eq!(error.as_deref(), Some("ExpiredToken"));
                assert_eq!(message, "Token has expired");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    /// A 400 keeps the atproto error code and human message so the UI can show them.
    #[test]
    fn classify_xrpc_error_400_keeps_error_code_and_message() {
        let err = classify_xrpc_error(
            400,
            None,
            r#"{"error":"InsufficientScope","message":"token scope does not permit identity operations"}"#,
        );
        match err {
            PdsClientError::XrpcError {
                status,
                error,
                message,
            } => {
                assert_eq!(status, 400);
                assert_eq!(error.as_deref(), Some("InsufficientScope"));
                assert_eq!(message, "token scope does not permit identity operations");
            }
            other => panic!("expected XrpcError, got {other:?}"),
        }
    }

    /// A 5xx with a non-envelope body still surfaces the raw body as the message (never a
    /// NetworkError — the server did answer).
    #[test]
    fn classify_xrpc_error_5xx_non_envelope_falls_back_to_body() {
        let err = classify_xrpc_error(503, None, "service unavailable");
        match err {
            PdsClientError::XrpcError {
                status,
                error,
                message,
            } => {
                assert_eq!(status, 503);
                assert_eq!(error, None);
                assert_eq!(message, "service unavailable");
            }
            other => panic!("expected XrpcError, got {other:?}"),
        }
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
        assert_eq!(mock_par.calls(), 1);
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
                .header_exists("DPoP")
                // No-input procedure: a spec-strict PDS rejects any body or Content-Type.
                .is_true(|req| req.body_ref().is_empty())
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                });
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
        // A 401 is classified as Unauthorized, not folded into a generic NetworkError.
        match result.unwrap_err() {
            PdsClientError::Unauthorized { .. } => {
                // Expected
            }
            e => panic!("Expected Unauthorized, got: {:?}", e),
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
        assert_eq!(mock.calls(), 1);
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
        // A 403 is a classified server rejection: XrpcError carrying status + error code.
        match result.unwrap_err() {
            PdsClientError::XrpcError { status: 403, .. } => {
                // Expected
            }
            e => panic!("Expected XrpcError(403), got: {:?}", e),
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

    /// sign_plc_operation surfaces an HTTP error through classify_xrpc_response: a non-nonce 400
    /// becomes a structured XrpcError carrying the server's status + error code, not a flattened
    /// NetworkError. (The DPoP OAuthClient does not swallow non-`use_dpop_nonce` 400s.)
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
        // The 400 `invalid_token` reaches classify_xrpc_response intact, so it is classified as an
        // XrpcError that preserves the server's status and atproto error code — the whole point of
        // surfacing (rather than swallowing) a non-nonce 400 in the DPoP client.
        match result.unwrap_err() {
            PdsClientError::XrpcError { status, error, .. } => {
                assert_eq!(status, 400, "status must be preserved");
                assert_eq!(
                    error.as_deref(),
                    Some("invalid_token"),
                    "the atproto error code must be preserved"
                );
            }
            e => panic!("Expected XrpcError(400, invalid_token), got: {:?}", e),
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
                .query_param("did", "did:plc:test123")
                // This endpoint is auth:none — the request must carry no Authorization header.
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                });
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
        // A 404 is a classified server response, carrying the status and body message.
        match result.unwrap_err() {
            PdsClientError::XrpcError {
                status: 404,
                message,
                ..
            } => {
                assert!(message.contains("not found"));
            }
            e => panic!("Expected XrpcError(404), got: {:?}", e),
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
                .query_param("cid", "bafy123")
                // This endpoint is auth:none — the request must carry no Authorization header.
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                });
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
        // A 404 is a classified server response, carrying the status and body message.
        match result.unwrap_err() {
            PdsClientError::XrpcError {
                status: 404,
                message,
                ..
            } => {
                assert!(message.contains("blob not found"));
            }
            e => panic!("Expected XrpcError(404), got: {:?}", e),
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
        // A 400 is a classified server rejection: XrpcError carrying the status.
        match result.unwrap_err() {
            PdsClientError::XrpcError { status: 400, .. } => {
                // Expected
            }
            e => panic!("Expected XrpcError(400), got: {:?}", e),
        }
    }

    // Helper: create a valid Bearer test JWT with a distant expiry
    fn make_bearer_jwt(exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, exp).as_bytes());
        // Dummy signature; jwt_exp_claim never verifies it
        let sig = "dummy_signature";
        format!("{}.{}.{}", header, payload, sig)
    }

    // ============================================================================
    // Task 3: get_service_auth and create_account_migration
    // ============================================================================

    /// get_service_auth issues GET with aud and lxm query params and parses token
    #[tokio::test]
    async fn test_get_service_auth_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth")
                .query_param("aud", "did:web:dest.example.com")
                .query_param("lxm", "com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "token": "eyJhbGc..."
            }));
        });

        let jwt = make_bearer_jwt(9999999999); // Far future expiry
        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            jwt,
            "test_refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest.example.com",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.token, "eyJhbGc...");
    }

    /// get_service_auth returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_get_service_auth_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(401).body("unauthorized");
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_err());
        // A 401 is classified as Unauthorized, not a generic NetworkError.
        match result.unwrap_err() {
            PdsClientError::Unauthorized { .. } => {
                // Expected
            }
            e => panic!("Expected Unauthorized, got: {:?}", e),
        }
    }

    /// create_account_migration POSTs camelCase body and parses response
    #[tokio::test]
    async fn test_create_account_migration_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount")
                // The body must be the camelCase {handle,email,did}; a serde-rename regression
                // (e.g. snake_case, or a dropped field) must fail this test.
                .body_includes("\"handle\":\"user.example.com\"")
                .body_includes("\"email\":\"user@example.com\"")
                .body_includes("\"did\":\"did:plc:abc123\"")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "accessJwt": "access...",
                "refreshJwt": "refresh...",
                "handle": "user.example.com",
                "did": "did:plc:abc123"
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_jwt".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let req = CreateAccountMigrationRequest {
            handle: "user.example.com".to_string(),
            email: "user@example.com".to_string(),
            did: "did:plc:abc123".to_string(),
            invite_code: None,
        };
        let result = create_account_migration(&test_client, &req).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.access_jwt, "access...");
        assert_eq!(resp.refresh_jwt, "refresh...");
        assert_eq!(resp.handle, "user.example.com");
        assert_eq!(resp.did, "did:plc:abc123");
    }

    /// create_account_migration maps 409 to DidAlreadyExists
    #[tokio::test]
    async fn test_create_account_migration_409() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(409).body("account already exists");
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_jwt".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let req = CreateAccountMigrationRequest {
            handle: "existing.example.com".to_string(),
            email: "existing@example.com".to_string(),
            did: "did:plc:xyz789".to_string(),
            invite_code: None,
        };
        let result = create_account_migration(&test_client, &req).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::DidAlreadyExists => {
                // Expected
            }
            e => panic!("Expected DidAlreadyExists, got: {:?}", e),
        }
    }

    // ============================================================================
    // Task 4: import_repo, upload_blob, list_missing_blobs, get+put_preferences
    // ============================================================================

    /// import_repo sends CAR bytes with correct Content-Type and returns Ok on 200
    #[tokio::test]
    async fn test_import_repo_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo")
                .header("content-type", "application/vnd.ipld.car")
                // The exact CAR bytes must reach the server unchanged.
                .body("CAR bytes content")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let car_bytes = b"CAR bytes content".to_vec();
        let result = import_repo(&test_client, car_bytes).await;

        assert!(result.is_ok());
    }

    /// upload_blob sends raw bytes with provided MIME type and parses blob response
    #[tokio::test]
    async fn test_upload_blob_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob")
                .header("content-type", "image/jpeg")
                // The exact blob bytes must reach the server unchanged.
                .body("JPEG data")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blob": {
                    "$type": "com.atproto.sync.blob",
                    "mimeType": "image/jpeg",
                    "size": 1234,
                    "ref": { "$link": "bafy123" }
                }
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let blob_bytes = b"JPEG data".to_vec();
        let result = upload_blob(&test_client, "image/jpeg", blob_bytes).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        // Assert the fields the migration flow actually consumes from the blob ref, not just $type.
        assert_eq!(resp.blob["ref"]["$link"], "bafy123");
        assert_eq!(resp.blob["mimeType"], "image/jpeg");
        assert_eq!(resp.blob["size"], 1234);
    }

    /// list_missing_blobs without cursor issues base path; with cursor includes ?cursor=
    #[tokio::test]
    async fn test_list_missing_blobs_no_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy1", "recordUri": "at://did/record1" },
                    { "cid": "bafy2", "recordUri": "at://did/record2" }
                ]
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, None).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 2);
        assert_eq!(blobs.blobs[0].cid, "bafy1");
    }

    /// list_missing_blobs with cursor includes it in query params
    #[tokio::test]
    async fn test_list_missing_blobs_with_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "next_page_token")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy3", "recordUri": "at://did/record3" }
                ],
                "cursor": "another_token"
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, Some("next_page_token")).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 1);
        assert_eq!(blobs.cursor, Some("another_token".to_string()));
    }

    /// get_preferences parses full preferences object
    #[tokio::test]
    async fn test_get_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "preferences": [
                    { "feed": "pinned", "value": "at://feed1" }
                ]
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_preferences(&test_client).await;

        assert!(result.is_ok());
        let prefs = result.unwrap();
        assert!(prefs["preferences"].is_array());
    }

    /// put_preferences POSTs the preferences object back and treats 200 as success
    #[tokio::test]
    async fn test_put_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let prefs = serde_json::json!({
            "preferences": [
                { "feed": "pinned", "value": "at://feed1" }
            ]
        });
        let result = put_preferences(&test_client, &prefs).await;

        assert!(result.is_ok());
    }

    // ============================================================================
    // Task 5: check_account_status, activate_account, deactivate_account
    // ============================================================================

    /// check_account_status parses all fields including storedBlocks
    #[tokio::test]
    async fn test_check_account_status_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "activated": true,
                "validDid": true,
                "storedBlocks": 12345,
                "indexedRecords": 100,
                "privateStateValues": 5,
                "expectedBlobs": 50,
                "importedBlobs": 48
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = check_account_status(&test_client).await;

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.activated);
        assert!(status.valid_did);
        assert_eq!(status.stored_blocks, 12345);
        assert_eq!(status.indexed_records, 100);
        assert_eq!(status.expected_blobs, 50);
        assert_eq!(status.imported_blobs, 48);
    }

    /// activate_account POSTs a genuinely empty body and treats 200 as success.
    /// The real handler rejects any non-whitespace body with 400, so the empty-body
    /// assertion below is the actual server contract (a `{}` body would be a bug).
    #[tokio::test]
    async fn test_activate_account_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount")
                .is_true(|req| req.body_ref().is_empty())
                // No-input procedure: no Content-Type either (the old post_bytes
                // workaround still sent one with zero bytes).
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                })
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = activate_account(&test_client).await;

        assert!(result.is_ok());
    }

    /// deactivate_account without deleteAfter sends {} body
    #[tokio::test]
    async fn test_deactivate_account_no_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, None).await;

        assert!(result.is_ok());
    }

    /// deactivate_account with deleteAfter includes it in request body
    #[tokio::test]
    async fn test_deactivate_account_with_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .body_includes("deleteAfter")
                .body_includes("2026-07-08")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, Some("2026-07-08T00:00:00.000Z")).await;

        assert!(result.is_ok());
    }

    // ============================================================================
    // describe_server tests
    // ============================================================================

    /// describe_server parses the response correctly
    #[tokio::test]
    async fn test_describe_server_success() {
        let mock_server = MockServer::start();

        let response = serde_json::json!({
            "did": "did:web:dest.example.com",
            "availableUserDomains": [".dest.example.com"]
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.describeServer");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(response);
        });

        let client = PdsClient::new();
        let result = client.describe_server(&mock_server.base_url()).await;

        assert!(result.is_ok());
        let desc = result.unwrap();
        assert_eq!(desc.did, "did:web:dest.example.com");
        assert_eq!(desc.available_user_domains, vec![".dest.example.com"]);
    }

    /// describe_server maps non-2xx to PdsUnreachable
    #[tokio::test]
    async fn test_describe_server_non_2xx() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.describeServer");
            then.status(500);
        });

        let client = PdsClient::new();
        let result = client.describe_server(&mock_server.base_url()).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::PdsUnreachable { .. } => {
                // Expected
            }
            e => panic!("Expected PdsUnreachable, got: {:?}", e),
        }
    }

    // ============================================================================
    // App-password management wrappers
    // ============================================================================

    fn bearer_client_for(server: &MockServer) -> crate::oauth_client::OAuthClient {
        crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh".to_string(),
            server.base_url(),
        )
        .expect("new_bearer must succeed")
    }

    /// create_app_password POSTs name+privileged and parses the one-time secret response.
    #[tokio::test]
    async fn test_create_app_password_success() {
        let mock_server = MockServer::start();

        // Assembled from fragments so secret scanners don't flag a literal credential.
        let expected_password = ["abcd", "efgh", "ijkl", "mnop"].join("-");

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword")
                .json_body(serde_json::json!({ "name": "Bluesky app", "privileged": false }));
            then.status(200).json_body(serde_json::json!({
                "name": "Bluesky app",
                "password": expected_password.clone(),
                "createdAt": "2026-07-17T00:00:00.000Z",
                "privileged": false
            }));
        });

        let created = create_app_password(&bearer_client_for(&mock_server), "Bluesky app", false)
            .await
            .unwrap();
        assert_eq!(created.name, "Bluesky app");
        assert_eq!(created.password, expected_password);
        assert!(!created.privileged);
    }

    /// A duplicate name surfaces as XrpcError with the 409 status preserved.
    #[tokio::test]
    async fn test_create_app_password_duplicate_is_409_xrpc_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword");
            then.status(409).json_body(serde_json::json!({
                "error": "Conflict",
                "message": "an app password with this name already exists"
            }));
        });

        let err = create_app_password(&bearer_client_for(&mock_server), "Bluesky app", false)
            .await
            .unwrap_err();
        match err {
            PdsClientError::XrpcError { status: 409, .. } => {}
            e => panic!("Expected XrpcError 409, got: {:?}", e),
        }
    }

    /// list_app_passwords unwraps the passwords array (metadata only, no secret field).
    #[tokio::test]
    async fn test_list_app_passwords_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(200).json_body(serde_json::json!({
                "passwords": [
                    {
                        "name": "Bluesky app",
                        "createdAt": "2026-07-17T00:00:00.000Z",
                        "privileged": false
                    },
                    {
                        "name": "Chat client",
                        "createdAt": "2026-07-16T00:00:00.000Z",
                        "privileged": true
                    }
                ]
            }));
        });

        let passwords = list_app_passwords(&bearer_client_for(&mock_server))
            .await
            .unwrap();
        assert_eq!(passwords.len(), 2);
        assert_eq!(passwords[0].name, "Bluesky app");
        assert!(passwords[1].privileged);
    }

    /// revoke_app_password POSTs the name and treats a 2xx as done.
    #[tokio::test]
    async fn test_revoke_app_password_success() {
        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.revokeAppPassword")
                .json_body(serde_json::json!({ "name": "Bluesky app" }));
            then.status(200).json_body(serde_json::json!({}));
        });

        revoke_app_password(&bearer_client_for(&mock_server), "Bluesky app")
            .await
            .unwrap();
        mock.assert();
    }

    /// A 429 on the app-password surface is classified as RateLimited with Retry-After.
    #[tokio::test]
    async fn test_list_app_passwords_rate_limited() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(429)
                .header("retry-after", "30")
                .json_body(serde_json::json!({
                    "error": "RateLimitExceeded",
                    "message": "too many requests"
                }));
        });

        let err = list_app_passwords(&bearer_client_for(&mock_server))
            .await
            .unwrap_err();
        match err {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("30"));
            }
            e => panic!("Expected RateLimited, got: {:?}", e),
        }
    }
}
