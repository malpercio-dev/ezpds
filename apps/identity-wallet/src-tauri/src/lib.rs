pub mod claim;
pub mod device_key;
pub mod home;
pub mod http;
pub mod identity_store;
pub mod keychain;
pub mod oauth;
pub mod oauth_client;
pub mod pds_client;
pub mod plc_monitor;
pub mod recovery;

use crypto::{build_did_plc_genesis_op_with_external_signer, CryptoError, DidKeyUri};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_deep_link::DeepLinkExt;

// ── Request / response types ────────────────────────────────────────────────

/// JSON body sent to POST /v1/accounts/mobile.
/// Field names match the relay's camelCase deserialization.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountRequest {
    email: String,
    handle: String,
    device_public_key: String,
    platform: String,
    claim_code: String,
}

/// Successful 201 response from the relay.
///
/// The relay returns additional fields (account_id, device_id) which are
/// silently ignored by serde's default behavior. This struct captures only
/// the three fields needed by the client.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountResponse {
    device_token: String,
    session_token: String,
    next_step: NextStep,
}

/// Response from GET /v1/relay/keys — the relay's active signing key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelaySigningKey {
    key_id: String,
    #[allow(dead_code)]
    public_key: String,
    #[allow(dead_code)]
    algorithm: String,
}

/// Request body for POST /v1/dids — submit the signed genesis op for DID promotion.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidRequest {
    rotation_key_public: String,
    signed_creation_op: serde_json::Value,
    /// Initial password stored as an argon2id PHC string by the relay.
    password: String,
}

/// Response from POST /v1/dids — the promoted DID, upgraded session token, and Shamir shares.
#[derive(Deserialize)]
struct CreateDidResponse {
    did: String,
    session_token: String,
    /// Share 1 of 3 — to be stored in iCloud Keychain by the app.
    shamir_share_1: String,
    /// Share 3 of 3 — to be shown to the user for manual backup.
    shamir_share_3: String,
}

/// Relay error envelope: { "error": { "code": "...", "message": "..." } }
#[derive(Deserialize)]
struct RelayErrorEnvelope {
    error: RelayErrorBody,
}

#[derive(Deserialize)]
struct RelayErrorBody {
    code: String,
}

// ── IPC result / error types (returned to the frontend) ─────────────────────

/// The next step the client should take after successful account creation.
///
/// If the relay returns an unrecognized value, serde deserialization fails and
/// `create_account` returns `CreateAccountError::Unknown` — unrecognized relay
/// protocol values are caught here rather than silently forwarded to the frontend.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NextStep {
    DidCreation,
}

/// Successful result returned to the Svelte frontend.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResult {
    pub next_step: NextStep,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "EXPIRED_CODE" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreateAccountError {
    #[error("claim code has expired")]
    ExpiredCode,
    #[error("claim code already redeemed")]
    RedeemedCode,
    #[error("email already taken")]
    EmailTaken,
    #[error("handle already taken")]
    HandleTaken,
    #[error("keychain storage failed")]
    KeychainError,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

/// Successful result returned to the Svelte frontend after DID ceremony completes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDCeremonyResult {
    pub did: String,
    /// Share 3 of 3 — the user's manual backup share.
    /// Share 1 has already been stored in iCloud Keychain by the Rust backend.
    pub share3: String,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "NO_RELAY_SIGNING_KEY" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DIDCeremonyError {
    #[error("failed to get or create device key")]
    KeyNotFound,
    #[error("failed to fetch relay signing key")]
    RelayKeyFetchFailed,
    #[error("relay has no signing key provisioned")]
    NoRelaySigningKey,
    #[error("device signing failed")]
    SigningFailed,
    #[error("DID creation request failed")]
    DidCreationFailed,
    #[error("keychain operation failed")]
    KeychainError,
    /// DID was committed at the relay but Share 1 could not be stored in Keychain.
    /// The DID exists — retrying the ceremony will fail. The user can retry the share
    /// storage separately once the Keychain is available.
    #[error("DID created but recovery share storage failed")]
    ShareStorageFailed,
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Subset of `GET /xrpc/com.atproto.server.describeServer` used internally.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DescribeServerResponse {
    available_user_domains: Vec<String>,
}

/// Request body for `POST /v1/handles`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateHandleRequest {
    account_id: String,
    handle: String,
}

/// Success response from `POST /v1/handles`.
#[derive(Deserialize)]
struct CreateHandleRelayResponse {
    dns_status: String,
}

/// Successful result returned to the Svelte frontend after handle registration.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterHandleResult {
    /// Full handle including domain, e.g. `alice.ezpds.com`.
    pub handle: String,
    /// `"propagating"` when DNS creation was requested; `"not_configured"` when no DNS provider
    /// is configured on the relay (handle still resolves via HTTP well-known).
    pub dns_status: String,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegisterHandleError {
    #[error("handle is already taken")]
    HandleTaken,
    #[error("handle format is invalid")]
    InvalidHandle,
    #[error("DNS record creation failed")]
    DnsError,
    #[error("keychain operation failed")]
    KeychainError,
    /// The relay rejected the session token (401). The token is expired or revoked — the user
    /// must re-authenticate via OAuth rather than restart the app.
    #[error("session token expired or revoked")]
    SessionExpired,
    #[error("relay has no user domains configured")]
    NoDomains,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

/// Error returned by relay URL configuration commands.
///
/// Serializes as `{ "code": "INVALID_URL" | "UNREACHABLE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelayConfigError {
    #[error("invalid relay URL: must be http or https with a non-empty host")]
    InvalidUrl,
    #[error("relay is unreachable or did not return a success response")]
    Unreachable,
    #[error("failed to save relay URL to device storage")]
    KeychainError,
}

/// Response shape from `GET /xrpc/com.atproto.identity.resolveHandle`.
#[derive(Deserialize)]
struct ResolveHandleResponse {
    did: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Map a relay 409 error subcode string to a typed `CreateAccountError` variant.
fn map_409_subcode(code: &str) -> CreateAccountError {
    match code {
        "CLAIM_CODE_REDEEMED" => CreateAccountError::RedeemedCode,
        "ACCOUNT_EXISTS" => CreateAccountError::EmailTaken,
        "HANDLE_TAKEN" => CreateAccountError::HandleTaken,
        other => CreateAccountError::Unknown {
            message: format!("409: {other}"),
        },
    }
}

/// Validate a relay URL: must parse as http or https with a non-empty host.
/// Strips any trailing slash and returns the normalized URL string.
fn normalize_relay_url(url: &str) -> Result<String, RelayConfigError> {
    let parsed = url::Url::parse(url).map_err(|_| RelayConfigError::InvalidUrl)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(RelayConfigError::InvalidUrl),
    }
    if parsed.host().is_none() {
        return Err(RelayConfigError::InvalidUrl);
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(RelayConfigError::InvalidUrl);
    }
    Ok(url.trim_end_matches('/').to_string())
}

// ── IPC command ─────────────────────────────────────────────────────────────

#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<CreateAccountResult, CreateAccountError> {
    // 1. Get or create the device's SE-backed (or simulator-fallback) P-256 key.
    let device_key = device_key::get_or_create().map_err(|e| {
        tracing::warn!(error = %e, "device key creation failed during account creation");
        CreateAccountError::KeychainError
    })?;

    // 2. POST to relay.
    let req = CreateMobileAccountRequest {
        email,
        handle,
        device_public_key: device_key.multibase,
        platform: "ios".to_string(),
        claim_code,
    };

    let resp = state
        .relay_client()
        .post("/v1/accounts/mobile", &req)
        .await
        .map_err(|e| CreateAccountError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();

    if status.is_success() {
        // 3. Deserialize success body.
        let body: CreateMobileAccountResponse =
            resp.json().await.map_err(|e| CreateAccountError::Unknown {
                message: e.to_string(),
            })?;

        // 4. Store tokens in Keychain.
        // If session-token write fails, best-effort remove the already-written device-token.
        // The device key is persistent by design and is NOT cleaned up on failure.
        keychain::store_item("device-token", body.device_token.as_bytes()).map_err(|_| {
            // device-token write failed — nothing to clean up; the device key is persistent by design.
            CreateAccountError::KeychainError
        })?;

        keychain::store_item("session-token", body.session_token.as_bytes()).map_err(|_| {
            // Best-effort cleanup: remove the already-written device-token.
            let _ = keychain::delete_item("device-token");
            CreateAccountError::KeychainError
        })?;

        Ok(CreateAccountResult {
            next_step: body.next_step,
        })
    } else {
        // 5. Map relay error codes to typed variants.
        match status.as_u16() {
            // 404: Relay returns this for both invalid (never-existed) and expired claim codes.
            // The frontend cannot distinguish them, so we map both to ExpiredCode.
            404 => Err(CreateAccountError::ExpiredCode),
            409 => {
                let envelope: RelayErrorEnvelope =
                    resp.json().await.map_err(|e| CreateAccountError::Unknown {
                        message: e.to_string(),
                    })?;
                Err(map_409_subcode(&envelope.error.code))
            }
            _ => Err(CreateAccountError::NetworkError {
                message: format!("HTTP {}", status.as_u16()),
            }),
        }
    }
}

#[tauri::command]
async fn get_or_create_device_key(
) -> Result<device_key::DevicePublicKey, device_key::DeviceKeyError> {
    device_key::get_or_create()
}

#[tauri::command]
async fn sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, device_key::DeviceKeyError> {
    device_key::sign(&data)
}

#[tauri::command]
async fn perform_did_ceremony(
    handle: String,
    password: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    // Step 1: Get or create the device's P-256 key (serves as rotation key).
    let device_key = device_key::get_or_create().map_err(|e| {
        tracing::warn!(error = %e, "device key creation failed during DID ceremony");
        DIDCeremonyError::KeyNotFound
    })?;

    // Step 2: Fetch the relay's active signing key (public, no auth required).
    let resp = state
        .relay_client()
        .get("/v1/relay/keys")
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();
    if status.as_u16() == 503 {
        return Err(DIDCeremonyError::NoRelaySigningKey);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to read GET /v1/relay/keys error body");
            "<body read failed>".to_string()
        });
        tracing::error!(status = %status, body = %body, "GET /v1/relay/keys returned non-success status");
        return Err(DIDCeremonyError::RelayKeyFetchFailed);
    }

    let relay_key: RelaySigningKey = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize relay signing key response");
        DIDCeremonyError::RelayKeyFetchFailed
    })?;

    // Step 3: Build signed genesis op — device key as rotation key, relay key as signing key.
    // On device, the private key never leaves the Secure Enclave; on Simulator and macOS, a software key is used instead.
    let rotation_key = DidKeyUri(device_key.key_id.clone());
    let signing_key = DidKeyUri(relay_key.key_id.clone());

    let genesis_op = build_did_plc_genesis_op_with_external_signer(
        &rotation_key,
        &signing_key,
        &handle,
        state.relay_client().base_url_str(),
        |data| {
            device_key::sign(data)
                .map_err(|e| CryptoError::PlcOperation(format!("device signing failed: {e}")))
        },
    )
    .map_err(|e| {
        tracing::error!(error = %e, "genesis op signing failed during DID ceremony");
        DIDCeremonyError::SigningFailed
    })?;

    // Step 4: Retrieve the pending session token from Keychain.
    let token_bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "failed to retrieve session-token from keychain");
        DIDCeremonyError::KeychainError
    })?;
    let pending_token = String::from_utf8(token_bytes).map_err(|e| {
        tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
        DIDCeremonyError::KeychainError
    })?;

    // Step 5: POST the signed genesis op to the relay to promote the account to a full DID.
    let create_did_req = CreateDidRequest {
        rotation_key_public: device_key.key_id,
        signed_creation_op: serde_json::from_str(&genesis_op.signed_op_json).map_err(|e| {
            tracing::error!(error = %e, "genesis op JSON is not valid JSON");
            DIDCeremonyError::SigningFailed
        })?,
        password,
    };

    let resp = state
        .relay_client()
        .post_with_bearer("/v1/dids", &create_did_req, &pending_token)
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to read POST /v1/dids error body");
            "<body read failed>".to_string()
        });
        tracing::error!(status = %status, body = %body, "POST /v1/dids returned non-success status");
        return Err(DIDCeremonyError::DidCreationFailed);
    }

    let create_did_resp: CreateDidResponse = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize POST /v1/dids response");
        DIDCeremonyError::DidCreationFailed
    })?;

    // Step 6: Overwrite session-token with the upgraded full session token.
    keychain::store_item("session-token", create_did_resp.session_token.as_bytes()).map_err(
        |e| {
            tracing::error!(error = %e, "failed to persist upgraded session-token to keychain");
            DIDCeremonyError::KeychainError
        },
    )?;

    // Step 7: Persist the DID for use in subsequent app sessions.
    keychain::store_item("did", create_did_resp.did.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, did = %create_did_resp.did, "failed to persist DID to keychain");
        DIDCeremonyError::KeychainError
    })?;

    // Step 8: Store Share 1 in iCloud Keychain for automatic backup.
    // Uses ShareStorageFailed (not KeychainError) because the DID is already committed:
    // retrying the ceremony will hit DidAlreadyExists. The frontend can surface a distinct
    // message rather than telling the user to retry the whole ceremony.
    keychain::store_item(
        "recovery-share-1",
        create_did_resp.shamir_share_1.as_bytes(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "DID committed but recovery share 1 keychain write failed");
        DIDCeremonyError::ShareStorageFailed
    })?;

    Ok(DIDCeremonyResult {
        did: create_did_resp.did,
        share3: create_did_resp.shamir_share_3,
    })
}

/// Register the user's handle with the relay and set up HTTP resolution.
///
/// Fetches the relay's primary user domain via `GET /xrpc/com.atproto.server.describeServer`,
/// constructs the full handle (`{handle_label}.{domain}`), reads the DID and session token
/// from Keychain, then POSTs to `POST /v1/handles`.
///
/// Returns the full handle and DNS propagation status on success.
#[tauri::command]
async fn register_handle(
    handle_label: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<RegisterHandleResult, RegisterHandleError> {
    // Step 1: Fetch the relay's primary user domain.
    let resp = state
        .relay_client()
        .get("/xrpc/com.atproto.server.describeServer")
        .await
        .map_err(|e| RegisterHandleError::NetworkError {
            message: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(RegisterHandleError::NetworkError {
            message: format!("describeServer returned HTTP {}", resp.status().as_u16()),
        });
    }

    let server_info: DescribeServerResponse =
        resp.json()
            .await
            .map_err(|e| RegisterHandleError::Unknown {
                message: format!("failed to parse describeServer response: {e}"),
            })?;

    let domain = server_info
        .available_user_domains
        .into_iter()
        .next()
        .ok_or(RegisterHandleError::NoDomains)?;

    let full_handle = format!("{handle_label}.{domain}");

    // Step 2: Read DID and session token from Keychain.
    // Missing DID here is a post-ceremony invariant violation — error! is appropriate.
    let did_bytes = keychain::get_item("did").map_err(|e| {
        tracing::error!(error = %e, "DID not found in Keychain during handle registration — ceremony invariant violated");
        RegisterHandleError::KeychainError
    })?;
    let did = String::from_utf8(did_bytes).map_err(|e| {
        tracing::error!(error = %e, "DID bytes are not valid UTF-8");
        RegisterHandleError::KeychainError
    })?;

    let token_bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "failed to read session-token from Keychain during handle registration");
        RegisterHandleError::KeychainError
    })?;
    let session_token = String::from_utf8(token_bytes).map_err(|e| {
        tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
        RegisterHandleError::KeychainError
    })?;

    // Step 3: POST to /v1/handles.
    let req = CreateHandleRequest {
        account_id: did,
        handle: full_handle.clone(),
    };

    let resp = state
        .relay_client()
        .post_with_bearer("/v1/handles", &req, &session_token)
        .await
        .map_err(|e| RegisterHandleError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();

    if status.is_success() {
        let body: CreateHandleRelayResponse =
            resp.json()
                .await
                .map_err(|e| RegisterHandleError::Unknown {
                    message: format!("failed to parse /v1/handles response: {e}"),
                })?;
        Ok(RegisterHandleResult {
            handle: full_handle,
            dns_status: body.dns_status,
        })
    } else {
        match status.as_u16() {
            400 => {
                let envelope: RelayErrorEnvelope =
                    resp.json()
                        .await
                        .map_err(|e| RegisterHandleError::Unknown {
                            message: e.to_string(),
                        })?;
                if envelope.error.code == "INVALID_HANDLE" {
                    Err(RegisterHandleError::InvalidHandle)
                } else {
                    Err(RegisterHandleError::Unknown {
                        message: format!("400: {}", envelope.error.code),
                    })
                }
            }
            // 401 means the relay rejected the session token — it's expired or revoked.
            // The Keychain read already succeeded; this is an auth problem, not a Keychain problem.
            401 => Err(RegisterHandleError::SessionExpired),
            409 => Err(RegisterHandleError::HandleTaken),
            502 => Err(RegisterHandleError::DnsError),
            other => Err(RegisterHandleError::NetworkError {
                message: format!("HTTP {other}"),
            }),
        }
    }
}

/// Return the saved relay base URL, or `None` if not yet configured.
///
/// The frontend calls this on mount to decide whether to show the relay
/// configuration screen.
#[tauri::command]
fn get_relay_url() -> Option<String> {
    keychain::load_relay_url()
}

/// Validate `url`, confirm the relay is reachable, save to Keychain, and
/// initialize the runtime relay client.
///
/// After this call succeeds, all subsequent IPC commands that use the relay
/// will use the saved URL for the remainder of the app session and on all
/// future launches.
#[tauri::command]
async fn save_relay_url(
    url: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<(), RelayConfigError> {
    let normalized = normalize_relay_url(&url)?;
    let resp = http::RelayClient::new_with_url(normalized.clone())
        .get("/xrpc/_health")
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, url = %normalized, "relay health check failed");
            RelayConfigError::Unreachable
        })?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            url = %normalized,
            "relay health check returned non-success status"
        );
        // Both transport failures (DNS, TLS, timeout) and non-2xx HTTP responses
        // map to Unreachable — the frontend only needs to know "can't use this URL".
        return Err(RelayConfigError::Unreachable);
    }
    keychain::store_relay_url(&normalized).map_err(|e| {
        tracing::error!(error = %e, "failed to save relay URL to Keychain");
        RelayConfigError::KeychainError
    })?;
    state.set_relay_client(normalized);
    Ok(())
}

/// Return the list of managed DIDs currently stored in the Keychain.
///
/// Returns an empty list if no identities have been claimed. Returns an error only if
/// the Keychain entry exists but contains invalid data (data corruption).
///
/// The frontend calls this on mount to check for existing identities and decide whether
/// to skip the mode selector.
#[tauri::command]
fn list_identities() -> Result<Vec<String>, identity_store::IdentityStoreError> {
    identity_store::IdentityStore.list_identities()
}

/// Retrieve the stored DID document for a claimed identity.
///
/// Returns the DID document as parsed JSON, or None if the DID is not registered or
/// the document has not been stored yet.
///
/// The frontend uses this to extract identity information (handle, PDS URL) for
/// multi-identity card display in IdentityListHome.
#[tauri::command]
fn get_stored_did_doc(
    did: String,
) -> Result<Option<serde_json::Value>, identity_store::IdentityStoreError> {
    let store = identity_store::IdentityStore;
    match store.get_did_doc(&did)? {
        Some(json_str) => {
            let value: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                identity_store::IdentityStoreError::SerializationError {
                    message: e.to_string(),
                }
            })?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

/// Retrieve the device key ID (did:key URI) for a claimed identity.
///
/// Returns the device key's did:key URI, which can be compared against rotation keys
/// in the DID document to determine if the device key is the primary rotation key.
///
/// The frontend uses this in IdentityListHome to show rotation key status badges.
#[tauri::command]
fn get_device_key_id(did: String) -> Result<String, identity_store::IdentityStoreError> {
    let store = identity_store::IdentityStore;
    let device_key = store.get_or_create_device_key(&did)?;
    Ok(device_key.key_id)
}

/// Check whether the relay can resolve `handle` to `expected_did` via the ATProto
/// `resolveHandle` endpoint.
///
/// Returns `true` when the relay resolves the handle to the expected DID (HTTP 200 + matching
/// `did` field). Returns `false` for any other response (handle not yet propagated, relay
/// unreachable, DID mismatch). Returns `Result<bool, String>` for Tauri IPC compatibility, but
/// never returns `Err` — callers can safely poll on an interval.
#[tauri::command]
async fn check_handle_resolution(
    handle: String,
    expected_did: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<bool, String> {
    // ATProto handles are alphanumeric + hyphens + dots — all URL-safe; no percent-encoding needed.
    let path = format!("/xrpc/com.atproto.identity.resolveHandle?handle={handle}");

    let resp = match state.relay_client().get(&path).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "check_handle_resolution: network error, returning false");
            return Ok(false);
        }
    };

    if !resp.status().is_success() {
        tracing::debug!(
            status = resp.status().as_u16(),
            "check_handle_resolution: non-success response, returning false"
        );
        return Ok(false);
    }

    match resp.json::<ResolveHandleResponse>().await {
        Ok(body) => Ok(body.did == expected_did),
        Err(e) => {
            tracing::debug!(error = %e, "check_handle_resolution: failed to parse response, returning false");
            Ok(false)
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(oauth::AppState::new())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Restore relay URL from Keychain if previously configured.
            if let Some(url) = keychain::load_relay_url() {
                app.state::<oauth::AppState>().set_relay_client(url);
            }

            let app_handle = app.app_handle().clone();
            app.deep_link().on_open_url(move |event| {
                let state = app_handle.state::<oauth::AppState>();
                oauth::handle_deep_link(event.urls(), &state);
            });

            // On relaunch: restore persisted session from Keychain and notify frontend.
            // The 300 ms delay lets the SvelteKit app boot and register its event listener
            // before the event fires — emitting synchronously here would be dropped.
            if let Some((access, refresh)) = keychain::load_oauth_tokens() {
                {
                    let state = app.state::<oauth::AppState>();
                    *state.oauth_session.lock().unwrap() = Some(oauth::OAuthSession {
                        access_token: access,
                        refresh_token: refresh,
                        // expires_at = 0 ensures OAuthClient refreshes immediately on first use.
                        expires_at: 0,
                        dpop_nonce: None,
                    });
                }
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    handle.emit("auth_ready", ()).ok();
                });
            }

            // Start PLC monitoring timer (15-minute interval)
            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(plc_monitor::run_monitoring_loop(monitor_handle));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_account,
            get_or_create_device_key,
            sign_with_device_key,
            perform_did_ceremony,
            register_handle,
            check_handle_resolution,
            list_identities,
            get_stored_did_doc,
            get_device_key_id,
            get_relay_url,
            save_relay_url,
            home::load_home_data,
            home::log_out,
            oauth::start_oauth_flow,
            claim::resolve_identity,
            claim::start_pds_auth,
            claim::request_claim_verification,
            claim::sign_and_verify_claim,
            claim::submit_claim,
            plc_monitor::check_identity_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CreateDidRequest serialization --
    #[test]
    fn create_did_request_serializes_password_and_camel_case() {
        let req = CreateDidRequest {
            rotation_key_public: "did:key:z123".into(),
            signed_creation_op: serde_json::json!({"type": "plc_operation"}),
            password: "mysecretpassword".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["rotationKeyPublic"], "did:key:z123");
        assert_eq!(json["password"], "mysecretpassword");
        assert!(json["signedCreationOp"].is_object());
    }

    // -- CreateMobileAccountRequest serialization --
    #[test]
    fn create_mobile_account_request_serializes_camel_case() {
        let req = CreateMobileAccountRequest {
            email: "test@example.com".into(),
            handle: "alice".into(),
            device_public_key: "pubkey123".into(),
            platform: "ios".into(),
            claim_code: "ABC123".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["handle"], "alice");
        assert_eq!(json["devicePublicKey"], "pubkey123");
        assert_eq!(json["platform"], "ios");
        assert_eq!(json["claimCode"], "ABC123");
    }

    // -- CreateAccountResult serialization --
    #[test]
    fn create_account_result_serializes_camel_case() {
        let result = CreateAccountResult {
            next_step: NextStep::DidCreation,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["nextStep"], "did_creation");
    }

    // -- NextStep serde round-trip --
    #[test]
    fn next_step_did_creation_deserializes_correctly() {
        let result: NextStep = serde_json::from_str(r#""did_creation""#).unwrap();
        assert_eq!(result, NextStep::DidCreation);
    }

    #[test]
    fn next_step_did_creation_serializes_correctly() {
        let json = serde_json::to_value(NextStep::DidCreation).unwrap();
        assert_eq!(json, "did_creation");
    }

    #[test]
    fn next_step_unknown_value_fails_deserialization() {
        let result: Result<NextStep, _> = serde_json::from_str(r#""email_verification""#);
        assert!(result.is_err());
    }

    // -- CreateAccountError::ExpiredCode serialization --
    #[test]
    fn error_expired_code_serializes_correctly() {
        let err = CreateAccountError::ExpiredCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EXPIRED_CODE");
    }

    // -- CreateAccountError::RedeemedCode serialization --
    #[test]
    fn error_redeemed_code_serializes_correctly() {
        let err = CreateAccountError::RedeemedCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "REDEEMED_CODE");
    }

    // -- CreateAccountError::EmailTaken serialization --
    #[test]
    fn error_email_taken_serializes_correctly() {
        let err = CreateAccountError::EmailTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EMAIL_TAKEN");
    }

    // -- CreateAccountError::HandleTaken serialization --
    #[test]
    fn error_handle_taken_serializes_correctly() {
        let err = CreateAccountError::HandleTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");
    }

    // -- CreateAccountError::NetworkError serialization --
    #[test]
    fn error_network_error_serializes_correctly() {
        let err = CreateAccountError::NetworkError {
            message: "Connection timeout".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection timeout");
    }

    // -- CreateAccountError::KeychainError serialization --
    #[test]
    fn error_keychain_error_serializes_correctly() {
        let err = CreateAccountError::KeychainError;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- CreateAccountError::Unknown serialization --
    #[test]
    fn error_unknown_serializes_correctly() {
        let err = CreateAccountError::Unknown {
            message: "Unexpected relay response".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert_eq!(json["message"], "Unexpected relay response");
    }

    // -- 409 subcode dispatch table --
    #[test]
    fn error_409_dispatch_maps_subcodes_correctly() {
        let json = serde_json::to_value(map_409_subcode("CLAIM_CODE_REDEEMED")).unwrap();
        assert_eq!(json["code"], "REDEEMED_CODE");

        let json = serde_json::to_value(map_409_subcode("ACCOUNT_EXISTS")).unwrap();
        assert_eq!(json["code"], "EMAIL_TAKEN");

        let json = serde_json::to_value(map_409_subcode("HANDLE_TAKEN")).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");

        let json = serde_json::to_value(map_409_subcode("UNKNOWN_SUBCODE")).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert!(json["message"].as_str().unwrap().contains("409:"));
    }

    // -- RegisterHandleResult serialization --

    #[test]
    fn register_handle_result_serializes_camel_case() {
        let result = RegisterHandleResult {
            handle: "alice.ezpds.com".into(),
            dns_status: "propagating".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["handle"], "alice.ezpds.com");
        assert_eq!(json["dnsStatus"], "propagating");
    }

    // -- RegisterHandleError serialization (one test per variant) --

    #[test]
    fn register_handle_error_handle_taken_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::HandleTaken).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");
    }

    #[test]
    fn register_handle_error_invalid_handle_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::InvalidHandle).unwrap();
        assert_eq!(json["code"], "INVALID_HANDLE");
    }

    #[test]
    fn register_handle_error_dns_error_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::DnsError).unwrap();
        assert_eq!(json["code"], "DNS_ERROR");
    }

    #[test]
    fn register_handle_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    #[test]
    fn register_handle_error_session_expired_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::SessionExpired).unwrap();
        assert_eq!(json["code"], "SESSION_EXPIRED");
    }

    #[test]
    fn register_handle_error_no_domains_serializes_correctly() {
        let json = serde_json::to_value(&RegisterHandleError::NoDomains).unwrap();
        assert_eq!(json["code"], "NO_DOMAINS");
    }

    #[test]
    fn register_handle_error_network_error_serializes_correctly() {
        let err = RegisterHandleError::NetworkError {
            message: "Connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection refused");
    }

    #[test]
    fn register_handle_error_unknown_serializes_correctly() {
        let err = RegisterHandleError::Unknown {
            message: "unexpected response".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert_eq!(json["message"], "unexpected response");
    }

    // Tests the device_key contract that create_account depends on: the returned key
    // is correctly formatted (multibase base58btc) and is idempotent (stable across calls).
    #[test]
    fn device_key_contract_satisfies_relay_format() {
        let key = crate::device_key::get_or_create()
            .expect("device_key::get_or_create must succeed — create_account depends on it");
        // The relay expects multibase: 'z' + base58btc(33-byte compressed P-256 point).
        assert!(
            key.multibase.starts_with('z'),
            "device_public_key sent to relay must be multibase base58btc ('z' prefix), got: {}",
            key.multibase
        );
        // Calling again returns the same key — create_account sends consistent device_public_key.
        let key2 = crate::device_key::get_or_create().expect("second call must also succeed");
        assert_eq!(
            key.multibase, key2.multibase,
            "device_public_key must be stable across calls (idempotent)"
        );
    }

    // -- DIDCeremonyResult serialization --
    #[test]
    fn did_ceremony_result_serializes_did_in_camel_case() {
        let result = DIDCeremonyResult {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            share3: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["did"], "did:plc:abcdefghijklmnopqrstuvwx");
        assert_eq!(
            json["share3"],
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"
        );
    }

    #[test]
    fn did_ceremony_result_serializes_share3_in_camel_case() {
        let share = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST";
        let result = DIDCeremonyResult {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            share3: share.into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["share3"], share);
    }

    // -- DIDCeremonyError serialization (one test per variant) --
    #[test]
    fn did_ceremony_error_key_not_found_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeyNotFound).unwrap();
        assert_eq!(json["code"], "KEY_NOT_FOUND");
    }

    #[test]
    fn did_ceremony_error_relay_key_fetch_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::RelayKeyFetchFailed).unwrap();
        assert_eq!(json["code"], "RELAY_KEY_FETCH_FAILED");
    }

    #[test]
    fn did_ceremony_error_no_relay_signing_key_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::NoRelaySigningKey).unwrap();
        assert_eq!(json["code"], "NO_RELAY_SIGNING_KEY");
    }

    #[test]
    fn did_ceremony_error_signing_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::SigningFailed).unwrap();
        assert_eq!(json["code"], "SIGNING_FAILED");
    }

    #[test]
    fn did_ceremony_error_did_creation_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::DidCreationFailed).unwrap();
        assert_eq!(json["code"], "DID_CREATION_FAILED");
    }

    #[test]
    fn did_ceremony_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    #[test]
    fn did_ceremony_error_network_error_serializes_with_message() {
        let err = DIDCeremonyError::NetworkError {
            message: "Connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection refused");
    }

    #[test]
    fn did_ceremony_error_share_storage_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::ShareStorageFailed).unwrap();
        assert_eq!(json["code"], "SHARE_STORAGE_FAILED");
    }

    // -- RelayConfigError serialization (one test per variant) --
    #[test]
    fn relay_config_error_invalid_url_serializes_correctly() {
        let json = serde_json::to_value(RelayConfigError::InvalidUrl).unwrap();
        assert_eq!(json["code"], "INVALID_URL");
    }

    #[test]
    fn relay_config_error_unreachable_serializes_correctly() {
        let json = serde_json::to_value(RelayConfigError::Unreachable).unwrap();
        assert_eq!(json["code"], "UNREACHABLE");
    }

    #[test]
    fn relay_config_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(RelayConfigError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- normalize_relay_url --

    #[test]
    fn normalize_relay_url_strips_trailing_slash() {
        assert_eq!(
            normalize_relay_url("https://relay.example.com/").unwrap(),
            "https://relay.example.com"
        );
    }

    #[test]
    fn normalize_relay_url_accepts_http_and_https() {
        assert!(normalize_relay_url("https://relay.example.com").is_ok());
        assert!(normalize_relay_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn normalize_relay_url_rejects_non_http_schemes() {
        assert!(matches!(
            normalize_relay_url("ftp://relay.example.com").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_relay_url("ws://relay.example.com").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_relay_url_rejects_malformed_input() {
        assert!(matches!(
            normalize_relay_url("not-a-url").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_relay_url("").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_relay_url_rejects_urls_with_paths() {
        assert!(matches!(
            normalize_relay_url("https://relay.example.com/api/v1").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
    }

    // -- get_relay_url / load_relay_url round-trip --

    #[test]
    fn get_relay_url_returns_none_before_save() {
        // Relies on the keychain mock starting empty for this key. The sibling test
        // relay_url_round_trips_through_keychain cleans up via delete_relay_url_test_only(),
        // so ordering is not a concern as long as both tests run in the same process.
        assert!(get_relay_url().is_none());
    }

    #[test]
    fn relay_url_round_trips_through_keychain() {
        let url = "https://relay.example.com";
        keychain::store_relay_url(url).unwrap();
        let loaded = keychain::load_relay_url().unwrap();
        assert_eq!(loaded, url);
        // Clean up so this test doesn't affect others sharing the mock store.
        keychain::delete_relay_url_test_only();
    }
}
