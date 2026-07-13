pub mod agents;
pub mod claim;
pub mod device_key;
pub mod home;
pub mod http;
pub mod identity_store;
pub mod keychain;
pub mod migrate;
pub mod migration_orchestrator;
pub mod oauth;
pub mod oauth_client;
pub mod pds_client;
pub mod plc_monitor;
pub mod recovery;
pub mod sovereign_session;

use crypto::{build_did_plc_genesis_op_with_external_signer, CryptoError, DidKeyUri};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

// ── Request / response types ────────────────────────────────────────────────

/// JSON body sent to POST /v1/accounts/mobile.
/// Field names match the PDS's camelCase deserialization.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountRequest {
    email: String,
    handle: String,
    device_public_key: String,
    platform: String,
    claim_code: String,
}

/// Successful 201 response from the PDS.
///
/// The PDS returns additional fields (account_id, device_id) which are
/// silently ignored by serde's default behavior. This struct captures only
/// the three fields needed by the client.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountResponse {
    device_token: String,
    session_token: String,
    next_step: NextStep,
}

/// Response from GET /v1/repo-signing-key — this account's per-account repo signing key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PdsSigningKey {
    key_id: String,
}

/// Request body for POST /v1/dids — submit the signed genesis op for DID promotion.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidRequest {
    rotation_key_public: String,
    signed_creation_op: serde_json::Value,
    /// Initial password stored as an argon2id PHC string by the PDS.
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

/// PDS error envelope: { "error": { "code": "...", "message": "..." } }
#[derive(Deserialize)]
struct PdsErrorEnvelope {
    error: PdsErrorBody,
}

#[derive(Deserialize)]
struct PdsErrorBody {
    code: String,
}

// ── IPC result / error types (returned to the frontend) ─────────────────────

/// The next step the client should take after successful account creation.
///
/// If the PDS returns an unrecognized value, serde deserialization fails and
/// `create_account` returns `CreateAccountError::Unknown` — unrecognized PDS
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
/// Serializes as `{ "code": "NO_PDS_SIGNING_KEY" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DIDCeremonyError {
    #[error("failed to get or create device key")]
    KeyNotFound,
    #[error("failed to fetch PDS signing key")]
    PdsKeyFetchFailed,
    #[error("PDS has no signing key provisioned")]
    NoPdsSigningKey,
    #[error("device signing failed")]
    SigningFailed,
    #[error("DID creation request failed")]
    DidCreationFailed,
    #[error("keychain operation failed")]
    KeychainError,
    /// DID was committed at the PDS but Share 1 could not be stored in Keychain.
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
struct CreateHandlePdsResponse {
    dns_status: String,
}

/// Successful result returned to the Svelte frontend after handle registration.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterHandleResult {
    /// Full handle including domain, e.g. `alice.ezpds.com`.
    pub handle: String,
    /// `"propagating"` when DNS creation was requested; `"not_configured"` when no DNS provider
    /// is configured on the PDS (handle still resolves via HTTP well-known).
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
    /// The PDS rejected the session token (401). The token is expired or revoked — the user
    /// must re-authenticate via OAuth rather than restart the app.
    #[error("session token expired or revoked")]
    SessionExpired,
    #[error("PDS has no user domains configured")]
    NoDomains,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

/// Error returned by PDS URL configuration commands.
///
/// Serializes as `{ "code": "INVALID_URL" | "UNREACHABLE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PdsConfigError {
    #[error("invalid PDS URL: must be http or https with a non-empty host")]
    InvalidUrl,
    #[error("PDS is unreachable or did not return a success response")]
    Unreachable,
    #[error("failed to save PDS URL to device storage")]
    KeychainError,
}

/// Response shape from `GET /xrpc/com.atproto.identity.resolveHandle`.
#[derive(Deserialize)]
struct ResolveHandleResponse {
    did: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Map a PDS 409 error subcode string to a typed `CreateAccountError` variant.
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

/// Validate a PDS URL: must parse as http or https with a non-empty host.
/// Strips any trailing slash and returns the normalized URL string.
fn normalize_pds_url(url: &str) -> Result<String, PdsConfigError> {
    let parsed = url::Url::parse(url).map_err(|_| PdsConfigError::InvalidUrl)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(PdsConfigError::InvalidUrl),
    }
    if parsed.host().is_none() {
        return Err(PdsConfigError::InvalidUrl);
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(PdsConfigError::InvalidUrl);
    }
    Ok(url.trim_end_matches('/').to_string())
}

/// Build a minimal PLC-format DID document for a freshly-created identity, from
/// data known at the end of the create flow.
///
/// `IdentityListHome` reads three fields off the stored document: `alsoKnownAs`
/// (the handle), `services.atproto_pds.endpoint` (the PDS host shown on the card),
/// and `rotationKeys[0]` (the device-key "root" badge). The document is built
/// locally rather than fetched so the create flow does not depend on plc.directory
/// propagation timing right after DID creation. `rotationKeys[0]` is always the
/// device key, so the badge stays accurate even if the PDS holds additional
/// rotation keys not reflected here.
fn build_create_flow_did_doc(
    did: &str,
    handle: &str,
    pds_url: &str,
    rotation_key_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "did": did,
        "alsoKnownAs": [format!("at://{handle}")],
        "rotationKeys": [rotation_key_id],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_url,
            }
        }
    })
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

    // 2. POST to PDS.
    let req = CreateMobileAccountRequest {
        email,
        handle,
        device_public_key: device_key.multibase,
        platform: "ios".to_string(),
        claim_code,
    };

    // Log the target PDS host so a wrong-host failure (e.g. a claim code minted on a different
    // server) is visible in logs instead of silently masquerading as "claim code expired".
    let host = state.custos_client().base_url_str().to_owned();
    let resp = state
        .custos_client()
        .post("/v1/accounts/mobile", &req)
        .await
        .map_err(|e| {
            tracing::warn!(host = %host, error = %e, "create_account: request to PDS failed");
            CreateAccountError::NetworkError {
                message: e.to_string(),
            }
        })?;

    let status = resp.status();
    tracing::info!(host = %host, status = status.as_u16(), "create_account: PDS responded");

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
        // 5. Map PDS error codes to typed variants.
        match status.as_u16() {
            // 404: PDS returns this for both invalid (never-existed) and expired claim codes.
            // The frontend cannot distinguish them, so we map both to ExpiredCode.
            404 => Err(CreateAccountError::ExpiredCode),
            409 => {
                let envelope: PdsErrorEnvelope =
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

    // Step 2: Retrieve the pending session token — needed to authenticate the
    // per-account signing-key request below and the DID promotion later.
    let pending_token = {
        let token_bytes = keychain::get_item("session-token").map_err(|e| {
            tracing::warn!(error = %e, "failed to retrieve session-token from keychain");
            DIDCeremonyError::KeychainError
        })?;
        String::from_utf8(token_bytes).map_err(|e| {
            tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
            DIDCeremonyError::KeychainError
        })?
    };

    // Step 3: Fetch this account's per-account repo signing key (pending-session auth).
    // The PDS issues it idempotently; we publish it as the DID's #atproto verification
    // method, and the PDS signs the repo's commits with the matching private key.
    let resp = state
        .custos_client()
        .get_with_bearer("/v1/repo-signing-key", &pending_token)
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();
    if status.as_u16() == 503 {
        return Err(DIDCeremonyError::NoPdsSigningKey);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to read GET /v1/repo-signing-key error body");
            "<body read failed>".to_string()
        });
        tracing::error!(status = %status, body = %body, "GET /v1/repo-signing-key returned non-success status");
        return Err(DIDCeremonyError::PdsKeyFetchFailed);
    }

    let pds_key: PdsSigningKey = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize repo signing key response");
        DIDCeremonyError::PdsKeyFetchFailed
    })?;

    // Step 4: Build signed genesis op — device key as rotation key, per-account repo key as signing key.
    // On device, the private key never leaves the Secure Enclave; on Simulator and macOS, a software key is used instead.
    let rotation_key = DidKeyUri(device_key.key_id.clone());
    let signing_key = DidKeyUri(pds_key.key_id.clone());

    let genesis_op = build_did_plc_genesis_op_with_external_signer(
        &rotation_key,
        &signing_key,
        &handle,
        state.custos_client().base_url_str(),
        |data| {
            device_key::sign(data)
                .map_err(|e| CryptoError::PlcOperation(format!("device signing failed: {e}")))
        },
    )
    .map_err(|e| {
        tracing::error!(error = %e, "genesis op signing failed during DID ceremony");
        DIDCeremonyError::SigningFailed
    })?;

    // Step 6: POST the signed genesis op to the PDS to promote the account to a full DID.
    let create_did_req = CreateDidRequest {
        rotation_key_public: device_key.key_id,
        signed_creation_op: serde_json::from_str(&genesis_op.signed_op_json).map_err(|e| {
            tracing::error!(error = %e, "genesis op JSON is not valid JSON");
            DIDCeremonyError::SigningFailed
        })?,
        password,
    };

    let resp = state
        .custos_client()
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

/// Register the user's (already-full) handle with the PDS and set up HTTP resolution.
///
/// `handle` is the complete handle (e.g. `alice.ezpds.com`), assembled on the client from the
/// PDS's `availableUserDomains` *before* the DID ceremony so it matches the published genesis
/// op's `alsoKnownAs` exactly. Reads the DID and session token from Keychain, then POSTs to
/// `POST /v1/handles`.
///
/// Returns the full handle and DNS propagation status on success.
#[tauri::command]
async fn register_handle(
    handle: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<RegisterHandleResult, RegisterHandleError> {
    let full_handle = handle;

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
        .custos_client()
        .post_with_bearer("/v1/handles", &req, &session_token)
        .await
        .map_err(|e| RegisterHandleError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();

    if status.is_success() {
        let body: CreateHandlePdsResponse =
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
                let envelope: PdsErrorEnvelope =
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
            // 401 means the PDS rejected the session token — it's expired or revoked.
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

/// Fetch the PDS's configured handle domains (`availableUserDomains` from describeServer) so the
/// client can build the full `{label}.{domain}` handle BEFORE the DID ceremony — ensuring the
/// did:plc genesis op's `alsoKnownAs` carries the real, resolvable handle.
///
/// Returns the (possibly empty) domain list on success; the caller decides what to do when the
/// list is empty. Rejects with a message string on network/parse failure.
#[tauri::command]
async fn get_available_user_domains(
    state: tauri::State<'_, oauth::AppState>,
) -> Result<Vec<String>, String> {
    let resp = state
        .custos_client()
        .get("/xrpc/com.atproto.server.describeServer")
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!(
            "describeServer returned HTTP {}",
            resp.status().as_u16()
        ));
    }

    let server_info: DescribeServerResponse = resp
        .json()
        .await
        .map_err(|e| format!("failed to parse describeServer response: {e}"))?;

    Ok(server_info.available_user_domains)
}

/// Return the saved PDS base URL, or `None` if not yet configured.
///
/// The frontend calls this on mount to decide whether to show the PDS
/// configuration screen.
#[tauri::command]
fn get_pds_url() -> Option<String> {
    keychain::load_pds_url()
}

/// The three values the in-app appearance setting can take. `"system"` means
/// no override (the WebView follows the iOS appearance via `color-scheme`).
const APPEARANCE_PREFERENCES: [&str; 3] = ["system", "light", "dark"];

/// Error returned by `set_appearance_preference`.
///
/// Serializes as `{ "code": "INVALID_PREFERENCE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppearanceError {
    #[error("appearance preference must be \"system\", \"light\", or \"dark\"")]
    InvalidPreference,
    #[error("failed to save appearance preference to device storage")]
    KeychainError,
}

/// Return the saved appearance preference (`"system"`, `"light"`, or `"dark"`),
/// or `None` if never set — both mean "follow the system".
///
/// A corrupt or unrecognized stored value is treated as absent rather than an
/// error: the worst outcome of losing this preference is following the system
/// appearance, which is the default anyway.
#[tauri::command]
fn get_appearance_preference() -> Option<String> {
    keychain::load_appearance_preference().filter(|p| APPEARANCE_PREFERENCES.contains(&p.as_str()))
}

/// Validate and persist the appearance preference to the Keychain.
///
/// The frontend applies the appearance instantly before calling this; the
/// Keychain write is what makes the choice survive app restarts.
#[tauri::command]
fn set_appearance_preference(preference: String) -> Result<(), AppearanceError> {
    if !APPEARANCE_PREFERENCES.contains(&preference.as_str()) {
        return Err(AppearanceError::InvalidPreference);
    }
    keychain::store_appearance_preference(&preference).map_err(|e| {
        tracing::error!(error = %e, "failed to save appearance preference to Keychain");
        AppearanceError::KeychainError
    })
}

/// Validate `url`, confirm the PDS is reachable, save to Keychain, and
/// initialize the runtime PDS client.
///
/// After this call succeeds, all subsequent IPC commands that use the PDS
/// will use the saved URL for the remainder of the app session and on all
/// future launches.
#[tauri::command]
async fn save_pds_url(
    url: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<(), PdsConfigError> {
    let normalized = normalize_pds_url(&url)?;
    let resp = http::CustosClient::new_with_url(normalized.clone())
        .get("/xrpc/_health")
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, url = %normalized, "PDS health check failed");
            PdsConfigError::Unreachable
        })?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            url = %normalized,
            "PDS health check returned non-success status"
        );
        // Both transport failures (DNS, TLS, timeout) and non-2xx HTTP responses
        // map to Unreachable — the frontend only needs to know "can't use this URL".
        return Err(PdsConfigError::Unreachable);
    }
    keychain::store_pds_url(&normalized).map_err(|e| {
        tracing::error!(error = %e, "failed to save PDS URL to Keychain");
        PdsConfigError::KeychainError
    })?;
    state.set_custos_client(normalized);
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

/// Errors from [`refresh_did_doc`], serialized as `{ code: "SCREAMING_SNAKE_CASE" }`
/// like every other IPC error enum so the frontend gets a branchable contract.
#[derive(Debug, serde::Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefreshDidDocError {
    /// plc.directory fetch failed (network, 404, or parse).
    #[error("failed to fetch PLC data document: {message}")]
    FetchFailed { message: String },
    /// Serializing or persisting the refreshed document failed.
    #[error("failed to store DID document: {message}")]
    StorageFailed { message: String },
}

/// Re-fetch a claimed identity's PLC data document from plc.directory and re-store it
/// in the per-identity cache, returning the fresh document.
///
/// The cache self-heal: earlier builds cached the W3C DID document (or a doc with
/// empty `rotationKeys`) after claim/migration/recovery, which starves the home
/// card's custody badge and hides the migrate entry. `IdentityListHome` calls this
/// (best-effort) whenever a cached doc is missing or has no `rotationKeys`, so stale
/// caches repair on the next home load without user action.
#[tauri::command]
async fn refresh_did_doc(
    state: tauri::State<'_, oauth::AppState>,
    did: String,
) -> Result<serde_json::Value, RefreshDidDocError> {
    let did_doc = state
        .pds_client()
        .fetch_plc_data_document(&did)
        .await
        .map_err(|e| RefreshDidDocError::FetchFailed {
            message: e.to_string(),
        })?;
    let json = serde_json::to_string(&did_doc).map_err(|e| RefreshDidDocError::StorageFailed {
        message: format!("failed to serialize DID document: {e}"),
    })?;
    identity_store::IdentityStore
        .store_did_doc(&did, &json)
        .map_err(|e| RefreshDidDocError::StorageFailed {
            message: e.to_string(),
        })?;
    Ok(did_doc)
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

/// Check whether the PDS can resolve `handle` to `expected_did` via the ATProto
/// `resolveHandle` endpoint.
///
/// Returns `true` when the PDS resolves the handle to the expected DID (HTTP 200 + matching
/// `did` field). Returns `false` for any other response (handle not yet propagated, PDS
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

    let resp = match state.custos_client().get(&path).await {
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

/// Error returned by `register_created_identity`.
///
/// Serializes as `{ "code": "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegisterIdentityError {
    #[error("failed to persist identity to device storage")]
    KeychainError,
}

/// Register a just-created identity in `IdentityStore` so it appears in
/// `IdentityListHome` on the home screen.
///
/// The PDS-OAuth create flow stores its session and DID outside `IdentityStore`
/// (OAuth tokens + the legacy `"did"` Keychain item), while the home screen lists
/// identities from `IdentityStore` alone — so without this step the freshly-created
/// identity never appears after login. This mirrors what the import flow does in
/// `claim::submit_claim`, with one addition: the create flow's genesis op was signed
/// with the *global* device key, so `adopt_global_device_key` aliases the per-DID
/// device key to it (keeps the "root key" badge and PLC monitoring honest).
///
/// Idempotent — safe to retry; tolerates an already-registered DID.
#[tauri::command]
async fn register_created_identity(
    did: String,
    handle: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<(), RegisterIdentityError> {
    let store = identity_store::IdentityStore;

    // 1. Register the DID (tolerate AlreadyExists from a prior attempt).
    if let Err(e) = store.add_identity(&did) {
        if !matches!(e, identity_store::IdentityStoreError::IdentityAlreadyExists) {
            tracing::error!(did = %did, error = %e, "register_created_identity: add_identity failed");
            return Err(RegisterIdentityError::KeychainError);
        }
    }

    // 2. Alias the per-DID device key to the global key used as rotationKeys[0].
    // Non-fatal: on failure the identity still lists; only the "root key" badge
    // and PLC-monitor classification degrade. Log and continue.
    if let Err(e) = store.adopt_global_device_key(&did) {
        tracing::warn!(did = %did, error = %e, "register_created_identity: adopt_global_device_key failed");
    }

    // 3. Build and store a local DID document so the card shows handle + PDS.
    let rotation_key_id = match device_key::get_or_create() {
        Ok(k) => k.key_id,
        Err(e) => {
            // The global device key was created earlier in the flow (perform_did_ceremony),
            // so a failure here is a genuine Keychain error — surface it rather than persist
            // a malformed `rotationKeys: [""]` doc that would show a wrong "Not root" badge.
            tracing::error!(did = %did, error = %e, "register_created_identity: device key unavailable for DID doc");
            return Err(RegisterIdentityError::KeychainError);
        }
    };
    let pds_url = state.custos_client().base_url_str().to_owned();
    let did_doc_json =
        build_create_flow_did_doc(&did, &handle, &pds_url, &rotation_key_id).to_string();

    if let Err(e) = store.store_did_doc(&did, &did_doc_json) {
        tracing::error!(did = %did, error = %e, "register_created_identity: store_did_doc failed");
        return Err(RegisterIdentityError::KeychainError);
    }

    tracing::info!(did = %did, "created identity registered in IdentityStore");
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .manage(oauth::AppState::new())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Debug)
                .build(),
        )
        // In-app OAuth session (ASWebAuthenticationSession on iOS/macOS). Invoked from the
        // frontend as `plugin:auth-session|start`; drives both the create-flow and claim-flow
        // PDS logins. (Replaced the deep-link + opener plugins, which depended on Safari
        // auto-launching the app from a custom-scheme redirect — which iOS blocks.)
        .plugin(tauri_plugin_auth_session::init());

    // Biometric (Face ID / Touch ID) gate on the migration PLC-op submission. Mobile-only —
    // registering it behind `#[cfg(mobile)]` keeps the macOS host build and its test suite
    // free of a dependency they cannot compile.
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_biometric::init());

    builder
        .setup(|app| {
            // Restore PDS URL from Keychain if previously configured.
            if let Some(url) = keychain::load_pds_url() {
                app.state::<oauth::AppState>().set_custos_client(url);
            }

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
            register_created_identity,
            check_handle_resolution,
            get_available_user_domains,
            list_identities,
            get_stored_did_doc,
            refresh_did_doc,
            get_device_key_id,
            get_pds_url,
            save_pds_url,
            get_appearance_preference,
            set_appearance_preference,
            home::load_home_data,
            home::log_out,
            oauth::prepare_oauth_flow,
            oauth::complete_oauth_flow,
            claim::resolve_identity,
            claim::authenticate_source_pds,
            claim::request_claim_verification,
            claim::sign_and_verify_claim,
            claim::submit_claim,
            agents::list_agents,
            agents::revoke_agent,
            agents::get_agent_audit,
            agents::preview_agent_claim,
            agents::confirm_agent_claim,
            plc_monitor::check_identity_status,
            recovery::build_recovery_override_cmd,
            recovery::submit_recovery_override_cmd,
            migrate::detect_migration_path_cmd,
            migrate::build_migration_op_cmd,
            migrate::submit_migration_op_cmd,
            migration_orchestrator::prepare_migration,
            migration_orchestrator::authenticate_migration_source,
            migration_orchestrator::create_destination_account,
            migration_orchestrator::transfer_repo,
            migration_orchestrator::transfer_blobs,
            migration_orchestrator::transfer_preferences,
            migration_orchestrator::verify_import,
            migration_orchestrator::arm_identity_leg,
            migration_orchestrator::finalize_migration,
            sovereign_session::sovereign_login,
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
            message: "Unexpected PDS response".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert_eq!(json["message"], "Unexpected PDS response");
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
    fn device_key_contract_satisfies_pds_format() {
        let key = crate::device_key::get_or_create()
            .expect("device_key::get_or_create must succeed — create_account depends on it");
        // The PDS expects multibase: 'z' + base58btc(33-byte compressed P-256 point).
        assert!(
            key.multibase.starts_with('z'),
            "device_public_key sent to PDS must be multibase base58btc ('z' prefix), got: {}",
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
    fn did_ceremony_error_pds_key_fetch_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::PdsKeyFetchFailed).unwrap();
        assert_eq!(json["code"], "PDS_KEY_FETCH_FAILED");
    }

    #[test]
    fn did_ceremony_error_no_pds_signing_key_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::NoPdsSigningKey).unwrap();
        assert_eq!(json["code"], "NO_PDS_SIGNING_KEY");
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

    // -- PdsConfigError serialization (one test per variant) --
    #[test]
    fn pds_config_error_invalid_url_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::InvalidUrl).unwrap();
        assert_eq!(json["code"], "INVALID_URL");
    }

    #[test]
    fn pds_config_error_unreachable_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::Unreachable).unwrap();
        assert_eq!(json["code"], "UNREACHABLE");
    }

    #[test]
    fn pds_config_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(PdsConfigError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- normalize_pds_url --

    #[test]
    fn normalize_pds_url_strips_trailing_slash() {
        assert_eq!(
            normalize_pds_url("https://PDS.example.com/").unwrap(),
            "https://PDS.example.com"
        );
    }

    #[test]
    fn normalize_pds_url_accepts_http_and_https() {
        assert!(normalize_pds_url("https://PDS.example.com").is_ok());
        assert!(normalize_pds_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn normalize_pds_url_rejects_non_http_schemes() {
        assert!(matches!(
            normalize_pds_url("ftp://PDS.example.com").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_pds_url("ws://PDS.example.com").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_pds_url_rejects_malformed_input() {
        assert!(matches!(
            normalize_pds_url("not-a-url").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_pds_url("").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_pds_url_rejects_urls_with_paths() {
        assert!(matches!(
            normalize_pds_url("https://PDS.example.com/api/v1").unwrap_err(),
            PdsConfigError::InvalidUrl
        ));
    }

    // -- build_create_flow_did_doc --

    // The locally-built DID document must expose exactly the fields IdentityListHome
    // reads to render a card: alsoKnownAs (handle), rotationKeys[0] (root-key badge),
    // and services.atproto_pds.endpoint (PDS host).
    #[test]
    fn build_create_flow_did_doc_exposes_card_fields() {
        let doc = build_create_flow_did_doc(
            "did:plc:abc",
            "alice.ezpds.com",
            "https://relay.ezpds.com",
            "did:key:zDevice",
        );
        assert_eq!(doc["did"], "did:plc:abc");
        // extractHandle() strips the "at://" prefix from alsoKnownAs entries.
        assert_eq!(doc["alsoKnownAs"][0], "at://alice.ezpds.com");
        // isDeviceKeyRoot() compares rotationKeys[0] against the device key id.
        assert_eq!(doc["rotationKeys"][0], "did:key:zDevice");
        // extractPdsFromPlcDoc() reads services.atproto_pds.endpoint.
        assert_eq!(
            doc["services"]["atproto_pds"]["endpoint"],
            "https://relay.ezpds.com"
        );
    }

    #[test]
    fn register_identity_error_serializes_as_code() {
        let json = serde_json::to_value(RegisterIdentityError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- get_pds_url / load_pds_url round-trip --

    #[test]
    fn get_pds_url_returns_none_before_save() {
        // Relies on the keychain mock starting empty for this key. The sibling test
        // pds_url_round_trips_through_keychain cleans up via delete_pds_url_test_only(),
        // so ordering is not a concern as long as both tests run in the same process.
        assert!(get_pds_url().is_none());
    }

    #[test]
    fn pds_url_round_trips_through_keychain() {
        let url = "https://PDS.example.com";
        keychain::store_pds_url(url).unwrap();
        let loaded = keychain::load_pds_url().unwrap();
        assert_eq!(loaded, url);
        // Clean up so this test doesn't affect others sharing the mock store.
        keychain::delete_pds_url_test_only();
    }

    // -- appearance preference --

    #[test]
    fn get_appearance_preference_returns_none_before_save() {
        keychain::clear_for_test();
        assert!(get_appearance_preference().is_none());
    }

    #[test]
    fn appearance_preference_round_trips_through_keychain() {
        keychain::clear_for_test();
        set_appearance_preference("dark".to_string()).unwrap();
        assert_eq!(get_appearance_preference().as_deref(), Some("dark"));
        set_appearance_preference("system".to_string()).unwrap();
        assert_eq!(get_appearance_preference().as_deref(), Some("system"));
        keychain::delete_appearance_preference_test_only();
    }

    #[test]
    fn set_appearance_preference_rejects_unknown_values() {
        keychain::clear_for_test();
        let err = set_appearance_preference("sepia".to_string()).unwrap_err();
        assert!(matches!(err, AppearanceError::InvalidPreference));
        assert!(get_appearance_preference().is_none());
    }

    #[test]
    fn get_appearance_preference_treats_corrupt_value_as_absent() {
        keychain::clear_for_test();
        // A value written outside set_appearance_preference's validation
        // (or corrupted) must read back as "follow the system", not an error.
        keychain::store_appearance_preference("neon").unwrap();
        assert!(get_appearance_preference().is_none());
        keychain::delete_appearance_preference_test_only();
    }

    #[test]
    fn appearance_error_serializes_as_code() {
        let json = serde_json::to_value(AppearanceError::InvalidPreference).unwrap();
        assert_eq!(json["code"], "INVALID_PREFERENCE");
        let json = serde_json::to_value(AppearanceError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }
}
