//! Obsign wallet backend: crate root, app wiring, and the small cross-cutting Tauri
//! IPC commands that belong to no flow module. Each flow module below owns its own
//! commands and contract; what lives *here* is:
//!
//! - `create_account` — device key + `POST /v1/accounts/mobile`; tokens to Keychain.
//! - `perform_did_ceremony` — the client-share did:plc ceremony (see its doc).
//! - `confirm_share_backup` — the ceremony teardown gate (Share 1 durable before the
//!   staging slot dies).
//! - `prepare_did_web_ceremony` / `complete_did_web_ceremony` — the did:web sibling
//!   ceremony (compose/export a reviewed `did.json`; submit only once resolvable).
//! - `import_did_web_identity` — bring an existing did:web under wallet management.
//! - `get_available_user_domains` — describeServer domains for handle composition.
//! - `register_created_identity` — register a create-flow identity in `IdentityStore`.
//! - `list_identities` / `get_stored_did_doc` / `get_device_key_id` — synchronous
//!   `IdentityStore` reads (no `async fn`, no `State<>` — Keychain access is
//!   synchronous, unlike most commands here).
//! - `get_pds_url` / `save_pds_url` — configured-PDS persistence, `_health`
//!   reachability check, `custos_client` init, and a best-effort capability re-probe.
//! - `get_pds_capabilities` — cached per-host capability read; an absent `custos`
//!   extension and an unreachable host both report an empty list, never an error.
//! - `get_appearance_preference` / `set_appearance_preference` — the three-value
//!   appearance override; a corrupt stored value reads as absent.
//!
//! `run()` is the iOS/Android entry point (`#[cfg_attr(mobile, tauri::mobile_entry_point)]`;
//! `main.rs` calls it on desktop). Its `setup` does the app wiring: command + plugin
//! registration, the startup OAuth-token restore into `AppState.oauth_session`
//! (`expires_at = 0` forces an immediate refresh; `auth_ready` emitted after a 300 ms
//! delay so SvelteKit can register its listener), `reconcile_share1_slots` (the two
//! additive Share 1 launch hops — see its doc), the PLC monitoring loop spawn, and the
//! iOS-only APNs + background-backup bridges.

pub mod agents;
/// The iOS APNs device-token bridge. iOS-only because it is nothing *but* platform plumbing:
/// every part with logic worth testing lives in [`notifications`].
#[cfg(target_os = "ios")]
pub mod apns;
pub mod app_passwords;
pub mod bg_backup;
pub mod blob_backup;
pub mod claim;
pub mod device_key;
pub mod diagnostics;
pub mod disaster_recovery;
pub mod endpoint_repair;
pub mod handle_change;
pub mod http;
pub mod identity_removal;
pub mod identity_store;
pub mod keychain;
pub mod migrate;
pub mod migration_orchestrator;
pub mod notification_routes;
pub mod notifications;
pub mod oauth;
pub mod oauth_client;
pub mod oauth_consent;
pub mod password_unlock;
pub mod pds_capabilities;
pub mod pds_client;
pub mod plc_monitor;
pub mod recovery;
pub mod rekey;
pub mod repo_backup;
pub mod rotate_repo_key;
pub mod self_held_kit;
pub mod session_provider;
pub mod share_ceremony;
pub mod share_recovery;
pub mod source_login;
pub mod sovereign_session;

use crypto::{
    build_did_plc_genesis_op_multi_rotation_with_external_signer, CryptoError, DidKeyUri,
};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_creation_op: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_web_document: Option<String>,
    /// Initial password stored as an argon2id PHC string by the PDS.
    ///
    /// `None` omits the field entirely (hence `skip_serializing_if`, not a `null`), which is how a
    /// passwordless account is requested — a host advertising `optionalPassword` accepts it, and
    /// any other host rejects it rather than silently creating a credential-less account. Never
    /// send `Some("")`: the server refuses an empty string under either policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    /// did:key of the wallet-derived recovery rotation key (client-share ceremony;
    /// did:plc only). Sent together with `escrow_share`, never alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_key: Option<String>,
    /// Share 2 of the wallet's client-side split as a base32 v2 share envelope — the
    /// escrow deposit, the only share Custos ever sees.
    #[serde(skip_serializing_if = "Option::is_none")]
    escrow_share: Option<String>,
}

/// Response from POST /v1/dids — the promoted DID and upgraded session token.
///
/// The server never returns share material: the client-share did:plc path leaves every
/// share with the wallet, and the did:web ceremony has no share-based recovery at all.
#[derive(Deserialize)]
struct CreateDidResponse {
    did: String,
    session_token: String,
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
    /// Share 3 of 3 — the user's manual backup share, in machine (base32 envelope)
    /// form, used for the QR rendering.
    /// Share 1 has already been written by the Rust backend to the Keychain's
    /// iCloud-synchronizable store; whether it has reached the user's Apple account is
    /// not observable from the app.
    pub share3: String,
    /// Share 3 rendered as the BIP-39-style word phrase (same envelope bytes) — the
    /// primary human-custody rendering on the backup screen. Both share fields are empty
    /// on the did:web ceremony, which has no share-based recovery.
    pub share3_words: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidWebPreparation {
    pub device_key_multibase: String,
    pub repo_key_multibase: String,
    pub pds_url: String,
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
    #[error("recovery share generation failed")]
    ShareGenerationFailed,
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
///
/// `availableUserDomains` is optional in the lexicon, so its absence must not reject a
/// response the wallet otherwise understands. The `custos` capability extension is read
/// separately, through `pds_capabilities`, which owns the per-host cache.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DescribeServerResponse {
    #[serde(default)]
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

/// Create a provisional mobile account on the configured PDS.
///
/// Gets or creates the global device key via `device_key::get_or_create()` (idempotent,
/// so a retry sends the PDS the same key), POSTs the claim code / email / handle to
/// `POST /v1/accounts/mobile`, and stores the returned tokens in the Keychain on
/// success. PDS refusals map to typed [`CreateAccountError`] variants the frontend
/// routes back to the originating screen (e.g. `EXPIRED_CODE` → the claim-code step).
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

struct DidCeremonyContext {
    device_key: device_key::DevicePublicKey,
    pending_token: String,
}

/// Load the device key and pending account token shared by both DID ceremony methods.
fn load_did_ceremony_context() -> Result<DidCeremonyContext, DIDCeremonyError> {
    let device_key = device_key::get_or_create().map_err(|e| {
        tracing::warn!(error = %e, "device key creation failed during DID ceremony");
        DIDCeremonyError::KeyNotFound
    })?;
    let token_bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "failed to retrieve session-token from keychain");
        DIDCeremonyError::KeychainError
    })?;
    let pending_token = String::from_utf8(token_bytes).map_err(|e| {
        tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
        DIDCeremonyError::KeychainError
    })?;
    Ok(DidCeremonyContext {
        device_key,
        pending_token,
    })
}

/// Fetch the account's reserved repo key with consistent status mapping and diagnostics.
async fn fetch_repo_signing_key(
    state: &oauth::AppState,
    pending_token: &str,
) -> Result<PdsSigningKey, DIDCeremonyError> {
    let response = state
        .custos_client()
        .get_with_bearer("/v1/repo-signing-key", pending_token)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "repo signing key request failed during DID ceremony");
            DIDCeremonyError::NetworkError {
                message: e.to_string(),
            }
        })?;
    let status = response.status();
    if status.as_u16() == 503 {
        return Err(DIDCeremonyError::NoPdsSigningKey);
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to read repo signing key error response");
            "<body read failed>".to_string()
        });
        tracing::error!(status = %status, body = %body, "repo signing key request returned non-success status");
        return Err(DIDCeremonyError::PdsKeyFetchFailed);
    }
    response.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize repo signing key response");
        DIDCeremonyError::PdsKeyFetchFailed
    })
}

/// Run the client-share did:plc ceremony (the ceremony inversion).
///
/// Fetches the PDS repo signing key (`GET /v1/repo-signing-key`), loads-or-generates
/// the client-side share set via `share_ceremony::load_or_create` (staged in the
/// `ceremony-staging` Keychain slot before the state-creating `POST /v1/dids` call —
/// the read-only signing-key `GET` precedes it — so a retry reuses the
/// identical set and set_id), builds the signed did:plc genesis op via
/// `crypto::build_did_plc_genesis_op_multi_rotation_with_external_signer` with
/// `rotationKeys = [device, recovery, PDS]` (ADR-0027) using the device key as signer,
/// and POSTs the op + password + `recoveryKey` + `escrowShare` (the Share 2 envelope —
/// the only share Custos ever sees) to `POST /v1/dids`. On success it persists the DID
/// and the upgraded session token, writes the wallet-generated Share 1 envelope to the
/// per-DID `recovery-share-1:{did}` slot with a read-back verify (per-DID, so a second
/// identity's ceremony cannot overwrite the first's — the re-key flow's convention),
/// and returns `{ did, share3, share3Words }` for the backup screen.
#[tauri::command]
async fn perform_did_ceremony(
    handle: String,
    password: Option<String>,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    let context = load_did_ceremony_context()?;
    let device_key = context.device_key;
    let pending_token = context.pending_token;
    let pds_key = fetch_repo_signing_key(&state, &pending_token).await?;

    // Step 3.5: Generate (or reload from staging) the client-side share set — seed,
    // derived recovery key, and the 2-of-3 envelope split. Staged before the
    // state-creating POST /v1/dids below, so a mid-ceremony retry reuses the identical
    // set (same set_id) instead of orphaning an escrow deposit. Custos only ever
    // receives Share 2.
    let pds_base_url = state.custos_client().base_url_str().to_owned();
    let shares = share_ceremony::load_or_create(&handle, &pds_base_url).map_err(|e| {
        tracing::error!(error = %e, "client-side share generation failed during DID ceremony");
        DIDCeremonyError::ShareGenerationFailed
    })?;

    // Step 4: Build signed genesis op with rotationKeys = [device, recovery, PDS] —
    // device key supreme (the 72h-override backstop), the derived recovery key above the
    // PDS key, the PDS's per-account repo key as the #atproto signing key.
    // On device, the private key never leaves the Secure Enclave; on Simulator and macOS, a software key is used instead.
    let rotation_keys = [
        DidKeyUri(device_key.key_id.clone()),
        DidKeyUri(shares.recovery_key_id.clone()),
        DidKeyUri(pds_key.key_id.clone()),
    ];
    let signing_key = DidKeyUri(pds_key.key_id.clone());

    let genesis_op = build_did_plc_genesis_op_multi_rotation_with_external_signer(
        &rotation_keys,
        &signing_key,
        &handle,
        &pds_base_url,
        |data| {
            device_key::sign(data)
                .map_err(|e| CryptoError::PlcOperation(format!("device signing failed: {e}")))
        },
    )
    .map_err(|e| {
        tracing::error!(error = %e, "genesis op signing failed during DID ceremony");
        DIDCeremonyError::SigningFailed
    })?;

    // Step 6: POST the signed genesis op to the PDS to promote the account to a full DID,
    // depositing the Share 2 envelope in the same request (the client-share ceremony).
    let create_did_req = CreateDidRequest {
        rotation_key_public: device_key.key_id,
        signed_creation_op: Some(serde_json::from_str(&genesis_op.signed_op_json).map_err(
            |e| {
                tracing::error!(error = %e, "genesis op JSON is not valid JSON");
                DIDCeremonyError::SigningFailed
            },
        )?),
        did_web_document: None,
        password,
        recovery_key: Some(shares.recovery_key_id.clone()),
        escrow_share: Some(shares.share2.to_string()),
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

    // Step 8: Store the wallet-generated Share 1 envelope in the per-DID Keychain slot in the
    // iCloud-synchronizable store, then verify the write by reading that same slot back —
    // Share 1's durability is a precondition for tearing down the staging slot later
    // (`confirm_share_backup`). The slot is per-DID (`recovery-share-1:{did}`, the same
    // convention re-key uses) so a second identity's ceremony can never overwrite the first
    // identity's Share 1, and the write carries `kSecAttrSynchronizable` so the share can
    // reach a replacement device — the whole point of the escrow-assisted recovery path.
    // The read-back never consults the device-local slot: only the synchronizable record
    // counts as evidence here.
    // Uses ShareStorageFailed (not KeychainError) because the DID is already committed:
    // retrying the ceremony will hit DidAlreadyExists. The frontend can surface a distinct
    // message rather than telling the user to retry the whole ceremony.
    rekey::store_share1(&create_did_resp.did, shares.share1.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, "DID committed but recovery share 1 keychain write failed");
        DIDCeremonyError::ShareStorageFailed
    })?;
    match rekey::read_share1_synced(&create_did_resp.did) {
        Ok(read_back) if read_back == shares.share1.as_bytes() => {}
        Ok(_) => {
            tracing::error!("recovery share 1 read-back does not match the written value");
            return Err(DIDCeremonyError::ShareStorageFailed);
        }
        Err(e) => {
            tracing::error!(error = %e, "recovery share 1 read-back failed after write");
            return Err(DIDCeremonyError::ShareStorageFailed);
        }
    }

    // Step 9: Provision the identity for child (agent) accounts by persisting the
    // delegation seed derived from this ceremony's recovery seed. This is the only
    // moment in the create flow where that seed exists and the DID is known, so it
    // happens here rather than in `register_created_identity`.
    //
    // Non-fatal: the DID is already committed and the account is fully usable without
    // it, and "Enable agent accounts" re-provisions from the user's shares at any time.
    // Failing the ceremony here would instead strand the user on a DID that
    // `DidAlreadyExists` refuses to re-create.
    if let Err(e) = identity_store::IdentityStore
        .store_delegation_seed(&create_did_resp.did, &shares.delegation_seed)
    {
        tracing::warn!(
            did = %create_did_resp.did,
            error = %e,
            "delegation seed not persisted; identity is unprovisioned for agent accounts"
        );
    }

    Ok(DIDCeremonyResult {
        did: create_did_resp.did,
        share3: shares.share3.to_string(),
        share3_words: shares.share3_words.to_string(),
    })
}

/// Error returned by `confirm_share_backup`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShareBackupError {
    /// Share 1 is not present in its durable Keychain slot — the staging material must
    /// not be destroyed while it is the only home of the seed.
    #[error("recovery share 1 is not durably stored")]
    ShareNotStored,
    #[error("keychain operation failed")]
    KeychainError,
}

/// Confirm the user has saved Share 3 and tear down the ceremony staging slot.
///
/// The teardown order is load-bearing: Share 1 must be verifiably present in the ceremony DID's
/// durable per-DID slot (`recovery-share-1:{did}`, written by `perform_did_ceremony` /
/// `complete_did_web_ceremony`) before the staging record — the seed's and Share 2's last local
/// copy — is destroyed. The DID is threaded from the frontend (the ceremony result's `did`) so
/// the durability check reads the exact identity just created, mirroring the re-key epilogue's
/// `confirm_rekey`. Idempotent; called by the frontend when the Shamir backup screen's
/// confirmation completes.
#[tauri::command]
fn confirm_share_backup(did: String) -> Result<(), ShareBackupError> {
    match rekey::load_share1(&did) {
        Ok(bytes) if !bytes.is_empty() => {}
        Ok(_) => {
            tracing::error!(
                "confirm_share_backup: recovery share 1 is empty; keeping staging slot"
            );
            return Err(ShareBackupError::ShareNotStored);
        }
        Err(ref e) if keychain::is_not_found(e) => {
            tracing::error!("confirm_share_backup: recovery share 1 missing; keeping staging slot");
            return Err(ShareBackupError::ShareNotStored);
        }
        // An operational Keychain failure is not evidence the share is absent —
        // report it as such so the caller can retry rather than re-run the ceremony.
        Err(e) => {
            tracing::error!(error = %e, "confirm_share_backup: keychain read failed; keeping staging slot");
            return Err(ShareBackupError::KeychainError);
        }
    }
    share_ceremony::clear_staging().map_err(|e| {
        tracing::error!(error = %e, "failed to clear ceremony staging slot");
        ShareBackupError::KeychainError
    })
}

#[tauri::command]
/// Prepare the device and reserved repository keys used to compose a did:web document.
async fn prepare_did_web_ceremony(
    state: tauri::State<'_, oauth::AppState>,
) -> Result<DidWebPreparation, DIDCeremonyError> {
    let context = load_did_ceremony_context()?;
    let repo_key = fetch_repo_signing_key(&state, &context.pending_token).await?;
    Ok(DidWebPreparation {
        // The server validates the document's #device against the did:key's multicodec-prefixed
        // multibase (`rotation_key_public` with "did:key:" stripped), so the bare compressed-point
        // encoding in `DevicePublicKey::multibase` can never satisfy it.
        device_key_multibase: context
            .device_key
            .key_id
            .strip_prefix("did:key:")
            .unwrap_or(&context.device_key.key_id)
            .to_string(),
        repo_key_multibase: repo_key
            .key_id
            .strip_prefix("did:key:")
            .unwrap_or(&repo_key.key_id)
            .to_string(),
        pds_url: state
            .custos_client()
            .base_url_str()
            .trim_end_matches('/')
            .to_string(),
    })
}

#[tauri::command]
/// Verify a published did:web document, promote the account, and persist recovery state.
async fn complete_did_web_ceremony(
    document_text: String,
    password: Option<String>,
    enable_managed_hosting: bool,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    let context = load_did_ceremony_context()?;
    let request = CreateDidRequest {
        rotation_key_public: context.device_key.key_id,
        signed_creation_op: None,
        did_web_document: Some(document_text),
        password,
        // did:web promotes with no escrow — a did:web document has no PLC rotationKeys for a
        // recovery key to bind to, so it carries neither client-share field.
        recovery_key: None,
        escrow_share: None,
    };
    let response = state
        .custos_client()
        .post_with_bearer("/v1/dids", &request, &context.pending_token)
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(DIDCeremonyError::DidCreationFailed);
    }
    let created: CreateDidResponse = response
        .json()
        .await
        .map_err(|_| DIDCeremonyError::DidCreationFailed)?;
    // A did:web document has no PLC rotationKeys for a recovery key to bind to, so the did:web
    // ceremony has no share-based recovery: the server generates and returns no shares, and the
    // wallet stores none. (Recovery for a did:web identity is domain/hosting control.)
    //
    // Promotion is already durable and cannot be retried. Persist every irreplaceable response
    // value before the optional hosting toggle so a transient failure cannot strand the user.
    keychain::store_item("session-token", created.session_token.as_bytes())
        .map_err(|_| DIDCeremonyError::KeychainError)?;
    keychain::store_item("did", created.did.as_bytes())
        .map_err(|_| DIDCeremonyError::KeychainError)?;
    if enable_managed_hosting {
        let hosting_result = state
            .custos_client()
            .post_with_bearer(
                "/v1/did-web/hosting",
                &serde_json::json!({ "enabled": true }),
                &created.session_token,
            )
            .await;
        match hosting_result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::warn!(status = %response.status(), did = %created.did, "DID created, but optional managed hosting was not enabled")
            }
            Err(error) => {
                tracing::warn!(error = %error, did = %created.did, "DID created, but optional managed hosting was unreachable")
            }
        }
    }
    Ok(DIDCeremonyResult {
        did: created.did,
        // A did:web identity has no share-based recovery, so there is nothing to back up —
        // the create flow skips the Shamir backup screen for this path.
        share3: String::new(),
        share3_words: String::new(),
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

/// Error returned by `get_available_user_domains`.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling wallet error
/// enums. Every `message` here is diagnostic only (ADR-0031): the screen keys on `code` and
/// writes its own sentence.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum AvailableDomainsError {
    /// The configured PDS answered `describeServer` with a non-2xx.
    #[error("describeServer returned HTTP {status}")]
    ServerError { status: u16 },
    /// The response body could not be parsed as a describeServer document.
    #[error("invalid describeServer response: {message}")]
    InvalidResponse { message: String },
    /// Transport failure reaching the configured PDS.
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Fetch the PDS's configured handle domains (`availableUserDomains` from describeServer) so the
/// client can build the full `{label}.{domain}` handle BEFORE the DID ceremony — ensuring the
/// did:plc genesis op's `alsoKnownAs` carries the real, resolvable handle.
///
/// Returns the (possibly empty) domain list on success; the caller decides what to do when the
/// list is empty.
#[tauri::command]
async fn get_available_user_domains(
    state: tauri::State<'_, oauth::AppState>,
) -> Result<Vec<String>, AvailableDomainsError> {
    let resp = state
        .custos_client()
        .get("/xrpc/com.atproto.server.describeServer")
        .await
        .map_err(|e| AvailableDomainsError::NetworkError {
            message: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(AvailableDomainsError::ServerError {
            status: resp.status().as_u16(),
        });
    }

    let server_info: DescribeServerResponse =
        resp.json()
            .await
            .map_err(|e| AvailableDomainsError::InvalidResponse {
                message: e.to_string(),
            })?;

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
    state.set_custos_client(normalized.clone());

    // Re-read what this host offers rather than trusting a cached answer: the user has
    // just deliberately pointed the wallet at it, which is exactly when a stale verdict
    // (from an earlier configuration of the same host, or a probe made while it was down)
    // would be wrong. Best-effort — an unreachable host here only costs a later re-probe,
    // and the health check above already established the URL is usable.
    pds_capabilities::forget(&normalized);
    let capabilities = pds_capabilities::probe(state.pds_client(), &normalized).await;
    tracing::info!(
        url = %normalized,
        version = ?capabilities.version,
        capabilities = ?capabilities.capabilities,
        "configured PDS capabilities"
    );

    Ok(())
}

/// Report what the configured PDS advertises, so the frontend can offer only the features
/// that host actually supports.
///
/// Answers from the per-host cache when it has one (populated by `save_pds_url` and by
/// every other describeServer call the wallet makes), otherwise describes the server once.
///
/// A host that advertises nothing — every PDS that is not Custos, and a Custos deployment
/// with capabilities switched off — reports an empty list rather than failing. **A host
/// that cannot be reached reports the same empty list**: the caller learns "no capabilities
/// to offer", which is the safe way to degrade, not "this feature is definitively absent".
#[tauri::command]
async fn get_pds_capabilities(
    state: tauri::State<'_, oauth::AppState>,
    pds_url: Option<String>,
) -> Result<pds_capabilities::ServerCapabilities, PdsConfigError> {
    let url = match pds_url {
        Some(url) => normalize_pds_url(&url)?,
        None => match keychain::load_pds_url() {
            Some(url) => url,
            None => {
                // No PDS configured yet: nothing to ask, and no error to report — the
                // frontend is in exactly the state where it offers no host-gated features.
                return Ok(pds_capabilities::ServerCapabilities::none());
            }
        },
    };

    Ok(pds_capabilities::probe(state.pds_client(), &url).await)
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
/// never returns `Err` — callers can safely poll on an interval. The nominal `String` error
/// type is the ADR-0031 allowance for a command that never rejects.
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

/// Error returned by `import_did_web_identity`.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImportDidWebError {
    #[error("not a usable did:web domain: {message}")]
    InvalidDomain { message: String },
    #[error("no DID document found at the domain")]
    DocumentNotFound,
    #[error("the domain's DID document is not usable: {message}")]
    InvalidDocument { message: String },
    #[error("the PDS in the DID document is unreachable")]
    PdsUnreachable,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("failed to persist identity to device storage")]
    KeychainError,
}

/// The imported identity's resolved coordinates, for the UI to route with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedDidWebIdentity {
    pub did: String,
    /// Preferred handle from the live document's `alsoKnownAs`, when it carries one.
    pub handle: Option<String>,
    pub pds_url: String,
}

/// Normalize user input ("example.com", "https://example.com/", "did:web:example.com")
/// to the hostname-form did:web the wallet supports. The shape rules mirror the
/// frontend's `didWebFromDomain`: no scheme, path, port, or userinfo — a colon would
/// smuggle a port or path segment into the document URL.
fn normalize_did_web_input(input: &str) -> Result<String, ImportDidWebError> {
    let mut host = input.trim().to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix("did:web:") {
        host = rest.to_string();
    }
    host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let valid_shape = !host.is_empty()
        && host.contains('.')
        && !host.contains([':', '/', '@'])
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    if !valid_shape {
        return Err(ImportDidWebError::InvalidDomain {
            message: "enter a public domain name without a path or port".to_string(),
        });
    }
    Ok(format!("did:web:{host}"))
}

/// Persist a resolved did:web identity into `IdentityStore` (the network-free half of
/// `import_did_web_identity`, split out for tests).
///
/// `rotationKeys` is deliberately empty: a did:web document has no PLC rotation keys, and
/// the per-DID device key minted here becomes authoritative only when a later flow (the
/// migration identity leg) publishes it as `#device` in the live document — showing it as
/// a root key before that would be a lie.
fn persist_imported_did_web(
    store: &identity_store::IdentityStore,
    did: &str,
    pds_url: &str,
    also_known_as: &[String],
) -> Result<Option<String>, ImportDidWebError> {
    if let Err(e) = store.add_identity(did) {
        if !matches!(e, identity_store::IdentityStoreError::IdentityAlreadyExists) {
            tracing::error!(did = %did, error = %e, "import_did_web_identity: add_identity failed");
            return Err(ImportDidWebError::KeychainError);
        }
    }
    // Mint the per-DID device key now so `detect_migration_path`'s did:web branch (which
    // requires a managed DID with a device key) can classify this identity as SelfSigned.
    store.get_or_create_device_key(did).map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: device key mint failed");
        ImportDidWebError::KeychainError
    })?;

    let did_doc_json = serde_json::json!({
        "did": did,
        "alsoKnownAs": also_known_as,
        "rotationKeys": [],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_url,
            }
        }
    })
    .to_string();
    store.store_did_doc(did, &did_doc_json).map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: store_did_doc failed");
        ImportDidWebError::KeychainError
    })?;

    Ok(migration_orchestrator::extract_handle_from_also_known_as(
        also_known_as,
    ))
}

/// Bring an EXISTING did:web identity under wallet management, so the method-agnostic
/// flows (outbound migration first among them) can operate on it.
///
/// For did:web there is no claim ceremony: control is proven by the domain (publishing
/// the document) and, later, by the source-PDS password login — so "import" is resolving
/// the live document, registering the DID, and minting a local device key. Registering an
/// identity you don't control grants nothing: every consequential flow still demands the
/// account password and a byte-exact document publish on the domain.
///
/// Idempotent — re-importing an already-managed DID refreshes its cached document.
#[tauri::command]
async fn import_did_web_identity(
    input: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<ImportedDidWebIdentity, ImportDidWebError> {
    let did = normalize_did_web_input(&input)?;

    // Resolve + validate the live document (fetch, parse, atproto_pds extraction, PDS
    // reachability probe) through the same seam every other did:web read uses.
    let (pds_url, doc) = state.pds_client().discover_pds(&did).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: discovery failed");
        match e {
            pds_client::PdsClientError::DidNotFound => ImportDidWebError::DocumentNotFound,
            pds_client::PdsClientError::PdsUnreachable { .. } => ImportDidWebError::PdsUnreachable,
            pds_client::PdsClientError::InvalidResponse { message } => {
                ImportDidWebError::InvalidDocument { message }
            }
            other => ImportDidWebError::NetworkError {
                message: other.to_string(),
            },
        }
    })?;

    let store = identity_store::IdentityStore;
    let handle = persist_imported_did_web(&store, &did, &pds_url, &doc.also_known_as)?;

    tracing::info!(did = %did, pds_url = %pds_url, "existing did:web identity imported");
    Ok(ImportedDidWebIdentity {
        did,
        handle,
        pds_url,
    })
}

/// Best-effort one-time migration of a pre-unification install's global `recovery-share-1` slot
/// into the primary identity's per-DID slot.
///
/// Installs that onboarded before the per-DID unification wrote Share 1 to a single app-global
/// `recovery-share-1` slot; the recovery ceremony now reads `recovery-share-1:{did}`. This copies
/// that global share into the per-DID slot for the primary DID (the create flow persists it under
/// the legacy `"did"` Keychain item) so those users keep share-based recovery once the ceremony
/// switches to the per-DID slot. Additive and idempotent: it never deletes the global slot and
/// skips when the per-DID slot already holds a value. Fully best-effort — any Keychain hiccup is
/// logged and swallowed, never blocking launch.
fn migrate_global_share1_to_per_did() {
    // The legacy global slot; absent on a fresh (post-unification) install — nothing to migrate.
    let global = match keychain::get_item("recovery-share-1") {
        // Sensitive key material — wipe the in-memory copy when this scope ends.
        Ok(bytes) if !bytes.is_empty() => zeroize::Zeroizing::new(bytes),
        Ok(_) => return,
        Err(ref e) if keychain::is_not_found(e) => return,
        Err(e) => {
            tracing::warn!(error = %e, "share1 migration: global slot read failed; skipping");
            return;
        }
    };
    // The primary identity's DID (the create/did:web flow persists it under "did").
    let did = match keychain::get_item("did") {
        Ok(bytes) if !bytes.is_empty() => match String::from_utf8(bytes) {
            Ok(did) => did,
            Err(_) => {
                tracing::warn!("share1 migration: stored DID is not valid UTF-8; skipping");
                return;
            }
        },
        // No primary DID recorded yet: nothing to key the per-DID slot on.
        _ => return,
    };
    let per_did = rekey::recovery_share1_account(&did);
    // Never clobber an already-populated per-DID slot — a newer ceremony or re-key owns it.
    match keychain::get_item(&per_did) {
        Ok(bytes) if !bytes.is_empty() => return,
        Ok(_) => {}
        Err(ref e) if keychain::is_not_found(e) => {}
        Err(e) => {
            tracing::warn!(error = %e, "share1 migration: per-DID slot read failed; skipping");
            return;
        }
    }
    match keychain::store_item(&per_did, &global) {
        Ok(()) => tracing::info!(
            "migrated global recovery-share-1 into the per-DID slot for the primary identity"
        ),
        Err(e) => tracing::warn!(error = %e, "share1 migration: per-DID slot write failed"),
    }
}

/// Reconcile every managed identity's Share 1 into the two Keychain slots it should occupy.
///
/// Runs the two additive hops in order, so a single launch can carry a pre-unification install
/// all the way: app-global → per-DID device-local ([`migrate_global_share1_to_per_did`]), then
/// per-DID device-local → per-DID iCloud-synchronizable ([`backfill_synced_share1`]).
fn reconcile_share1_slots() {
    migrate_global_share1_to_per_did();
    backfill_synced_share1();
}

/// Best-effort launch repair: register the primary DID in `IdentityStore` if the create flow
/// finished without it.
///
/// The create flow persists its DID under the legacy `"did"` account during the ceremony
/// (`perform_did_ceremony`, step 7) and only later registers it in the managed index via
/// `register_created_identity`. The home screen lists identities from the managed index alone,
/// so if that later step does not land — a Keychain fault, or the app never reaching it — the
/// identity exists, is funded with keys and shares, and is invisible. Nothing retried it: the
/// state survived relaunch, and the only exit was the share-recovery ceremony, which re-adds
/// the DID as a side effect of rebuilding an identity that was never actually lost.
///
/// This closes that hole from the other side. The DID is written *before* the fragile step, so
/// it is always on hand; re-registering it is idempotent and additive.
///
/// **Never resurrects a forgotten identity.** Nothing clears the legacy `"did"` account — not
/// local removal, not migration — so "absent from the managed index" alone cannot distinguish
/// a stranded create from a deliberate `forget_identity_locally`. The tombstone index
/// (`IdentityStore::is_forgotten`) carries that intent, and it fails closed: an unreadable
/// tombstone index means no re-registration.
///
/// The DID document is deliberately not rebuilt here. `IdentityListHome` already treats a
/// missing document as a refresh trigger and re-fetches it from plc.directory on first render,
/// which needs neither the handle nor the PDS URL at launch.
fn reconcile_created_identity() {
    let did = match keychain::get_item("did") {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(did) if !did.is_empty() => did,
            Ok(_) => return,
            Err(_) => {
                tracing::warn!("identity reconcile: stored DID is not valid UTF-8; skipping");
                return;
            }
        },
        // No primary DID recorded: a fresh install, or an import-only wallet.
        _ => return,
    };

    let store = identity_store::IdentityStore;
    match store.list_identities() {
        Ok(dids) if dids.contains(&did) => return,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "identity reconcile: managed-DID index unreadable; skipping");
            return;
        }
    }

    if store.is_forgotten(&did) {
        tracing::debug!(
            did = %did,
            "identity reconcile: DID was unregistered on purpose; leaving it out"
        );
        return;
    }

    if let Err(e) = store.add_identity(&did) {
        tracing::warn!(did = %did, error = %e, "identity reconcile: add_identity failed");
        return;
    }

    // Mirrors `register_created_identity`: the create flow's genesis op was signed with the
    // global device key, so alias the per-DID key to it. Non-fatal — the identity lists either
    // way; only the "root key" badge and PLC-monitor classification degrade without it.
    if let Err(e) = store.adopt_global_device_key(&did) {
        tracing::warn!(did = %did, error = %e, "identity reconcile: adopt_global_device_key failed");
    }

    tracing::info!(
        did = %did,
        "identity reconcile: re-registered a created identity missing from the managed index"
    );
}

/// Best-effort launch backfill: copy each managed identity's device-local Share 1 into the
/// iCloud-synchronizable slot.
///
/// Wallet builds before the synchronizable write path wrote Share 1 with no
/// `kSecAttrSynchronizable` attribute, which meant it never left the device that created it —
/// so the escrow-assisted recovery path (Share 1 from iCloud + Share 2 from escrow, no
/// user-held secret) was unavailable on a replacement device. This puts an existing share into
/// the store that can travel.
///
/// **Copy, never flip.** The synchronizable and device-local records are distinct items, and
/// `SecItem.h` documents the key for *targeting* synced items in update/delete but never for
/// changing an item's synchronizability — so an in-place flip is unsupported. Copying is the
/// safer shape regardless: the device-local slot may be the share's only surviving copy, and
/// it is preserved untouched.
///
/// Additive and idempotent: a populated synchronizable slot is never overwritten, and only a
/// device-local value that decodes as a valid v2 index-1 envelope is copied (a bare
/// pre-envelope share cannot auto-load into the recovery ceremony anyway, so syncing it would
/// spend an iCloud secret for no recovery benefit). Fully best-effort — any Keychain hiccup is
/// logged and swallowed, never blocking launch.
///
/// **What this cannot reach.** It runs on-device, so it only helps a device that still holds
/// Share 1 *and* opens this build at least once. A user whose device is already lost is not
/// helped and stays on Share 2 + Share 3 for the life of that identity. And with iCloud
/// Keychain switched off, the item is written carrying the attribute and propagates nowhere;
/// enabling it later syncs it with no further involvement from this app.
fn backfill_synced_share1() {
    for did in share1_backfill_dids() {
        // Never overwrite a populated synchronizable slot — a ceremony, re-key, or recovery
        // epilogue owns it, and it is by definition at least as current as the local one.
        match rekey::read_share1_synced(&did) {
            Ok(bytes) if !bytes.is_empty() => continue,
            Ok(_) => {}
            Err(ref e) if keychain::is_not_found(e) => {}
            Err(e) => {
                tracing::warn!(error = %e, "share1 backfill: synced slot read failed; skipping");
                continue;
            }
        }
        // Sensitive key material — wipe the in-memory copy when this scope ends.
        let local = match keychain::get_item(&rekey::recovery_share1_account(&did)) {
            Ok(bytes) if !bytes.is_empty() => zeroize::Zeroizing::new(bytes),
            Ok(_) => continue,
            Err(ref e) if keychain::is_not_found(e) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "share1 backfill: local slot read failed; skipping");
                continue;
            }
        };
        if share_recovery::decode_share1_envelope(&local).is_none() {
            tracing::debug!("share1 backfill: local slot is not a v2 Share 1 envelope; skipping");
            continue;
        }
        match rekey::store_share1(&did, &local) {
            Ok(()) => tracing::info!("backfilled Share 1 into the iCloud-synchronizable slot"),
            Err(e) => tracing::warn!(error = %e, "share1 backfill: synced slot write failed"),
        }
    }
}

/// The DIDs the backfill sweeps: every identity in `IdentityStore`, plus the legacy primary
/// DID under the `"did"` account. The union matters because a pre-unification install may hold
/// a share for a DID that was never registered in the managed-DIDs index.
fn share1_backfill_dids() -> Vec<String> {
    let mut dids = identity_store::IdentityStore
        .list_identities()
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "share1 backfill: managed-DID index unreadable");
            Vec::new()
        });
    if let Ok(bytes) = keychain::get_item("did") {
        if let Ok(did) = String::from_utf8(bytes) {
            if !did.is_empty() && !dids.contains(&did) {
                dids.push(did);
            }
        }
    }
    dids
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

    // Mobile-only plugins: biometric (Face ID / Touch ID) gate on signing actions, the iOS Share
    // Pane, and camera QR scanning for the OAuth consent scan path. Registering them behind
    // `#[cfg(mobile)]` keeps the macOS host build and its test suite free of dependencies they
    // cannot compile.
    #[cfg(mobile)]
    let builder = builder
        .plugin(tauri_plugin_biometric::init())
        .plugin(tauri_plugin_sharesheet::init())
        .plugin(tauri_plugin_barcode_scanner::init());

    builder
        .setup(|app| {
            // Restore PDS URL from Keychain if previously configured.
            if let Some(url) = keychain::load_pds_url() {
                app.state::<oauth::AppState>().set_custos_client(url);
            }

            // Best-effort, idempotent: move a pre-unification install's global Share 1 into
            // the primary identity's per-DID slot so share-based recovery survives the switch,
            // then copy every managed identity's device-local Share 1 into the
            // iCloud-synchronizable slot so it can reach a replacement device. Both hops are
            // additive; neither deletes the slot it read from.
            reconcile_share1_slots();

            // Best-effort, idempotent: re-register a created identity whose create flow
            // persisted its DID but never reached the managed index, so it stops being
            // invisible on the home screen. Skips DIDs the user unregistered on purpose.
            reconcile_created_identity();

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

            // iOS only: register the background media-backup task and submit the first
            // request, so an opted-in identity's iCloud mirror stays topped up without the
            // app being opened. Must run before app launch completes — `setup` does. A
            // no-op off-device (scheduling is a device concern; the harness is untouched).
            #[cfg(target_os = "ios")]
            bg_backup::register_and_schedule(app.handle());

            // iOS only: install the APNs device-token callbacks and ask for notification
            // permission. Must run in `setup` — the delegate methods have to exist before iOS
            // delivers the token, which it does shortly after launch. Off-device this is absent
            // entirely, and every caller treats a token-less device as an ordinary state.
            #[cfg(target_os = "ios")]
            apns::register_for_remote_notifications(app.handle());

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_account,
            perform_did_ceremony,
            confirm_share_backup,
            prepare_did_web_ceremony,
            complete_did_web_ceremony,
            register_handle,
            register_created_identity,
            import_did_web_identity,
            check_handle_resolution,
            get_available_user_domains,
            list_identities,
            get_stored_did_doc,
            refresh_did_doc,
            get_device_key_id,
            get_pds_url,
            save_pds_url,
            get_pds_capabilities,
            get_appearance_preference,
            set_appearance_preference,
            diagnostics::export_diagnostics,
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
            agents::agent_accounts_provisioned,
            agents::mint_child_from_claim,
            oauth_consent::preview_oauth_consent,
            oauth_consent::preview_oauth_consent_by_request_id,
            oauth_consent::confirm_oauth_consent,
            app_passwords::create_app_password,
            app_passwords::list_app_passwords,
            app_passwords::revoke_app_password,
            blob_backup::get_blob_backup_status,
            blob_backup::set_blob_backup_enabled,
            blob_backup::run_blob_backup,
            blob_backup::restore_blob_backup,
            repo_backup::get_repo_backup_status,
            repo_backup::set_repo_backup_enabled,
            repo_backup::run_repo_backup,
            repo_backup::export_repo_backup,
            bg_backup::get_background_backup_settings,
            bg_backup::set_background_backup_settings,
            notifications::register_for_notifications,
            notifications::refresh_notification_sender_keys,
            notifications::get_notification_diagnostics,
            notifications::clear_notification_failures,
            notification_routes::take_pending_notification_route,
            plc_monitor::check_identity_status,
            plc_monitor::get_monitor_history,
            recovery::build_recovery_override_cmd,
            rotate_repo_key::build_repo_key_rotation_cmd,
            rotate_repo_key::submit_repo_key_rotation_cmd,
            rekey::build_rekey_cmd,
            rekey::submit_rekey_cmd,
            rekey::confirm_rekey_cmd,
            rekey::rekey_in_progress_cmd,
            self_held_kit::build_self_held_kit_cmd,
            self_held_kit::submit_self_held_kit_cmd,
            self_held_kit::confirm_self_held_kit_cmd,
            self_held_kit::self_held_kit_in_progress_cmd,
            self_held_kit::self_held_kit_escrow_offer_cmd,
            recovery::submit_recovery_override_cmd,
            identity_removal::get_identity_removal_route,
            identity_removal::request_identity_removal,
            identity_removal::confirm_identity_removal,
            identity_removal::tombstone_identity,
            identity_removal::list_pending_removals,
            identity_removal::forget_identity_locally,
            migrate::detect_migration_path_cmd,
            migrate::build_migration_op_cmd,
            migrate::submit_migration_op_cmd,
            migrate::build_did_web_migration_document_cmd,
            migrate::submit_did_web_migration_document_cmd,
            migration_orchestrator::prepare_migration,
            migration_orchestrator::authenticate_migration_source,
            migration_orchestrator::create_destination_account,
            migration_orchestrator::transfer_repo,
            migration_orchestrator::transfer_blobs,
            migration_orchestrator::transfer_preferences,
            migration_orchestrator::verify_import,
            migration_orchestrator::arm_identity_leg,
            migration_orchestrator::finalize_migration,
            disaster_recovery::prepare_disaster_recovery,
            disaster_recovery::enroll_recovery_signing_key,
            disaster_recovery::await_recovery_key_visibility,
            disaster_recovery::create_recovery_destination_account,
            disaster_recovery::recovery_transfer_repo,
            sovereign_session::sovereign_login,
            session_provider::ensure_identity_session,
            password_unlock::get_identity_unlock_route,
            password_unlock::unlock_identity_with_password,
            handle_change::change_handle_cmd,
            handle_change::get_identity_handle_domains,
            handle_change::check_custom_handle_dns,
            endpoint_repair::repair_hosting_endpoint,
            share_recovery::start_share_recovery,
            share_recovery::add_recovery_share,
            share_recovery::remove_recovery_share,
            share_recovery::initiate_escrow_release,
            share_recovery::request_escrow_release,
            share_recovery::verify_recovery_shares,
            share_recovery::recover_identity,
            share_recovery::run_recovery_epilogue,
            share_recovery::get_pending_recovery_epilogue,
            share_recovery::confirm_recovery_backup,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app, event| {
            // The Camera-app half of the consent QR. tao runs the UIScene lifecycle on iOS,
            // so a URL opened from outside the app arrives as `scene:openURLContexts:` and
            // surfaces here as `RunEvent::Opened` — never through an application-delegate
            // `openURL` method (adding one is dead code under scenes). Routed through the
            // same pending-route slot + event a tapped notification uses, so cold-start
            // drain and warm-foreground listener both already handle it.
            if let tauri::RunEvent::Opened { urls } = event {
                use tauri::Emitter;
                for url in urls {
                    if let Some(route) = notification_routes::route_from_handoff_url(url.as_str()) {
                        notification_routes::store_pending_route(route.clone());
                        let _ = app.emit("notification_route", route);
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CreateDidRequest serialization --
    #[test]
    fn create_did_request_serializes_password_and_camel_case() {
        let req = CreateDidRequest {
            rotation_key_public: "did:key:z123".into(),
            signed_creation_op: Some(serde_json::json!({"type": "plc_operation"})),
            did_web_document: None,
            password: Some("mysecretpassword".into()),
            recovery_key: Some("did:key:zRecovery".into()),
            escrow_share: Some("SHARE2ENVELOPE".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["rotationKeyPublic"], "did:key:z123");
        assert_eq!(json["password"], "mysecretpassword");
        assert!(json["signedCreationOp"].is_object());
        assert_eq!(json["recoveryKey"], "did:key:zRecovery");
        assert_eq!(json["escrowShare"], "SHARE2ENVELOPE");
    }

    /// A passwordless ceremony omits `password` from the wire entirely — not `null`, not `""`.
    ///
    /// This is the whole contract of the `optionalPassword` capability: the server refuses an
    /// empty string under either policy (it cannot tell one from an uninitialized field), and a
    /// JSON `null` would deserialize to the same `None` but is a different thing to send. Only an
    /// absent key is an unambiguous request for a passwordless account, which is what
    /// `skip_serializing_if` buys — and nothing else here would catch its removal.
    #[test]
    fn create_did_request_omits_password_entirely_when_passwordless() {
        let req = CreateDidRequest {
            rotation_key_public: "did:key:z123".into(),
            signed_creation_op: Some(serde_json::json!({"type": "plc_operation"})),
            did_web_document: None,
            password: None,
            recovery_key: Some("did:key:zRecovery".into()),
            escrow_share: Some("SHARE2ENVELOPE".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(
            json.get("password").is_none(),
            "a passwordless request must omit the key, not send null or an empty string; got: {}",
            json["password"]
        );
        // The rest of the ceremony is unaffected by the password's absence.
        assert_eq!(json["rotationKeyPublic"], "did:key:z123");
        assert_eq!(json["escrowShare"], "SHARE2ENVELOPE");
    }

    /// The did:web request shape carries no client-share fields — a did:web identity has no
    /// PLC rotationKeys for a recovery key to bind to, so it promotes with no escrow.
    #[test]
    fn create_did_request_omits_absent_client_share_fields() {
        let req = CreateDidRequest {
            rotation_key_public: "did:key:z123".into(),
            signed_creation_op: None,
            did_web_document: Some("{}".into()),
            password: Some("mysecretpassword".into()),
            recovery_key: None,
            escrow_share: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("recoveryKey").is_none());
        assert!(json.get("escrowShare").is_none());
    }

    // -- CreateDidResponse deserializes the share-less body the server always returns --
    #[test]
    fn create_did_response_deserializes_without_shares() {
        let resp: CreateDidResponse = serde_json::from_str(
            r#"{"did":"did:plc:abc","session_token":"tok","did_document":{},"status":"active"}"#,
        )
        .unwrap();
        assert_eq!(resp.did, "did:plc:abc");
        assert_eq!(resp.session_token, "tok");
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
            share3_words: "arena baker cabin".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["did"], "did:plc:abcdefghijklmnopqrstuvwx");
        assert_eq!(
            json["share3"],
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"
        );
        assert_eq!(json["share3Words"], "arena baker cabin");
    }

    #[test]
    fn did_ceremony_result_serializes_share3_in_camel_case() {
        let share = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST";
        let result = DIDCeremonyResult {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            share3: share.into(),
            share3_words: String::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["share3"], share);
    }

    // -- ShareBackupError serialization --
    #[test]
    fn share_backup_error_variants_serialize_correctly() {
        let json = serde_json::to_value(&ShareBackupError::ShareNotStored).unwrap();
        assert_eq!(json["code"], "SHARE_NOT_STORED");
        let json = serde_json::to_value(&ShareBackupError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- confirm_share_backup teardown ordering --
    #[test]
    fn confirm_share_backup_requires_durable_share1() {
        keychain::clear_for_test();
        let did = "did:plc:aliceceremony";
        share_ceremony::load_or_create("alice.example.com", "https://pds.example.com").unwrap();

        // Share 1 not yet in its durable per-DID slot: the staging record must survive.
        assert!(matches!(
            confirm_share_backup(did.to_string()),
            Err(ShareBackupError::ShareNotStored)
        ));
        assert!(keychain::get_item(share_ceremony::STAGING_ACCOUNT).is_ok());

        // A different identity's Share 1 must NOT satisfy this DID's durability check — the
        // teardown is gated on the exact ceremony DID's slot, not any global one.
        keychain::store_item(
            &rekey::recovery_share1_account("did:plc:someoneelse"),
            b"OTHER1",
        )
        .unwrap();
        assert!(matches!(
            confirm_share_backup(did.to_string()),
            Err(ShareBackupError::ShareNotStored)
        ));
        assert!(keychain::get_item(share_ceremony::STAGING_ACCOUNT).is_ok());

        // Once THIS DID's Share 1 is durably stored, confirmation tears the staging slot down.
        // The synchronizable slot is what a fresh ceremony writes; the gate must see it.
        rekey::store_share1(did, b"SHARE1ENVELOPE").unwrap();
        confirm_share_backup(did.to_string()).expect("confirmation should succeed");
        assert!(matches!(
            keychain::get_item(share_ceremony::STAGING_ACCOUNT),
            Err(ref e) if keychain::is_not_found(e)
        ));
        // Idempotent repeat.
        confirm_share_backup(did.to_string()).expect("repeat confirmation is a no-op");
    }

    // -- legacy global -> per-DID Share 1 migration --
    #[test]
    fn migrate_global_share1_copies_into_primary_per_did_slot() {
        keychain::clear_for_test();
        let did = "did:plc:legacyprimary";

        // Pre-unification install: Share 1 in the global slot, primary DID under "did", and no
        // per-DID slot yet.
        keychain::store_item("recovery-share-1", b"LEGACY1").unwrap();
        keychain::store_item("did", did.as_bytes()).unwrap();

        migrate_global_share1_to_per_did();

        // The per-DID slot now mirrors the global one; the global slot is left intact.
        assert_eq!(
            keychain::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            b"LEGACY1"
        );
        assert_eq!(keychain::get_item("recovery-share-1").unwrap(), b"LEGACY1");
    }

    #[test]
    fn migrate_global_share1_never_clobbers_existing_per_did_slot() {
        keychain::clear_for_test();
        let did = "did:plc:legacyprimary";

        // A per-DID slot already populated by a fresh ceremony/re-key must win over any stale
        // global slot left behind.
        keychain::store_item("recovery-share-1", b"STALE_GLOBAL").unwrap();
        keychain::store_item("did", did.as_bytes()).unwrap();
        keychain::store_item(&rekey::recovery_share1_account(did), b"CURRENT_PER_DID").unwrap();

        migrate_global_share1_to_per_did();

        assert_eq!(
            keychain::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            b"CURRENT_PER_DID"
        );
    }

    #[test]
    fn migrate_global_share1_noop_without_global_slot() {
        keychain::clear_for_test();
        let did = "did:plc:freshinstall";
        keychain::store_item("did", did.as_bytes()).unwrap();

        // Fresh (post-unification) install has no global slot: nothing is written.
        migrate_global_share1_to_per_did();

        assert!(matches!(
            keychain::get_item(&rekey::recovery_share1_account(did)),
            Err(ref e) if keychain::is_not_found(e)
        ));
    }

    // -- device-local -> iCloud-synchronizable Share 1 backfill --

    /// A real v2 index-1 Share 1 envelope, produced the way the ceremony produces one.
    /// The backfill only copies bytes that decode as such, so fixtures must be genuine.
    fn ceremony_share1() -> String {
        let set =
            share_ceremony::load_or_create("alice.example.com", "https://pds.example.com").unwrap();
        let share1 = set.share1.to_string();
        share_ceremony::clear_staging().unwrap();
        share1
    }

    #[test]
    fn backfill_copies_local_share1_into_the_synced_slot_and_keeps_the_local_one() {
        keychain::clear_for_test();
        let did = "did:plc:preSyncInstall";
        let share1 = ceremony_share1();

        // A build from before the synchronizable write path: Share 1 exists, but only in the
        // device-local store, where it can never reach a replacement device.
        identity_store::IdentityStore.add_identity(did).unwrap();
        keychain::store_item(&rekey::recovery_share1_account(did), share1.as_bytes()).unwrap();
        assert!(rekey::read_share1_synced(did).is_err());

        backfill_synced_share1();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
        // Copy, never move: the local slot may be the share's only surviving copy.
        assert_eq!(
            keychain::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            share1.as_bytes()
        );

        // Idempotent: a second launch changes nothing.
        backfill_synced_share1();
        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
    }

    #[test]
    fn backfill_never_overwrites_a_populated_synced_slot() {
        keychain::clear_for_test();
        let did = "did:plc:alreadysynced";

        // A re-key or recovery epilogue owns the synchronizable slot; a stale local copy from
        // before that rotation must not be allowed to overwrite it.
        identity_store::IdentityStore.add_identity(did).unwrap();
        rekey::store_share1(did, ceremony_share1().as_bytes()).unwrap();
        let current = rekey::read_share1_synced(did).unwrap();
        keychain::store_item(&rekey::recovery_share1_account(did), b"STALE_LOCAL").unwrap();

        backfill_synced_share1();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), current);
    }

    #[test]
    fn backfill_skips_a_local_slot_that_is_not_a_v2_share1_envelope() {
        keychain::clear_for_test();
        let did = "did:plc:bareshareinstall";

        // did:web ceremonies stored a bare base32 share, which the recovery ceremony's
        // auto-load cannot use anyway — syncing it would spend an iCloud secret for nothing.
        identity_store::IdentityStore.add_identity(did).unwrap();
        keychain::store_item(&rekey::recovery_share1_account(did), b"NOTANENVELOPE").unwrap();

        backfill_synced_share1();

        assert!(matches!(
            rekey::read_share1_synced(did),
            Err(ref e) if keychain::is_not_found(e)
        ));
    }

    #[test]
    fn backfill_reaches_a_legacy_primary_did_absent_from_the_managed_index() {
        keychain::clear_for_test();
        let did = "did:plc:legacyprimaryonly";
        let share1 = ceremony_share1();

        // Pre-unification install: the global slot plus a primary DID that was never
        // registered in `managed-dids`. One launch must carry it through both hops.
        keychain::store_item("recovery-share-1", share1.as_bytes()).unwrap();
        keychain::store_item("did", did.as_bytes()).unwrap();

        reconcile_share1_slots();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
        // Neither source slot is disturbed.
        assert_eq!(
            keychain::get_item("recovery-share-1").unwrap(),
            share1.as_bytes()
        );
        assert_eq!(
            keychain::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            share1.as_bytes()
        );
    }

    // -- created-identity reconciliation --

    #[test]
    fn reconcile_registers_a_created_identity_missing_from_the_managed_index() {
        keychain::clear_for_test();
        let did = "did:plc:strandedcreate";

        // The state the reported bug leaves behind: the ceremony persisted the DID, but
        // `register_created_identity` never landed, so the home screen lists nothing.
        keychain::store_item("did", did.as_bytes()).unwrap();
        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());

        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
    }

    #[test]
    fn reconcile_never_resurrects_a_deliberately_forgotten_identity() {
        keychain::clear_for_test();
        let did = "did:plc:forgottenonpurpose";

        // Forgetting an identity locally leaves the legacy "did" slot untouched, so the
        // tombstone is the only thing standing between the user's decision and a relaunch
        // putting the identity straight back on the home screen.
        keychain::store_item("did", did.as_bytes()).unwrap();
        identity_store::IdentityStore.add_identity(did).unwrap();
        identity_store::IdentityStore.remove_identity(did).unwrap();

        reconcile_created_identity();

        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reconcile_is_idempotent_and_never_duplicates() {
        keychain::clear_for_test();
        let did = "did:plc:idempotentreconcile";
        keychain::store_item("did", did.as_bytes()).unwrap();

        reconcile_created_identity();
        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
    }

    #[test]
    fn reconcile_is_a_no_op_without_a_primary_did() {
        keychain::clear_for_test();

        // A fresh install, or an import-only wallet: nothing to reconcile from.
        reconcile_created_identity();

        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reconcile_leaves_an_already_registered_identity_alone() {
        keychain::clear_for_test();
        let did = "did:plc:alreadyregistered";
        keychain::store_item("did", did.as_bytes()).unwrap();
        identity_store::IdentityStore.add_identity(did).unwrap();

        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
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

    // -- import_did_web_identity --

    #[test]
    fn normalize_did_web_input_accepts_domain_did_and_url_forms() {
        for input in [
            "malpercio.dev",
            "  Malpercio.DEV ",
            "https://malpercio.dev/",
            "did:web:malpercio.dev",
        ] {
            assert_eq!(
                normalize_did_web_input(input).unwrap(),
                "did:web:malpercio.dev",
                "input {input:?}"
            );
        }
    }

    #[test]
    fn normalize_did_web_input_rejects_unsupported_shapes() {
        // Ports, paths, userinfo, bare labels, and empty input all refuse rather than
        // misresolve into a wrong document URL.
        for input in [
            "",
            "localhost",
            "example.com:8080",
            "did:web:example.com:user:alice",
            "example.com/path",
            "user@example.com",
            ".example.com",
            "example.com.",
        ] {
            assert!(
                matches!(
                    normalize_did_web_input(input),
                    Err(ImportDidWebError::InvalidDomain { .. })
                ),
                "input {input:?} should be rejected"
            );
        }
    }

    #[test]
    fn persist_imported_did_web_registers_and_stores_doc() {
        crate::keychain::clear_for_test();
        let store = identity_store::IdentityStore;
        let did = "did:web:import.example";
        let aka = vec!["at://import.example".to_string()];

        let handle = persist_imported_did_web(&store, did, "https://pds.example", &aka).unwrap();
        assert_eq!(handle.as_deref(), Some("import.example"));

        // Registered, device key minted, and the stored doc carries the card fields
        // with rotationKeys honestly empty (a did:web has none until migration
        // publishes #device).
        assert!(store.list_identities().unwrap().contains(&did.to_string()));
        assert!(store.get_or_create_device_key(did).is_ok());
        let doc: serde_json::Value =
            serde_json::from_str(&store.get_did_doc(did).unwrap().unwrap()).unwrap();
        assert_eq!(doc["did"], did);
        assert_eq!(doc["alsoKnownAs"][0], "at://import.example");
        assert_eq!(doc["rotationKeys"].as_array().unwrap().len(), 0);
        assert_eq!(
            doc["services"]["atproto_pds"]["endpoint"],
            "https://pds.example"
        );

        // Idempotent: a re-import refreshes rather than fails.
        let again = persist_imported_did_web(&store, did, "https://pds2.example", &aka).unwrap();
        assert_eq!(again.as_deref(), Some("import.example"));
        let doc: serde_json::Value =
            serde_json::from_str(&store.get_did_doc(did).unwrap().unwrap()).unwrap();
        assert_eq!(
            doc["services"]["atproto_pds"]["endpoint"],
            "https://pds2.example"
        );

        let _ = store.remove_identity(did);
    }

    #[test]
    fn import_did_web_error_serializes_as_code() {
        let json = serde_json::to_value(ImportDidWebError::DocumentNotFound).unwrap();
        assert_eq!(json["code"], "DOCUMENT_NOT_FOUND");
        let json = serde_json::to_value(ImportDidWebError::InvalidDomain {
            message: "x".into(),
        })
        .unwrap();
        assert_eq!(json["code"], "INVALID_DOMAIN");
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
