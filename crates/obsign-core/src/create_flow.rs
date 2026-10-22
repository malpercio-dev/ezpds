// pattern: Imperative Shell

//! The create flow: the door through which a new identity is created on a Custos PDS.
//!
//! The commands, in the order the screens call them: `create_account` (device key +
//! `POST /v1/accounts/mobile`; tokens to the Keychain), then one DID ceremony —
//! `perform_did_ceremony` (the client-share did:plc ceremony, see its doc) or the did:web pair
//! `prepare_did_web_ceremony` / `complete_did_web_ceremony` (compose and export a reviewed
//! `did.json`; submit only once resolvable) — then `confirm_share_backup` (the ceremony teardown
//! gate: Share 1 durable before the staging slot dies), `register_handle`, and
//! `register_created_identity` (the identity enters `IdentityStore`, or the home screen never
//! lists it). `get_available_user_domains` feeds handle composition before the ceremony;
//! `check_handle_resolution` is the post-registration propagation poll.
//!
//! The flow's cross-step state is three Keychain items — [`DEVICE_TOKEN_ACCOUNT`],
//! [`SESSION_TOKEN_ACCOUNT`] (pending before the ceremony, upgraded after it), and
//! [`LEGACY_DID_ACCOUNT`] — which the shell's startup reconcile reads to finish a create that
//! died between steps. The genesis op is signed with the global device key (`device_key`), which
//! `register_created_identity` then aliases to the per-DID key.

use crate::oauth::Core;
use crate::{device_key, identity_store, rekey, share_ceremony};
use crypto::{
    build_did_plc_genesis_op_multi_rotation_with_external_signer, CryptoError, DidKeyUri,
};
use serde::{Deserialize, Serialize};

/// The device token `create_account` receives alongside the session.
pub const DEVICE_TOKEN_ACCOUNT: &str = "device-token";
/// The pending (pre-DID) or upgraded (post-DID) session token.
pub const SESSION_TOKEN_ACCOUNT: &str = "session-token";
/// The create flow's legacy primary-DID marker.
pub const LEGACY_DID_ACCOUNT: &str = "did";

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
pub async fn create_account(
    state: &Core,
    claim_code: String,
    email: String,
    handle: String,
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
        crate::keystore::store_item(DEVICE_TOKEN_ACCOUNT, body.device_token.as_bytes()).map_err(
            |_| {
                // device-token write failed — nothing to clean up; the device key is persistent by design.
                CreateAccountError::KeychainError
            },
        )?;

        crate::keystore::store_item(SESSION_TOKEN_ACCOUNT, body.session_token.as_bytes()).map_err(
            |_| {
                // Best-effort cleanup: remove the already-written device-token.
                let _ = crate::keystore::delete_item(DEVICE_TOKEN_ACCOUNT);
                CreateAccountError::KeychainError
            },
        )?;

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
    let token_bytes = crate::keystore::get_item(SESSION_TOKEN_ACCOUNT).map_err(|e| {
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
    state: &Core,
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
pub async fn perform_did_ceremony(
    state: &Core,
    handle: String,
    password: Option<String>,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    let context = load_did_ceremony_context()?;
    let device_key = context.device_key;
    let pending_token = context.pending_token;
    let pds_key = fetch_repo_signing_key(state, &pending_token).await?;

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
    crate::keystore::store_item(
        SESSION_TOKEN_ACCOUNT,
        create_did_resp.session_token.as_bytes(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to persist upgraded session-token to keychain");
        DIDCeremonyError::KeychainError
    })?;

    // Step 7: Persist the DID for use in subsequent app sessions.
    crate::keystore::store_item(LEGACY_DID_ACCOUNT, create_did_resp.did.as_bytes()).map_err(|e| {
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

use crate::share_recovery::ShareBackupError;

/// Confirm the user has saved Share 3 and tear down the ceremony staging slot.
///
/// The teardown order is load-bearing: Share 1 must be verifiably present in the ceremony DID's
/// durable per-DID slot (`recovery-share-1:{did}`, written by `perform_did_ceremony` /
/// `complete_did_web_ceremony`) before the staging record — the seed's and Share 2's last local
/// copy — is destroyed. The DID is threaded from the frontend (the ceremony result's `did`) so
/// the durability check reads the exact identity just created, mirroring the re-key epilogue's
/// `confirm_rekey`. Idempotent; called by the frontend when the Shamir backup screen's
/// confirmation completes.
pub fn confirm_share_backup(did: String) -> Result<(), ShareBackupError> {
    match rekey::load_share1(&did) {
        Ok(bytes) if !bytes.is_empty() => {}
        Ok(_) => {
            tracing::error!(
                "confirm_share_backup: recovery share 1 is empty; keeping staging slot"
            );
            return Err(ShareBackupError::ShareNotStored);
        }
        Err(ref e) if crate::keystore::is_not_found(e) => {
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

/// Prepare the device and reserved repository keys used to compose a did:web document.
pub async fn prepare_did_web_ceremony(state: &Core) -> Result<DidWebPreparation, DIDCeremonyError> {
    let context = load_did_ceremony_context()?;
    let repo_key = fetch_repo_signing_key(state, &context.pending_token).await?;
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

/// Verify a published did:web document, promote the account, and persist recovery state.
pub async fn complete_did_web_ceremony(
    state: &Core,
    document_text: String,
    password: Option<String>,
    enable_managed_hosting: bool,
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
    crate::keystore::store_item(SESSION_TOKEN_ACCOUNT, created.session_token.as_bytes())
        .map_err(|_| DIDCeremonyError::KeychainError)?;
    crate::keystore::store_item(LEGACY_DID_ACCOUNT, created.did.as_bytes())
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
pub async fn register_handle(
    state: &Core,
    handle: String,
) -> Result<RegisterHandleResult, RegisterHandleError> {
    let full_handle = handle;

    // Step 2: Read DID and session token from Keychain.
    // Missing DID here is a post-ceremony invariant violation — error! is appropriate.
    let did_bytes = crate::keystore::get_item(LEGACY_DID_ACCOUNT).map_err(|e| {
        tracing::error!(error = %e, "DID not found in Keychain during handle registration — ceremony invariant violated");
        RegisterHandleError::KeychainError
    })?;
    let did = String::from_utf8(did_bytes).map_err(|e| {
        tracing::error!(error = %e, "DID bytes are not valid UTF-8");
        RegisterHandleError::KeychainError
    })?;

    let token_bytes = crate::keystore::get_item(SESSION_TOKEN_ACCOUNT).map_err(|e| {
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
pub async fn get_available_user_domains(
    state: &Core,
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

/// Check whether the PDS can resolve `handle` to `expected_did` via the ATProto
/// `resolveHandle` endpoint.
///
/// Returns `true` when the PDS resolves the handle to the expected DID (HTTP 200 + matching
/// `did` field). Returns `false` for any other response (handle not yet propagated, PDS
/// unreachable, DID mismatch). Returns `Result<bool, String>` for Tauri IPC compatibility, but
/// never returns `Err` — callers can safely poll on an interval. The nominal `String` error
/// type is the ADR-0031 allowance for a command that never rejects.
pub async fn check_handle_resolution(
    state: &Core,
    handle: String,
    expected_did: String,
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
pub async fn register_created_identity(
    state: &Core,
    did: String,
    handle: String,
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
        crate::keystore::clear_for_test();
        let did = "did:plc:aliceceremony";
        share_ceremony::load_or_create("alice.example.com", "https://pds.example.com").unwrap();

        // Share 1 not yet in its durable per-DID slot: the staging record must survive.
        assert!(matches!(
            confirm_share_backup(did.to_string()),
            Err(ShareBackupError::ShareNotStored)
        ));
        assert!(crate::keystore::get_item(share_ceremony::STAGING_ACCOUNT).is_ok());

        // A different identity's Share 1 must NOT satisfy this DID's durability check — the
        // teardown is gated on the exact ceremony DID's slot, not any global one.
        crate::keystore::store_item(
            &rekey::recovery_share1_account("did:plc:someoneelse"),
            b"OTHER1",
        )
        .unwrap();
        assert!(matches!(
            confirm_share_backup(did.to_string()),
            Err(ShareBackupError::ShareNotStored)
        ));
        assert!(crate::keystore::get_item(share_ceremony::STAGING_ACCOUNT).is_ok());

        // Once THIS DID's Share 1 is durably stored, confirmation tears the staging slot down.
        // The synchronizable slot is what a fresh ceremony writes; the gate must see it.
        rekey::store_share1(did, b"SHARE1ENVELOPE").unwrap();
        confirm_share_backup(did.to_string()).expect("confirmation should succeed");
        assert!(matches!(
            crate::keystore::get_item(share_ceremony::STAGING_ACCOUNT),
            Err(ref e) if crate::keystore::is_not_found(e)
        ));
        // Idempotent repeat.
        confirm_share_backup(did.to_string()).expect("repeat confirmation is a no-op");
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
}
