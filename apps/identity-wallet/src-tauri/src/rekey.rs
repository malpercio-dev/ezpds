// pattern: Mixed (Functional Core guard/diff; Imperative Shell build/submit/confirm commands)
//
// Functional Core: the strict additive re-key guard and the review-diff computation (pure).
// Imperative Shell: build_rekey / submit_rekey / confirm_rekey (share generation + network +
//                   Keychain + signing) and their Tauri command wrappers.
//
// This is the "re-key migration" for existing OLD-MODEL accounts. Every account
// created before the ceremony inversion carries a server-generated 2-of-3 split of a secret
// bound to nothing: the shares protect nothing, and the server saw all three at generation.
// Such an account's `rotationKeys` are the 2-key `[device, PDS]` array — no recovery key. The
// account's real safety net is unchanged from today: the device key itself.
//
// The re-key moves the account onto the client-generated recovery model, exactly like a fresh
// ceremony but against an existing identity:
//   1. Generate a NEW recovery seed client-side, derive its recovery key, split 2-of-3 (v2
//      envelopes), staged in a per-DID Keychain slot BEFORE any network call.
//   2. Device-key-sign a PLC rotation op INSERTING the recovery key at `rotationKeys[1]` — the
//      device key stays at `[0]`, the existing PDS key shifts to `[2]`. Nothing is removed.
//   3. `PUT /v1/recovery/escrow-share` with the new Share 2 (the server deposits it and voids the
//      dead legacy `accounts.recovery_share` in the same transaction).
//   4. Overwrite the per-DID Keychain Share 1 slot with the new Share 1 (verified read-back).
//   5. Walk the user through saving the new Share 3 (frontend reuses ShamirBackupScreen), then
//      refresh the cached DID doc and tear down the staging slot.
//
// ADDITIVE-ONLY SAFETY. The device key never leaves `rotationKeys[0]`; the new shares are staged
// before the PLC op; escrow deposit follows it. A failure at any step leaves the account no less
// recoverable than today (device key only), and a resumed re-key converges to the same terminal
// state — every network/Keychain step below is idempotent. There is no window in which the
// account is worse off. Old shares are VOIDED by the re-key, not merely rotated — the honest
// framing, since they never protected anything.
//
// Unlike the sovereign repo-key rotation (which routes its op through the PDS so the commit
// signer cuts over atomically), a re-key never changes `verificationMethods.atproto` — the PDS
// key is the SAME key, only repositioned — so the wallet submits this op to plc.directory
// directly, like the migration and recovery legs.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claim::OpDiff;
use crate::handle_change::{latest_full_state, CurrentHandleState};
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::PdsClient;
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};
use crypto::PlcService;

/// The atproto PDS service id — its endpoint is the per-DID staging discriminator.
const ATPROTO_PDS_SERVICE_ID: &str = "atproto_pds";

/// Per-DID Keychain account holding this identity's durable, iCloud-synced Share 1.
///
/// A per-DID slot (never a single app-global one) so writing one identity's Share 1 can never
/// overwrite a sibling identity's — which would drop that sibling's recovery capability below its
/// baseline. Every write path shares this convention: the create ceremony, the did:web ceremony,
/// and this re-key flow. The single source of the `recovery-share-1:{did}` naming.
pub(crate) fn recovery_share1_account(did: &str) -> String {
    format!("recovery-share-1:{did}")
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the old-model re-key flow.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling wallet error
/// enums (`RotationError`, `MigrateError`, `RecoveryError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum RekeyError {
    /// The DID is a did:web identity — it has no PLC `rotationKeys`, so the recovery-key
    /// model does not apply. The frontend must never prompt these, but the command guards too.
    #[error("re-key applies only to did:plc identities")]
    NotDidPlc,
    /// The identity already carries a recovery key (new-model), so there is nothing to re-key.
    #[error("identity is already on the client-generated recovery model")]
    AlreadyRekeyed,
    /// The wallet's device key is not at `rotationKeys[0]`, so this wallet cannot additively
    /// re-key the identity (an interop account manages its own rotation keys).
    #[error("wallet device key is not the root rotation key for this DID")]
    WalletNotAuthorized,
    /// The identity's session could not be resolved without a passwordless unlock — the
    /// frontend should run the biometric sovereign login and retry.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The PDS or plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("re-key operation rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Client-side recovery-share generation or staging failed.
    #[error("recovery share generation failed: {message}")]
    ShareGenerationFailed { message: String },
    /// Local signing failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// Submitting the rotation op to plc.directory failed.
    #[error("PLC submission failed: {message}")]
    PlcSubmissionFailed { message: String },
    /// The escrow deposit of the new Share 2 failed.
    #[error("escrow deposit failed (HTTP {status}): {message}")]
    EscrowFailed { status: u16, message: String },
    /// Writing (or verifying) the new Share 1 to its durable Keychain slot failed. Distinct
    /// from a generic Keychain error because the PLC op has already landed: the frontend
    /// surfaces "your identity was upgraded but the local backup did not save — retry" rather
    /// than telling the user to restart.
    #[error("recovery share 1 could not be durably stored: {message}")]
    ShareStorageFailed { message: String },
    /// Confirm was called before Share 1 reached its durable slot — the staging record must
    /// not be destroyed while it is the only home of the new seed material.
    #[error("recovery share 1 is not durably stored")]
    ShareNotStored,
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The DID's device key or identity record could not be found.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
}

/// Map a session-lifecycle failure into the re-key surface (mirrors `rotate_repo_key`).
fn map_session_error(error: SessionError) -> RekeyError {
    match error {
        SessionError::NeedsUnlock { reason } => RekeyError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => RekeyError::RateLimited { retry_after },
        SessionError::IdentityNotFound => RekeyError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => RekeyError::NetworkError { message },
        other => RekeyError::NetworkError {
            message: other.to_string(),
        },
    }
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs to decide whether a proposed re-key is safe to
/// sign. Flattened to plain values so the guard is a pure, trivially-testable function.
#[derive(Debug, Clone)]
pub struct RekeyInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must be `current_rotation_keys[0]`.
    pub device_key_id: String,
    /// The recovery key derived from the freshly generated seed — the ONLY key that may enter
    /// the DID document through this flow.
    pub recovery_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op). Old model is 2 keys.
    pub current_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op.
    pub proposed_rotation_keys: Vec<String>,
    /// CURRENT verificationMethods — must be preserved unchanged (the PDS key does not move).
    pub current_verification_methods: BTreeMap<String, String>,
    /// The verificationMethods we intend to put in the op — must EQUAL the current.
    pub proposed_verification_methods: BTreeMap<String, String>,
    /// CURRENT services — must be preserved unchanged.
    pub current_services: BTreeMap<String, PlcService>,
    /// The services we intend to put in the op — must EQUAL the current.
    pub proposed_services: BTreeMap<String, PlcService>,
    /// CURRENT alsoKnownAs — must be preserved unchanged.
    pub current_also_known_as: Vec<String>,
    /// The alsoKnownAs we intend to put in the op — must EQUAL the current.
    pub proposed_also_known_as: Vec<String>,
}

// ── The strict pre-sign guard (STRICT ADDITIVE ALLOWLIST) ────────────────────

/// Reject the proposed re-key operation unless it satisfies the strict additive allowlist.
/// The device key can technically sign anything, so safety comes entirely from validating the
/// INPUTS before a signature is produced.
///
/// The allowlist: insert the freshly-derived recovery key at `rotationKeys[1]`, keeping the
/// device key at `[0]` and shifting every other current key down by one — nothing else may
/// change, and nothing is removed.
///
/// Rules:
///  1. Authorization + shape: the device key is exactly `current_rotation_keys[0]`.
///  2. Old model: the current key set has exactly 2 keys (`[device, PDS]`) — a longer set
///     already carries a recovery slot and must not be re-keyed by this flow.
///  3. Freshness: the recovery key is not already among the current keys.
///  4. Additive insertion: `proposed_rotation_keys` is exactly
///     `[device, recovery, ...current_rotation_keys[1..]]` — the device key stays at index 0,
///     the recovery key takes index 1, every prior key shifts down, and no other key rides along.
///  5. verificationMethods unchanged (the PDS key does not move — a re-key is not a repo-key rotation).
///  6. services unchanged (the account does not move PDS).
///  7. alsoKnownAs unchanged (the handle set is untouched).
pub fn guard_rekey_op(inputs: &RekeyInputs) -> Result<(), RekeyError> {
    // Rule 1 (authorization + shape): the device key must be the current root key.
    if inputs.current_rotation_keys.first() != Some(&inputs.device_key_id) {
        return Err(RekeyError::WalletNotAuthorized);
    }

    // Rule 2 (old model): exactly 2 keys, else it already has a recovery slot.
    if inputs.current_rotation_keys.len() != 2 {
        return Err(RekeyError::AlreadyRekeyed);
    }

    // Rule 3 (freshness): the recovery key must not already be installed.
    if inputs
        .current_rotation_keys
        .contains(&inputs.recovery_key_id)
    {
        return Err(RekeyError::GuardRejected {
            reason: "recovery key is already installed in the DID document".to_string(),
        });
    }

    // Rule 4 (additive insertion): [device, recovery, ...rest].
    let mut expected_keys = Vec::with_capacity(inputs.current_rotation_keys.len() + 1);
    expected_keys.push(inputs.device_key_id.clone());
    expected_keys.push(inputs.recovery_key_id.clone());
    expected_keys.extend_from_slice(&inputs.current_rotation_keys[1..]);
    if inputs.proposed_rotation_keys != expected_keys {
        return Err(RekeyError::GuardRejected {
            reason: "rotationKeys must be exactly [device key, recovery key, ...current tail]"
                .to_string(),
        });
    }

    // Rule 5 (verificationMethods unchanged): a re-key never touches the repo signing key.
    if inputs.proposed_verification_methods != inputs.current_verification_methods {
        return Err(RekeyError::GuardRejected {
            reason: "verificationMethods must be preserved across a re-key".to_string(),
        });
    }

    // Rule 6 (services unchanged).
    if inputs.proposed_services != inputs.current_services {
        return Err(RekeyError::GuardRejected {
            reason: "services must be preserved across a re-key".to_string(),
        });
    }

    // Rule 7 (alsoKnownAs unchanged).
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(RekeyError::GuardRejected {
            reason: "alsoKnownAs must be preserved across a re-key".to_string(),
        });
    }

    Ok(())
}

// ── Review diff ──────────────────────────────────────────────────────────────

/// Compute the review-screen diff for a re-key: the recovery key enters, NOTHING leaves,
/// services never change. Pure. The empty `removed_keys` is the calm, honest framing — a
/// re-key adds a safety net without taking anything away.
pub(crate) fn build_rekey_diff(recovery_key_id: &str, prev_cid: &str) -> OpDiff {
    OpDiff {
        added_keys: vec![recovery_key_id.to_string()],
        removed_keys: Vec::new(),
        changed_services: Vec::new(),
        prev_cid: Some(prev_cid.to_string()),
    }
}

// ── Output types ─────────────────────────────────────────────────────────────

/// The preview returned by `build_rekey`, driving the review screen.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RekeyPreview {
    /// Human-readable diff — the additive key insertion (added: [recovery], removed: []).
    pub diff: OpDiff,
    /// The recovery `did:key` that will be inserted at `rotationKeys[1]`.
    pub recovery_key_id: String,
}

/// The result of `submit_rekey`, once the op has landed and the escrow + Share 1 are in place.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RekeyResult {
    /// The refreshed DID document (PLC data shape) so the home card updates immediately.
    pub updated_did_doc: serde_json::Value,
    /// The new Share 3 envelope (base32 QR form) for the user to save.
    pub share3: String,
    /// The new Share 3 rendered as the BIP-39-style word phrase.
    pub share3_words: String,
}

// ── Imperative shell helpers ─────────────────────────────────────────────────

/// Guard: a re-key only applies to a did:plc identity.
fn require_did_plc(did: &str) -> Result<(), RekeyError> {
    if did.starts_with("did:plc:") {
        Ok(())
    } else {
        Err(RekeyError::NotDidPlc)
    }
}

/// Fetch the DID's current full state (prev CID + rotationKeys/VMs/services/alsoKnownAs) from
/// the authoritative plc.directory audit log.
async fn fetch_current_state(
    pds_client: &PdsClient,
    did: &str,
) -> Result<CurrentHandleState, RekeyError> {
    let log_json = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| RekeyError::NetworkError {
            message: format!("failed to fetch audit log: {e}"),
        })?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| RekeyError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    latest_full_state(&audit_log).map_err(|e| RekeyError::InvalidAuditLog {
        message: e.to_string(),
    })
}

/// The account's PDS endpoint — the stable per-DID discriminator for the staging slot.
fn pds_endpoint(current: &CurrentHandleState) -> String {
    current
        .services
        .get(ATPROTO_PDS_SERVICE_ID)
        .map(|s| s.endpoint.clone())
        .unwrap_or_default()
}

/// The proposed rotation keys for a re-key: recovery inserted at [1], device kept at [0].
fn proposed_rekey_keys(current_rotation_keys: &[String], recovery_key_id: &str) -> Vec<String> {
    let mut keys = Vec::with_capacity(current_rotation_keys.len() + 1);
    keys.push(current_rotation_keys[0].clone());
    keys.push(recovery_key_id.to_string());
    keys.extend_from_slice(&current_rotation_keys[1..]);
    keys
}

/// `PUT /v1/recovery/escrow-share` over the account-owner session, depositing (or replacing)
/// the new Share 2. Idempotent server-side (replace-or-insert), and it voids the legacy column.
async fn deposit_escrow_share(
    session: &crate::oauth_client::OAuthClient,
    share2: &str,
) -> Result<(), RekeyError> {
    let response = session
        .put(
            "/v1/recovery/escrow-share",
            &serde_json::json!({ "share": share2 }),
        )
        .await
        .map_err(|e| RekeyError::NetworkError {
            message: format!("escrow deposit request failed: {e}"),
        })?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status().as_u16();
    if status == 429 {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        return Err(RekeyError::RateLimited { retry_after });
    }
    let body = response.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| {
            if body.is_empty() {
                format!("escrow deposit returned HTTP {status}")
            } else {
                body
            }
        });
    Err(RekeyError::EscrowFailed { status, message })
}

/// Overwrite the per-DID Share 1 Keychain slot with `share1`, verifying the write by reading it
/// back — Share 1's durability is the precondition for tearing down the staging slot later.
fn store_and_verify_share1(did: &str, share1: &str) -> Result<(), RekeyError> {
    let account = recovery_share1_account(did);
    crate::keychain::store_item(&account, share1.as_bytes()).map_err(|e| {
        RekeyError::ShareStorageFailed {
            message: format!("keychain write failed: {e}"),
        }
    })?;
    match crate::keychain::get_item(&account) {
        Ok(read_back) if read_back == share1.as_bytes() => Ok(()),
        Ok(_) => Err(RekeyError::ShareStorageFailed {
            message: "recovery share 1 read-back does not match the written value".to_string(),
        }),
        Err(e) => Err(RekeyError::ShareStorageFailed {
            message: format!("recovery share 1 read-back failed: {e}"),
        }),
    }
}

// ── Imperative shell: build / submit / confirm ───────────────────────────────

/// Build the re-key preview: generate + stage the new recovery share set, fetch current state,
/// prove the account is an eligible old-model did:plc identity, and return the additive diff.
///
/// Idempotent — the staged set is reused across retries (same recovery key, same `set_id`), so
/// re-running build never orphans a prior attempt's material. Signs nothing; `submit_rekey`
/// does the single device-key signature.
pub async fn build_rekey(pds_client: &PdsClient, did: &str) -> Result<RekeyPreview, RekeyError> {
    require_did_plc(did)?;
    let store = IdentityStore;

    let device = store
        .get_or_create_device_key(did)
        .map_err(|e| RekeyError::IdentityNotFound {
            message: format!("failed to get device key: {e}"),
        })?;

    let current = fetch_current_state(pds_client, did).await?;
    let pds_url = pds_endpoint(&current);

    // Eligibility precheck BEFORE generating/staging anything: a fresh re-key requires the 2-key
    // old model, but a re-key already in flight (a staging slot exists) is always resumable — even
    // after its PLC op landed and the identity reads as new-model — because escrow/Share 1 may
    // still be unfinished. A new-model identity with no in-flight re-key has nothing to do.
    let staging_exists = crate::share_ceremony::rekey_staging_exists(did);
    if !staging_exists && current.rotation_keys.len() != 2 {
        return Err(RekeyError::AlreadyRekeyed);
    }

    let shares = crate::share_ceremony::load_or_create_for_rekey(did, &pds_url).map_err(|e| {
        RekeyError::ShareGenerationFailed {
            message: e.to_string(),
        }
    })?;

    // Only run the strict additive guard when the recovery key is not yet on-chain — i.e. this
    // build will additively insert it. On a resumed re-key whose op already landed, the recovery
    // key is present and the guard's "current is exactly [device, PDS]" precondition no longer
    // holds; the remaining work (escrow/Share 1) is finished by `submit_rekey`.
    if !current.rotation_keys.contains(&shares.recovery_key_id) {
        let proposed_rotation_keys =
            proposed_rekey_keys(&current.rotation_keys, &shares.recovery_key_id);
        let inputs = RekeyInputs {
            device_key_id: device.key_id.clone(),
            recovery_key_id: shares.recovery_key_id.clone(),
            current_rotation_keys: current.rotation_keys.clone(),
            proposed_rotation_keys,
            current_verification_methods: current.verification_methods.clone(),
            proposed_verification_methods: current.verification_methods.clone(),
            current_services: current.services.clone(),
            proposed_services: current.services.clone(),
            current_also_known_as: current.also_known_as.clone(),
            proposed_also_known_as: current.also_known_as.clone(),
        };
        guard_rekey_op(&inputs)?;
    }

    Ok(RekeyPreview {
        diff: build_rekey_diff(&shares.recovery_key_id, &current.prev_cid),
        recovery_key_id: shares.recovery_key_id.clone(),
    })
}

/// Run the re-key: post the additive rotation op (device-key-signed) to plc.directory if it has
/// not already landed, deposit the new Share 2 to escrow, overwrite the durable Share 1, and
/// refresh the cached DID doc. Returns the new Share 3 for the backup screen.
///
/// Every step is idempotent, so a re-key interrupted at any point converges on re-run:
///  - the PLC op is skipped when the recovery key is already on-chain (resume after it landed);
///  - the escrow `PUT` is replace-or-insert;
///  - the Share 1 write is a verified overwrite;
///  - the cache refresh is a plain re-fetch.
///
/// Because the device key never leaves `rotationKeys[0]`, no intermediate state drops recovery
/// capability below the pre-re-key baseline (device key only).
pub async fn submit_rekey(pds_client: &PdsClient, did: &str) -> Result<RekeyResult, RekeyError> {
    require_did_plc(did)?;
    let store = IdentityStore;

    let device = store
        .get_or_create_device_key(did)
        .map_err(|e| RekeyError::IdentityNotFound {
            message: format!("failed to get device key: {e}"),
        })?;

    let current = fetch_current_state(pds_client, did).await?;
    let pds_url = pds_endpoint(&current);

    // Reload the exact staged set built in the preview (durable across app kills). This is the
    // only home of the new seed material until the ceremony is confirmed.
    let shares = crate::share_ceremony::load_or_create_for_rekey(did, &pds_url).map_err(|e| {
        RekeyError::ShareGenerationFailed {
            message: e.to_string(),
        }
    })?;
    let recovery_key_id = shares.recovery_key_id.clone();

    // Step 1: post the additive rotation op — unless the recovery key is already on-chain
    // (a resumed re-key whose op already landed). The device key stays supreme at [0].
    if !current.rotation_keys.contains(&recovery_key_id) {
        let proposed_rotation_keys = proposed_rekey_keys(&current.rotation_keys, &recovery_key_id);
        let inputs = RekeyInputs {
            device_key_id: device.key_id.clone(),
            recovery_key_id: recovery_key_id.clone(),
            current_rotation_keys: current.rotation_keys.clone(),
            proposed_rotation_keys: proposed_rotation_keys.clone(),
            current_verification_methods: current.verification_methods.clone(),
            proposed_verification_methods: current.verification_methods.clone(),
            current_services: current.services.clone(),
            proposed_services: current.services.clone(),
            current_also_known_as: current.also_known_as.clone(),
            proposed_also_known_as: current.also_known_as.clone(),
        };
        guard_rekey_op(&inputs)?;

        let sign_closure =
            crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
                PerDidSignError::DeviceKeyNotFound { message } => {
                    RekeyError::IdentityNotFound { message }
                }
                PerDidSignError::SigningSetupFailed { message } => {
                    RekeyError::SigningFailed { message }
                }
            })?;
        let signed = crypto::build_did_plc_rotation_op(
            &current.prev_cid,
            proposed_rotation_keys,
            current.verification_methods.clone(),
            current.also_known_as.clone(),
            current.services.clone(),
            sign_closure,
        )
        .map_err(|e| RekeyError::SigningFailed {
            message: format!("failed to build re-key op: {e}"),
        })?;
        let signed_op: serde_json::Value =
            serde_json::from_str(&signed.signed_op_json).map_err(|e| {
                RekeyError::SigningFailed {
                    message: format!("failed to parse signed op JSON: {e}"),
                }
            })?;
        pds_client
            .post_plc_operation(did, &signed_op)
            .await
            .map_err(|e| RekeyError::PlcSubmissionFailed {
                message: format!("failed to submit re-key op: {e}"),
            })?;
    }

    // Step 2: escrow the new Share 2 over the account-owner session. The server nulls the dead
    // legacy `accounts.recovery_share` in the same transaction.
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| RekeyError::SigningFailed {
            message: "system clock is unavailable".to_string(),
        })?;
    let session = SessionProvider
        .full_access_client(pds_client, &store, did, now)
        .await
        .map_err(map_session_error)?;
    deposit_escrow_share(&session.client, &shares.share2).await?;

    // Step 3: overwrite the durable per-DID Share 1 slot with the new Share 1 (verified).
    store_and_verify_share1(did, &shares.share1)?;

    // Step 4: refresh the cached PLC log + DID document (PLC *data* shape — the home card reads
    // rotationKeys; caching the W3C form instead strips them and degrades the card, so the
    // post-op refresh must re-cache the data shape).
    let updated_log =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RekeyError::NetworkError {
                message: format!("failed to fetch updated audit log: {e}"),
            })?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| RekeyError::ShareStorageFailed {
            message: format!("failed to cache updated PLC log: {e}"),
        })?;
    let did_doc =
        pds_client
            .fetch_plc_data_document(did)
            .await
            .map_err(|e| RekeyError::NetworkError {
                message: format!("failed to fetch DID document: {e}"),
            })?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| RekeyError::ShareStorageFailed {
            message: format!("failed to cache updated DID document: {e}"),
        })?;

    Ok(RekeyResult {
        updated_did_doc: did_doc,
        share3: shares.share3.to_string(),
        share3_words: shares.share3_words.to_string(),
    })
}

/// Confirm the user has saved the new Share 3 and tear down the per-DID staging slot.
///
/// The teardown order is load-bearing: Share 1 must be verifiably present in its durable slot
/// (written by `submit_rekey`) before the staging record — the new seed's and Share 2's last
/// local copy — is destroyed. Idempotent.
pub fn confirm_rekey(did: &str) -> Result<(), RekeyError> {
    let account = recovery_share1_account(did);
    match crate::keychain::get_item(&account) {
        Ok(bytes) if !bytes.is_empty() => {}
        Ok(_) => return Err(RekeyError::ShareNotStored),
        Err(ref e) if crate::keychain::is_not_found(e) => return Err(RekeyError::ShareNotStored),
        Err(e) => {
            return Err(RekeyError::ShareStorageFailed {
                message: format!("keychain read failed: {e}"),
            })
        }
    }
    crate::share_ceremony::clear_rekey_staging(did).map_err(|e| RekeyError::ShareStorageFailed {
        message: format!("failed to clear re-key staging slot: {e}"),
    })
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: build the re-key preview (stage shares, prove eligibility, return the diff).
#[tauri::command]
pub async fn build_rekey_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RekeyPreview, RekeyError> {
    build_rekey(state.pds_client(), &did).await
}

/// Tauri command: run the re-key (post op + escrow + Share 1 + refresh). Idempotent/resumable.
#[tauri::command]
pub async fn submit_rekey_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RekeyResult, RekeyError> {
    submit_rekey(state.pds_client(), &did).await
}

/// Tauri command: confirm the new Share 3 is saved and tear down the staging slot.
#[tauri::command]
pub fn confirm_rekey_cmd(did: String) -> Result<(), RekeyError> {
    confirm_rekey(&did)
}

/// Tauri command: whether a re-key is mid-flight for this DID (a staging slot exists).
///
/// The home surface prompts a re-key when the identity is old-model OR when a re-key is in
/// progress — the latter resurfaces an interrupted upgrade whose PLC op already landed (so the
/// identity reads as new-model) but whose escrow/Share 1/confirmation did not complete.
#[tauri::command]
pub fn rekey_in_progress_cmd(did: String) -> bool {
    crate::share_ceremony::rekey_staging_exists(&did)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:key:zDEVICE";
    const PDS: &str = "did:key:zPDS";
    const RECOVERY: &str = "did:key:zRECOVERY";
    const PREV: &str = "bafyreiaaaa";

    fn vms(atproto: &str) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("atproto".to_string(), atproto.to_string());
        m
    }

    fn services() -> BTreeMap<String, PlcService> {
        let mut m = BTreeMap::new();
        m.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example".to_string(),
            },
        );
        m
    }

    /// A well-formed old-model re-key: recovery inserted at [1], device kept at [0], PDS shifts
    /// to [2]; VMs / services / alsoKnownAs all preserved.
    fn ok_inputs() -> RekeyInputs {
        RekeyInputs {
            device_key_id: DEVICE.to_string(),
            recovery_key_id: RECOVERY.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), PDS.to_string()],
            proposed_rotation_keys: vec![DEVICE.to_string(), RECOVERY.to_string(), PDS.to_string()],
            current_verification_methods: vms(PDS),
            proposed_verification_methods: vms(PDS),
            current_services: services(),
            proposed_services: services(),
            current_also_known_as: vec!["at://alice.example.com".to_string()],
            proposed_also_known_as: vec!["at://alice.example.com".to_string()],
        }
    }

    #[test]
    fn guard_accepts_a_well_formed_rekey() {
        assert!(guard_rekey_op(&ok_inputs()).is_ok());
    }

    #[test]
    fn guard_rejects_when_device_is_not_root() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![PDS.to_string(), DEVICE.to_string()];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_an_already_rekeyed_identity() {
        let mut inputs = ok_inputs();
        // Already 3 keys — a recovery slot exists.
        inputs.current_rotation_keys = vec![
            DEVICE.to_string(),
            "did:key:zOLDRECOVERY".to_string(),
            PDS.to_string(),
        ];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::AlreadyRekeyed)
        ));
    }

    #[test]
    fn guard_rejects_a_recovery_key_already_present() {
        let mut inputs = ok_inputs();
        // 2 keys, but the "recovery" key is one of them (freshness violation).
        inputs.current_rotation_keys = vec![DEVICE.to_string(), RECOVERY.to_string()];
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            RECOVERY.to_string(),
            RECOVERY.to_string(),
        ];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_demoted_device_key() {
        let mut inputs = ok_inputs();
        // Recovery placed at [0], device demoted — inverts enclave supremacy.
        inputs.proposed_rotation_keys =
            vec![RECOVERY.to_string(), DEVICE.to_string(), PDS.to_string()];
        assert!(matches!(
            guard_rekey_op(&inputs),
            // device is still current[0], so rule 4 (shape) rejects, not rule 1.
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_removed_pds_key() {
        let mut inputs = ok_inputs();
        // The op drops the PDS key instead of shifting it down — not additive.
        inputs.proposed_rotation_keys = vec![DEVICE.to_string(), RECOVERY.to_string()];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_smuggled_extra_key() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            RECOVERY.to_string(),
            PDS.to_string(),
            "did:key:zEVIL".to_string(),
        ];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_moved_repo_key() {
        let mut inputs = ok_inputs();
        // A re-key must not touch verificationMethods.atproto (that is a repo-key rotation).
        inputs.proposed_verification_methods = vms(RECOVERY);
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_service_change() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_services
            .get_mut("atproto_pds")
            .unwrap()
            .endpoint = "https://evil.example".to_string();
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_an_also_known_as_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.example.com".to_string()];
        assert!(matches!(
            guard_rekey_op(&inputs),
            Err(RekeyError::GuardRejected { .. })
        ));
    }

    #[test]
    fn proposed_keys_insert_recovery_at_index_one() {
        let current = vec![DEVICE.to_string(), PDS.to_string()];
        let proposed = proposed_rekey_keys(&current, RECOVERY);
        assert_eq!(
            proposed,
            vec![DEVICE.to_string(), RECOVERY.to_string(), PDS.to_string()]
        );
    }

    #[test]
    fn diff_is_additive_only() {
        let diff = build_rekey_diff(RECOVERY, PREV);
        assert_eq!(diff.added_keys, vec![RECOVERY.to_string()]);
        assert!(
            diff.removed_keys.is_empty(),
            "a re-key removes nothing — the calm, honest framing"
        );
        assert!(diff.changed_services.is_empty());
        assert_eq!(diff.prev_cid.as_deref(), Some(PREV));
    }

    #[test]
    fn require_did_plc_rejects_did_web() {
        assert!(matches!(
            require_did_plc("did:web:example.com"),
            Err(RekeyError::NotDidPlc)
        ));
        assert!(require_did_plc("did:plc:abc123").is_ok());
    }
}
