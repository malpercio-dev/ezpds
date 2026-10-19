// pattern: Mixed (Functional Core guard/diff; Imperative Shell build/submit/confirm commands)

//! THE SELF-HELD SHAMIR KIT — the escrow-less recovery-key install ("Add a recovery
//! key" on the identity screen). An identity brought in through the claim ceremony
//! holds its wallet device key at `rotationKeys[0]` but lives on a PDS that is not
//! Custos: it gets the sovereign half of the recovery story for free (PLC monitoring,
//! the 72h override, user-held backups) but not the recovery *seed* — the
//! client-generated 2-of-3 split is fused, in `rekey.rs`, to an escrow deposit a
//! non-Custos host has no route for. This flow is that ceremony minus the escrow.
//! Four Tauri IPC commands:
//!
//! - `build_self_held_kit(did)` — generate a NEW recovery seed client-side, derive its
//!   recovery key, split 2-of-3 (v2 envelopes), staged in the per-DID
//!   `self-held-kit-staging:{did}` Keychain slot BEFORE any network call; prove
//!   eligibility and return the additive review diff + the host's URL.
//! - `submit_self_held_kit(did)` — device-key-sign a PLC rotation op INSERTING the
//!   derived recovery key directly after the device key (the device key stays at
//!   `[0]`, the whole current tail shifts down one index; nothing is removed), POST it
//!   straight to plc.directory, write Share 1 to the per-DID iCloud-synchronizable
//!   slot with read-back verify, refresh the cached PLC log + doc, and record the
//!   durable `{did}:self-held-kit` marker. Biometric-gated in the frontend.
//! - `confirm_self_held_kit(did)` — teardown gate mirroring `confirm_rekey`: Share 1
//!   must be verifiably durable before the staging slot — the last local home of
//!   Shares 2 and 3 — is destroyed.
//! - `self_held_kit_in_progress_cmd(did)` — whether a kit is mid-flight (a staging slot
//!   exists) for this DID.
//!
//! Share custody: Share 1 → the Keychain; Shares 2 AND 3 → the user. With no escrow
//! there is no third party, and the user's two shares are the whole threshold — the
//! sovereign recovery path (`share_recovery.rs`) reconstructs from any two with zero
//! PDS involvement. The staging slot is deliberately SEPARATE from the re-key's
//! `rekey-staging:{did}`: the two ceremonies disagree about who keeps Share 2 (the
//! re-key escrows it, the kit hands it to the user), so a set staged by one must
//! never be picked up and completed by the other; both share `ceremony-staging`'s
//! fail-closed contract and its load-bearing teardown order.
//!
//! WHAT THIS TALKS TO. plc.directory is the only peer for anything touching the
//! identity: the audit-log read, the op submit, the post-op cache refresh. There is
//! no session, no escrow `PUT`, and no `/v1/*` call — hence no `SESSION_LOCKED` and
//! no `ESCROW_FAILED` in the error surface. The one request that does reach the
//! hosting PDS is the public, unauthenticated `describeServer` capability probe
//! (often served from the `pds_capabilities` cache, so frequently no request at all)
//! proving the host offers no escrow — where the richer `rekey.rs` flow belongs. It
//! carries no share material and no credential, but it IS a request: user-facing copy
//! must say "no share is sent to your server", never "your server is never contacted".
//!
//! `guard_self_held_kit_op` is the SEVENTH strict wallet allowlist, not a flag on
//! `guard_rekey_op`: that guard requires the current layout be exactly `[device, PDS]`
//! — the pre-inversion Custos migration shape — and treats anything longer as
//! `AlreadyRekeyed`, which would reject every claimed identity (they carry whatever
//! rotation keys their host wrote before the claim). The kit's rules: device key
//! pinned at `[0]`, the fresh recovery key inserted at `[1]`, every other rotation
//! key shifted but preserved verbatim, and verificationMethods / services /
//! alsoKnownAs byte-identical. Additive-only safety, same as the re-key: shares are
//! staged before the op, the device key never leaves `rotationKeys[0]`, and every
//! step is idempotent — an interrupted kit converges on re-run and no intermediate
//! state is less recoverable than the pre-kit baseline.
//!
//! `SelfHeldKitError` (NOT_DID_PLC, WALLET_NOT_AUTHORIZED, HOST_OFFERS_ESCROW,
//! RATE_LIMITED, GUARD_REJECTED, INVALID_AUDIT_LOG, SHARE_GENERATION_FAILED,
//! SIGNING_FAILED, PLC_SUBMISSION_FAILED, PLC_DIRECTORY_ERROR, SHARE_STORAGE_FAILED,
//! SHARE_NOT_STORED, NETWORK_ERROR, IDENTITY_NOT_FOUND) serializes as
//! `{ code: "SCREAMING_SNAKE_CASE" }` with camelCase fields.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claim::OpDiff;
use crate::handle_change::CurrentHandleState;
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::{PdsClient, PdsClientError};
use crate::rekey::store_and_verify_share1;
use crypto::PlcService;

/// The atproto PDS service id — its endpoint is the staging discriminator and the host whose
/// capabilities decide whether this flow (rather than the escrow-backed re-key) applies.
const ATPROTO_PDS_SERVICE_ID: &str = "atproto_pds";

/// Per-DID Keychain account recording that the self-held kit is installed for this identity.
///
/// The single purpose is the upsell *seam*: an identity that later moves to a host advertising
/// `escrow` can be offered — once, as an option — to deposit a share there. Without the marker
/// the offer could not tell a self-held kit from an identity that never had a recovery key at
/// all, and would be a nag rather than an upgrade.
pub(crate) fn self_held_kit_account(did: &str) -> String {
    format!("{did}:self-held-kit")
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the self-held Shamir kit.
///
/// Deliberately shorter than [`crate::rekey::RekeyError`]: with no session and no escrow leg
/// there is no `SESSION_LOCKED`, no `ESCROW_FAILED`, and no server-verdict surface to classify.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum SelfHeldKitError {
    /// The DID is a did:web identity — it has no PLC `rotationKeys`, so the recovery-key
    /// model does not apply.
    #[error("the self-held kit applies only to did:plc identities")]
    NotDidPlc,
    /// The wallet's device key is not at `rotationKeys[0]`, so this wallet cannot additively
    /// install a recovery key (the identity's rotation keys are somebody else's to manage).
    #[error("wallet device key is not the root rotation key for this DID")]
    WalletNotAuthorized,
    /// The identity's host advertises `escrow`. The escrow-backed ceremony is strictly better
    /// there (a share the user cannot lose), so this flow steps aside rather than installing a
    /// second, weaker recovery key alongside it.
    #[error("this identity's server offers recovery escrow")]
    HostOffersEscrow,
    /// plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("operation rejected by pre-sign guard: {reason}")]
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
    /// plc.directory answered a read with an HTTP failure — a directory outage or verdict,
    /// distinct from `NetworkError` so it is never reported as "check your connection".
    #[error("plc.directory error: {message}")]
    PlcDirectoryError { message: String },
    /// Writing (or verifying) Share 1 to its durable Keychain slot failed. Distinct from a
    /// generic Keychain error because the PLC op has already landed.
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

/// Map a plc.directory read failure: a throttle is retryable, an HTTP verdict is the
/// directory's problem, and only a transport failure is `NetworkError`.
fn map_plc_fetch_error(context: &str, error: PdsClientError) -> SelfHeldKitError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            SelfHeldKitError::RateLimited { retry_after }
        }
        PdsClientError::XrpcError {
            status, message, ..
        } => SelfHeldKitError::PlcDirectoryError {
            message: format!("{context}: plc.directory returned HTTP {status}: {message}"),
        },
        PdsClientError::Unauthorized { message, .. } => SelfHeldKitError::PlcDirectoryError {
            message: format!("{context}: plc.directory returned HTTP 401: {message}"),
        },
        other => SelfHeldKitError::NetworkError {
            message: format!("{context}: {other}"),
        },
    }
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs. Flattened to plain values so the guard is a
/// pure, trivially-testable function.
#[derive(Debug, Clone)]
pub struct SelfHeldKitInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must be `current_rotation_keys[0]`.
    pub device_key_id: String,
    /// The recovery key derived from the freshly generated seed — the ONLY key that may enter
    /// the DID document through this flow.
    pub recovery_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op). Arbitrary length: a
    /// claimed identity carries whatever its host wrote before the claim.
    pub current_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op.
    pub proposed_rotation_keys: Vec<String>,
    /// CURRENT verificationMethods — must be preserved unchanged.
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

// ── The strict pre-sign guard (SEVENTH STRICT ALLOWLIST) ─────────────────────

/// Reject the proposed operation unless it satisfies the strict additive allowlist. The device
/// key can technically sign anything, so safety comes entirely from validating the INPUTS
/// before a signature is produced.
///
/// The allowlist: insert the freshly-derived recovery key at `rotationKeys[1]`, keeping the
/// device key at `[0]` and shifting every other current key down by one — nothing else may
/// change, and nothing is removed.
///
/// Rules:
///  1. Authorization + shape: the device key is exactly `current_rotation_keys[0]`.
///  2. Freshness: the recovery key is not already among the current keys.
///  3. Additive insertion: `proposed_rotation_keys` is exactly
///     `[device, recovery, ...current_rotation_keys[1..]]`.
///  4. verificationMethods unchanged (this is not a repo-key rotation).
///  5. services unchanged (the account does not move PDS).
///  6. alsoKnownAs unchanged (the handle set is untouched).
///
/// Note the rule that is deliberately ABSENT relative to [`crate::rekey::guard_rekey_op`]:
/// there is no "current must be exactly two keys" precondition. That rule encodes the
/// pre-inversion Custos layout `[device, PDS]`; a claimed foreign-hosted identity carries an
/// arbitrary tail, and rejecting it would reject the entire population this flow exists for.
/// The safety the length check bought there is bought here by rules 1 and 3 together: whatever
/// the tail is, it survives verbatim one index lower, and the device key stays supreme.
pub fn guard_self_held_kit_op(inputs: &SelfHeldKitInputs) -> Result<(), SelfHeldKitError> {
    // Rule 1 (authorization + shape): the device key must be the current root key.
    if inputs.current_rotation_keys.first() != Some(&inputs.device_key_id) {
        return Err(SelfHeldKitError::WalletNotAuthorized);
    }

    // Rule 2 (freshness): the recovery key must not already be installed.
    if inputs
        .current_rotation_keys
        .contains(&inputs.recovery_key_id)
    {
        return Err(SelfHeldKitError::GuardRejected {
            reason: "recovery key is already installed in the DID document".to_string(),
        });
    }

    // Rule 3 (additive insertion): [device, recovery, ...rest].
    if inputs.proposed_rotation_keys
        != proposed_kit_keys(&inputs.current_rotation_keys, &inputs.recovery_key_id)
    {
        return Err(SelfHeldKitError::GuardRejected {
            reason: "rotationKeys must be exactly [device key, recovery key, ...current tail]"
                .to_string(),
        });
    }

    // Rule 4 (verificationMethods unchanged): this never touches the repo signing key.
    if inputs.proposed_verification_methods != inputs.current_verification_methods {
        return Err(SelfHeldKitError::GuardRejected {
            reason: "verificationMethods must be preserved".to_string(),
        });
    }

    // Rule 5 (services unchanged).
    if inputs.proposed_services != inputs.current_services {
        return Err(SelfHeldKitError::GuardRejected {
            reason: "services must be preserved".to_string(),
        });
    }

    // Rule 6 (alsoKnownAs unchanged).
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(SelfHeldKitError::GuardRejected {
            reason: "alsoKnownAs must be preserved".to_string(),
        });
    }

    Ok(())
}

// ── Review diff ──────────────────────────────────────────────────────────────

/// Compute the review-screen diff: the recovery key enters, NOTHING leaves, services never
/// change. Pure.
pub(crate) fn build_kit_diff(recovery_key_id: &str, prev_cid: &str) -> OpDiff {
    OpDiff {
        added_keys: vec![recovery_key_id.to_string()],
        removed_keys: Vec::new(),
        changed_services: Vec::new(),
        prev_cid: Some(prev_cid.to_string()),
    }
}

/// The proposed rotation keys: recovery inserted at [1], device kept at [0], tail shifted.
///
/// The single source of the shape both the guard checks and the shell proposes — computing it
/// twice would let the two drift into a guard that validates a different op than the one signed.
///
/// Total on purpose. The shell computes this BEFORE the guard runs, and on a resumed kit the
/// root-key precheck is skipped, so a malformed audit log yielding no rotation keys would reach
/// an indexing panic in a signing path instead of the clean `WalletNotAuthorized` rule 1 exists
/// to return. An empty input therefore yields an empty proposal, which rule 1 rejects first.
fn proposed_kit_keys(current_rotation_keys: &[String], recovery_key_id: &str) -> Vec<String> {
    let Some((device_key, tail)) = current_rotation_keys.split_first() else {
        return Vec::new();
    };
    let mut keys = Vec::with_capacity(current_rotation_keys.len() + 1);
    keys.push(device_key.clone());
    keys.push(recovery_key_id.to_string());
    keys.extend_from_slice(tail);
    keys
}

// ── Output types ─────────────────────────────────────────────────────────────

/// The preview returned by `build_self_held_kit`, driving the review screen.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SelfHeldKitPreview {
    /// Human-readable diff — the additive key insertion (added: [recovery], removed: []).
    pub diff: OpDiff,
    /// The recovery `did:key` that will be inserted at `rotationKeys[1]`.
    pub recovery_key_id: String,
    /// The identity's hosting PDS, named on the review screen so the user can see which server
    /// this kit is being held *against* — the one that will hold none of it.
    pub pds_url: String,
}

/// The result of `submit_self_held_kit`, once the op has landed and Share 1 is durable.
///
/// Carries **two** shares, not one: with no escrow, Shares 2 and 3 are both the user's to keep.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SelfHeldKitResult {
    /// The refreshed DID document (PLC data shape) so the identity card updates immediately.
    pub updated_did_doc: serde_json::Value,
    /// Share 2 envelope (base32 QR form) — the user's, since no server escrows it.
    pub share2: String,
    /// Share 2 rendered as the BIP-39-style word phrase.
    pub share2_words: String,
    /// Share 3 envelope (base32 QR form).
    pub share3: String,
    /// Share 3 rendered as the BIP-39-style word phrase.
    pub share3_words: String,
}

// ── Imperative shell helpers ─────────────────────────────────────────────────

/// Guard: the recovery-key model only applies to a did:plc identity.
fn require_did_plc(did: &str) -> Result<(), SelfHeldKitError> {
    if did.starts_with("did:plc:") {
        Ok(())
    } else {
        Err(SelfHeldKitError::NotDidPlc)
    }
}

/// Fetch the DID's current full state from the authoritative plc.directory audit log.
async fn fetch_current_state(
    pds_client: &PdsClient,
    did: &str,
) -> Result<CurrentHandleState, SelfHeldKitError> {
    crate::handle_change::fetch_current_state(
        pds_client,
        did,
        |e| map_plc_fetch_error("failed to fetch audit log", e),
        |message| SelfHeldKitError::InvalidAuditLog { message },
    )
    .await
}

/// The account's PDS endpoint — the staging discriminator and the capability-probe target.
fn pds_endpoint(current: &CurrentHandleState) -> String {
    current
        .services
        .get(ATPROTO_PDS_SERVICE_ID)
        .map(|s| s.endpoint.clone())
        .unwrap_or_default()
}

/// Refuse when the identity's host advertises `escrow` — there the escrow-backed ceremony
/// (`rekey.rs`) is the right flow, and installing a second recovery key beside it would be
/// strictly worse for the user.
///
/// A host that could not be asked is **not** refused: `probe` reports no capabilities for an
/// unreachable host without caching that verdict, and treating "we could not ask" as "escrow
/// exists" would strand a user behind a transient outage on the one flow that needs no server.
async fn require_no_escrow_capability(
    pds_client: &PdsClient,
    pds_url: &str,
) -> Result<(), SelfHeldKitError> {
    if pds_url.is_empty() {
        return Ok(());
    }
    if crate::pds_capabilities::probe(pds_client, pds_url)
        .await
        .escrow()
    {
        return Err(SelfHeldKitError::HostOffersEscrow);
    }
    Ok(())
}

/// Record that this identity now carries a self-held kit. Best-effort — nothing must fail a
/// completed kit over a marker write.
fn mark_installed(did: &str) {
    if let Err(e) = crate::keychain::store_item(&self_held_kit_account(did), b"true") {
        tracing::warn!(error = %e, "failed to record the self-held kit marker");
    }
}

/// Whether this identity carries a self-held kit. Test-only: its one production reader (the
/// escrow-upsell seam) was retired, so this now just proves the marker round-trips.
#[cfg(test)]
fn is_installed(did: &str) -> bool {
    matches!(crate::keychain::get_item(&self_held_kit_account(did)), Ok(v) if v == b"true")
}

// ── Imperative shell: build / submit / confirm ───────────────────────────────

/// Build the preview: generate + stage the share set, fetch current state, prove the identity
/// and host are eligible, and return the additive diff.
///
/// Idempotent — the staged set is reused across retries (same recovery key, same `set_id`), so
/// re-running never orphans a prior attempt's material. Signs nothing; `submit` does the single
/// device-key signature.
pub async fn build_self_held_kit(
    pds_client: &PdsClient,
    did: &str,
) -> Result<SelfHeldKitPreview, SelfHeldKitError> {
    require_did_plc(did)?;
    let store = IdentityStore;

    let device =
        store
            .get_or_create_device_key(did)
            .map_err(|e| SelfHeldKitError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;

    let current = fetch_current_state(pds_client, did).await?;
    let pds_url = pds_endpoint(&current);

    // Eligibility BEFORE generating anything. A kit already in flight (a staging slot exists)
    // is always resumable — even after its op landed — because Share 1 and the user's own
    // backup confirmation may still be unfinished.
    let staging_exists = crate::share_ceremony::self_held_kit_staging_exists(did);
    if !staging_exists {
        if current.rotation_keys.first() != Some(&device.key_id) {
            return Err(SelfHeldKitError::WalletNotAuthorized);
        }
        require_no_escrow_capability(pds_client, &pds_url).await?;
    }

    let shares = crate::share_ceremony::load_or_create_for_self_held_kit(did).map_err(|e| {
        SelfHeldKitError::ShareGenerationFailed {
            message: e.to_string(),
        }
    })?;

    // Run the strict guard only while the recovery key is not yet on-chain — i.e. this build
    // would additively insert it. On a resumed kit whose op already landed, the key is present
    // and rule 2 (freshness) no longer holds; the remaining work is Share 1 + confirmation.
    if !current.rotation_keys.contains(&shares.recovery_key_id) {
        let inputs = kit_inputs(&device.key_id, &shares.recovery_key_id, &current);
        guard_self_held_kit_op(&inputs)?;
    }

    Ok(SelfHeldKitPreview {
        diff: build_kit_diff(&shares.recovery_key_id, &current.prev_cid),
        recovery_key_id: shares.recovery_key_id.clone(),
        pds_url,
    })
}

/// Assemble the guard inputs for an op that changes nothing but the rotation-key insertion.
/// Every non-rotationKeys field is passed through as `current == proposed`, so the guard is
/// proving a shape the shell literally builds rather than one it merely intends.
fn kit_inputs(
    device_key_id: &str,
    recovery_key_id: &str,
    current: &CurrentHandleState,
) -> SelfHeldKitInputs {
    SelfHeldKitInputs {
        device_key_id: device_key_id.to_string(),
        recovery_key_id: recovery_key_id.to_string(),
        current_rotation_keys: current.rotation_keys.clone(),
        proposed_rotation_keys: proposed_kit_keys(&current.rotation_keys, recovery_key_id),
        current_verification_methods: current.verification_methods.clone(),
        proposed_verification_methods: current.verification_methods.clone(),
        current_services: current.services.clone(),
        proposed_services: current.services.clone(),
        current_also_known_as: current.also_known_as.clone(),
        proposed_also_known_as: current.also_known_as.clone(),
    }
}

/// Install the kit: post the additive rotation op (device-key-signed) to plc.directory if it
/// has not already landed, write the durable Share 1, refresh the cached DID doc, and record
/// the kit marker. Returns Shares 2 and 3 for the user to save.
///
/// Every step is idempotent, so a kit interrupted at any point converges on re-run:
///  - the PLC op is skipped when the recovery key is already on-chain;
///  - the Share 1 write is a verified overwrite;
///  - the cache refresh is a plain re-fetch.
///
/// Because the device key never leaves `rotationKeys[0]`, no intermediate state drops recovery
/// capability below the pre-kit baseline (device key only).
pub async fn submit_self_held_kit(
    pds_client: &PdsClient,
    did: &str,
) -> Result<SelfHeldKitResult, SelfHeldKitError> {
    require_did_plc(did)?;
    let store = IdentityStore;

    let device =
        store
            .get_or_create_device_key(did)
            .map_err(|e| SelfHeldKitError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;

    let current = fetch_current_state(pds_client, did).await?;

    // Reload the exact staged set built in the preview (durable across app kills). Until the
    // confirmation gate this is the only home of the new seed material.
    let shares = crate::share_ceremony::load_or_create_for_self_held_kit(did).map_err(|e| {
        SelfHeldKitError::ShareGenerationFailed {
            message: e.to_string(),
        }
    })?;
    let recovery_key_id = shares.recovery_key_id.clone();

    // Step 1: post the additive rotation op — unless it already landed (a resumed kit).
    if !current.rotation_keys.contains(&recovery_key_id) {
        let inputs = kit_inputs(&device.key_id, &recovery_key_id, &current);
        guard_self_held_kit_op(&inputs)?;

        let sign_closure =
            crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
                PerDidSignError::DeviceKeyNotFound { message } => {
                    SelfHeldKitError::IdentityNotFound { message }
                }
                PerDidSignError::SigningSetupFailed { message } => {
                    SelfHeldKitError::SigningFailed { message }
                }
            })?;
        let signed = crypto::build_did_plc_rotation_op(
            &current.prev_cid,
            inputs.proposed_rotation_keys,
            current.verification_methods.clone(),
            current.also_known_as.clone(),
            current.services.clone(),
            sign_closure,
        )
        .map_err(|e| SelfHeldKitError::SigningFailed {
            message: format!("failed to build the recovery-key op: {e}"),
        })?;
        let signed_op: serde_json::Value =
            serde_json::from_str(&signed.signed_op_json).map_err(|e| {
                SelfHeldKitError::SigningFailed {
                    message: format!("failed to parse signed op JSON: {e}"),
                }
            })?;
        pds_client
            .post_plc_operation(did, &signed_op)
            .await
            .map_err(|e| match e {
                PdsClientError::RateLimited { retry_after, .. } => {
                    SelfHeldKitError::RateLimited { retry_after }
                }
                other => SelfHeldKitError::PlcSubmissionFailed {
                    message: format!("failed to submit the recovery-key op: {other}"),
                },
            })?;
    }

    // Step 2: write the durable per-DID Share 1 slot (verified read-back). No escrow step
    // follows — Shares 2 and 3 go home with the user.
    store_and_verify_share1(did, &shares.share1)
        .map_err(|message| SelfHeldKitError::ShareStorageFailed { message })?;

    // Step 3: refresh the cached PLC log + DID document (PLC *data* shape — the identity card
    // reads rotationKeys, which the W3C form strips).
    let updated_log = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| map_plc_fetch_error("failed to fetch updated audit log", e))?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| SelfHeldKitError::ShareStorageFailed {
            message: format!("failed to cache updated PLC log: {e}"),
        })?;
    let did_doc = pds_client
        .fetch_plc_data_document(did)
        .await
        .map_err(|e| map_plc_fetch_error("failed to fetch DID document", e))?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| SelfHeldKitError::ShareStorageFailed {
            message: format!("failed to cache updated DID document: {e}"),
        })?;

    mark_installed(did);

    Ok(SelfHeldKitResult {
        updated_did_doc: did_doc,
        share2: shares.share2.to_string(),
        share2_words: shares.share2_words.to_string(),
        share3: shares.share3.to_string(),
        share3_words: shares.share3_words.to_string(),
    })
}

/// Confirm the user has saved Shares 2 and 3, and tear down the per-DID staging slot.
///
/// The teardown order is load-bearing: Share 1 must be verifiably present in its durable slot
/// (written by `submit`) before the staging record — the last local copy of the seed and of
/// Shares 2 and 3 — is destroyed. Idempotent.
pub fn confirm_self_held_kit(did: &str) -> Result<(), SelfHeldKitError> {
    match crate::rekey::load_share1(did) {
        Ok(bytes) if !bytes.is_empty() => {}
        Ok(_) => return Err(SelfHeldKitError::ShareNotStored),
        Err(ref e) if crate::keychain::is_not_found(e) => {
            return Err(SelfHeldKitError::ShareNotStored)
        }
        Err(e) => {
            return Err(SelfHeldKitError::ShareStorageFailed {
                message: format!("keychain read failed: {e}"),
            })
        }
    }
    crate::share_ceremony::clear_self_held_kit_staging(did).map_err(|e| {
        SelfHeldKitError::ShareStorageFailed {
            message: format!("failed to clear the staging slot: {e}"),
        }
    })
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: build the preview (stage shares, prove eligibility, return the diff).
#[tauri::command]
pub async fn build_self_held_kit_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SelfHeldKitPreview, SelfHeldKitError> {
    build_self_held_kit(state.pds_client(), &did).await
}

/// Tauri command: install the kit (post op + Share 1 + refresh). Idempotent/resumable.
#[tauri::command]
pub async fn submit_self_held_kit_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SelfHeldKitResult, SelfHeldKitError> {
    submit_self_held_kit(state.pds_client(), &did).await
}

/// Tauri command: confirm Shares 2 and 3 are saved and tear down the staging slot.
#[tauri::command]
pub fn confirm_self_held_kit_cmd(did: String) -> Result<(), SelfHeldKitError> {
    confirm_self_held_kit(&did)
}

/// Tauri command: whether a kit is mid-flight for this DID (a staging slot exists).
///
/// The identity surface resurfaces "finish your recovery kit" on this, which is what catches a
/// kit whose PLC op landed (so the document already shows the recovery key) but whose Share 1
/// or user confirmation never completed.
#[tauri::command]
pub fn self_held_kit_in_progress_cmd(did: String) -> bool {
    crate::share_ceremony::self_held_kit_staging_exists(&did)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:key:zDEVICE";
    const OLD_PDS: &str = "did:key:zOLDPDS";
    const OTHER: &str = "did:key:zOTHER";
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
                endpoint: "https://bsky.social".to_string(),
            },
        );
        m
    }

    /// A claimed foreign-hosted identity: device key at [0] with a THREE-key tail the old host
    /// wrote — the exact shape `guard_rekey_op` refuses as `AlreadyRekeyed`.
    fn ok_inputs() -> SelfHeldKitInputs {
        let current = vec![DEVICE.to_string(), OLD_PDS.to_string(), OTHER.to_string()];
        SelfHeldKitInputs {
            device_key_id: DEVICE.to_string(),
            recovery_key_id: RECOVERY.to_string(),
            proposed_rotation_keys: proposed_kit_keys(&current, RECOVERY),
            current_rotation_keys: current,
            current_verification_methods: vms(OLD_PDS),
            proposed_verification_methods: vms(OLD_PDS),
            current_services: services(),
            proposed_services: services(),
            current_also_known_as: vec!["at://alice.bsky.social".to_string()],
            proposed_also_known_as: vec!["at://alice.bsky.social".to_string()],
        }
    }

    #[test]
    fn guard_accepts_an_arbitrary_length_claimed_tail() {
        assert!(guard_self_held_kit_op(&ok_inputs()).is_ok());
    }

    /// The defining difference from `rekey::guard_rekey_op`: a three-key claimed identity is
    /// eligible here and rejected there. If this ever fails, the two guards have converged and
    /// the foreign-hosted population has lost its only route to a recovery key.
    #[test]
    fn the_rekey_guard_would_reject_what_this_guard_accepts() {
        let inputs = ok_inputs();
        assert!(guard_self_held_kit_op(&inputs).is_ok());

        let rekey_inputs = crate::rekey::RekeyInputs {
            device_key_id: inputs.device_key_id.clone(),
            recovery_key_id: inputs.recovery_key_id.clone(),
            current_rotation_keys: inputs.current_rotation_keys.clone(),
            proposed_rotation_keys: inputs.proposed_rotation_keys.clone(),
            current_verification_methods: inputs.current_verification_methods.clone(),
            proposed_verification_methods: inputs.proposed_verification_methods.clone(),
            current_services: inputs.current_services.clone(),
            proposed_services: inputs.proposed_services.clone(),
            current_also_known_as: inputs.current_also_known_as.clone(),
            proposed_also_known_as: inputs.proposed_also_known_as.clone(),
        };
        assert!(matches!(
            crate::rekey::guard_rekey_op(&rekey_inputs),
            Err(crate::rekey::RekeyError::AlreadyRekeyed)
        ));
    }

    /// A two-key identity (the shape both flows can express) is still accepted here.
    #[test]
    fn guard_accepts_a_two_key_identity() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![DEVICE.to_string(), OLD_PDS.to_string()];
        inputs.proposed_rotation_keys = proposed_kit_keys(&inputs.current_rotation_keys, RECOVERY);
        assert!(guard_self_held_kit_op(&inputs).is_ok());
    }

    #[test]
    fn guard_rejects_when_device_is_not_root() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![OLD_PDS.to_string(), DEVICE.to_string()];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_a_recovery_key_already_present() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![DEVICE.to_string(), RECOVERY.to_string()];
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            RECOVERY.to_string(),
            RECOVERY.to_string(),
        ];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_demoted_device_key() {
        let mut inputs = ok_inputs();
        // Recovery at [0], device demoted — inverts enclave supremacy.
        inputs.proposed_rotation_keys = vec![
            RECOVERY.to_string(),
            DEVICE.to_string(),
            OLD_PDS.to_string(),
            OTHER.to_string(),
        ];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    /// The tail must survive verbatim — dropping a key the old host relies on is not additive,
    /// and is the failure mode the missing length check might otherwise have let through.
    #[test]
    fn guard_rejects_a_dropped_tail_key() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            RECOVERY.to_string(),
            OLD_PDS.to_string(),
        ];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_reordered_tail() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            RECOVERY.to_string(),
            OTHER.to_string(),
            OLD_PDS.to_string(),
        ];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_smuggled_extra_key() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_rotation_keys
            .push("did:key:zEVIL".to_string());
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_moved_repo_key() {
        let mut inputs = ok_inputs();
        inputs.proposed_verification_methods = vms(RECOVERY);
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
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
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_an_also_known_as_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.example.com".to_string()];
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::GuardRejected { .. })
        ));
    }

    #[test]
    fn proposed_keys_insert_recovery_at_index_one_and_shift_the_tail() {
        let current = vec![DEVICE.to_string(), OLD_PDS.to_string(), OTHER.to_string()];
        assert_eq!(
            proposed_kit_keys(&current, RECOVERY),
            vec![
                DEVICE.to_string(),
                RECOVERY.to_string(),
                OLD_PDS.to_string(),
                OTHER.to_string(),
            ]
        );
    }

    /// The shell builds the proposal before the guard runs, and a resumed kit skips the
    /// root-key precheck — so this must return a clean refusal, never panic on an empty slice.
    #[test]
    fn empty_rotation_keys_refuse_rather_than_panic() {
        assert!(proposed_kit_keys(&[], RECOVERY).is_empty());

        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = Vec::new();
        inputs.proposed_rotation_keys = proposed_kit_keys(&[], RECOVERY);
        assert!(matches!(
            guard_self_held_kit_op(&inputs),
            Err(SelfHeldKitError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn diff_is_additive_only() {
        let diff = build_kit_diff(RECOVERY, PREV);
        assert_eq!(diff.added_keys, vec![RECOVERY.to_string()]);
        assert!(
            diff.removed_keys.is_empty(),
            "the kit removes nothing — the honest framing"
        );
        assert!(diff.changed_services.is_empty());
        assert_eq!(diff.prev_cid.as_deref(), Some(PREV));
    }

    #[test]
    fn require_did_plc_rejects_did_web() {
        assert!(matches!(
            require_did_plc("did:web:example.com"),
            Err(SelfHeldKitError::NotDidPlc)
        ));
        assert!(require_did_plc("did:plc:abc123").is_ok());
    }

    /// A directory throttle and a directory HTTP verdict must reach the UI as RATE_LIMITED /
    /// PLC_DIRECTORY_ERROR — only a transport failure may say "check your connection".
    #[test]
    fn plc_fetch_errors_classify_by_status() {
        assert!(matches!(
            map_plc_fetch_error(
                "ctx",
                PdsClientError::RateLimited {
                    retry_after: Some("30".to_string()),
                    message: "slow down".to_string(),
                }
            ),
            SelfHeldKitError::RateLimited { retry_after: Some(ref r) } if r == "30"
        ));
        assert!(matches!(
            map_plc_fetch_error(
                "ctx",
                PdsClientError::XrpcError {
                    status: 502,
                    error: None,
                    message: "bad gateway".to_string(),
                }
            ),
            SelfHeldKitError::PlcDirectoryError { ref message } if message.contains("502")
        ));
        assert!(matches!(
            map_plc_fetch_error(
                "ctx",
                PdsClientError::NetworkError {
                    message: "dns failure".to_string(),
                }
            ),
            SelfHeldKitError::NetworkError { .. }
        ));
    }

    #[test]
    fn installed_marker_round_trips_and_defaults_to_absent() {
        crate::keychain::clear_for_test();
        let did = "did:plc:kittest0123456789abcdef";
        assert!(!is_installed(did), "a fresh identity carries no kit");
        mark_installed(did);
        assert!(is_installed(did));
    }
}
