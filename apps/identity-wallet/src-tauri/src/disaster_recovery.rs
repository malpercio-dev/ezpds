// pattern: Mixed (Functional Core guard/helpers + Imperative Shell commands)
//
// Sovereign disaster recovery: rebuild the account on a new (or the same) PDS from the
// iCloud backups when the source PDS is gone or uncooperative — the "adversarial
// migration" pattern, automated by a wallet that holds `rotationKeys[0]`.
//
// The identity half lives here; the transfer half reuses the migration orchestrator.
// Flow (two guarded PLC ops, createAccount + import sandwiched between):
//   1. `enroll_recovery_signing_key` — PLC op #1, device-key-signed, submitted DIRECTLY
//      to plc.directory: enroll a fresh self-controlled `atproto` signing key, changing
//      NOTHING else (rotationKeys, alsoKnownAs, services all preserved — the strict
//      guard proves it). The `services.atproto_pds` repoint is deferred to op #2, which
//      reuses `migrate.rs` verbatim.
//   2. `await_recovery_key_visibility` — poll the plc.directory audit log until op #1
//      is globally visible; `createAccount` cannot verify the offline JWT before the
//      signing-key change propagates.
//   3. `create_recovery_destination_account` — mint the service-auth JWT OFFLINE with
//      the self-controlled key (`iss` = account DID, `aud` = destination server DID,
//      `lxm` = com.atproto.server.createAccount) and run the standard migration
//      `createAccount` path against the destination — which verifies the JWT against
//      the key it resolves from plc.directory, so this works against any PDS.
//   4. `recovery_transfer_repo` — importRepo from the validated iCloud CAR snapshot
//      (`repo_backup::mirror_repo_car`); blobs drain from the iCloud mirror via the
//      shared `transfer_blobs` (mirror-primary in recovery mode).
//   5. The identity leg (PLC op #2: adopt the destination's recommended keys +
//      `services` repoint, wallet device key still at `rotationKeys[0]`) and the
//      finalize (activateAccount, no source to deactivate) reuse `migrate.rs` and the
//      orchestrator unchanged.
//
// Unlike `rotate_repo_key.rs` — which deliberately routes its op through the live PDS —
// every PLC write here goes straight to plc.directory: a dead or hostile source PDS is
// exactly the scenario. The account stays deactivated (inert) until the final
// activation, so an abort at any earlier step leaves nothing half-live.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::handle_change::latest_full_state;
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::migration_orchestrator::{
    ensure_phase_did, preferred_login_identifier, MigrationError, MigrationPhase,
    OutboundMigrationState,
};
use crate::pds_client::{PdsClient, PdsClientError};
use crypto::{AuditEntry, PlcService};

/// Lexicon method the offline service-auth JWT authorizes — the migration-mode
/// `createAccount` the destination PDS verifies it against.
const CREATE_ACCOUNT_LXM: &str = "com.atproto.server.createAccount";

/// Offline service-auth JWT lifetime in seconds (~1h, the atproto maximum for an
/// `lxm`-bound token).
const SERVICE_AUTH_TTL_SECS: u64 = 3600;

// ── Error type ───────────────────────────────────────────────────────────────

/// Error returned by the identity-side disaster-recovery commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` with camelCase fields, matching
/// the wallet's established error contract.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisasterRecoveryError {
    /// The wallet holds no key in the DID's current rotationKeys — it cannot
    /// self-sign the enroll op, and there is no interop fallback with a dead source.
    #[error("wallet not authorized for this DID")]
    WalletNotAuthorized,
    /// The strict pre-sign guard refused the proposed enroll operation.
    #[error("guard rejected: {reason}")]
    GuardRejected { reason: String },
    /// The plc.directory audit log is missing, malformed, or fully nullified.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Device-key signing (or key setup) failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// A Keychain read/write failed (including the recovery signing key persist).
    #[error("keychain error: {message}")]
    KeychainError { message: String },
    /// The DID is not registered in the wallet's identity store.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// plc.directory rejected a request with an HTTP verdict.
    #[error("plc.directory error: {message}")]
    PlcDirectoryError { message: String },
    /// plc.directory rate-limited the request.
    #[error("rate limited")]
    RateLimited {
        #[serde(rename = "retryAfter")]
        retry_after: Option<String>,
    },
    /// No recovery signing key has been enrolled for this DID yet.
    #[error("no recovery signing key enrolled: {message}")]
    KeyNotEnrolled { message: String },
    /// The destination PDS could not be reached or described.
    #[error("destination unreachable: {message}")]
    DestinationUnreachable { message: String },
    /// Recovery state absent, DID mismatch, or phase too low.
    #[error("recovery not ready: {message}")]
    RecoveryNotReady { message: String },
    /// A transport-level network failure.
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Classify a plc.directory / discovery read failure: throttling and HTTP verdicts are
/// named, only genuine transport failures become NETWORK_ERROR.
fn map_plc_fetch_error(context: &str, e: PdsClientError) -> DisasterRecoveryError {
    match e {
        PdsClientError::RateLimited { retry_after, .. } => {
            DisasterRecoveryError::RateLimited { retry_after }
        }
        PdsClientError::NetworkError { .. } => DisasterRecoveryError::NetworkError {
            message: format!("{context}: {e}"),
        },
        other => DisasterRecoveryError::PlcDirectoryError {
            message: format!("{context}: {other}"),
        },
    }
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs to decide whether a proposed
/// signing-key-enroll operation is safe to sign. Flattened to plain values so the guard
/// is a pure, trivially testable function.
#[derive(Debug, Clone)]
pub struct RecoveryEnrollInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must stay at rotationKeys[0].
    pub device_key_id: String,
    /// The freshly generated self-controlled signing key the op enrolls.
    pub new_signing_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op).
    pub current_rotation_keys: Vec<String>,
    /// The DID's CURRENT verificationMethods map.
    pub current_verification_methods: BTreeMap<String, String>,
    /// The DID's CURRENT alsoKnownAs.
    pub current_also_known_as: Vec<String>,
    /// The DID's CURRENT services map.
    pub current_services: BTreeMap<String, PlcService>,
    /// The rotation keys the op proposes (must be IDENTICAL to current).
    pub proposed_rotation_keys: Vec<String>,
    /// The verificationMethods the op proposes (current with ONLY `atproto` swapped).
    pub proposed_verification_methods: BTreeMap<String, String>,
    /// The alsoKnownAs the op proposes (must be identical to current).
    pub proposed_also_known_as: Vec<String>,
    /// The services the op proposes (must be identical to current).
    pub proposed_services: BTreeMap<String, PlcService>,
}

// ── The strict pre-sign guard (STRICT ALLOWLIST) ─────────────────────────────

/// Reject the proposed enroll operation unless it satisfies the strict allowlist.
///
/// The FIFTH wallet allowlist guard, and the narrowest: an enroll op may change
/// **only** the `atproto` verification method, to exactly the freshly generated
/// self-controlled key. Everything else — rotationKeys (the sovereignty anchor, wallet
/// device key at `[0]`), alsoKnownAs, services, every other verification method — must
/// be re-signed byte-for-byte unchanged. Buchanan's central warning about adversarial
/// migration is that accidentally dropping your own rotation key permanently locks you
/// out; requiring `proposed_rotation_keys == current` (with the device key first) makes
/// that impossible to sign.
pub fn guard_recovery_enroll_op(
    inputs: &RecoveryEnrollInputs,
) -> Result<(), DisasterRecoveryError> {
    // Authorization first: the wallet must hold a current rotation key, or it cannot
    // self-sign at all. The distinct signal wins over any proposed-op quibble.
    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(DisasterRecoveryError::WalletNotAuthorized);
    }

    // Sovereignty: rotationKeys must be UNCHANGED, with the device key at [0].
    if inputs.proposed_rotation_keys != inputs.current_rotation_keys {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: "rotationKeys must be preserved unchanged by a signing-key enroll".to_string(),
        });
    }
    if inputs.proposed_rotation_keys.first() != Some(&inputs.device_key_id) {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: format!(
                "device key must be rotationKeys[0]; found {:?}",
                inputs.proposed_rotation_keys.first()
            ),
        });
    }

    // Freshness: the enrolled key must be genuinely new — not a rotation key, not the
    // key being replaced, and not the device key doing double duty.
    if !inputs.new_signing_key_id.starts_with("did:key:") {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: format!(
                "enrolled signing key is not a did:key URI: {}",
                inputs.new_signing_key_id
            ),
        });
    }
    if inputs
        .current_rotation_keys
        .contains(&inputs.new_signing_key_id)
        || inputs
            .current_verification_methods
            .values()
            .any(|v| v == &inputs.new_signing_key_id)
    {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: "enrolled signing key must be fresh (already present in the DID document)"
                .to_string(),
        });
    }

    // Verification methods: identical to current except `atproto`, which must be
    // exactly the new key.
    let mut expected_vms = inputs.current_verification_methods.clone();
    expected_vms.insert("atproto".to_string(), inputs.new_signing_key_id.clone());
    if inputs.proposed_verification_methods != expected_vms {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: "verificationMethods may change only the 'atproto' method, to the enrolled key"
                .to_string(),
        });
    }

    // Handle preservation.
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: "alsoKnownAs (handle) must be preserved by a signing-key enroll".to_string(),
        });
    }

    // Service preservation: the atproto_pds repoint belongs to PLC op #2 (the migrate.rs
    // identity leg), never to the enroll.
    if inputs.proposed_services != inputs.current_services {
        return Err(DisasterRecoveryError::GuardRejected {
            reason: "services must be preserved by a signing-key enroll".to_string(),
        });
    }

    Ok(())
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// Whether the enrolled signing key is visible as the DID's current `atproto`
/// verification method in the (freshly fetched) audit log — the propagation gate
/// `createAccount` waits behind.
pub(crate) fn enrolled_key_visible(audit_log: &[AuditEntry], key_id: &str) -> bool {
    audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .and_then(|e| {
            e.operation
                .get("verificationMethods")
                .and_then(|vms| vms.get("atproto"))
                .and_then(|v| v.as_str())
        })
        .is_some_and(|current| current == key_id)
}

/// Derive the `did:key:z...` URI for a stored P-256 recovery signing key scalar. The
/// same multicodec (`[0x80, 0x24]`) + base58btc encoding as every other wallet key.
fn did_key_for_scalar(scalar: &[u8; 32]) -> Result<String, DisasterRecoveryError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::from_bytes(scalar.as_slice().into()).map_err(|e| {
        DisasterRecoveryError::SigningFailed {
            message: format!("stored recovery signing key is not a valid P-256 scalar: {e}"),
        }
    })?;
    let compressed = secret.public_key().to_encoded_point(true);
    let mut multikey = Vec::with_capacity(2 + compressed.as_bytes().len());
    multikey.extend_from_slice(&[0x80, 0x24]);
    multikey.extend_from_slice(compressed.as_bytes());
    Ok(format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &multikey)
    ))
}

/// Signing closure over the stored recovery signing key scalar: deterministic (RFC
/// 6979) P-256 ECDSA, low-S normalized, raw 64-byte r‖s — the contract every crypto
/// builder and the service-auth JWT verifier expect.
fn recovery_sign_closure(
    scalar: zeroize::Zeroizing<[u8; 32]>,
) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
    move |data: &[u8]| {
        use p256::ecdsa::signature::Signer;
        let sk = p256::ecdsa::SigningKey::from_bytes(scalar.as_slice().into())
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("invalid signing key: {e}")))?;
        let sig: p256::ecdsa::Signature = sk.sign(data);
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    }
}

// ── Result types ─────────────────────────────────────────────────────────────

/// What `prepare_disaster_recovery` resolved, for the recovery start screen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedRecovery {
    /// The handle the destination account will be created with (the DID's current
    /// handle, or the caller's override when the old handle domain no longer resolves).
    pub handle: String,
    /// The destination server's DID (`did:web:<host>`) — the offline JWT's `aud`.
    pub dest_did: String,
    /// The dead source PDS endpoint from the DID document (display only).
    pub source_pds_url: String,
}

/// Outcome of `enroll_recovery_signing_key`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEnrollment {
    /// The enrolled self-controlled signing key's did:key URI.
    pub signing_key_id: String,
    /// The submitted enroll op's CID (or the current head when already enrolled).
    pub op_cid: String,
    /// True when the key was already the DID's `atproto` method (a reconciled retry) —
    /// nothing was signed or submitted.
    pub already_enrolled: bool,
}

/// Outcome of one `await_recovery_key_visibility` poll.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyStatus {
    /// Whether the enrolled key is now the DID's `atproto` method on plc.directory.
    pub visible: bool,
}

// ── prepare ──────────────────────────────────────────────────────────────────

/// Resolve the destination and the DID's current PLC state, and open a recovery
/// orchestration session (phase `Resolved`, `recovery = true`).
///
/// Deliberately does NOT contact the source PDS — `discover_pds`'s reachability probe
/// would fail against a dead host, and the whole point is not to depend on it. The
/// current state comes from the plc.directory audit log alone. `handle_override` is the
/// escape hatch for the offline-handle-domain edge case: when the old PDS served the
/// handle's domain, the caller falls back to a destination-served handle.
#[tauri::command]
pub async fn prepare_disaster_recovery(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    dest_pds_url: String,
    handle_override: Option<String>,
) -> Result<PreparedRecovery, DisasterRecoveryError> {
    tracing::info!(did = %did, dest_url = %dest_pds_url, "prepare_disaster_recovery");
    let pds_client = state.pds_client();

    // 1. Destination server DID (the offline JWT's `aud`).
    let dest_describe = pds_client
        .describe_server(&dest_pds_url)
        .await
        .map_err(|e| DisasterRecoveryError::DestinationUnreachable {
            message: format!("describeServer failed: {e}"),
        })?;

    // 2. Current DID state from plc.directory (never the dead source PDS).
    let log_json = pds_client
        .fetch_audit_log(&did)
        .await
        .map_err(|e| map_plc_fetch_error("failed to fetch audit log", e))?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| DisasterRecoveryError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current =
        latest_full_state(&audit_log).map_err(|e| DisasterRecoveryError::InvalidAuditLog {
            message: e.to_string(),
        })?;

    let source_pds_url = current
        .services
        .get("atproto_pds")
        .map(|s| s.endpoint.clone())
        .unwrap_or_default();
    let handle = handle_override
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| preferred_login_identifier(&current.also_known_as, &did));

    let prepared = PreparedRecovery {
        handle: handle.clone(),
        dest_did: dest_describe.did.clone(),
        source_pds_url: source_pds_url.clone(),
    };

    // 3. Open the recovery orchestration session. Same state machine as an outbound
    //    migration, but flagged `recovery` so the shared steps skip the source side.
    *state.orchestration_state.lock().await = Some(OutboundMigrationState {
        did,
        source_pds_url,
        dest_pds_url,
        dest_did: dest_describe.did,
        handle,
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Resolved,
        accepted_blob_loss: Vec::new(),
        recovery: true,
    });

    Ok(prepared)
}

// ── enroll (PLC op #1) ───────────────────────────────────────────────────────

/// Build, guard, device-key-sign, and submit the signing-key enroll op directly to
/// plc.directory, persisting the self-controlled key's scalar in the Keychain FIRST
/// (read-back-verified) so a landed op can never outrun the key that must sign the JWT.
///
/// Idempotent across retries: a persisted-but-not-yet-enrolled key is reused (the same
/// key across attempts, like the ceremony staging slot), and a key that already IS the
/// DID's `atproto` method reconciles to success without signing anything.
#[tauri::command]
pub async fn enroll_recovery_signing_key(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RecoveryEnrollment, DisasterRecoveryError> {
    tracing::info!(did = %did, "enroll_recovery_signing_key");
    enroll_recovery_signing_key_impl(state.pds_client(), &did).await
}

async fn enroll_recovery_signing_key_impl(
    pds_client: &PdsClient,
    did: &str,
) -> Result<RecoveryEnrollment, DisasterRecoveryError> {
    let store = IdentityStore;

    // 1. Per-DID device key (the op's signer).
    let device_pub = store.get_or_create_device_key(did).map_err(|e| {
        DisasterRecoveryError::IdentityNotFound {
            message: format!("failed to get device key: {e}"),
        }
    })?;
    let device_key_id = device_pub.key_id;

    // 2. Current state from the audit log.
    let log_json = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| map_plc_fetch_error("failed to fetch audit log", e))?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| DisasterRecoveryError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current =
        latest_full_state(&audit_log).map_err(|e| DisasterRecoveryError::InvalidAuditLog {
            message: e.to_string(),
        })?;

    // 3. Reuse a persisted key across retries; generate + persist a fresh one
    //    otherwise. Persist happens BEFORE the network submit.
    let key_id = match store.load_recovery_signing_key(did).map_err(|e| {
        DisasterRecoveryError::KeychainError {
            message: e.to_string(),
        }
    })? {
        Some(scalar) => did_key_for_scalar(&scalar)?,
        None => {
            let keypair = crypto::generate_p256_keypair().map_err(|e| {
                DisasterRecoveryError::SigningFailed {
                    message: format!("failed to generate recovery signing key: {e}"),
                }
            })?;
            store
                .store_recovery_signing_key(did, &keypair.private_key_bytes)
                .map_err(|e| DisasterRecoveryError::KeychainError {
                    message: e.to_string(),
                })?;
            keypair.key_id.0
        }
    };

    // 4. Reconcile: a prior attempt's op may already have landed.
    if enrolled_key_visible(&audit_log, &key_id) {
        tracing::info!(did = %did, "recovery signing key already enrolled; reconciled without re-submitting");
        return Ok(RecoveryEnrollment {
            signing_key_id: key_id,
            op_cid: current.prev_cid,
            already_enrolled: true,
        });
    }

    // 5. Propose: swap ONLY the atproto verification method.
    let mut proposed_vms = current.verification_methods.clone();
    proposed_vms.insert("atproto".to_string(), key_id.clone());

    // 6. Strict pre-sign guard — the security gate.
    let inputs = RecoveryEnrollInputs {
        device_key_id: device_key_id.clone(),
        new_signing_key_id: key_id.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        current_verification_methods: current.verification_methods.clone(),
        current_also_known_as: current.also_known_as.clone(),
        current_services: current.services.clone(),
        proposed_rotation_keys: current.rotation_keys.clone(),
        proposed_verification_methods: proposed_vms.clone(),
        proposed_also_known_as: current.also_known_as.clone(),
        proposed_services: current.services.clone(),
    };
    guard_recovery_enroll_op(&inputs)?;

    // 7. Device-key-sign and submit directly to plc.directory.
    let sign_closure = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            DisasterRecoveryError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => {
            DisasterRecoveryError::SigningFailed { message }
        }
    })?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        inputs.proposed_rotation_keys,
        proposed_vms,
        inputs.proposed_also_known_as,
        inputs.proposed_services,
        sign_closure,
    )
    .map_err(|e| DisasterRecoveryError::SigningFailed {
        message: format!("failed to build enroll op: {e}"),
    })?;
    let signed_op: serde_json::Value =
        serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            DisasterRecoveryError::SigningFailed {
                message: format!("failed to parse signed op JSON: {e}"),
            }
        })?;

    pds_client
        .post_plc_operation(did, &signed_op)
        .await
        .map_err(|e| map_plc_fetch_error("plc.directory rejected the enroll operation", e))?;

    // Best-effort cache refresh so the monitor sees the wallet's own op as expected.
    if let Ok(updated) = pds_client.fetch_audit_log(did).await {
        let _ = store.store_plc_log(did, &updated);
    }

    Ok(RecoveryEnrollment {
        signing_key_id: key_id,
        op_cid: signed.cid,
        already_enrolled: false,
    })
}

// ── propagation poll ─────────────────────────────────────────────────────────

/// One poll of the plc.directory audit log: is the enrolled key the DID's `atproto`
/// method yet? On the first visible poll, advances the recovery session past the
/// (sourceless) auth phase so `create_recovery_destination_account`'s gate opens —
/// `createAccount` cannot run before op #1 has propagated.
#[tauri::command]
pub async fn await_recovery_key_visibility(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RecoveryKeyStatus, DisasterRecoveryError> {
    let store = IdentityStore;
    let scalar = store
        .load_recovery_signing_key(&did)
        .map_err(|e| DisasterRecoveryError::KeychainError {
            message: e.to_string(),
        })?
        .ok_or_else(|| DisasterRecoveryError::KeyNotEnrolled {
            message: "run enroll_recovery_signing_key first".to_string(),
        })?;
    let key_id = did_key_for_scalar(&scalar)?;
    drop(scalar);

    let log_json = state
        .pds_client()
        .fetch_audit_log(&did)
        .await
        .map_err(|e| map_plc_fetch_error("failed to fetch audit log", e))?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| DisasterRecoveryError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;

    if !enrolled_key_visible(&audit_log, &key_id) {
        return Ok(RecoveryKeyStatus { visible: false });
    }

    // Visible — advance the recovery session so createAccount's phase gate opens.
    let mut orchestration = state.orchestration_state.lock().await;
    match orchestration.as_mut() {
        Some(mig) if mig.did == did && mig.recovery => {
            if mig.phase < MigrationPhase::SourceAuthed {
                mig.phase = MigrationPhase::SourceAuthed;
            }
            Ok(RecoveryKeyStatus { visible: true })
        }
        _ => Err(DisasterRecoveryError::RecoveryNotReady {
            message: "no matching recovery session; run prepare_disaster_recovery first"
                .to_string(),
        }),
    }
}

// ── createAccount with the offline JWT ───────────────────────────────────────

/// Mint the service-auth JWT offline with the self-controlled signing key.
fn mint_offline_service_auth(
    scalar: zeroize::Zeroizing<[u8; 32]>,
    did: &str,
    dest_did: &str,
) -> Result<String, MigrationError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| MigrationError::ServiceAuthFailed {
            message: format!("system clock is before the Unix epoch: {e}"),
        })?
        .as_secs();
    crypto::mint_service_auth_jwt(
        recovery_sign_closure(scalar),
        did,
        dest_did,
        Some(CREATE_ACCOUNT_LXM),
        now,
        now + SERVICE_AUTH_TTL_SECS,
    )
    .map_err(|e| MigrationError::ServiceAuthFailed {
        message: format!("failed to mint offline service-auth JWT: {e}"),
    })
}

/// Create the (deactivated) destination account using the offline-minted service-auth
/// JWT — the sourceless twin of `create_destination_account`. Re-verifies that op #1 is
/// visible on plc.directory before minting (defense in depth behind the poll's phase
/// gate), then runs the shared reserve-key → createAccount → Bearer-session core.
#[tauri::command]
pub async fn create_recovery_destination_account(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    email: String,
    invite_code: Option<String>,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "create_recovery_destination_account");

    // Gate + extract dependencies.
    let (dest_pds_url, dest_did, handle, existing_dest_client) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::SourceAuthed)?;
        if !mig.recovery {
            return Err(MigrationError::MigrationNotReady {
                message: "active session is a migration, not a disaster recovery".into(),
            });
        }
        (
            mig.dest_pds_url.clone(),
            mig.dest_did.clone(),
            mig.handle.clone(),
            mig.dest_client.clone(),
        )
    }; // lock released

    let pds_client = state.pds_client();
    let store = IdentityStore;

    // Load the self-controlled signing key.
    let scalar = store
        .load_recovery_signing_key(&did)
        .map_err(|e| MigrationError::ServiceAuthFailed {
            message: format!("failed to load recovery signing key: {e}"),
        })?
        .ok_or_else(|| MigrationError::ServiceAuthFailed {
            message: "no recovery signing key enrolled for this DID".to_string(),
        })?;
    let key_id = did_key_for_scalar(&scalar).map_err(|e| MigrationError::ServiceAuthFailed {
        message: e.to_string(),
    })?;

    // Defense in depth: never mint against a key plc.directory doesn't serve yet — the
    // destination would just reject the JWT with a confusing signature error.
    let log_json =
        pds_client
            .fetch_audit_log(&did)
            .await
            .map_err(|e| MigrationError::NetworkError {
                message: format!("failed to fetch audit log: {e}"),
            })?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| MigrationError::ServiceAuthFailed {
            message: format!("failed to parse audit log: {e}"),
        })?;
    if !enrolled_key_visible(&audit_log, &key_id) {
        return Err(MigrationError::ServiceAuthFailed {
            message: "the enrolled signing key is not yet visible on plc.directory; keep polling"
                .to_string(),
        });
    }

    // Reserve a signing key at the destination (as the standard migration does), mint
    // the JWT offline, and run the shared createAccount core.
    if existing_dest_client.is_none() {
        pds_client
            .reserve_signing_key(&dest_pds_url, &did)
            .await
            .map_err(|e| MigrationError::AccountCreationFailed {
                message: format!("failed to reserve signing key: {e}"),
            })?;
    }
    let token = mint_offline_service_auth(scalar, &did, &dest_did)?;

    let dest_client = crate::migration_orchestrator::create_destination_account_with_token(
        &token,
        &dest_pds_url,
        &did,
        &handle,
        &email,
        invite_code,
        existing_dest_client,
    )
    .await?;

    // Store the destination session and advance.
    let mut orchestration = state.orchestration_state.lock().await;
    match orchestration.as_mut() {
        Some(mig) if mig.did == did && mig.recovery => {
            mig.dest_client = Some(dest_client);
            if mig.phase < MigrationPhase::DestCreated {
                mig.phase = MigrationPhase::DestCreated;
            }
            Ok(())
        }
        _ => Err(MigrationError::MigrationNotReady {
            message: "recovery state changed during account creation".into(),
        }),
    }
}

// ── repo import from the iCloud snapshot ─────────────────────────────────────

/// Import the repo into the destination from the validated iCloud CAR snapshot — the
/// sourceless twin of `transfer_repo`. The snapshot is re-validated on read
/// (`repo_backup::mirror_repo_car` is fail-closed), so a rotten file can never be
/// imported.
#[tauri::command]
pub async fn recovery_transfer_repo(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "recovery_transfer_repo: importing from the iCloud snapshot");

    let dest_client = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::DestCreated)?;
        if !mig.recovery {
            return Err(MigrationError::MigrationNotReady {
                message: "active session is a migration, not a disaster recovery".into(),
            });
        }
        mig.dest_client.clone()
    }; // lock released

    let Some(dest_client) = dest_client else {
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let Some((root, _location)) = crate::blob_backup::resolve_backup_root(&app) else {
        return Err(MigrationError::BackupUnavailable {
            message: "no backup location is available on this device (is iCloud Drive enabled?)"
                .into(),
        });
    };
    let Some(car) = crate::repo_backup::mirror_repo_car(&root, &did).await else {
        return Err(MigrationError::BackupUnavailable {
            message: "no valid repo snapshot in the backup — the account cannot be rebuilt \
                      without one"
                .into(),
        });
    };

    tracing::debug!(did = %did, car_len = car.len(), "importing snapshot into destination");
    crate::pds_client::import_repo(&dest_client, car)
        .await
        .map_err(|e| MigrationError::RepoTransferFailed {
            message: format!("failed to import repository: {e}"),
        })?;

    let mut orchestration = state.orchestration_state.lock().await;
    match orchestration.as_mut() {
        Some(mig) if mig.did == did && mig.recovery => {
            if mig.phase < MigrationPhase::RepoTransferred {
                mig.phase = MigrationPhase::RepoTransferred;
            }
            Ok(())
        }
        _ => Err(MigrationError::MigrationNotReady {
            message: "recovery state changed during repo import".into(),
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:key:zDEVICE";
    const OLD_SIGNING: &str = "did:key:zOLDPDSKEY";
    const NEW_SIGNING: &str = "did:key:zNEWSELFKEY";
    const OTHER_ROTATION: &str = "did:key:zRECOVERY";
    const HANDLE: &str = "at://alice.test";

    fn pds_service(endpoint: &str) -> PlcService {
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: endpoint.to_string(),
        }
    }

    fn ok_inputs() -> RecoveryEnrollInputs {
        let current_vms: BTreeMap<String, String> =
            [("atproto".to_string(), OLD_SIGNING.to_string())].into();
        let mut proposed_vms = current_vms.clone();
        proposed_vms.insert("atproto".to_string(), NEW_SIGNING.to_string());
        let services: BTreeMap<String, PlcService> =
            [("atproto_pds".to_string(), pds_service("https://old.pds"))].into();
        RecoveryEnrollInputs {
            device_key_id: DEVICE.to_string(),
            new_signing_key_id: NEW_SIGNING.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), OTHER_ROTATION.to_string()],
            current_verification_methods: current_vms,
            current_also_known_as: vec![HANDLE.to_string()],
            current_services: services.clone(),
            proposed_rotation_keys: vec![DEVICE.to_string(), OTHER_ROTATION.to_string()],
            proposed_verification_methods: proposed_vms,
            proposed_also_known_as: vec![HANDLE.to_string()],
            proposed_services: services,
        }
    }

    // ── Guard (strict allowlist) ─────────────────────────────────────────────

    #[test]
    fn guard_accepts_a_well_formed_enroll() {
        assert!(guard_recovery_enroll_op(&ok_inputs()).is_ok());
    }

    #[test]
    fn guard_rejects_when_wallet_holds_no_current_key() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![OTHER_ROTATION.to_string()];
        inputs.proposed_rotation_keys = vec![OTHER_ROTATION.to_string()];
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_any_rotation_key_change() {
        // Dropping the other rotation key — Buchanan's lockout scenario in miniature.
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![DEVICE.to_string()];
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_dropping_the_device_key_from_rotation_keys() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![OTHER_ROTATION.to_string(), NEW_SIGNING.to_string()];
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_device_key_not_at_index_zero() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![OTHER_ROTATION.to_string(), DEVICE.to_string()];
        inputs.proposed_rotation_keys = vec![OTHER_ROTATION.to_string(), DEVICE.to_string()];
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_stale_reused_signing_key() {
        // The "fresh" key is already the DID's atproto method — not fresh.
        let mut inputs = ok_inputs();
        inputs.new_signing_key_id = OLD_SIGNING.to_string();
        inputs
            .proposed_verification_methods
            .insert("atproto".to_string(), OLD_SIGNING.to_string());
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_enrolling_a_rotation_key_as_signer() {
        let mut inputs = ok_inputs();
        inputs.new_signing_key_id = OTHER_ROTATION.to_string();
        inputs
            .proposed_verification_methods
            .insert("atproto".to_string(), OTHER_ROTATION.to_string());
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_smuggled_extra_verification_method() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_verification_methods
            .insert("evil".to_string(), "did:key:zEVIL".to_string());
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_handle_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.test".to_string()];
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_service_repoint() {
        // The atproto_pds repoint belongs to op #2, never the enroll.
        let mut inputs = ok_inputs();
        inputs
            .proposed_services
            .insert("atproto_pds".to_string(), pds_service("https://new.pds"));
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_non_did_key_signing_key() {
        let mut inputs = ok_inputs();
        inputs.new_signing_key_id = "not-a-did-key".to_string();
        inputs
            .proposed_verification_methods
            .insert("atproto".to_string(), "not-a-did-key".to_string());
        assert!(matches!(
            guard_recovery_enroll_op(&inputs),
            Err(DisasterRecoveryError::GuardRejected { .. })
        ));
    }

    // ── Propagation-poll helper ──────────────────────────────────────────────

    fn audit_entry(cid: &str, nullified: bool, atproto_key: &str) -> AuditEntry {
        let json = serde_json::json!([{
            "did": "did:plc:alice",
            "cid": cid,
            "createdAt": "2026-07-23T00:00:00Z",
            "nullified": nullified,
            "operation": {
                "type": "plc_operation",
                "rotationKeys": [DEVICE],
                "verificationMethods": { "atproto": atproto_key },
                "alsoKnownAs": [HANDLE],
                "services": {}
            }
        }]);
        crypto::parse_audit_log(&json.to_string())
            .unwrap()
            .remove(0)
    }

    #[test]
    fn enrolled_key_visible_when_latest_op_carries_it() {
        let log = vec![
            audit_entry("cid1", false, OLD_SIGNING),
            audit_entry("cid2", false, NEW_SIGNING),
        ];
        assert!(enrolled_key_visible(&log, NEW_SIGNING));
        assert!(!enrolled_key_visible(&log, OLD_SIGNING));
    }

    #[test]
    fn enrolled_key_not_visible_before_propagation() {
        let log = vec![audit_entry("cid1", false, OLD_SIGNING)];
        assert!(!enrolled_key_visible(&log, NEW_SIGNING));
    }

    #[test]
    fn enrolled_key_ignores_nullified_entries() {
        // The enroll op was nullified (e.g. contested) — it must NOT count as visible.
        let log = vec![
            audit_entry("cid1", false, OLD_SIGNING),
            audit_entry("cid2", true, NEW_SIGNING),
        ];
        assert!(!enrolled_key_visible(&log, NEW_SIGNING));
    }

    #[test]
    fn enrolled_key_not_visible_on_an_empty_log() {
        assert!(!enrolled_key_visible(&[], NEW_SIGNING));
    }

    // ── did:key derivation round trip ────────────────────────────────────────

    #[test]
    fn did_key_for_scalar_matches_crypto_derivation() {
        let kp = crypto::generate_p256_keypair().unwrap();
        let derived = did_key_for_scalar(&kp.private_key_bytes).unwrap();
        assert_eq!(derived, kp.key_id.0);
    }

    // ── Offline JWT mint ─────────────────────────────────────────────────────

    #[test]
    fn offline_jwt_carries_the_service_auth_claims() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let kp = crypto::generate_p256_keypair().unwrap();
        let scalar = zeroize::Zeroizing::new(*kp.private_key_bytes);
        let jwt =
            mint_offline_service_auth(scalar, "did:plc:alice", "did:web:dest.example").unwrap();

        let payload_b64 = jwt.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(payload["iss"], "did:plc:alice");
        assert_eq!(payload["aud"], "did:web:dest.example");
        assert_eq!(payload["lxm"], CREATE_ACCOUNT_LXM);
        let iat = payload["iat"].as_u64().unwrap();
        let exp = payload["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, SERVICE_AUTH_TTL_SECS);

        // And the signature verifies as ES256 against the self-controlled key.
        let (signing_input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        crypto::verify_p256_signature(&kp.key_id, signing_input.as_bytes(), &sig).unwrap();
    }
}
