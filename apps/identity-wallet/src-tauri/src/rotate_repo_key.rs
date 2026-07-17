// pattern: Mixed (Functional Core guard/diff; Imperative Shell build/submit commands)
//
// Functional Core: the strict rotation guard and the review-diff computation (pure).
// Imperative Shell: build_repo_key_rotation / submit_repo_key_rotation (network +
//                   Keychain + signing) and their Tauri command wrappers.
//
// This is the sovereign "rotate repo signing key" flow for a wallet-custodied did:plc
// identity. The PDS-held repo signing key (`verificationMethods.atproto`, also the PDS
// slot in `rotationKeys` — the key that signs every repo commit) can be compromised
// (attacker read the PDS database and master key) or lost (master key gone). Either way
// the fix is a FRESH key, and only the wallet can authorize it: the PDS's own key is the
// exact key being replaced, while the wallet device key at `rotationKeys[0]` outranks it.
//
// The two existing wallet guards both forbid this op — migration must move `services`
// and recovery must change nothing — so this module is a FOURTH allowlist, scoped to
// exactly one mutation: `verificationMethods.atproto` and the PDS `rotationKeys` slot
// move to a key the hosting PDS just staged; everything else must be preserved.
//
// The flow is fully passwordless end to end (sovereign login + the per-DID session
// provider supply the full-access session; the biometric gate lives in the frontend,
// in front of the Secure-Enclave signing):
//   1. Resolve a full-access session for the DID via SessionProvider.
//   2. `POST /v1/repo-keys/rotation` on the hosting PDS — it stages a fresh key and
//      returns the `did:key` id the op must install.
//   3. Build + device-key-sign the rotation op (strict guard) — but do NOT POST it to
//      plc.directory: the signed op goes back to the PDS.
//   4. `POST /v1/repo-keys/rotation/complete` — the PDS submits the op to plc.directory
//      and cuts its commit signer over under the account's repo write lock, so no
//      commit is ever signed by a key absent from the DID document. (This is why the
//      wallet must not submit this op itself, unlike the recovery/migration legs.)
//   5. Refresh the cached PLC log + DID document so the home card updates.
//
// The PDS `complete` endpoint is retry-safe (an op that already landed skips the
// re-submit and just cuts over), so a lost response is healed by re-running submit.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claim::{ClaimResult, OpDiff};
use crate::handle_change::latest_full_state;
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::PdsClient;
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};
use crypto::PlcService;

/// The atproto verification-method id in a PLC operation's `verificationMethods` map.
const ATPROTO_VERIFICATION_METHOD_ID: &str = "atproto";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the sovereign repo signing-key rotation flow.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`MigrateError`, `RecoveryError`, `HandleChangeError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum RotationError {
    /// The wallet holds no authorized key in the DID's current rotationKeys, so it
    /// cannot self-sign the rotation op.
    #[error("wallet is not authorized to self-sign for this DID (no device key in current rotationKeys)")]
    WalletNotAuthorized,
    /// The identity's session could not be resolved without a passwordless unlock —
    /// the frontend should run the biometric sovereign login and retry.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting PDS or plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("rotation operation rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Local signing failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// The hosting PDS rejected a rotation call for a reason the wallet does not
    /// model specifically.
    #[error("rotation request failed (HTTP {status}): {message}")]
    RotationFailed { status: u16, message: String },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The DID's device key or identity record could not be found.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// No built rotation op is pending for this DID (build must run first).
    #[error("no rotation operation is pending")]
    NoPendingRotation,
}

/// Map a session-lifecycle failure into the rotation surface. A needed unlock stays a
/// distinct, actionable signal; a rate limit is preserved; everything else degrades to
/// a transport error the frontend can retry.
fn map_session_error(error: SessionError) -> RotationError {
    match error {
        SessionError::NeedsUnlock { reason } => RotationError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => RotationError::RateLimited { retry_after },
        SessionError::IdentityNotFound => RotationError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => RotationError::NetworkError { message },
        other => RotationError::NetworkError {
            message: other.to_string(),
        },
    }
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs to decide whether a proposed rotation is
/// safe to sign. Flattened to plain values so the guard is a pure, trivially-testable
/// function (mirrors `HandleChangeInputs` / `MigrationInputs`).
#[derive(Debug, Clone)]
pub struct RotationInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must be in the current set.
    pub device_key_id: String,
    /// The replacement key the hosting PDS staged (`did:key:z...`) — the ONLY key that
    /// may enter the DID document through this flow.
    pub staged_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op).
    pub current_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op.
    pub proposed_rotation_keys: Vec<String>,
    /// The DID's CURRENT verificationMethods.
    pub current_verification_methods: BTreeMap<String, String>,
    /// The verificationMethods we intend to put in the op.
    pub proposed_verification_methods: BTreeMap<String, String>,
    /// The DID's CURRENT services — must be preserved unchanged.
    pub current_services: BTreeMap<String, PlcService>,
    /// The services we intend to put in the op — must EQUAL the current.
    pub proposed_services: BTreeMap<String, PlcService>,
    /// The DID's CURRENT alsoKnownAs — must be preserved unchanged.
    pub current_also_known_as: Vec<String>,
    /// The alsoKnownAs we intend to put in the op — must EQUAL the current.
    pub proposed_also_known_as: Vec<String>,
}

// ── The strict pre-sign guard (STRICT ALLOWLIST) ─────────────────────────────

/// Reject the proposed rotation operation unless it satisfies the strict allowlist.
/// This is the security core of the flow: the device key can technically sign
/// anything, so safety comes entirely from validating the INPUTS before a signature
/// is produced.
///
/// The allowlist: the atproto verification method and the PDS `rotationKeys` slot move
/// to the PDS-staged key — nothing else may change.
///
/// Rules:
///  1. Authorization: `device_key_id` is present in `current_rotation_keys`.
///  2. Freshness: the staged key differs from the device key and from every current
///     rotation key / the current atproto method (a "rotation" to an already-installed
///     key would be a no-op signed for nothing).
///  3. Sovereignty: `proposed_rotation_keys` is exactly `[device_key_id, staged_key_id]`
///     — the device key stays at index 0 (ADR-0001), the staged key takes the PDS slot,
///     and no other key can ride along.
///  4. Verification methods: `proposed_verification_methods` equals the current map
///     with ONLY the `atproto` entry replaced by the staged key.
///  5. Services unchanged: a rotation must not move the account off its PDS.
///  6. alsoKnownAs unchanged: a rotation must not touch the handle set.
pub fn guard_rotation_op(inputs: &RotationInputs) -> Result<(), RotationError> {
    // Rule 1 (authorization): checked first so the distinct `WalletNotAuthorized`
    // signal wins over any proposed-op quibble.
    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(RotationError::WalletNotAuthorized);
    }

    // Rule 2 (freshness).
    if inputs.staged_key_id == inputs.device_key_id {
        return Err(RotationError::GuardRejected {
            reason: "staged key must not be the device key".to_string(),
        });
    }
    if inputs.current_rotation_keys.contains(&inputs.staged_key_id)
        || inputs
            .current_verification_methods
            .get(ATPROTO_VERIFICATION_METHOD_ID)
            == Some(&inputs.staged_key_id)
    {
        return Err(RotationError::GuardRejected {
            reason: "staged key is already installed in the DID document".to_string(),
        });
    }

    // Rule 3 (sovereignty + no smuggled keys).
    let expected_keys = vec![inputs.device_key_id.clone(), inputs.staged_key_id.clone()];
    if inputs.proposed_rotation_keys != expected_keys {
        return Err(RotationError::GuardRejected {
            reason: "rotationKeys must be exactly [device key, staged key]".to_string(),
        });
    }

    // Rule 4 (verification methods: only the atproto entry moves, to the staged key).
    let mut expected_vms = inputs.current_verification_methods.clone();
    expected_vms.insert(
        ATPROTO_VERIFICATION_METHOD_ID.to_string(),
        inputs.staged_key_id.clone(),
    );
    if inputs.proposed_verification_methods != expected_vms {
        return Err(RotationError::GuardRejected {
            reason: "verificationMethods may only replace the atproto entry with the staged key"
                .to_string(),
        });
    }

    // Rule 5 (services unchanged): the atproto_pds endpoint must not move.
    if inputs.proposed_services != inputs.current_services {
        return Err(RotationError::GuardRejected {
            reason: "services must be preserved across a key rotation".to_string(),
        });
    }

    // Rule 6 (alsoKnownAs unchanged).
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(RotationError::GuardRejected {
            reason: "alsoKnownAs must be preserved across a key rotation".to_string(),
        });
    }

    Ok(())
}

// ── Review diff ──────────────────────────────────────────────────────────────

/// Compute the review-screen diff for a rotation: the staged key enters, every current
/// rotation key / atproto method not carried forward leaves, services never change.
/// Pure.
pub(crate) fn build_rotation_diff(
    current_rotation_keys: &[String],
    current_atproto_key: Option<&str>,
    proposed_rotation_keys: &[String],
    staged_key_id: &str,
    prev_cid: &str,
) -> OpDiff {
    let mut removed_keys: Vec<String> = current_rotation_keys
        .iter()
        .filter(|k| !proposed_rotation_keys.contains(k))
        .cloned()
        .collect();
    // The outgoing atproto method may not have been in rotationKeys at all (a
    // non-canonical document); it is still being removed from the document.
    if let Some(old_atproto) = current_atproto_key {
        if old_atproto != staged_key_id
            && !removed_keys.iter().any(|k| k == old_atproto)
            && !proposed_rotation_keys.iter().any(|k| k == old_atproto)
        {
            removed_keys.push(old_atproto.to_string());
        }
    }
    OpDiff {
        added_keys: vec![staged_key_id.to_string()],
        removed_keys,
        changed_services: Vec::new(),
        prev_cid: Some(prev_cid.to_string()),
    }
}

// ── Output types / pending state ─────────────────────────────────────────────

/// A rotation operation, built and signed locally, ready to hand to the PDS.
///
/// Mirrors `SignedRecoveryOp`: the `diff` drives the review / biometric-approval UI,
/// and `signed_op` is the JSON the PDS will submit to plc.directory.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedRotationOp {
    /// Human-readable diff of what the rotation changes (the key swap).
    pub diff: OpDiff,
    /// The signed PLC operation JSON, submitted via the PDS `complete` endpoint.
    pub signed_op: serde_json::Value,
}

/// State for a pending rotation, held between build and submit (mirrors
/// `RecoveryState`).
pub struct RotationState {
    /// The DID being rotated.
    pub did: String,
    /// The signed PLC op, set by `build_repo_key_rotation_cmd`. Kept parked across a
    /// failed submit (the PDS `complete` endpoint is retry-safe); cleared on success.
    pub signed_op: serde_json::Value,
}

// ── PDS rotation endpoints ───────────────────────────────────────────────────

/// Read an atproto-style error envelope `{ error, message }` from a non-success
/// response and map it into a `RotationError`.
async fn classify_rotation_response(response: reqwest::Response) -> RotationError {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.text().await.unwrap_or_default();
    if status == 429 {
        return RotationError::RateLimited { retry_after };
    }
    let envelope: Option<serde_json::Value> = serde_json::from_str(&body).ok();
    let message = envelope
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| {
            if body.is_empty() {
                format!("rotation request returned HTTP {status}")
            } else {
                body.clone()
            }
        });
    RotationError::RotationFailed { status, message }
}

/// `POST /v1/repo-keys/rotation` on the hosting PDS: stage a fresh replacement key and
/// return its `did:key` id.
async fn begin_rotation_on_pds(
    session: &crate::oauth_client::OAuthClient,
) -> Result<String, RotationError> {
    let response = session
        .post_no_body("/v1/repo-keys/rotation")
        .await
        .map_err(|e| RotationError::NetworkError {
            message: format!("rotation begin request failed: {e}"),
        })?;
    if !response.status().is_success() {
        return Err(classify_rotation_response(response).await);
    }
    let body: serde_json::Value =
        response
            .json()
            .await
            .map_err(|e| RotationError::NetworkError {
                message: format!("failed to read rotation begin response: {e}"),
            })?;
    body.get("signingKey")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| RotationError::NetworkError {
            message: "rotation begin response is missing signingKey".to_string(),
        })
}

/// `POST /v1/repo-keys/rotation/complete` on the hosting PDS: submit the signed op for
/// plc.directory submission + atomic signer cutover.
async fn complete_rotation_on_pds(
    session: &crate::oauth_client::OAuthClient,
    signed_op: &serde_json::Value,
) -> Result<(), RotationError> {
    let response = session
        .post(
            "/v1/repo-keys/rotation/complete",
            &serde_json::json!({ "operation": signed_op }),
        )
        .await
        .map_err(|e| RotationError::NetworkError {
            message: format!("rotation complete request failed: {e}"),
        })?;
    if !response.status().is_success() {
        return Err(classify_rotation_response(response).await);
    }
    Ok(())
}

// ── Imperative shell: build + submit ─────────────────────────────────────────

/// Build and locally device-key-sign the repo signing-key rotation operation.
///
/// Stages a fresh key on the hosting PDS, fetches the DID's audit log (for `prev` +
/// current state), composes the rotation op, runs the strict pre-sign guard (which
/// proves ONLY the repo key moved, to exactly the PDS-staged key), and signs with the
/// per-DID device key. The op is NOT submitted anywhere yet — it is returned for the
/// review screen and parked for `submit_repo_key_rotation`.
pub async fn build_repo_key_rotation(
    pds_client: &PdsClient,
    did: &str,
) -> Result<SignedRotationOp, RotationError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| RotationError::SigningFailed {
            message: "system clock is unavailable".to_string(),
        })?;
    let store = IdentityStore;

    // 1. Full-access session on the hosting PDS (the per-DID session-provider seam).
    let session = SessionProvider
        .full_access_client(pds_client, &store, did, now)
        .await
        .map_err(map_session_error)?;

    // 2. Stage a fresh replacement key on the PDS. Idempotency note: re-running build
    //    stages another fresh key, which simply replaces the previous staged one.
    let staged_key_id = begin_rotation_on_pds(&session.client).await?;

    // 3. Per-DID device key (rotationKeys[0] for a wallet-custodied identity).
    let device =
        store
            .get_or_create_device_key(did)
            .map_err(|e| RotationError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;
    let device_key_id = device.key_id;

    // 4. Current audit log -> prev + full current state.
    let log_json =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RotationError::NetworkError {
                message: format!("failed to fetch audit log: {e}"),
            })?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| RotationError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current = latest_full_state(&audit_log).map_err(|e| RotationError::InvalidAuditLog {
        message: e.to_string(),
    })?;

    // 5. Compose the proposed op: device key keeps rotationKeys[0], the staged key
    //    takes the PDS slot and the atproto verification method; nothing else moves.
    let proposed_rotation_keys = vec![device_key_id.clone(), staged_key_id.clone()];
    let mut proposed_vms = current.verification_methods.clone();
    proposed_vms.insert(
        ATPROTO_VERIFICATION_METHOD_ID.to_string(),
        staged_key_id.clone(),
    );

    // 6. Strict pre-sign guard — the security gate.
    let inputs = RotationInputs {
        device_key_id: device_key_id.clone(),
        staged_key_id: staged_key_id.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        proposed_rotation_keys: proposed_rotation_keys.clone(),
        current_verification_methods: current.verification_methods.clone(),
        proposed_verification_methods: proposed_vms.clone(),
        current_services: current.services.clone(),
        proposed_services: current.services.clone(),
        current_also_known_as: current.also_known_as.clone(),
        proposed_also_known_as: current.also_known_as.clone(),
    };
    guard_rotation_op(&inputs)?;

    // 7. Sign locally with the per-DID device key.
    let sign_closure = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            RotationError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => RotationError::SigningFailed { message },
    })?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        proposed_rotation_keys.clone(),
        proposed_vms,
        current.also_known_as.clone(),
        current.services.clone(),
        sign_closure,
    )
    .map_err(|e| RotationError::SigningFailed {
        message: format!("failed to build rotation op: {e}"),
    })?;

    let diff = build_rotation_diff(
        &current.rotation_keys,
        current
            .verification_methods
            .get(ATPROTO_VERIFICATION_METHOD_ID)
            .map(String::as_str),
        &proposed_rotation_keys,
        &staged_key_id,
        &current.prev_cid,
    );

    Ok(SignedRotationOp {
        diff,
        signed_op: serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            RotationError::SigningFailed {
                message: format!("failed to parse signed op JSON: {e}"),
            }
        })?,
    })
}

/// Hand the signed rotation op to the hosting PDS for submission + cutover, then
/// refresh the local cache.
///
/// The PDS submits the op to plc.directory itself, holding the account's repo write
/// lock across submission and its local key flip — the wallet must NOT post this op to
/// plc.directory directly, or commits could be signed by a key the DID document no
/// longer lists. `complete` is retry-safe on the PDS side, so a lost response is
/// healed by calling this again with the same parked op.
pub async fn submit_repo_key_rotation(
    pds_client: &PdsClient,
    did: &str,
    signed_op: &serde_json::Value,
) -> Result<ClaimResult, RotationError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| RotationError::SigningFailed {
            message: "system clock is unavailable".to_string(),
        })?;
    let store = IdentityStore;

    let session = SessionProvider
        .full_access_client(pds_client, &store, did, now)
        .await
        .map_err(map_session_error)?;
    complete_rotation_on_pds(&session.client, signed_op).await?;

    // Refresh the cached PLC log + DID document (PLC *data* shape — the home card's
    // custody badge reads `rotationKeys[0]`; the W3C form would degrade it).
    let updated_log =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RotationError::NetworkError {
                message: format!("failed to fetch updated audit log: {e}"),
            })?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| RotationError::SigningFailed {
            message: format!("failed to cache updated PLC log: {e}"),
        })?;
    let did_doc =
        pds_client
            .fetch_plc_data_document(did)
            .await
            .map_err(|e| RotationError::NetworkError {
                message: format!("failed to fetch DID document: {e}"),
            })?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| RotationError::SigningFailed {
            message: format!("failed to cache updated DID document: {e}"),
        })?;

    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: build + device-key-sign the rotation op for review.
///
/// Passwordless end to end. The frontend gates the subsequent submit behind
/// `authenticateBiometric()` and, on a `SESSION_LOCKED` result, runs
/// `sovereignLogin(did)` before retrying.
#[tauri::command]
pub async fn build_repo_key_rotation_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SignedRotationOp, RotationError> {
    let built = build_repo_key_rotation(state.pds_client(), &did).await?;
    let mut pending = state.rotation_state.lock().await;
    *pending = Some(RotationState {
        did,
        signed_op: built.signed_op.clone(),
    });
    Ok(built)
}

/// Tauri command: hand the pending rotation op to the PDS and refresh caches.
#[tauri::command]
pub async fn submit_repo_key_rotation_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ClaimResult, RotationError> {
    let signed_op = {
        let pending = state.rotation_state.lock().await;
        match pending.as_ref() {
            Some(rotation) if rotation.did == did => rotation.signed_op.clone(),
            _ => return Err(RotationError::NoPendingRotation),
        }
    };

    let result = submit_repo_key_rotation(state.pds_client(), &did, &signed_op).await?;

    // Only clear the parked op once the PDS confirmed the cutover — a failed or lost
    // submit stays retryable.
    let mut pending = state.rotation_state.lock().await;
    if pending.as_ref().is_some_and(|r| r.did == did) {
        *pending = None;
    }
    Ok(result)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:key:zDEVICE";
    const OLD_PDS: &str = "did:key:zOLDPDS";
    const STAGED: &str = "did:key:zSTAGED";
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

    /// A well-formed rotation: the staged key replaces the old PDS key everywhere,
    /// nothing else moves.
    fn ok_inputs() -> RotationInputs {
        RotationInputs {
            device_key_id: DEVICE.to_string(),
            staged_key_id: STAGED.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), OLD_PDS.to_string()],
            proposed_rotation_keys: vec![DEVICE.to_string(), STAGED.to_string()],
            current_verification_methods: vms(OLD_PDS),
            proposed_verification_methods: vms(STAGED),
            current_services: services(),
            proposed_services: services(),
            current_also_known_as: vec!["at://alice.example.com".to_string()],
            proposed_also_known_as: vec!["at://alice.example.com".to_string()],
        }
    }

    // ── Guard ────────────────────────────────────────────────────────────────

    #[test]
    fn guard_accepts_a_well_formed_rotation() {
        assert!(guard_rotation_op(&ok_inputs()).is_ok());
    }

    #[test]
    fn guard_rejects_when_wallet_holds_no_current_key() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![OLD_PDS.to_string()];
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_a_staged_key_equal_to_the_device_key() {
        let mut inputs = ok_inputs();
        inputs.staged_key_id = DEVICE.to_string();
        inputs.proposed_rotation_keys = vec![DEVICE.to_string(), DEVICE.to_string()];
        inputs.proposed_verification_methods = vms(DEVICE);
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_staged_key_already_in_the_document() {
        let mut inputs = ok_inputs();
        inputs.staged_key_id = OLD_PDS.to_string();
        inputs.proposed_rotation_keys = vec![DEVICE.to_string(), OLD_PDS.to_string()];
        inputs.proposed_verification_methods = vms(OLD_PDS);
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_demoted_device_key() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![STAGED.to_string(), DEVICE.to_string()];
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_smuggled_extra_key() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![
            DEVICE.to_string(),
            STAGED.to_string(),
            "did:key:zEVIL".to_string(),
        ];
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_verification_method_pointing_elsewhere() {
        let mut inputs = ok_inputs();
        inputs.proposed_verification_methods = vms("did:key:zEVIL");
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_dropping_an_unrelated_verification_method() {
        let mut inputs = ok_inputs();
        inputs
            .current_verification_methods
            .insert("other".to_string(), "did:key:zOTHER".to_string());
        // proposed keeps only atproto — the unrelated entry was silently dropped.
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_preserves_an_unrelated_verification_method() {
        let mut inputs = ok_inputs();
        inputs
            .current_verification_methods
            .insert("other".to_string(), "did:key:zOTHER".to_string());
        inputs
            .proposed_verification_methods
            .insert("other".to_string(), "did:key:zOTHER".to_string());
        assert!(guard_rotation_op(&inputs).is_ok());
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
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_an_also_known_as_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.example.com".to_string()];
        assert!(matches!(
            guard_rotation_op(&inputs),
            Err(RotationError::GuardRejected { .. })
        ));
    }

    // ── Diff ─────────────────────────────────────────────────────────────────

    #[test]
    fn diff_reports_the_key_swap() {
        let current = vec![DEVICE.to_string(), OLD_PDS.to_string()];
        let proposed = vec![DEVICE.to_string(), STAGED.to_string()];
        let diff = build_rotation_diff(&current, Some(OLD_PDS), &proposed, STAGED, PREV);
        assert_eq!(diff.added_keys, vec![STAGED.to_string()]);
        assert_eq!(diff.removed_keys, vec![OLD_PDS.to_string()]);
        assert!(diff.changed_services.is_empty());
        assert_eq!(diff.prev_cid.as_deref(), Some(PREV));
    }

    #[test]
    fn diff_includes_an_atproto_key_absent_from_rotation_keys() {
        // Non-canonical document: the atproto method never appeared in rotationKeys.
        let current = vec![DEVICE.to_string()];
        let proposed = vec![DEVICE.to_string(), STAGED.to_string()];
        let diff = build_rotation_diff(&current, Some(OLD_PDS), &proposed, STAGED, PREV);
        assert_eq!(diff.removed_keys, vec![OLD_PDS.to_string()]);
    }
}
