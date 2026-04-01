# Recovery Override Implementation Plan

**Goal:** Build the recovery override mechanism that allows the identity wallet to detect unauthorized PLC changes and submit counter-operations signed by the device key's root authority to restore the user's identity state.

**Architecture:** The recovery module (`recovery.rs`) sits in the identity-wallet Rust backend alongside the existing `plc_monitor.rs` and `claim.rs`. It reuses the crypto crate's `build_did_plc_rotation_op` for counter-operation construction, `parse_audit_log`/`verify_plc_operation` for fork point identification, and `IdentityStore` for per-DID key access and cached log persistence. The frontend adds a `RecoveryOverrideScreen` component wired into the existing state machine from `AlertDetailScreen`.

**Tech Stack:** Rust (Tauri v2 backend), SvelteKit 2 + Svelte 5 (frontend), crypto crate (PLC operations), iOS Keychain (key storage)

**Scope:** 4 phases from design Phase 7 (recovery override)

**Codebase verified:** 2026-03-31

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC7: Recovery override
- **plc-key-management.AC7.1 Success:** `build_recovery_override` produces a signed PLC operation with `prev` pointing to the fork point CID
- **plc-key-management.AC7.2 Success:** Recovery operation restores the pre-unauthorized `rotationKeys`, `services`, and `verificationMethods`
- **plc-key-management.AC7.3 Success:** Recovery operation is signed by the device key (highest authority)
- **plc-key-management.AC7.5 Failure:** `build_recovery_override` returns `RECOVERY_WINDOW_EXPIRED` when the 72-hour deadline has passed
- **plc-key-management.AC7.7 Edge:** Multiple unauthorized operations in sequence — recovery override targets the earliest fork point

---

## Phase 2: build_recovery_override implementation

This phase implements the core `build_recovery_override` function that constructs a signed counter-operation.

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Implement build_op_diff helper

**Verifies:** plc-key-management.AC7.2 (diff shows pre-unauthorized state restoration)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`

**Implementation:**

Add a helper that computes the `OpDiff` between the unauthorized state and the restored (fork-point) state. This reuses `OpDiff`, `ServiceChange`, and `ChangeType` from `claim.rs`.

```rust
use crate::claim::{ChangeType, OpDiff, ServiceChange};

/// Computes the diff between the current unauthorized state and the state being
/// restored by the recovery operation.
///
/// `fork_point_state`: the VerifiedPlcOp at the fork point (state to restore)
/// `fork_point_cid`: the CID of the fork point operation (becomes `prev` in counter-op)
pub(crate) fn build_op_diff(
    fork_point_state: &crypto::VerifiedPlcOp,
    fork_point_cid: &str,
) -> OpDiff {
    // The recovery op restores fork_point_state, so the "added" keys are those
    // in the fork point but not in the current (unauthorized) state. Since we
    // don't have the unauthorized state readily available as a VerifiedPlcOp,
    // we report the full fork-point state as what's being restored.
    OpDiff {
        added_keys: fork_point_state.rotation_keys.clone(),
        removed_keys: vec![],
        changed_services: fork_point_state
            .services
            .iter()
            .map(|(id, svc)| ServiceChange {
                id: id.clone(),
                change_type: ChangeType::Modified,
                old_endpoint: None,
                new_endpoint: Some(svc.endpoint.clone()),
            })
            .collect(),
        prev_cid: Some(fork_point_cid.to_string()),
    }
}
```

**Verification:**
Run: `cargo build -p identity-wallet`
Expected: Build succeeds

**Commit:** `feat(identity-wallet): add recovery op diff builder`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement build_recovery_override function

**Verifies:** plc-key-management.AC7.1, plc-key-management.AC7.2, plc-key-management.AC7.3, plc-key-management.AC7.5, plc-key-management.AC7.7

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`

**Implementation:**

This is the core function. It:
1. Fetches the audit log from plc.directory
2. Finds the unauthorized operation and checks the recovery window
3. Identifies the fork point (handling multiple sequential unauthorized ops per AC7.7)
4. Builds a counter-operation restoring the fork-point state
5. Signs with the per-DID device key

```rust
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;

/// Builds a signed recovery override operation.
///
/// Fetches the full audit log, identifies the fork point (last device-key-signed
/// operation before the unauthorized change), builds a PLC rotation op that
/// restores the pre-unauthorized state, and signs it with the per-DID device key.
///
/// For multiple sequential unauthorized ops (AC7.7), targets the earliest fork point.
pub async fn build_recovery_override(
    pds_client: &PdsClient,
    did: &str,
    unauthorized_op_cid: &str,
) -> Result<SignedRecoveryOp, RecoveryError> {
    let store = IdentityStore;

    // 1. Fetch the current full audit log from plc.directory.
    let audit_log_json = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to fetch audit log: {e}"),
        })?;

    let audit_log = crypto::parse_audit_log(&audit_log_json).map_err(|e| {
        RecoveryError::SigningFailed {
            message: format!("Failed to parse audit log: {e}"),
        }
    })?;

    // 2. Find the unauthorized operation and check the recovery window.
    let unauthorized_entry = audit_log
        .iter()
        .find(|e| e.cid == unauthorized_op_cid)
        .ok_or(RecoveryError::UnauthorizedChangeNotFound)?;

    check_recovery_window(&unauthorized_entry.created_at)?;

    // 3. Get the device key for this DID.
    let device_pub = store.get_or_create_device_key(did).map_err(|e| {
        RecoveryError::IdentityNotFound {
            message: format!("Failed to get device key: {e}"),
        }
    })?;
    let device_key_uri = DidKeyUri(device_pub.key_id.clone());

    // 4. Identify the fork point.
    let (fork_entry, fork_state) =
        find_fork_point(&audit_log, unauthorized_op_cid, &device_key_uri)?;

    // 5. Build the counter-operation restoring the fork-point state.
    //    The `prev` field points to the fork point's CID.
    let diff = build_op_diff(&fork_state, &fork_entry.cid);

    // 6. Sign with the per-DID device key.
    //    On macOS/simulator: read private key bytes from Keychain, sign with P-256.
    //    On real iOS: use Secure Enclave via the app label in Keychain.
    let signed_op = sign_recovery_op(
        did,
        &fork_entry.cid,
        &fork_state,
    )?;

    Ok(SignedRecoveryOp {
        diff,
        signed_op: serde_json::from_str(&signed_op.signed_op_json).map_err(|e| {
            RecoveryError::SigningFailed {
                message: format!("Failed to parse signed op JSON: {e}"),
            }
        })?,
    })
}

/// Signs a recovery operation using the per-DID device key.
///
/// Uses the same `#[cfg]` dispatch pattern as `identity_store.rs`:
/// - macOS/simulator: reads private key bytes from Keychain, creates P-256 signing closure
/// - Real iOS: reads SE app label from Keychain, signs via Secure Enclave
fn sign_recovery_op(
    did: &str,
    prev_cid: &str,
    fork_state: &crypto::VerifiedPlcOp,
) -> Result<crypto::SignedPlcOperation, RecoveryError> {
    let sign_closure = build_sign_closure(did)?;

    crypto::build_did_plc_rotation_op(
        prev_cid,
        fork_state.rotation_keys.clone(),
        fork_state.verification_methods.clone(),
        fork_state.also_known_as.clone(),
        fork_state.services.clone(),
        sign_closure,
    )
    .map_err(|e| RecoveryError::SigningFailed {
        message: format!("Failed to build rotation op: {e}"),
    })
}

/// Builds a signing closure for the per-DID device key.
///
/// macOS/simulator path: reads the raw P-256 private key scalar from Keychain
/// and returns a closure that signs CBOR bytes using RFC 6979 deterministic ECDSA.
#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
fn build_sign_closure(
    did: &str,
) -> Result<impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>, RecoveryError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let account = format!("{did}:device-key");
    let private_bytes = crate::keychain::get_item(&account).map_err(|e| {
        if crate::keychain::is_not_found(&e) {
            RecoveryError::IdentityNotFound {
                message: "Device key not found in Keychain".to_string(),
            }
        } else {
            RecoveryError::SigningFailed {
                message: format!("Keychain error: {e}"),
            }
        }
    })?;

    let signing_key = SigningKey::from_slice(&private_bytes).map_err(|_| {
        RecoveryError::SigningFailed {
            message: "Invalid P-256 private key in Keychain".to_string(),
        }
    })?;

    Ok(move |data: &[u8]| -> Result<Vec<u8>, crypto::CryptoError> {
        let signature: Signature = signing_key.sign(data);
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    })
}

/// Builds a signing closure for the per-DID device key (Secure Enclave path).
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn build_sign_closure(
    did: &str,
) -> Result<impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>, RecoveryError> {
    use p256::ecdsa::Signature;

    let app_label_account = format!("{did}:device-key-app-label");
    let app_label = crate::keychain::get_item(&app_label_account).map_err(|e| {
        if crate::keychain::is_not_found(&e) {
            RecoveryError::IdentityNotFound {
                message: "Device key app label not found in Keychain".to_string(),
            }
        } else {
            RecoveryError::SigningFailed {
                message: format!("Keychain error: {e}"),
            }
        }
    })?;

    Ok(move |data: &[u8]| -> Result<Vec<u8>, crypto::CryptoError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
        use security_framework::key::Algorithm;

        let query_results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .application_label(&app_label)
            .load_refs(true)
            .search()
            .map_err(|e| {
                crypto::CryptoError::PlcOperation(format!("SE key lookup failed: {e}"))
            })?;

        let sec_key = match query_results.first() {
            Some(SearchResult::Ref(r)) => r.as_sec_key().ok_or_else(|| {
                crypto::CryptoError::PlcOperation("SE result is not a key".into())
            })?,
            _ => {
                return Err(crypto::CryptoError::PlcOperation(
                    "SE key not found".into(),
                ))
            }
        };

        let der_sig = sec_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| {
                crypto::CryptoError::PlcOperation(format!("SE signing failed: {e}"))
            })?;

        let sig = Signature::from_der(&der_sig).map_err(|e| {
            crypto::CryptoError::PlcOperation(format!("DER decode failed: {e}"))
        })?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    })
}
```

**Testing:**

Tests must verify:
- plc-key-management.AC7.1: The built counter-op has `prev` pointing to the fork point CID
- plc-key-management.AC7.2: The counter-op restores the fork-point `rotationKeys`, `services`, and `verificationMethods`
- plc-key-management.AC7.3: The counter-op is signed by the device key (verifiable via `crypto::verify_plc_operation`)
- plc-key-management.AC7.5: Calling with a timestamp >72h ago returns `RecoveryWindowExpired`
- plc-key-management.AC7.7: With multiple sequential unauthorized ops, the counter-op's `prev` targets the earliest fork point

Test approach: Use `httpmock::MockServer` to mock plc.directory audit log responses (following the pattern in `plc_monitor.rs` tests). Use `setup_identity(did)` to register a DID and generate a device key. Build a chain of real signed operations via the crypto crate, inject unauthorized ops signed by a different key, and verify that `build_recovery_override` produces the correct counter-op.

Reference `apps/identity-wallet/src-tauri/src/plc_monitor.rs` lines 271-768 for the test helper `setup_identity` and the httpmock patterns used there.

**Verification:**
Run: `cargo test -p identity-wallet build_recovery_override`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement build_recovery_override with per-DID signing`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Store pending recovery op in AppState

**Verifies:** None (infrastructure — state management for submit flow)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (add recovery_state field to AppState)

**Implementation:**

Add a `RecoveryState` to hold the pending signed recovery operation between build and submit, following the same `Mutex<Option<T>>` pattern as `ClaimState` in `oauth.rs`.

In `recovery.rs`, add:
```rust
/// State for a pending recovery override, held between build and submit.
pub struct RecoveryState {
    pub did: String,
    pub signed_op: serde_json::Value,
}
```

In `oauth.rs`, add `recovery_state` to `AppState`:
```rust
pub recovery_state: tokio::sync::Mutex<Option<crate::recovery::RecoveryState>>,
```

Initialize as `recovery_state: tokio::sync::Mutex::new(None)` in `AppState::new()`.

Update `build_recovery_override` to store the signed op in `RecoveryState` after building (or have the Tauri command wrapper do this — see Phase 3, Task 1).

**Verification:**
Run: `cargo build -p identity-wallet`
Expected: Build succeeds

**Commit:** `feat(identity-wallet): add RecoveryState to AppState for pending recovery ops`

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
