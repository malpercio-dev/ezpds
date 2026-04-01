// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: Types and error enums for recovery override operations
// Imperative Shell: Recovery override building and submission commands

use crate::claim::{ChangeType, ClaimResult, OpDiff, ServiceChange};
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;
use chrono::{DateTime, Duration, Utc};
use crypto::{AuditEntry, DidKeyUri};
use serde::Serialize;

/// Result of building a recovery override operation.
/// Mirrors `VerifiedClaimOp` from `claim.rs` but without `warnings`.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedRecoveryOp {
    /// Human-readable diff of what the recovery operation changes.
    pub diff: OpDiff,
    /// The signed PLC operation JSON, ready to POST to plc.directory.
    pub signed_op: serde_json::Value,
}

/// State for a pending recovery override, held between build and submit.
#[derive(Debug, Clone)]
pub struct RecoveryState {
    /// The DID being recovered.
    pub did: String,
    /// The signed PLC operation, ready for submission.
    pub signed_op: serde_json::Value,
}

/// Errors from recovery override operations.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryError {
    #[error("Recovery window has expired (72 hours elapsed)")]
    RecoveryWindowExpired,
    #[error("Signing failed: {message}")]
    SigningFailed { message: String },
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    #[error("Network error: {message}")]
    NetworkError { message: String },
    #[error("Identity not found: {message}")]
    IdentityNotFound { message: String },
    #[error("No unauthorized changes found for the given CID")]
    UnauthorizedChangeNotFound,
}

/// Identifies the fork point — the last legitimate operation before unauthorized changes began.
///
/// Walks backward through the audit log from the target unauthorized operation CID.
/// For multiple sequential unauthorized ops (AC7.7), returns the earliest fork point
/// (the last device-key-signed op before the first unauthorized op in the sequence).
///
/// Returns `(fork_point_entry, pre_unauthorized_state)` where:
/// - `fork_point_entry` is the last legitimate AuditEntry (its CID becomes the `prev` for the counter-op)
/// - `pre_unauthorized_state` is the VerifiedPlcOp representing the state to restore
pub(crate) fn find_fork_point(
    audit_log: &[AuditEntry],
    unauthorized_op_cid: &str,
    device_key: &DidKeyUri,
) -> Result<(AuditEntry, crypto::VerifiedPlcOp), RecoveryError> {
    // Find the index of the unauthorized operation in the audit log.
    let target_idx = audit_log
        .iter()
        .position(|e| e.cid == unauthorized_op_cid)
        .ok_or(RecoveryError::UnauthorizedChangeNotFound)?;

    if target_idx == 0 {
        return Err(RecoveryError::SigningFailed {
            message: "Cannot recover from the genesis operation".to_string(),
        });
    }

    // Walk backward from the operation BEFORE the unauthorized one to find the
    // last operation signed by the device key. This handles AC7.7: if multiple
    // unauthorized ops are in sequence, we skip past all of them to find the
    // earliest fork point.
    for i in (0..target_idx).rev() {
        let entry = &audit_log[i];
        let op_json =
            serde_json::to_string(&entry.operation).map_err(|e| RecoveryError::SigningFailed {
                message: format!("Failed to serialize operation: {e}"),
            })?;

        // Try to verify with the device key. If verification succeeds,
        // this is the last legitimate operation (the fork point).
        match crypto::verify_plc_operation(&op_json, std::slice::from_ref(device_key)) {
            Ok(verified) => return Ok((entry.clone(), verified)),
            Err(_) => continue, // Not signed by device key, keep looking
        }
    }

    Err(RecoveryError::SigningFailed {
        message: "No device-key-signed operation found before the unauthorized change".to_string(),
    })
}

const RECOVERY_WINDOW_HOURS: i64 = 72;

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

/// Checks whether the 72-hour recovery window is still open for an unauthorized operation.
///
/// Returns `Ok(())` if recovery is still possible, or `Err(RecoveryWindowExpired)` if
/// the 72-hour deadline has passed.
pub(crate) fn check_recovery_window(unauthorized_op_created_at: &str) -> Result<(), RecoveryError> {
    let op_time = DateTime::parse_from_rfc3339(unauthorized_op_created_at)
        .map_err(|e| RecoveryError::SigningFailed {
            message: format!("Failed to parse operation timestamp: {e}"),
        })?
        .with_timezone(&Utc);

    let deadline = op_time + Duration::hours(RECOVERY_WINDOW_HOURS);

    if Utc::now() > deadline {
        return Err(RecoveryError::RecoveryWindowExpired);
    }

    Ok(())
}

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
    let audit_log_json =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RecoveryError::NetworkError {
                message: format!("Failed to fetch audit log: {e}"),
            })?;

    let audit_log =
        crypto::parse_audit_log(&audit_log_json).map_err(|e| RecoveryError::SigningFailed {
            message: format!("Failed to parse audit log: {e}"),
        })?;

    // 2. Find the unauthorized operation and check the recovery window.
    let unauthorized_entry = audit_log
        .iter()
        .find(|e| e.cid == unauthorized_op_cid)
        .ok_or(RecoveryError::UnauthorizedChangeNotFound)?;

    check_recovery_window(&unauthorized_entry.created_at)?;

    // 3. Get the device key for this DID.
    let device_pub =
        store
            .get_or_create_device_key(did)
            .map_err(|e| RecoveryError::IdentityNotFound {
                message: format!("Failed to get device key: {e}"),
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
    let signed_op = sign_recovery_op(did, &fork_entry.cid, &fork_state)?;

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

    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| RecoveryError::SigningFailed {
            message: "Invalid P-256 private key in Keychain".to_string(),
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
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("SE key lookup failed: {e}")))?;

        let sec_key = match query_results.first() {
            Some(SearchResult::Ref(r)) => r.as_sec_key().ok_or_else(|| {
                crypto::CryptoError::PlcOperation("SE result is not a key".into())
            })?,
            _ => return Err(crypto::CryptoError::PlcOperation("SE key not found".into())),
        };

        let der_sig = sec_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("SE signing failed: {e}")))?;

        let sig = Signature::from_der(&der_sig)
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("DER decode failed: {e}")))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    })
}

/// Submits the pending recovery override operation to plc.directory.
///
/// Reads the signed op from RecoveryState (set by build_recovery_override),
/// POSTs it to plc.directory, and updates the cached PLC audit log.
pub async fn submit_recovery_override(
    pds_client: &PdsClient,
    did: &str,
    signed_op: &serde_json::Value,
) -> Result<ClaimResult, RecoveryError> {
    let store = IdentityStore;

    // 1. POST the signed operation to plc.directory.
    pds_client
        .post_plc_operation(did, signed_op)
        .await
        .map_err(|e| RecoveryError::PlcDirectoryError {
            message: format!("PLC directory rejected the operation: {e}"),
        })?;

    // 2. Re-fetch the audit log to update the cache.
    let updated_log =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RecoveryError::NetworkError {
                message: format!("Failed to fetch updated audit log: {e}"),
            })?;

    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to cache updated PLC log in Keychain: {e}"),
        })?;

    // 3. Re-fetch the DID document (it should now reflect the recovered state).
    // Use the raw plc.directory endpoint, not the audit log.
    let did_doc_url = format!("{}/{}", pds_client.plc_directory_url(), did);
    let resp = pds_client
        .client()
        .get(&did_doc_url)
        .send()
        .await
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to fetch DID document: {e}"),
        })?;

    if !resp.status().is_success() {
        return Err(RecoveryError::NetworkError {
            message: format!("DID document fetch returned {}", resp.status()),
        });
    }

    let did_doc: serde_json::Value =
        resp.json().await.map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to parse DID document: {e}"),
        })?;

    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to cache updated DID document in Keychain: {e}"),
        })?;

    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}

/// Tauri command: Build a recovery override operation.
///
/// Stores the built operation in RecoveryState for subsequent submission.
#[tauri::command]
pub async fn build_recovery_override_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    operation_cid: String,
) -> Result<SignedRecoveryOp, RecoveryError> {
    let result = build_recovery_override(state.pds_client(), &did, &operation_cid).await?;

    // Store in RecoveryState for submit_recovery_override_cmd.
    let mut recovery = state.recovery_state.lock().await;
    *recovery = Some(RecoveryState {
        did: did.clone(),
        signed_op: result.signed_op.clone(),
    });

    Ok(result)
}

/// Tauri command: Submit the pending recovery override to plc.directory.
#[tauri::command]
pub async fn submit_recovery_override_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ClaimResult, RecoveryError> {
    let recovery = state.recovery_state.lock().await;
    let recovery_state = recovery.as_ref().ok_or(RecoveryError::SigningFailed {
        message: "No pending recovery operation. Call build_recovery_override first.".to_string(),
    })?;

    if recovery_state.did != did {
        return Err(RecoveryError::SigningFailed {
            message: format!(
                "Recovery state DID mismatch: expected {}, got {}",
                recovery_state.did, did
            ),
        });
    }

    let signed_op = recovery_state.signed_op.clone();
    drop(recovery); // Release lock before network calls.

    let result = submit_recovery_override(state.pds_client(), &did, &signed_op).await?;

    // Clear recovery state on success.
    let mut recovery = state.recovery_state.lock().await;
    *recovery = None;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_error_serialization() {
        let err = RecoveryError::RecoveryWindowExpired;
        let serialized = serde_json::to_value(&err).unwrap();
        assert_eq!(
            serialized.get("code").map(|v| v.as_str()),
            Some(Some("RECOVERY_WINDOW_EXPIRED"))
        );

        let err2 = RecoveryError::SigningFailed {
            message: "test error".to_string(),
        };
        let serialized2 = serde_json::to_value(&err2).unwrap();
        assert_eq!(
            serialized2.get("code").map(|v| v.as_str()),
            Some(Some("SIGNING_FAILED"))
        );
    }

    #[test]
    fn test_find_fork_point_single_unauthorized_after_genesis() {
        // Setup: Generate two keys - the device key will sign operations, another rotation key for initial setup
        let device_key = crypto::generate_p256_keypair().expect("device key generation");
        let device_key_uri = device_key.key_id;

        let rotation_key = crypto::generate_p256_keypair().expect("rotation key generation");

        // Build genesis operation where device key is the signing key (simulating a device-signed operation)
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &device_key_uri,
            &device_key.private_key_bytes,
            "alice.test",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse genesis op json");

        let genesis_cid = "bafy_genesis";
        let did = &genesis_op.did;

        // Create an unauthorized operation entry (signed by attacker, not device key)
        let attacker_key = crypto::generate_p256_keypair().expect("attacker key generation");
        let unauth_operation = serde_json::json!({
            "type": "plc_operation",
            "prev": genesis_cid,
            "rotationKeys": [attacker_key.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_signature_from_attacker"
        });

        // Create audit log JSON and parse it to get proper AuditEntry structs
        let unauthorized_cid = "bafy_unauthorized";
        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": genesis_cid,
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_operation
            },
            {
                "did": did,
                "cid": unauthorized_cid,
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": unauth_operation
            }
        ]);

        let audit_log_str = serde_json::to_string(&audit_log_json).expect("serialize audit log");
        let audit_log = crypto::parse_audit_log(&audit_log_str).expect("parse audit log");

        // Test: find_fork_point should return the genesis entry (which was signed by device_key)
        let (fork_entry, _verified) =
            find_fork_point(&audit_log, unauthorized_cid, &device_key_uri)
                .expect("find_fork_point succeeds");

        assert_eq!(fork_entry.cid, genesis_cid);
        assert_eq!(fork_entry.created_at, "2026-03-29T00:00:00Z");
    }

    #[test]
    fn test_find_fork_point_target_cid_not_found() {
        let device_key = crypto::generate_p256_keypair().expect("device key generation");
        let device_key_uri = device_key.key_id;

        let audit_log = vec![];

        let result = find_fork_point(&audit_log, "bafy_nonexistent", &device_key_uri);
        assert!(matches!(
            result,
            Err(RecoveryError::UnauthorizedChangeNotFound)
        ));
    }

    #[test]
    fn test_find_fork_point_target_is_genesis() {
        let device_key = crypto::generate_p256_keypair().expect("device key generation");
        let device_key_uri = device_key.key_id;

        let relay_key = crypto::generate_p256_keypair().expect("relay key generation");
        let genesis_op = crypto::build_did_plc_genesis_op(
            &device_key_uri,
            &relay_key.key_id,
            &relay_key.private_key_bytes,
            "alice.test",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse genesis op json");

        let genesis_cid = "bafy_genesis";

        // Create audit log with just the genesis entry
        let audit_log_json = serde_json::json!([{
            "did": genesis_op.did.as_str(),
            "cid": genesis_cid,
            "createdAt": "2026-03-29T00:00:00Z",
            "nullified": false,
            "operation": genesis_operation
        }]);

        let audit_log_str = serde_json::to_string(&audit_log_json).expect("serialize audit log");
        let audit_log = crypto::parse_audit_log(&audit_log_str).expect("parse audit log");

        // Trying to recover from genesis should fail
        let result = find_fork_point(&audit_log, genesis_cid, &device_key_uri);
        assert!(matches!(result, Err(RecoveryError::SigningFailed { .. })));
    }

    #[test]
    fn test_find_fork_point_multiple_unauthorized_ops_in_sequence() {
        // Setup: Generate device key that will sign the genesis
        let device_key = crypto::generate_p256_keypair().expect("device key generation");
        let device_key_uri = device_key.key_id;

        let rotation_key = crypto::generate_p256_keypair().expect("rotation key generation");

        // Genesis (device-key signed with rotation_key in rotationKeys[0])
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &device_key_uri,
            &device_key.private_key_bytes,
            "alice.test",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse genesis op json");

        let genesis_cid = "bafy_genesis";
        let did = &genesis_op.did;

        // First unauthorized operation (created by attacker1)
        let attacker1 = crypto::generate_p256_keypair().expect("attacker1 key generation");
        let unauth_op1 = serde_json::json!({
            "type": "plc_operation",
            "prev": genesis_cid,
            "rotationKeys": [attacker1.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_sig_1"
        });

        // Second unauthorized operation (built on top of first)
        let attacker2 = crypto::generate_p256_keypair().expect("attacker2 key generation");
        let unauth_cid1 = "bafy_unauth1";
        let unauth_op2 = serde_json::json!({
            "type": "plc_operation",
            "prev": unauth_cid1,
            "rotationKeys": [attacker2.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_sig_2"
        });

        // Create audit log with all three entries
        let unauth_cid2 = "bafy_unauth2";
        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": genesis_cid,
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_operation
            },
            {
                "did": did,
                "cid": unauth_cid1,
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": unauth_op1
            },
            {
                "did": did,
                "cid": unauth_cid2,
                "createdAt": "2026-03-29T02:00:00Z",
                "nullified": false,
                "operation": unauth_op2
            }
        ]);

        let audit_log_str = serde_json::to_string(&audit_log_json).expect("serialize audit log");
        let audit_log = crypto::parse_audit_log(&audit_log_str).expect("parse audit log");

        // When targeting the second unauthorized op, should find the earliest fork point (genesis)
        let (fork_entry, _) = find_fork_point(&audit_log, unauth_cid2, &device_key_uri)
            .expect("find_fork_point succeeds");

        assert_eq!(fork_entry.cid, genesis_cid);
    }

    #[test]
    fn test_check_recovery_window_expired() {
        // Create a timestamp 73 hours in the past (beyond the 72-hour window)
        let expired_time = Utc::now() - Duration::hours(73);
        let expired_timestamp = expired_time.to_rfc3339();

        let result = check_recovery_window(&expired_timestamp);
        assert!(matches!(result, Err(RecoveryError::RecoveryWindowExpired)));
    }

    #[test]
    fn test_check_recovery_window_at_boundary() {
        // Create a timestamp 71.5 hours in the past (well within the window)
        // We use 71.5 hours instead of exactly 72 to avoid race conditions
        // in the test where the calculation happens between two system calls
        let boundary_time = Utc::now() - Duration::hours(71) - Duration::minutes(30);
        let boundary_timestamp = boundary_time.to_rfc3339();

        // Should be OK since we're within the 72-hour window
        let result = check_recovery_window(&boundary_timestamp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_recovery_window_valid() {
        // Create a timestamp 1 hour in the past (well within the window)
        let valid_time = Utc::now() - Duration::hours(1);
        let valid_timestamp = valid_time.to_rfc3339();

        let result = check_recovery_window(&valid_timestamp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_recovery_window_very_recent() {
        // Create a timestamp just 1 minute in the past
        let recent_time = Utc::now() - Duration::minutes(1);
        let recent_timestamp = recent_time.to_rfc3339();

        let result = check_recovery_window(&recent_timestamp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_recovery_window_invalid_timestamp() {
        let result = check_recovery_window("not a valid timestamp");
        assert!(matches!(result, Err(RecoveryError::SigningFailed { .. })));
    }

    #[test]
    fn test_check_recovery_window_malformed_rfc3339() {
        let result = check_recovery_window("2026-03-31T12:00");
        assert!(matches!(result, Err(RecoveryError::SigningFailed { .. })));
    }

    /// AC7.1: build_op_diff includes fork-point CID as prev
    #[test]
    fn test_ac7_1_build_op_diff_includes_fork_cid() {
        let device_key = crypto::generate_p256_keypair().expect("device key gen");
        let rotation_key = crypto::generate_p256_keypair().expect("rotation key gen");

        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &device_key.key_id,
            &device_key.private_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let verified = crypto::verify_plc_operation(
            &genesis_op.signed_op_json,
            std::slice::from_ref(&device_key.key_id),
        )
        .expect("verify genesis op");

        // AC7.1: build_op_diff should include the fork-point CID as prev
        let diff = build_op_diff(&verified, "bafy_genesis");
        assert_eq!(
            diff.prev_cid.as_deref(),
            Some("bafy_genesis"),
            "OpDiff.prev_cid should be the fork point CID"
        );
    }

    /// AC7.2: build_op_diff restores fork-point rotationKeys and services
    #[test]
    fn test_ac7_2_build_op_diff_restores_keys_and_services() {
        let device_key = crypto::generate_p256_keypair().expect("device key gen");
        let rotation_key = crypto::generate_p256_keypair().expect("rotation key gen");

        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &device_key.key_id,
            &device_key.private_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let verified = crypto::verify_plc_operation(
            &genesis_op.signed_op_json,
            std::slice::from_ref(&device_key.key_id),
        )
        .expect("verify genesis op");

        // AC7.2: OpDiff should show what's being restored
        let diff = build_op_diff(&verified, "bafy_genesis");

        // Genesis has rotation_keys, so added_keys should reflect the fork-point state
        assert!(
            !diff.added_keys.is_empty(),
            "Should have added_keys from fork point state"
        );

        // Genesis has atproto_pds service, should be in changed_services
        assert!(
            diff.changed_services.len() > 0,
            "Should have changed_services from fork point state"
        );

        // All changes should be "Modified" since we're restoring the fork-point state
        for svc in &diff.changed_services {
            assert_eq!(
                svc.change_type,
                ChangeType::Modified,
                "Service changes in recovery should all be Modified"
            );
        }
    }

    /// AC7.5: Recovery window check rejects expired operations
    #[test]
    fn test_ac7_5_recovery_window_rejects_expired() {
        let expired_time = Utc::now() - Duration::hours(73);
        let expired_timestamp = expired_time.to_rfc3339();

        let result = check_recovery_window(&expired_timestamp);
        assert!(
            matches!(result, Err(RecoveryError::RecoveryWindowExpired)),
            "Should reject operations older than 72 hours"
        );
    }

    /// AC7.7: find_fork_point handles multiple unauthorized ops correctly
    #[test]
    fn test_ac7_7_fork_point_with_multiple_unauthorized_ops() {
        let device_key = crypto::generate_p256_keypair().expect("device key gen");
        let rotation_key = crypto::generate_p256_keypair().expect("rotation key gen");

        // Build genesis op signed by device key
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &device_key.key_id,
            &device_key.private_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse op");

        // Create two unauthorized ops (not signed by device key)
        let attacker1 = crypto::generate_p256_keypair().expect("attacker1 gen");
        let unauth_op1 = serde_json::json!({
            "type": "plc_operation",
            "prev": "bafy_genesis",
            "rotationKeys": [attacker1.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_sig_1"
        });

        let attacker2 = crypto::generate_p256_keypair().expect("attacker2 gen");
        let unauth_op2 = serde_json::json!({
            "type": "plc_operation",
            "prev": "bafy_unauth1",
            "rotationKeys": [attacker2.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_sig_2"
        });

        let audit_log_json = serde_json::json!([
            {
                "did": "did:plc:test",
                "cid": "bafy_genesis",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_operation
            },
            {
                "did": "did:plc:test",
                "cid": "bafy_unauth1",
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": unauth_op1
            },
            {
                "did": "did:plc:test",
                "cid": "bafy_unauth2",
                "createdAt": "2026-03-29T02:00:00Z",
                "nullified": false,
                "operation": unauth_op2
            }
        ]);

        let audit_log_str = serde_json::to_string(&audit_log_json).expect("serialize");
        let audit_log = crypto::parse_audit_log(&audit_log_str).expect("parse audit log");

        // AC7.7: When targeting the second unauthorized op, should find genesis (earliest fork point)
        let (fork_entry, _) = find_fork_point(&audit_log, "bafy_unauth2", &device_key.key_id)
            .expect("find_fork_point succeeded");

        assert_eq!(
            fork_entry.cid, "bafy_genesis",
            "Should find earliest fork point (genesis), not first unauthorized op"
        );
    }

    /// AC7.3: build_recovery_override returns a SignedRecoveryOp that can be verified with device key.
    /// Sets up an identity with IdentityStore, generates real keys and signed operations,
    /// starts a httpmock::MockServer serving an audit log with genesis + unauthorized op,
    /// calls build_recovery_override with PdsClient pointed at the mock server,
    /// and verifies the returned SignedRecoveryOp signature and diff integrity.
    ///
    /// This test requires socket binding which is blocked in sandboxed environments.
    /// Run with: cargo test -p identity-wallet test_ac7_3_build_recovery_override_signs_with_device_key -- --ignored
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_ac7_3_build_recovery_override_signs_with_device_key() {
        use httpmock::prelude::*;

        let did = "did:plc:ac73build";

        // Setup identity with IdentityStore (pattern from plc_monitor.rs)
        let store = IdentityStore;
        let _ = store.remove_identity(did);
        store.add_identity(did).expect("add_identity");
        let device_pub = store
            .get_or_create_device_key(did)
            .expect("device key generation failed");
        let device_priv_bytes: [u8; 32] = crate::keychain::get_item(&format!("{did}:device-key"))
            .expect("device key retrieval")
            .try_into()
            .expect("device key 32 bytes");

        // Generate rotation key for genesis
        let rotation_key = crypto::generate_p256_keypair().expect("rotation key generation");

        // Build real genesis operation signed by device key
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &crypto::DidKeyUri(device_pub.key_id.clone()),
            &device_priv_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse genesis op json");

        // Create unauthorized operation (signed by attacker, not device key)
        let attacker_key = crypto::generate_p256_keypair().expect("attacker key generation");
        let unauth_operation = serde_json::json!({
            "type": "plc_operation",
            "prev": "bafy_genesis",
            "rotationKeys": [attacker_key.key_id.0.as_str()],
            "verificationMethods": {},
            "services": {},
            "alsoKnownAs": [],
            "sig": "fake_attacker_signature"
        });

        // Build audit log JSON with dynamic timestamps within the 72-hour recovery window
        let genesis_time = (Utc::now() - Duration::hours(2)).to_rfc3339();
        let unauth_time = (Utc::now() - Duration::hours(1)).to_rfc3339();

        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": "bafy_genesis",
                "createdAt": genesis_time,
                "nullified": false,
                "operation": genesis_operation
            },
            {
                "did": did,
                "cid": "bafy_unauthorized",
                "createdAt": unauth_time,
                "nullified": false,
                "operation": unauth_operation
            }
        ]);

        // Setup mock server
        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());

        // Mock GET /{did}/log/audit — returns audit log with genesis + unauthorized op
        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json.clone());
        });

        // Execute build_recovery_override
        let signed_recovery = build_recovery_override(&client, did, "bafy_unauthorized")
            .await
            .expect("build_recovery_override should succeed");

        // Verify AC7.1: diff.prev_cid is the fork point CID (genesis)
        assert_eq!(
            signed_recovery.diff.prev_cid,
            Some("bafy_genesis".to_string()),
            "AC7.1: prev_cid should be the fork point (genesis) CID"
        );

        // Verify AC7.2: diff.added_keys contains the fork-point rotation keys
        assert!(
            !signed_recovery.diff.added_keys.is_empty(),
            "AC7.2: added_keys should contain rotation keys from fork point"
        );
        assert!(
            signed_recovery
                .diff
                .added_keys
                .contains(&rotation_key.key_id.0),
            "AC7.2: rotation_key should be in added_keys"
        );

        // Verify AC7.3: signed_op can be verified via crypto::verify_plc_operation with device key
        let signed_op_json =
            serde_json::to_string(&signed_recovery.signed_op).expect("serialize signed op to JSON");
        let device_key_uri = crypto::DidKeyUri(device_pub.key_id.clone());
        let verification_result =
            crypto::verify_plc_operation(&signed_op_json, std::slice::from_ref(&device_key_uri));
        assert!(
            verification_result.is_ok(),
            "AC7.3: Recovery operation must be verifiable with device key; got: {:?}",
            verification_result.err()
        );
    }

    /// AC7.4: SignedRecoveryOp serializes correctly with camelCase
    #[test]
    fn test_ac7_4_signed_recovery_op_serializes_camel_case() {
        let signed_op = SignedRecoveryOp {
            diff: OpDiff {
                added_keys: vec!["did:key:z6MkhaXgBZDvotzL".to_string()],
                removed_keys: vec![],
                changed_services: vec![],
                prev_cid: Some("bafy_cid".to_string()),
            },
            signed_op: serde_json::json!({
                "type": "plc_operation",
                "sig": "test_sig"
            }),
        };

        let json = serde_json::to_value(&signed_op).expect("serialize");

        // Verify camelCase serialization: "signed_op" -> "signedOp"
        assert!(
            json.get("signedOp").is_some(),
            "signed_op should be serialized as signedOp"
        );

        // Verify the diff is included
        assert!(json.get("diff").is_some(), "diff should be present");
    }

    /// AC7.4: submit_recovery_override POSTs to plc.directory and updates cached log
    /// Uses httpmock::MockServer to verify the submission flow.
    ///
    /// This test requires socket binding which is blocked in sandboxed environments.
    /// Run with: cargo test -p identity-wallet test_ac7_4_submit_recovery_override -- --ignored
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_ac7_4_submit_recovery_override() {
        use httpmock::prelude::*;

        let did = "did:plc:ac74submit";

        // Setup identity with device key
        let store = IdentityStore;
        let _ = store.remove_identity(did);
        store.add_identity(did).expect("add_identity");
        let device_pub = store
            .get_or_create_device_key(did)
            .expect("device key generation failed");

        // Start mock server
        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());

        // Generate a test genesis operation
        let device_priv_bytes =
            crate::keychain::get_item(&format!("{did}:device-key")).expect("device key retrieval");
        let device_priv_array: [u8; 32] =
            device_priv_bytes.try_into().expect("device key 32 bytes");
        let rotation_key = crypto::generate_p256_keypair().expect("rotation key generation");

        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key.key_id,
            &crypto::DidKeyUri(device_pub.key_id.clone()),
            &device_priv_array,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let genesis_operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse genesis op json");

        // Create a recovery operation (restored state matches genesis)
        use std::collections::BTreeMap;
        let mut verification_methods = BTreeMap::new();
        verification_methods.insert(
            "atproto".to_string(),
            crypto::DidKeyUri(device_pub.key_id.clone()).0,
        );

        let recovery_op = crypto::build_did_plc_rotation_op(
            "bafy_genesis",
            genesis_operation
                .get("rotationKeys")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            verification_methods,
            vec![],
            BTreeMap::new(),
            |data: &[u8]| -> Result<Vec<u8>, crypto::CryptoError> {
                use p256::ecdsa::signature::Signer;
                use p256::ecdsa::{Signature, SigningKey};
                let signing_key = SigningKey::from_slice(&device_priv_array)
                    .map_err(|_| crypto::CryptoError::KeyGeneration("Invalid key".into()))?;
                let signature: Signature = signing_key.sign(data);
                let signature = signature.normalize_s().unwrap_or(signature);
                Ok(signature.to_bytes().to_vec())
            },
        )
        .expect("build recovery op");

        let recovery_signed_op_value: serde_json::Value =
            serde_json::from_str(&recovery_op.signed_op_json).expect("parse recovery op json");

        // Updated audit log (after recovery operation is applied)
        let genesis_time = (Utc::now() - Duration::hours(2)).to_rfc3339();

        let updated_audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": "bafy_genesis",
                "createdAt": genesis_time,
                "nullified": false,
                "operation": genesis_operation
            }
        ]);

        // DID document reflecting recovered state
        let recovered_did_doc = serde_json::json!({
            "id": did,
            "verificationMethod": [],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.test"
                }
            ]
        });

        // Setup mock expectations:
        // 1. POST /{did} - submit recovery operation
        mock_server.mock(|when, then| {
            when.method(POST).path(format!("/{did}"));
            then.status(200).json_body(serde_json::json!({}));
        });

        // 2. GET /{did}/log/audit - fetch updated audit log
        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(updated_audit_log_json.clone());
        });

        // 3. GET /{did} - fetch updated DID document
        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(recovered_did_doc.clone());
        });

        // Execute submit_recovery_override
        let result = submit_recovery_override(&client, did, &recovery_signed_op_value)
            .await
            .expect("submit_recovery_override should succeed");

        // Verify the cache was updated with the new audit log
        let cached_log = store.get_plc_log(did).expect("get_plc_log should succeed");
        assert!(
            cached_log.is_some(),
            "PLC log should be cached after submission"
        );

        // Verify the DID document was stored
        let cached_did_doc = store.get_did_doc(did).expect("get_did_doc should succeed");
        assert!(
            cached_did_doc.is_some(),
            "DID document should be cached after submission"
        );

        // Verify the result contains the updated DID doc
        assert_eq!(
            result.updated_did_doc, recovered_did_doc,
            "Result should contain the recovered DID document"
        );
    }
}
