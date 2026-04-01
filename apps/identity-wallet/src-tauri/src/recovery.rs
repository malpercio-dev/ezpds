// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: Types and error enums for recovery override operations
// Imperative Shell: Recovery override building and submission commands (in later phases)

use crate::claim::OpDiff;
use serde::Serialize;
use crypto::{AuditEntry, DidKeyUri};
use chrono::{DateTime, Duration, Utc};

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
#[allow(dead_code)]
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
        let op_json = serde_json::to_string(&entry.operation).map_err(|e| {
            RecoveryError::SigningFailed {
                message: format!("Failed to serialize operation: {e}"),
            }
        })?;

        // Try to verify with the device key. If verification succeeds,
        // this is the last legitimate operation (the fork point).
        match crypto::verify_plc_operation(&op_json, &[device_key.clone()]) {
            Ok(verified) => return Ok((entry.clone(), verified)),
            Err(_) => continue, // Not signed by device key, keep looking
        }
    }

    Err(RecoveryError::SigningFailed {
        message: "No device-key-signed operation found before the unauthorized change".to_string(),
    })
}

const RECOVERY_WINDOW_HOURS: i64 = 72;

/// Checks whether the 72-hour recovery window is still open for an unauthorized operation.
///
/// Returns `Ok(())` if recovery is still possible, or `Err(RecoveryWindowExpired)` if
/// the 72-hour deadline has passed.
#[allow(dead_code)]
pub(crate) fn check_recovery_window(
    unauthorized_op_created_at: &str,
) -> Result<(), RecoveryError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_error_serialization() {
        let err = RecoveryError::RecoveryWindowExpired;
        let serialized = serde_json::to_value(&err).unwrap();
        assert_eq!(serialized.get("code").map(|v| v.as_str()), Some(Some("RECOVERY_WINDOW_EXPIRED")));

        let err2 = RecoveryError::SigningFailed {
            message: "test error".to_string(),
        };
        let serialized2 = serde_json::to_value(&err2).unwrap();
        assert_eq!(serialized2.get("code").map(|v| v.as_str()), Some(Some("SIGNING_FAILED")));
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
        let (fork_entry, _verified) = find_fork_point(&audit_log, unauthorized_cid, &device_key_uri)
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
        assert!(matches!(result, Err(RecoveryError::UnauthorizedChangeNotFound)));
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
}
