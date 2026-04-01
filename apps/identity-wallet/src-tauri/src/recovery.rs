// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: Types and error enums for recovery override operations
// Imperative Shell: Recovery override building and submission commands (in later phases)

use crate::claim::OpDiff;
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
}
