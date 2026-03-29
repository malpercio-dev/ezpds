// pattern: Mixed (Functional Core types + Imperative Shell command)
//
// Functional Core: IdentityInfo, VerifiedClaimOp, OpDiff, ServiceChange, ClaimResult,
//                  ClaimState, ResolveError, ClaimError (types and errors)
// Imperative Shell: resolve_identity (command: resolves handle/DID, fetches DID doc from
//                   plc.directory, checks IdentityStore, stores state, returns IdentityInfo)

use serde::Serialize;

use crate::identity_store::IdentityStore;
use crate::oauth_client::OAuthClient;
use crate::pds_client::{PlcDidDocument, PdsClientError};

// ── Output types ───────────────────────────────────────────────────────────

/// Identity information resolved from a handle or DID.
///
/// Returned by `resolve_identity` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    /// The DID (e.g., "did:plc:abc123...")
    pub did: String,
    /// The handle (e.g., "alice.test")
    pub handle: String,
    /// The PDS endpoint URL (e.g., "https://pds.example.com")
    pub pds_url: String,
    /// Current rotation keys from the DID document
    pub current_rotation_keys: Vec<String>,
    /// Whether the device key is a rotation key (true if device key == rotation_keys[0])
    pub device_key_is_root: bool,
}

/// Verified claim operation ready for submission.
///
/// Returned by `verify_claim` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedClaimOp {
    /// Diff of keys and services between current DID doc and proposed operation
    pub diff: OpDiff,
    /// Signed operation (ready for PLC submission)
    pub signed_op: String,
    /// Warnings from verification (e.g., "This operation will break X")
    pub warnings: Vec<String>,
}

/// Diff of changes between current DID document and proposed operation.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpDiff {
    /// Keys being added in this operation
    pub added_keys: Vec<String>,
    /// Keys being removed in this operation
    pub removed_keys: Vec<String>,
    /// Service endpoint changes (added/removed/modified)
    pub changed_services: Vec<ServiceChange>,
    /// Previous CID (content identifier) of the DID document
    pub prev_cid: String,
}

/// Change to a service endpoint in the DID document.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChange {
    /// Service ID (e.g., "atproto_pds")
    pub id: String,
    /// Type of change: "added", "removed", or "modified"
    pub change_type: String,
    /// Old endpoint URL (None if added)
    pub old_endpoint: Option<String>,
    /// New endpoint URL (None if removed)
    pub new_endpoint: Option<String>,
}

/// Result of a successful claim submission.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    /// Updated DID document after claim was applied
    pub updated_did_doc: serde_json::Value,
}

// ── State persisted across the claim flow ──────────────────────────────────

/// Claim flow state persisted in `AppState`.
///
/// This state is set by `resolve_identity` and used by subsequent
/// `start_pds_auth`, `request_claim_verification`, `sign_and_verify_claim`,
/// and `submit_claim` commands within the same claim flow session.
pub struct ClaimState {
    /// The DID being claimed (resolved by `resolve_identity`)
    pub did: String,
    /// The PDS endpoint URL (discovered by `resolve_identity`)
    pub pds_url: String,
    /// The DID document fetched from plc.directory (discovered by `resolve_identity`)
    pub did_doc: PlcDidDocument,
    /// OAuth client for the PDS (set after `start_pds_auth` succeeds)
    pub pds_oauth_client: Option<OAuthClient>,
    /// Verified signed operation (set after `sign_and_verify_claim` succeeds)
    pub verified_signed_op: Option<String>,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Error returned by `resolve_identity` command.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the
/// existing error pattern (CreateAccountError, DeviceKeyError, etc.).
#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveError {
    /// Handle resolution failed (DNS and HTTP fallback both failed)
    HandleNotFound,
    /// DID not found in plc.directory (404 response)
    DidNotFound,
    /// PDS endpoint is unreachable
    PdsUnreachable,
    /// Network error during discovery (timeout, connection refused, etc.)
    NetworkError { message: String },
}

/// Error returned by claim flow commands (`verify_claim`, `request_claim_verification`, etc.).
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", "message": "..." }` matching
/// the existing error pattern.
#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimError {
    /// PDS XRPC token request failed or returned invalid token
    InvalidToken,
    /// Claim verification failed (operation verification, signature validation, etc.)
    VerificationFailed { message: String },
    /// PLC directory operation submission failed
    PlcDirectoryError { message: String },
    /// User is not authorized for this operation
    Unauthorized,
    /// Network error during claim flow (timeout, connection refused, etc.)
    NetworkError { message: String },
}

// ── resolve_identity Tauri command ──────────────────────────────────────────

/// Resolve a handle or DID to identity information.
///
/// This is the first command in the claim flow. It:
/// 1. Determines if input is a DID (starts with "did:") or a handle
/// 2. If handle: resolves to DID via `PdsClient::resolve_handle()`
/// 3. Fetches DID doc from plc.directory via `PdsClient::discover_pds()`
/// 4. Extracts handle from `also_known_as` (format: `at://handle`)
/// 5. Checks IdentityStore to determine if DID is registered
/// 6. If registered: gets or creates device key and compares to rotation_keys[0]
/// 7. Stores resolved state in AppState.claim_state
/// 8. Returns IdentityInfo with all discovery data
#[tauri::command]
pub async fn resolve_identity(
    state: tauri::State<'_, crate::oauth::AppState>,
    handle_or_did: String,
) -> Result<IdentityInfo, ResolveError> {
    let pds_client = state.pds_client();

    // Determine if input is a DID or handle
    let is_did = handle_or_did.starts_with("did:");
    let (did, mut handle_for_fallback) = if is_did {
        (handle_or_did.clone(), None)
    } else {
        (
            pds_client
                .resolve_handle(&handle_or_did)
                .await
                .map_err(map_pds_error_to_resolve)?,
            Some(handle_or_did.clone()),
        )
    };

    // Fetch DID document and PDS endpoint from plc.directory
    let (pds_url, did_doc) = pds_client
        .discover_pds(&did)
        .await
        .map_err(map_pds_error_to_resolve)?;

    // Extract handle from also_known_as (format: at://handle)
    let handle = extract_handle_from_also_known_as(&did_doc.also_known_as)
        .or_else(|| handle_for_fallback.take())
        .unwrap_or_else(|| {
            if is_did {
                "unknown".to_string()
            } else {
                // We already resolved this handle, use it
                handle_or_did.clone()
            }
        });

    // Check if DID is registered and get device key status
    let device_key_is_root = {
        let identity_store = IdentityStore;
        match identity_store.list_identities() {
            Ok(identities) => {
                if identities.contains(&did) {
                    // DID is registered, get device key and compare to rotation_keys[0]
                    match identity_store.get_or_create_device_key(&did) {
                        Ok(device_key) => {
                            // Compare multibase-encoded device key with rotation_keys[0]
                            did_doc
                                .rotation_keys
                                .first()
                                .map(|first_key| device_key.multibase == *first_key)
                                .unwrap_or(false)
                        }
                        Err(_) => false, // Key generation failed, assume not root
                    }
                } else {
                    false // DID not registered
                }
            }
            Err(_) => false, // Store lookup failed, assume not root
        }
    };

    // Store claim state in AppState
    let claim_state = ClaimState {
        did: did.clone(),
        pds_url: pds_url.clone(),
        did_doc: did_doc.clone(),
        pds_oauth_client: None,
        verified_signed_op: None,
    };

    let mut state_lock = state.claim_state.lock().await;
    *state_lock = Some(claim_state);
    drop(state_lock);

    Ok(IdentityInfo {
        did,
        handle,
        pds_url,
        current_rotation_keys: did_doc.rotation_keys,
        device_key_is_root,
    })
}

/// Map PdsClientError to ResolveError.
fn map_pds_error_to_resolve(err: PdsClientError) -> ResolveError {
    match err {
        PdsClientError::HandleNotFound => ResolveError::HandleNotFound,
        PdsClientError::DidNotFound => ResolveError::DidNotFound,
        PdsClientError::PdsUnreachable { .. } => ResolveError::PdsUnreachable,
        PdsClientError::NetworkError { message } => ResolveError::NetworkError { message },
        PdsClientError::InvalidResponse { message } => ResolveError::NetworkError { message },
        PdsClientError::OauthFailed { message } => ResolveError::NetworkError { message },
    }
}

/// Extract handle from also_known_as entries.
///
/// Searches for entries of the form "at://handle" and returns the first match.
/// Returns None if no such entries are found.
fn extract_handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    for entry in also_known_as {
        if let Some(handle) = entry.strip_prefix("at://") {
            return Some(handle.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolve_identity tests ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_identity_maps_pds_error_handle_not_found() {
        let err = PdsClientError::HandleNotFound;
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::HandleNotFound => {}
            _ => panic!("Expected HandleNotFound"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_did_not_found() {
        let err = PdsClientError::DidNotFound;
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::DidNotFound => {}
            _ => panic!("Expected DidNotFound"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_pds_unreachable() {
        let err = PdsClientError::PdsUnreachable {
            reason: "Connection refused".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::PdsUnreachable => {}
            _ => panic!("Expected PdsUnreachable"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_network_error() {
        let err = PdsClientError::NetworkError {
            message: "Timeout".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::NetworkError { message } => {
                assert_eq!(message, "Timeout");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_invalid_response() {
        let err = PdsClientError::InvalidResponse {
            message: "Invalid JSON".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::NetworkError { message } => {
                assert_eq!(message, "Invalid JSON");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_extract_handle_from_also_known_as_valid() {
        let entries = vec!["at://alice.test".to_string()];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, Some("alice.test".to_string()));
    }

    #[test]
    fn test_extract_handle_from_also_known_as_multiple_entries() {
        let entries = vec![
            "https://example.com/user/alice".to_string(),
            "at://alice.test".to_string(),
        ];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, Some("alice.test".to_string()));
    }

    #[test]
    fn test_extract_handle_from_also_known_as_empty() {
        let entries: Vec<String> = vec![];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_handle_from_also_known_as_no_at_prefix() {
        let entries = vec!["https://example.com/user/alice".to_string()];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    // ── Serialization tests for claim types ──────────────────────────────────

    #[test]
    fn test_identity_info_serializes_camel_case() {
        let info = IdentityInfo {
            did: "did:plc:test".to_string(),
            handle: "alice.test".to_string(),
            pds_url: "https://pds.example.com".to_string(),
            current_rotation_keys: vec!["did:key:zQ3rot1".to_string()],
            device_key_is_root: true,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["did"], "did:plc:test");
        assert_eq!(json["handle"], "alice.test");
        assert_eq!(json["pdsUrl"], "https://pds.example.com");
        assert_eq!(json["currentRotationKeys"][0], "did:key:zQ3rot1");
        assert_eq!(json["deviceKeyIsRoot"], true);
    }

    #[test]
    fn test_verified_claim_op_serializes_camel_case() {
        let op = VerifiedClaimOp {
            diff: OpDiff {
                added_keys: vec!["did:key:zQ3new".to_string()],
                removed_keys: vec![],
                changed_services: vec![],
                prev_cid: "bagXXX".to_string(),
            },
            signed_op: "eyJzaWciOiAi...".to_string(),
            warnings: vec!["This will change ownership".to_string()],
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["signedOp"], "eyJzaWciOiAi...");
        assert!(json["diff"].is_object());
        assert_eq!(json["warnings"][0], "This will change ownership");
    }

    #[test]
    fn test_op_diff_serializes_camel_case() {
        let diff = OpDiff {
            added_keys: vec!["did:key:zQ3new".to_string()],
            removed_keys: vec!["did:key:zQ3old".to_string()],
            changed_services: vec![],
            prev_cid: "bagXXX".to_string(),
        };

        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["addedKeys"][0], "did:key:zQ3new");
        assert_eq!(json["removedKeys"][0], "did:key:zQ3old");
        assert_eq!(json["prevCid"], "bagXXX");
        assert!(json["changedServices"].is_array());
    }

    #[test]
    fn test_service_change_serializes_camel_case() {
        let change = ServiceChange {
            id: "atproto_pds".to_string(),
            change_type: "modified".to_string(),
            old_endpoint: Some("https://pds-old.example.com".to_string()),
            new_endpoint: Some("https://pds-new.example.com".to_string()),
        };

        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(json["id"], "atproto_pds");
        assert_eq!(json["changeType"], "modified");
        assert_eq!(json["oldEndpoint"], "https://pds-old.example.com");
        assert_eq!(json["newEndpoint"], "https://pds-new.example.com");
    }

    #[test]
    fn test_claim_result_serializes_camel_case() {
        let result = ClaimResult {
            updated_did_doc: serde_json::json!({
                "did": "did:plc:test",
                "rotationKeys": ["did:key:zQ3new"]
            }),
        };

        let json = serde_json::to_value(&result).unwrap();
        assert!(json["updatedDidDoc"].is_object());
        assert_eq!(json["updatedDidDoc"]["did"], "did:plc:test");
    }

    #[test]
    fn test_resolve_error_handle_not_found_serializes_correctly() {
        let err = ResolveError::HandleNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "HANDLE_NOT_FOUND");
    }

    #[test]
    fn test_resolve_error_did_not_found_serializes_correctly() {
        let err = ResolveError::DidNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DID_NOT_FOUND");
    }

    #[test]
    fn test_resolve_error_pds_unreachable_serializes_correctly() {
        let err = ResolveError::PdsUnreachable;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "PDS_UNREACHABLE");
    }

    #[test]
    fn test_resolve_error_network_error_serializes_correctly() {
        let err = ResolveError::NetworkError {
            message: "Connection timeout".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection timeout");
    }

    #[test]
    fn test_claim_error_invalid_token_serializes_correctly() {
        let err = ClaimError::InvalidToken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "INVALID_TOKEN");
    }

    #[test]
    fn test_claim_error_verification_failed_serializes_correctly() {
        let err = ClaimError::VerificationFailed {
            message: "Signature mismatch".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "VERIFICATION_FAILED");
        assert_eq!(json["message"], "Signature mismatch");
    }

    #[test]
    fn test_claim_error_plc_directory_error_serializes_correctly() {
        let err = ClaimError::PlcDirectoryError {
            message: "Invalid operation".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "PLC_DIRECTORY_ERROR");
        assert_eq!(json["message"], "Invalid operation");
    }

    #[test]
    fn test_claim_error_unauthorized_serializes_correctly() {
        let err = ClaimError::Unauthorized;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[test]
    fn test_claim_error_network_error_serializes_correctly() {
        let err = ClaimError::NetworkError {
            message: "DNS resolution failed".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "DNS resolution failed");
    }
}
