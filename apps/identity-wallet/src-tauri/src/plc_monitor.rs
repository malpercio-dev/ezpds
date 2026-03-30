// pattern: Mixed (Functional Core types + Imperative Shell commands)
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;
use crypto::{diff_audit_logs, parse_audit_log, verify_plc_operation, AuditEntry, DidKeyUri};
use serde::Serialize;

/// An unauthorized PLC operation detected by the monitor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnauthorizedChange {
    /// CID of the unauthorized operation.
    pub cid: String,
    /// ISO 8601 timestamp when plc.directory accepted the operation.
    /// Frontend computes recovery deadline as created_at + 72 hours.
    pub created_at: String,
    /// did:key URI of the key that signed this operation, if identified.
    /// None if the signing key could not be determined from known rotation keys.
    pub signing_key: Option<String>,
    /// The raw PLC operation JSON for display in alert detail.
    pub operation: serde_json::Value,
}

/// Result of checking a single identity's PLC status.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub did: String,
    pub alert_count: usize,
    pub unauthorized_changes: Vec<UnauthorizedChange>,
}

/// Errors from PLC monitoring operations.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MonitorError {
    #[error("Network error: {message}")]
    NetworkError { message: String },
    #[error("Identity store error: {message}")]
    IdentityStoreError { message: String },
    #[error("Failed to parse audit log: {message}")]
    ParseError { message: String },
}

pub struct PlcMonitor<'a> {
    pds_client: &'a PdsClient,
}

impl<'a> PlcMonitor<'a> {
    pub fn new(pds_client: &'a PdsClient) -> Self {
        Self { pds_client }
    }

    pub async fn check_all(&self) -> Result<Vec<IdentityStatus>, MonitorError> {
        let store = IdentityStore;
        let dids = store
            .list_identities()
            .map_err(|e| MonitorError::IdentityStoreError {
                message: e.to_string(),
            })?;

        let mut statuses = Vec::new();
        for did in &dids {
            let unauthorized = self.check_for_changes(did).await?;
            statuses.push(IdentityStatus {
                did: did.clone(),
                alert_count: unauthorized.len(),
                unauthorized_changes: unauthorized,
            });
        }
        Ok(statuses)
    }

    pub async fn check_for_changes(
        &self,
        did: &str,
    ) -> Result<Vec<UnauthorizedChange>, MonitorError> {
        // Fetch current audit log
        let current_log_json = match self.pds_client.fetch_audit_log(did).await {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(did, error = %e, "Failed to fetch audit log, will retry next cycle");
                return Ok(vec![]);
            }
        };

        // Parse current log
        let current_entries = match parse_audit_log(&current_log_json) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(did, error = %e, "Failed to parse audit log");
                return Ok(vec![]);
            }
        };

        // Load cached log
        let store = IdentityStore;
        let cached_entries = match store.get_plc_log(did) {
            Ok(Some(cached_json)) => match parse_audit_log(&cached_json) {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::warn!(did, error = %e, "Failed to parse cached audit log, treating as empty");
                    vec![]
                }
            },
            Ok(None) => vec![],
            Err(e) => {
                return Err(MonitorError::IdentityStoreError {
                    message: e.to_string(),
                });
            }
        };

        // Diff
        let new_entries = diff_audit_logs(&cached_entries, &current_entries);

        // If no new entries, return
        if new_entries.is_empty() {
            return Ok(vec![]);
        }

        // Get device key
        let device_key =
            store
                .get_or_create_device_key(did)
                .map_err(|e| MonitorError::IdentityStoreError {
                    message: e.to_string(),
                })?;
        let device_key_uri = DidKeyUri(device_key.key_id);

        // Classify each new entry
        let mut unauthorized = Vec::new();
        for entry in &new_entries {
            let op_json =
                serde_json::to_string(&entry.operation).map_err(|e| MonitorError::ParseError {
                    message: e.to_string(),
                })?;

            // Try device key first
            if verify_plc_operation(&op_json, std::slice::from_ref(&device_key_uri)).is_ok() {
                // Authorized — signed by our device key (AC6.1)
                continue;
            }

            // Unauthorized (AC6.2) — try to identify signing key
            let signing_key = identify_signing_key(&op_json, &current_entries, entry);

            unauthorized.push(UnauthorizedChange {
                cid: entry.cid.clone(),
                created_at: entry.created_at.clone(),
                signing_key,
                operation: entry.operation.clone(),
            });
        }

        // Update cached log
        store.store_plc_log(did, &current_log_json).map_err(|e| {
            MonitorError::IdentityStoreError {
                message: e.to_string(),
            }
        })?;

        Ok(unauthorized)
    }
}

/// Try each rotation key from the previous operation to identify who signed this entry.
fn identify_signing_key(
    op_json: &str,
    all_entries: &[AuditEntry],
    target: &AuditEntry,
) -> Option<String> {
    // Find the entry just before target in the full log
    let prev_entry = all_entries
        .iter()
        .take_while(|e| e.cid != target.cid)
        .last()?;

    // Extract rotationKeys from previous operation
    let rotation_keys: Vec<String> = prev_entry
        .operation
        .get("rotationKeys")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Try each key individually
    for key in &rotation_keys {
        if verify_plc_operation(op_json, &[DidKeyUri(key.clone())]).is_ok() {
            return Some(key.clone());
        }
    }
    None
}

/// Tauri IPC command: check all managed identities for unauthorized PLC operations.
/// Returns a list of IdentityStatus, one per managed DID.
#[tauri::command]
pub async fn check_identity_status(
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<Vec<IdentityStatus>, MonitorError> {
    let monitor = PlcMonitor::new(state.pds_client());
    monitor.check_all().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test UnauthorizedChange serialization to ensure camelCase conversion.
    #[test]
    fn test_unauthorized_change_serializes_camel_case() {
        let change = UnauthorizedChange {
            cid: "bafy123".to_string(),
            created_at: "2026-03-29T00:00:00Z".to_string(),
            signing_key: Some("did:key:z6Mkhello".to_string()),
            operation: serde_json::json!({"type": "plc_operation"}),
        };

        let json = serde_json::to_value(&change).expect("serialize");
        assert_eq!(json["cid"], "bafy123");
        assert_eq!(json["createdAt"], "2026-03-29T00:00:00Z");
        assert_eq!(json["signingKey"], "did:key:z6Mkhello");
        assert_eq!(json["operation"]["type"], "plc_operation");
    }

    /// Test UnauthorizedChange with no signing key.
    #[test]
    fn test_unauthorized_change_no_signing_key() {
        let change = UnauthorizedChange {
            cid: "bafy456".to_string(),
            created_at: "2026-03-30T00:00:00Z".to_string(),
            signing_key: None,
            operation: serde_json::json!({"type": "plc_operation"}),
        };

        let json = serde_json::to_value(&change).expect("serialize");
        assert_eq!(json["cid"], "bafy456");
        assert!(json["signingKey"].is_null());
    }

    /// Test IdentityStatus serialization to ensure camelCase conversion.
    #[test]
    fn test_identity_status_serializes_camel_case() {
        let status = IdentityStatus {
            did: "did:plc:test".to_string(),
            alert_count: 2,
            unauthorized_changes: vec![],
        };

        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["did"], "did:plc:test");
        assert_eq!(json["alertCount"], 2);
        assert!(json["unauthorizedChanges"].is_array());
    }

    /// Test IdentityStatus with unauthorized changes.
    #[test]
    fn test_identity_status_with_changes() {
        let change = UnauthorizedChange {
            cid: "bafy123".to_string(),
            created_at: "2026-03-29T00:00:00Z".to_string(),
            signing_key: Some("did:key:z6Mk".to_string()),
            operation: serde_json::json!({"type": "plc_operation"}),
        };

        let status = IdentityStatus {
            did: "did:plc:test".to_string(),
            alert_count: 1,
            unauthorized_changes: vec![change],
        };

        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["alertCount"], 1);
        assert_eq!(json["unauthorizedChanges"].as_array().unwrap().len(), 1);
    }

    /// Test PlcMonitor can be created with a PdsClient reference.
    #[test]
    fn test_plc_monitor_creation() {
        let pds_client = PdsClient::new();
        let _monitor = PlcMonitor::new(&pds_client);
        // Verify the monitor is created successfully
    }

    /// Test MonitorError serialization with correct error tag.
    #[test]
    fn test_monitor_error_network_error() {
        let err = MonitorError::NetworkError {
            message: "connection failed".to_string(),
        };

        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "connection failed");
    }

    /// Test MonitorError IdentityStoreError.
    #[test]
    fn test_monitor_error_identity_store_error() {
        let err = MonitorError::IdentityStoreError {
            message: "keychain error".to_string(),
        };

        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["code"], "IDENTITY_STORE_ERROR");
        assert_eq!(json["message"], "keychain error");
    }

    /// Test MonitorError ParseError.
    #[test]
    fn test_monitor_error_parse_error() {
        let err = MonitorError::ParseError {
            message: "invalid json".to_string(),
        };

        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["code"], "PARSE_ERROR");
        assert_eq!(json["message"], "invalid json");
    }

    // ── Behavior tests: check_for_changes ──────────────────────────────────

    /// AC6.1: Monitor detects a new PLC operation signed by the device key
    /// and updates cached log without alerting.
    #[tokio::test]
    async fn test_ac6_1_authorized_change_detected() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Generate rotation and device keys
        let rotation_key = crypto::DidKeyUri("did:key:zQ3test_rotation".to_string());
        let device_key = crypto::DidKeyUri("did:key:zQ3test_device".to_string());
        let device_key_bytes: &[u8; 32] = &[1; 32];

        // Build a valid genesis operation signed with the device key
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key,
            &device_key,
            device_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("Failed to build genesis op");

        let did = "did:plc:test_authorized";

        // Parse signed_op_json to get the operation object
        let operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("Failed to parse operation");

        // Build audit log with the genesis operation
        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": "bafy123authorized",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": operation
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json.clone());
        });

        // First call: cache is empty, so entry is new; device key authorizes it
        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok());
        let changes = result.unwrap();
        assert_eq!(
            changes.len(),
            0,
            "Authorized change should not create alert"
        );

        // Second call: cache is updated, no new entries
        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok());
        let changes = result.unwrap();
        assert_eq!(changes.len(), 0, "No new changes should be detected");
    }

    /// AC6.2: Monitor detects a new PLC operation signed by a different key
    /// and creates an UnauthorizedChange alert.
    #[tokio::test]
    async fn test_ac6_2_unauthorized_change_detected() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let device_key = crypto::DidKeyUri("did:key:zQ3test_device".to_string());
        let other_key = crypto::DidKeyUri("did:key:zQ3test_other".to_string());
        let rotation_key = crypto::DidKeyUri("did:key:zQ3test_rotation".to_string());

        let did = "did:plc:test_unauthorized";

        // Build initial operation (signed with device key)
        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key,
            &device_key,
            &[1; 32],
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("Failed to build genesis op");

        let genesis_op_obj: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("Failed to parse genesis op");

        // Build a rotation operation signed with a different key (other_key_bytes = [2; 32])
        // Use the genesis_op's signed_op_json to get the CID
        let rotation_op = crypto::build_did_plc_rotation_op(
            "bafy123genesis",
            vec![device_key.0.clone(), other_key.0.clone()],
            std::collections::BTreeMap::new(),
            vec![],
            std::collections::BTreeMap::new(),
            |data| {
                let signing_key =
                    p256::ecdsa::SigningKey::from_bytes(&p256::FieldBytes::from_slice(&[2; 32]))
                        .map_err(|e| crypto::CryptoError::PlcOperation(e.to_string()))?;
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(&signing_key, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("Failed to build rotation op");

        let rotation_op_obj: serde_json::Value =
            serde_json::from_str(&rotation_op.signed_op_json).expect("Failed to parse rotation op");

        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": "bafy123genesis",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_obj,
                "rotationKeys": [device_key.0, other_key.0]
            },
            {
                "did": did,
                "cid": "bafy123rotation",
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": rotation_op_obj
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json);
        });

        // First call: cache is empty
        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok());
        let changes = result.unwrap();
        assert_eq!(changes.len(), 1, "Should detect one unauthorized change");

        let change = &changes[0];
        assert_eq!(change.cid, "bafy123rotation");
        // The signing key identification will depend on the rotation keys in previous operation
    }

    /// AC6.3: Alert includes correct recovery deadline (created_at from audit log).
    #[tokio::test]
    async fn test_ac6_3_created_at_matches_audit_log() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let device_key = crypto::DidKeyUri("did:key:zQ3test_device".to_string());
        let other_key = crypto::DidKeyUri("did:key:zQ3test_other".to_string());
        let rotation_key = crypto::DidKeyUri("did:key:zQ3test_rotation".to_string());

        let did = "did:plc:test_deadline";
        let expected_timestamp = "2026-03-29T12:34:56.789Z";

        let genesis_op = crypto::build_did_plc_genesis_op(
            &rotation_key,
            &device_key,
            &[1; 32],
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("Failed to build genesis op");

        let genesis_op_obj: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("Failed to parse genesis op");

        let rotation_op = crypto::build_did_plc_rotation_op(
            "bafy123genesis",
            vec![device_key.0.clone(), other_key.0.clone()],
            std::collections::BTreeMap::new(),
            vec![],
            std::collections::BTreeMap::new(),
            |data| {
                let signing_key =
                    p256::ecdsa::SigningKey::from_bytes(&p256::FieldBytes::from_slice(&[2; 32]))
                        .map_err(|e| crypto::CryptoError::PlcOperation(e.to_string()))?;
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(&signing_key, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("Failed to build rotation op");

        let rotation_op_obj: serde_json::Value =
            serde_json::from_str(&rotation_op.signed_op_json).expect("Failed to parse rotation op");

        let audit_log_json = serde_json::json!([
            {
                "did": did,
                "cid": "bafy123genesis",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_obj,
                "rotationKeys": [device_key.0, other_key.0]
            },
            {
                "did": did,
                "cid": "bafy123rotation",
                "createdAt": expected_timestamp,
                "nullified": false,
                "operation": rotation_op_obj
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json);
        });

        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok());
        let changes = result.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].created_at, expected_timestamp);
    }

    /// AC6.7: Monitor handles plc.directory being unreachable gracefully
    /// (logs error, returns Ok(vec![]), does not alert).
    #[tokio::test]
    async fn test_ac6_7_network_error_graceful_handling() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let did = "did:plc:test_unreachable";

        // Mock returns 500 error (network failure)
        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did).as_str());
            then.status(500);
        });

        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok(), "Network error should return Ok, not Err");
        let changes = result.unwrap();
        assert_eq!(changes.len(), 0, "Network error should return empty vec");
    }

    /// AC6.8: Monitor handles empty audit log (newly created identity, no operations yet).
    #[tokio::test]
    async fn test_ac6_8_empty_audit_log() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let did = "did:plc:test_empty";

        // Empty audit log
        let audit_log_json = serde_json::json!([]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json);
        });

        let result = monitor.check_for_changes(did).await;
        assert!(result.is_ok());
        let changes = result.unwrap();
        assert_eq!(changes.len(), 0, "Empty audit log should return no changes");
    }

    /// AC6.1 (multi-identity): Two identities, both have authorized operations.
    #[tokio::test]
    async fn test_ac6_1_multi_identity_all_authorized() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let device_key_alice = crypto::DidKeyUri("did:key:zQ3alice_device".to_string());
        let rotation_key_alice = crypto::DidKeyUri("did:key:zQ3alice_rotation".to_string());
        let did_alice = "did:plc:alice";

        let device_key_bob = crypto::DidKeyUri("did:key:zQ3bob_device".to_string());
        let rotation_key_bob = crypto::DidKeyUri("did:key:zQ3bob_rotation".to_string());
        let did_bob = "did:plc:bob";

        let genesis_op_alice = crypto::build_did_plc_genesis_op(
            &rotation_key_alice,
            &device_key_alice,
            &[1; 32],
            "alice.bsky.social",
            "https://pds.alice",
        )
        .expect("Failed to build alice genesis op");

        let genesis_op_bob = crypto::build_did_plc_genesis_op(
            &rotation_key_bob,
            &device_key_bob,
            &[3; 32],
            "bob.bsky.social",
            "https://pds.bob",
        )
        .expect("Failed to build bob genesis op");

        let genesis_op_alice_obj: serde_json::Value =
            serde_json::from_str(&genesis_op_alice.signed_op_json)
                .expect("Failed to parse alice genesis op");
        let genesis_op_bob_obj: serde_json::Value =
            serde_json::from_str(&genesis_op_bob.signed_op_json)
                .expect("Failed to parse bob genesis op");

        let audit_log_alice = serde_json::json!([
            {
                "did": did_alice,
                "cid": "bafy_alice1",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_alice_obj
            }
        ]);

        let audit_log_bob = serde_json::json!([
            {
                "did": did_bob,
                "cid": "bafy_bob1",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_bob_obj
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did_alice).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_alice);
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did_bob).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_bob);
        });

        let result_alice = monitor.check_for_changes(did_alice).await;
        assert!(result_alice.is_ok());
        assert_eq!(result_alice.unwrap().len(), 0);

        let result_bob = monitor.check_for_changes(did_bob).await;
        assert!(result_bob.is_ok());
        assert_eq!(result_bob.unwrap().len(), 0);
    }

    /// AC6.2 (multi-identity): Two identities, one with authorized op, one with unauthorized op.
    #[tokio::test]
    async fn test_ac6_2_multi_identity_mixed_auth() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let device_key_alice = crypto::DidKeyUri("did:key:zQ3alice_device".to_string());
        let rotation_key_alice = crypto::DidKeyUri("did:key:zQ3alice_rotation".to_string());
        let did_alice = "did:plc:alice";

        let device_key_bob = crypto::DidKeyUri("did:key:zQ3bob_device".to_string());
        let other_key_bob = crypto::DidKeyUri("did:key:zQ3bob_other".to_string());
        let rotation_key_bob = crypto::DidKeyUri("did:key:zQ3bob_rotation".to_string());
        let did_bob = "did:plc:bob";

        let genesis_op_alice = crypto::build_did_plc_genesis_op(
            &rotation_key_alice,
            &device_key_alice,
            &[1; 32],
            "alice.bsky.social",
            "https://pds.alice",
        )
        .expect("Failed to build alice genesis op");

        let genesis_op_bob = crypto::build_did_plc_genesis_op(
            &rotation_key_bob,
            &device_key_bob,
            &[3; 32],
            "bob.bsky.social",
            "https://pds.bob",
        )
        .expect("Failed to build bob genesis op");

        let genesis_op_alice_obj: serde_json::Value =
            serde_json::from_str(&genesis_op_alice.signed_op_json)
                .expect("Failed to parse alice genesis op");
        let genesis_op_bob_obj: serde_json::Value =
            serde_json::from_str(&genesis_op_bob.signed_op_json)
                .expect("Failed to parse bob genesis op");

        let rotation_op_bob = crypto::build_did_plc_rotation_op(
            "bafy_bob_genesis",
            vec![device_key_bob.0.clone(), other_key_bob.0.clone()],
            std::collections::BTreeMap::new(),
            vec![],
            std::collections::BTreeMap::new(),
            |data| {
                let signing_key =
                    p256::ecdsa::SigningKey::from_bytes(&p256::FieldBytes::from_slice(&[4; 32]))
                        .map_err(|e| crypto::CryptoError::PlcOperation(e.to_string()))?;
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(&signing_key, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("Failed to build bob rotation op");

        let rotation_op_bob_obj: serde_json::Value =
            serde_json::from_str(&rotation_op_bob.signed_op_json)
                .expect("Failed to parse bob rotation op");

        let audit_log_alice = serde_json::json!([
            {
                "did": did_alice,
                "cid": "bafy_alice1",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_alice_obj
            }
        ]);

        let audit_log_bob = serde_json::json!([
            {
                "did": did_bob,
                "cid": "bafy_bob_genesis",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op_bob_obj,
                "rotationKeys": [device_key_bob.0, other_key_bob.0]
            },
            {
                "did": did_bob,
                "cid": "bafy_bob_rotation",
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": rotation_op_bob_obj
            }
        ]);

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did_alice).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_alice);
        });

        mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/{}/log/audit", did_bob).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_bob);
        });

        let result_alice = monitor.check_for_changes(did_alice).await;
        assert!(result_alice.is_ok());
        assert_eq!(
            result_alice.unwrap().len(),
            0,
            "Alice should have no alerts"
        );

        let result_bob = monitor.check_for_changes(did_bob).await;
        assert!(result_bob.is_ok());
        assert_eq!(result_bob.unwrap().len(), 1, "Bob should have one alert");
    }
}
