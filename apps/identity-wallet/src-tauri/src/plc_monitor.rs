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

    pub async fn check_for_changes(&self, did: &str) -> Result<Vec<UnauthorizedChange>, MonitorError> {
        // Step 1: Fetch current audit log
        let current_log_json = match self.pds_client.fetch_audit_log(did).await {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(did, error = %e, "Failed to fetch audit log, will retry next cycle");
                return Ok(vec![]);
            }
        };

        // Step 2: Parse current log
        let current_entries = match parse_audit_log(&current_log_json) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(did, error = %e, "Failed to parse audit log");
                return Ok(vec![]);
            }
        };

        // Step 3: Load cached log
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

        // Step 4: Diff
        let new_entries = diff_audit_logs(&cached_entries, &current_entries);

        // Step 5: If no new entries, return
        if new_entries.is_empty() {
            return Ok(vec![]);
        }

        // Step 6: Get device key
        let device_key = store
            .get_or_create_device_key(did)
            .map_err(|e| MonitorError::IdentityStoreError {
                message: e.to_string(),
            })?;
        let device_key_uri = DidKeyUri(device_key.key_id);

        // Step 7: Classify each new entry
        let mut unauthorized = Vec::new();
        for entry in &new_entries {
            let op_json = serde_json::to_string(&entry.operation).map_err(|e| {
                MonitorError::ParseError {
                    message: e.to_string(),
                }
            })?;

            // Try device key first
            if verify_plc_operation(&op_json, &[device_key_uri.clone()]).is_ok() {
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

        // Step 8: Update cached log
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
        let monitor = PlcMonitor::new(&pds_client);
        // Just verify it constructs without panic
        assert!(true);
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
}
