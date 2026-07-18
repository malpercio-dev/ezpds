// pattern: Mixed (Functional Core types + Imperative Shell commands)
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;
use crypto::{diff_audit_logs, parse_audit_log, verify_plc_operation, AuditEntry, DidKeyUri};
use serde::Serialize;
use std::time::Duration;
use tauri::{Emitter, Manager};
use tokio::time::{interval, MissedTickBehavior};

/// An unauthorized PLC operation detected by the monitor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnauthorizedChange {
    /// CID of the unauthorized operation.
    pub cid: String,
    /// ISO 8601 timestamp when plc.directory accepted the operation.
    /// Frontend computes recovery deadline from this timestamp.
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
    /// True when the monitor could not reach plc.directory or parse the audit log.
    /// The frontend should show a degraded-monitoring indicator instead of "all clear."
    pub check_failed: bool,
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
            match self.check_for_changes(did).await {
                Ok(unauthorized) => {
                    statuses.push(IdentityStatus {
                        did: did.clone(),
                        check_failed: false,
                        unauthorized_changes: unauthorized,
                    });
                }
                Err(e) => {
                    tracing::warn!(did = did.as_str(), error = %e, "check failed for identity, continuing with remaining");
                    statuses.push(IdentityStatus {
                        did: did.clone(),
                        check_failed: true,
                        unauthorized_changes: vec![],
                    });
                }
            }
        }
        Ok(statuses)
    }

    pub async fn check_for_changes(
        &self,
        did: &str,
    ) -> Result<Vec<UnauthorizedChange>, MonitorError> {
        // Fetch current audit log
        let current_log_json = self.pds_client.fetch_audit_log(did).await.map_err(|e| {
            tracing::warn!(did, error = %e, "failed to fetch audit log, will retry next cycle");
            MonitorError::NetworkError {
                message: e.to_string(),
            }
        })?;

        // Parse current log
        let current_entries = parse_audit_log(&current_log_json).map_err(|e| {
            tracing::warn!(did, error = %e, "failed to parse audit log");
            MonitorError::ParseError {
                message: e.to_string(),
            }
        })?;

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
                // Authorized — signed by our device key
                continue;
            }

            // Unauthorized — try to identify signing key
            let signing_key = identify_signing_key(&op_json, &current_entries, entry);

            unauthorized.push(UnauthorizedChange {
                cid: entry.cid.clone(),
                created_at: entry.created_at.clone(),
                signing_key,
                operation: entry.operation.clone(),
            });
        }

        // Update cached log — warn on failure but still return detected changes
        if let Err(e) = store.store_plc_log(did, &current_log_json) {
            tracing::warn!(did, error = %e, "failed to update cached audit log, changes may be re-detected next cycle");
        }

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
    let rotation_keys: Vec<String> = match prev_entry.operation.get("rotationKeys") {
        Some(v) => serde_json::from_value(v.clone()).unwrap_or_else(|e| {
            tracing::debug!(cid = target.cid, error = %e, "failed to parse rotationKeys from previous operation");
            vec![]
        }),
        None => vec![],
    };

    // Try each key individually
    for key in &rotation_keys {
        if verify_plc_operation(op_json, &[DidKeyUri(key.clone())]).is_ok() {
            return Some(key.clone());
        }
    }
    None
}

const MONITOR_INTERVAL_SECS: u64 = 15 * 60; // 15 minutes

/// Run a single monitoring cycle. Extracted from the loop for testability.
/// Returns the list of identity statuses with any alerts.
pub async fn run_monitoring_cycle(monitor: &PlcMonitor<'_>) -> Vec<IdentityStatus> {
    match monitor.check_all().await {
        Ok(statuses) => statuses,
        Err(e) => {
            tracing::warn!(error = %e, "Monitoring cycle check_all failed");
            vec![]
        }
    }
}

/// Run the PLC monitoring loop. Spawned once during app setup.
/// Checks all managed identities every MONITOR_INTERVAL_SECS and emits
/// "plc_alert" events to the frontend when unauthorized changes are detected.
pub async fn run_monitoring_loop(app_handle: tauri::AppHandle) {
    let mut interval = interval(Duration::from_secs(MONITOR_INTERVAL_SECS));
    // Don't burst-fire missed ticks after iOS suspension
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Skip the first immediate tick — let the app finish initializing
    interval.tick().await;

    loop {
        interval.tick().await;

        let state = app_handle.state::<crate::oauth::AppState>();
        let monitor = PlcMonitor::new(state.pds_client());
        let statuses = run_monitoring_cycle(&monitor).await;

        emit_if_alerts(&app_handle, &statuses);
    }
    // If the loop ever exits (shouldn't happen), log it so we know monitoring died.
    // The `loop` above has no `break`, so control never falls through here — the
    // allow keeps this defensive epilogue compiling as intentional dead code.
    #[allow(unreachable_code)]
    {
        tracing::error!("PLC monitoring loop exited unexpectedly");
    }
}

/// Emit "plc_alert" event to the frontend if any identity has unauthorized changes.
fn emit_if_alerts(app_handle: &tauri::AppHandle, statuses: &[IdentityStatus]) {
    let has_alerts = statuses.iter().any(|s| !s.unauthorized_changes.is_empty());
    if has_alerts {
        if let Err(e) = app_handle.emit("plc_alert", statuses) {
            tracing::warn!(error = %e, "failed to emit plc_alert event");
        }
    }
}

/// Tauri IPC command: check all managed identities for unauthorized PLC operations.
/// Also emits "plc_alert" event so IdentityListHome's event listener receives updates.
#[tauri::command]
pub async fn check_identity_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<Vec<IdentityStatus>, MonitorError> {
    let monitor = PlcMonitor::new(state.pds_client());
    let statuses = monitor.check_all().await?;
    emit_if_alerts(&app, &statuses);
    Ok(statuses)
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
            check_failed: false,
            unauthorized_changes: vec![],
        };

        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["did"], "did:plc:test");
        assert_eq!(json["checkFailed"], false);
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
            check_failed: false,
            unauthorized_changes: vec![change],
        };

        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["unauthorizedChanges"].as_array().unwrap().len(), 1);
        assert_eq!(json["checkFailed"], false);
    }

    /// PlcMonitor borrows PdsClient; verify the reference is well-formed.
    #[test]
    fn test_plc_monitor_creation() {
        let pds_client = PdsClient::new();
        let _monitor = PlcMonitor::new(&pds_client);
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
    //
    // Each test registers DIDs with IdentityStore, generates real device keys,
    // and builds properly-signed PLC operations via the crypto crate.

    /// Register a DID in IdentityStore and return its device key info + private bytes.
    fn setup_identity(did: &str) -> (crate::device_key::DevicePublicKey, [u8; 32]) {
        let store = IdentityStore;
        // add_identity may fail if already registered from a prior test — ignore
        let _ = store.add_identity(did);
        // Clear per-DID keychain entries to ensure fresh device key generation
        for suffix in [
            "device-key",
            "device-key-pub",
            "device-key-app-label",
            "did-doc",
            "plc-log",
            "oauth-tokens",
        ] {
            let _ = crate::keychain::delete_item(&format!("{did}:{suffix}"));
        }
        let device_pub = store
            .get_or_create_device_key(did)
            .expect("device key generation failed");
        let priv_bytes_vec = crate::keychain::get_item(&format!("{did}:device-key"))
            .expect("device key not in keychain");
        let priv_bytes: [u8; 32] = priv_bytes_vec
            .try_into()
            .expect("device key bytes not 32 bytes");
        (device_pub, priv_bytes)
    }

    /// Authorized change (device-key-signed) produces no alert and updates cache.
    #[tokio::test]
    async fn test_ac6_1_authorized_change_detected() {
        use httpmock::prelude::*;

        let did = "did:plc:ac61auth";

        let (device_pub, device_priv) = setup_identity(did);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Use a separate rotation key (rotationKeys[0]); device key signs as rotationKeys[1]
        let other_kp = crypto::generate_p256_keypair().expect("keygen");
        let genesis_op = crypto::build_did_plc_genesis_op(
            &other_kp.key_id,
            &DidKeyUri(device_pub.key_id.clone()),
            &device_priv,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse op json");

        let audit_log = serde_json::json!([{
            "did": did,
            "cid": "bafy_ac61_genesis",
            "createdAt": "2026-03-29T00:00:00Z",
            "nullified": false,
            "operation": operation
        }]);

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log.clone());
        });

        // First call: new entry signed by device key → authorized → no alert
        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(changes.len(), 0, "Device-key-signed op should not alert");

        // Second call: cache updated, no new entries
        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(changes.len(), 0, "No new changes after cache update");
    }

    /// The wallet's own re-key op — a device-key-signed rotation that inserts a recovery key at
    /// rotationKeys[1] (device stays [0], the PDS key shifts to [2]) — must be treated as an
    /// AUTHORIZED change and raise no tamper alert. Authorization is by signature
    /// (the device key signed it), independent of what the op does to the key set.
    #[tokio::test]
    async fn rekey_op_signed_by_device_key_is_authorized() {
        use httpmock::prelude::*;
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::FieldBytes;
        use std::collections::BTreeMap;

        let did = "did:plc:rekeyauthorized";
        let (device_pub, device_priv) = setup_identity(did);
        let device_uri = DidKeyUri(device_pub.key_id.clone());

        // The PDS repo key and the fresh recovery key (in reality HKDF-derived; any did:key
        // stands in for the monitor, which only checks the op's signature).
        let pds_kp = crypto::generate_p256_keypair().expect("pds keygen");
        let recovery_kp = crypto::generate_p256_keypair().expect("recovery keygen");

        // A device-key sign closure (low-S) — the same shape `per_did_sign_closure` produces.
        // `device_priv` is `[u8; 32]` (Copy), so both closures below capture their own copy.
        let device_sign = move |data: &[u8]| {
            let field_bytes: FieldBytes = device_priv.into();
            let sk = SigningKey::from_bytes(&field_bytes).expect("valid device key");
            let sig: p256::ecdsa::Signature = Signer::sign(&sk, data);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok::<_, crypto::CryptoError>(sig.to_bytes().to_vec())
        };

        // Old-model genesis: rotationKeys = [device, PDS], signed by the device key.
        let genesis = crypto::build_did_plc_genesis_op_with_external_signer(
            &device_uri,
            &pds_kp.key_id,
            "alice.test",
            "https://pds.test",
            device_sign,
        )
        .expect("genesis op");
        let genesis_op: serde_json::Value =
            serde_json::from_str(&genesis.signed_op_json).expect("parse genesis");

        // The re-key: additively insert the recovery key at [1], device stays [0], PDS → [2].
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), pds_kp.key_id.0.clone());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.test".to_string(),
            },
        );
        let rekey = crypto::build_did_plc_rotation_op(
            "bafy_rekey_genesis",
            vec![
                device_pub.key_id.clone(),
                recovery_kp.key_id.0.clone(),
                pds_kp.key_id.0.clone(),
            ],
            vms,
            vec!["at://alice.test".to_string()],
            services,
            device_sign,
        )
        .expect("re-key rotation op");
        let rekey_op: serde_json::Value =
            serde_json::from_str(&rekey.signed_op_json).expect("parse re-key");

        let audit_log = serde_json::json!([
            {
                "did": did,
                "cid": "bafy_rekey_genesis",
                "createdAt": "2026-03-29T00:00:00Z",
                "nullified": false,
                "operation": genesis_op
            },
            {
                "did": did,
                "cid": "bafy_rekey_rotation",
                "createdAt": "2026-03-29T01:00:00Z",
                "nullified": false,
                "operation": rekey_op
            }
        ]);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);
        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log.clone());
        });

        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(
            changes.len(),
            0,
            "a device-key-signed re-key must not trigger a tamper alert"
        );
    }

    /// Unauthorized change (different key) creates an UnauthorizedChange alert.
    #[tokio::test]
    async fn test_ac6_2_unauthorized_change_detected() {
        use httpmock::prelude::*;

        let did = "did:plc:ac62unauth";

        let (device_pub, _device_priv) = setup_identity(did);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Sign the genesis op with a DIFFERENT key (not the device key)
        let other_kp = crypto::generate_p256_keypair().expect("keygen");
        let genesis_op = crypto::build_did_plc_genesis_op(
            &DidKeyUri(device_pub.key_id.clone()),
            &other_kp.key_id,
            &other_kp.private_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse op json");

        let audit_log = serde_json::json!([{
            "did": did,
            "cid": "bafy_ac62_genesis",
            "createdAt": "2026-03-29T01:00:00Z",
            "nullified": false,
            "operation": operation
        }]);

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log);
        });

        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(changes.len(), 1, "Should detect one unauthorized change");
        assert_eq!(changes[0].cid, "bafy_ac62_genesis");
    }

    /// Alert created_at matches the audit log timestamp for deadline computation.
    #[tokio::test]
    async fn test_ac6_3_created_at_matches_audit_log() {
        use httpmock::prelude::*;

        let did = "did:plc:ac63time";

        let (device_pub, _device_priv) = setup_identity(did);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let expected_timestamp = "2026-03-29T12:34:56.789Z";

        let other_kp = crypto::generate_p256_keypair().expect("keygen");
        let genesis_op = crypto::build_did_plc_genesis_op(
            &DidKeyUri(device_pub.key_id.clone()),
            &other_kp.key_id,
            &other_kp.private_key_bytes,
            "test.bsky.social",
            "https://pds.test",
        )
        .expect("build genesis op");

        let operation: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("parse op json");

        let audit_log = serde_json::json!([{
            "did": did,
            "cid": "bafy_ac63_genesis",
            "createdAt": expected_timestamp,
            "nullified": false,
            "operation": operation
        }]);

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log);
        });

        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].created_at, expected_timestamp,
            "created_at must match the audit log timestamp for frontend deadline computation"
        );
    }

    /// Network error returns Err, check_all sets check_failed for that identity.
    #[tokio::test]
    async fn test_ac6_7_network_error_graceful_handling() {
        use httpmock::prelude::*;

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        let did = "did:plc:ac67net";

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(500);
        });

        let result = monitor.check_for_changes(did).await;
        assert!(result.is_err(), "Network error should return Err");
        match result.unwrap_err() {
            MonitorError::NetworkError { .. } => {}
            _ => panic!("Expected NetworkError"),
        }
    }

    /// Empty audit log (newly created identity) returns no changes.
    #[tokio::test]
    async fn test_ac6_8_empty_audit_log() {
        use httpmock::prelude::*;

        let did = "did:plc:ac68empty";

        let _ = setup_identity(did);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([]));
        });

        let changes = monitor.check_for_changes(did).await.expect("check failed");
        assert_eq!(changes.len(), 0, "Empty audit log should return no changes");
    }

    /// Multi-identity: both identities authorized, no alerts.
    #[tokio::test]
    async fn test_ac6_1_multi_identity_all_authorized() {
        use httpmock::prelude::*;

        let did_alice = "did:plc:ac61alice";
        let did_bob = "did:plc:ac61bob";
        let (alice_pub, alice_priv) = setup_identity(did_alice);
        let (bob_pub, bob_priv) = setup_identity(did_bob);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Alice: genesis signed by alice's device key
        let alice_rot = crypto::generate_p256_keypair().expect("keygen");
        let alice_genesis = crypto::build_did_plc_genesis_op(
            &alice_rot.key_id,
            &DidKeyUri(alice_pub.key_id.clone()),
            &alice_priv,
            "alice.bsky.social",
            "https://pds.alice",
        )
        .expect("build alice genesis");
        let alice_op: serde_json::Value =
            serde_json::from_str(&alice_genesis.signed_op_json).expect("parse");

        // Bob: genesis signed by bob's device key
        let bob_rot = crypto::generate_p256_keypair().expect("keygen");
        let bob_genesis = crypto::build_did_plc_genesis_op(
            &bob_rot.key_id,
            &DidKeyUri(bob_pub.key_id.clone()),
            &bob_priv,
            "bob.bsky.social",
            "https://pds.bob",
        )
        .expect("build bob genesis");
        let bob_op: serde_json::Value =
            serde_json::from_str(&bob_genesis.signed_op_json).expect("parse");

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did_alice}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([{
                    "did": did_alice, "cid": "bafy_alice1",
                    "createdAt": "2026-03-29T00:00:00Z",
                    "nullified": false, "operation": alice_op
                }]));
        });

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did_bob}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([{
                    "did": did_bob, "cid": "bafy_bob1",
                    "createdAt": "2026-03-29T00:00:00Z",
                    "nullified": false, "operation": bob_op
                }]));
        });

        let statuses = monitor.check_all().await.expect("check_all failed");
        // Filter to our test DIDs (other parallel tests may register additional DIDs)
        let alice_status = statuses.iter().find(|s| s.did == did_alice).unwrap();
        assert!(
            alice_status.unauthorized_changes.is_empty(),
            "Alice should have no alerts"
        );
        let bob_status = statuses.iter().find(|s| s.did == did_bob).unwrap();
        assert!(
            bob_status.unauthorized_changes.is_empty(),
            "Bob should have no alerts"
        );
    }

    /// Multi-identity: one authorized, one unauthorized.
    #[tokio::test]
    async fn test_ac6_2_multi_identity_mixed_auth() {
        use httpmock::prelude::*;

        let did_alice = "did:plc:ac62alice";
        let did_bob = "did:plc:ac62bob";
        let (alice_pub, alice_priv) = setup_identity(did_alice);
        let (bob_pub, _bob_priv) = setup_identity(did_bob);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Alice: genesis signed by alice's device key → authorized
        let alice_rot = crypto::generate_p256_keypair().expect("keygen");
        let alice_genesis = crypto::build_did_plc_genesis_op(
            &alice_rot.key_id,
            &DidKeyUri(alice_pub.key_id.clone()),
            &alice_priv,
            "alice.bsky.social",
            "https://pds.alice",
        )
        .expect("build alice genesis");
        let alice_op: serde_json::Value =
            serde_json::from_str(&alice_genesis.signed_op_json).expect("parse");

        // Bob: genesis signed by a DIFFERENT key → unauthorized
        let bob_other = crypto::generate_p256_keypair().expect("keygen");
        let bob_genesis = crypto::build_did_plc_genesis_op(
            &DidKeyUri(bob_pub.key_id.clone()),
            &bob_other.key_id,
            &bob_other.private_key_bytes,
            "bob.bsky.social",
            "https://pds.bob",
        )
        .expect("build bob genesis");
        let bob_op: serde_json::Value =
            serde_json::from_str(&bob_genesis.signed_op_json).expect("parse");

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did_alice}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([{
                    "did": did_alice, "cid": "bafy_alice1",
                    "createdAt": "2026-03-29T00:00:00Z",
                    "nullified": false, "operation": alice_op
                }]));
        });

        mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did_bob}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([{
                    "did": did_bob, "cid": "bafy_bob1",
                    "createdAt": "2026-03-29T00:00:00Z",
                    "nullified": false, "operation": bob_op
                }]));
        });

        let statuses = monitor.check_all().await.expect("check_all failed");
        // Filter to our test DIDs (other parallel tests may register additional DIDs)
        let alice_status = statuses.iter().find(|s| s.did == did_alice).unwrap();
        assert!(
            alice_status.unauthorized_changes.is_empty(),
            "Alice should have no alerts"
        );

        let bob_status = statuses.iter().find(|s| s.did == did_bob).unwrap();
        assert_eq!(
            bob_status.unauthorized_changes.len(),
            1,
            "Bob should have one alert"
        );
    }
}
