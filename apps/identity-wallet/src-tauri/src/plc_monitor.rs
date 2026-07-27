// pattern: Mixed (Functional Core types + Imperative Shell commands)
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;
use chrono::{DateTime, SecondsFormat, Utc};
use crypto::{diff_audit_logs, parse_audit_log, verify_plc_operation, AuditEntry, DidKeyUri};
use serde::{Deserialize, Serialize};
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
///
/// Only monitored identities appear. A DID whose method has no PLC audit log is absent
/// from the sweep entirely rather than present with a verdict — see [`is_monitorable`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub did: String,
    /// True when the monitor could not reach plc.directory or parse the audit log.
    /// The frontend should show a degraded-monitoring indicator instead of "all clear."
    ///
    /// This means what it says: a question was asked and went unanswered. It is never set
    /// for an identity the monitor had no business asking about.
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

/// Whether this monitor has anything to say about `did`.
///
/// What the monitor does is diff an identity's PLC audit log, which lives at
/// `plc.directory/{did}/log/audit` and exists only for a `did:plc:`. A `did:web` is anchored
/// by control of a domain, and the directory holds no record of it to fetch, diff, or find a
/// forged operation in — the fetch 404s every pass.
///
/// So a non-`did:plc:` identity is skipped rather than checked-and-failed. Reporting
/// `check_failed` for one would spend a mobile round trip on a question with no answer and
/// then state something untrue: not "the directory was unreachable" but "we asked the wrong
/// registry". The wallet's honest position on a `did:web` is that it has nothing to report,
/// which the sweep expresses by leaving it out — both frontend consumers already treat an
/// absent DID as "no news", where a `check_failed` verdict would have to be explained away.
fn is_monitorable(did: &str) -> bool {
    did.starts_with("did:plc:")
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
            if !is_monitorable(did) {
                tracing::debug!(
                    did = did.as_str(),
                    "identity has no PLC audit log; omitted from the sweep"
                );
                continue;
            }
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
            // A background identity check that can't reach the directory fails silently to
            // the user. Record the transport case so an exported diagnostics log shows it —
            // server verdicts are already captured at the XRPC classification seam, so this
            // is gated to transport failures to avoid double-counting.
            if matches!(e, crate::pds_client::PdsClientError::NetworkError { .. }) {
                crate::diagnostics::record_transport(
                    "plc_monitor.fetch_audit_log",
                    None,
                    "unreachable",
                );
            }
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

// ── Sweep history ───────────────────────────────────────────────────────────
//
// The monitor is the wallet's one continuously-running defence, and until now a
// *successful* pass left no trace: only detections were recorded (the cached audit log,
// the `plc_alert` event). So the app could assert that it was watching the public record
// but could never show it, which wastes the trust the work is actually earning. This
// records what each pass did, so the Protection surface can show protection happening.
//
// Nothing here is secret — it is counts and timestamps about DIDs the Keychain already
// indexes in plaintext under `managed-dids`.

/// What started a sweep. The distinction is the point of the log: a user asking "is this
/// thing actually running?" is asking about the background timer specifically, and a burst
/// of foreground checks must not be able to answer for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SweepTrigger {
    /// The unattended timer (`MONITOR_INTERVAL_SECS`).
    Background,
    /// A check the app asked for — opening the app, foregrounding it, opening a screen.
    Foreground,
}

/// One completed pass over every managed identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepRecord {
    /// ISO 8601 (UTC, second resolution) — when the pass finished.
    pub at: String,
    pub trigger: SweepTrigger,
    /// Identities the sweep asked plc.directory about.
    pub identities_checked: u32,
    /// Of those, the ones the directory did not answer for.
    pub identities_failed: u32,
    /// Unauthorized changes standing at the end of the pass, across all identities.
    pub unauthorized_found: u32,
}

/// When the directory last answered for one identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityLastChecked {
    pub did: String,
    /// ISO 8601 of the most recent sweep in which the directory answered for this DID, or
    /// `None` if it never has. A failed sweep leaves the previous value standing — the last
    /// verification is still a fact, and overwriting it with the failure would erase the
    /// only thing the row can honestly say.
    pub last_verified_at: Option<String>,
}

/// The whole user-visible record of the monitor's work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorHistory {
    /// Newest first, capped at `MAX_SWEEP_RECORDS`.
    pub sweeps: Vec<SweepRecord>,
    /// One entry per identity in the most recent sweep, in that sweep's order.
    pub identities: Vec<IdentityLastChecked>,
    /// How often the unattended sweep runs. Filled from `MONITOR_INTERVAL_SECS` on every
    /// read rather than trusted from the stored record: the constant is the truth, and a
    /// record written by an older build must not report a cadence the app no longer keeps.
    #[serde(default)]
    pub interval_secs: u64,
}

/// Keychain account holding the serialized [`MonitorHistory`].
const HISTORY_ACCOUNT: &str = "monitor-history";

/// Roughly five hours of unattended sweeps — enough to show a cadence without turning the
/// Protection surface into a scroll.
const MAX_SWEEP_RECORDS: usize = 20;

/// Foreground checks closer together than this collapse into one entry.
///
/// The app checks on launch, on foreground, and on entering the identity screen, so a
/// minute of ordinary navigation can fire half a dozen identical passes. Left alone they
/// would push every background sweep out of a 20-entry log — the log would stop answering
/// the one question it exists for. Background sweeps are 15 minutes apart and so never
/// collapse into each other.
const COALESCE_SECS: i64 = 5 * 60;

/// Fold a completed sweep into the history. Pure — the Keychain round trip is the caller's.
pub fn fold_sweep(
    prev: MonitorHistory,
    statuses: &[IdentityStatus],
    trigger: SweepTrigger,
    at: DateTime<Utc>,
) -> MonitorHistory {
    let at_iso = at.to_rfc3339_opts(SecondsFormat::Secs, true);

    let record = SweepRecord {
        at: at_iso.clone(),
        trigger,
        identities_checked: statuses.len() as u32,
        identities_failed: statuses.iter().filter(|s| s.check_failed).count() as u32,
        unauthorized_found: statuses
            .iter()
            .map(|s| s.unauthorized_changes.len() as u32)
            .sum(),
    };

    // Only the entries for identities in THIS sweep survive, so a removed identity leaves
    // the log the moment the next sweep runs — the managed-DIDs index stays the one source
    // of which identities exist, and this record can never resurrect a forgotten DID.
    let identities = statuses
        .iter()
        .map(|s| IdentityLastChecked {
            did: s.did.clone(),
            last_verified_at: if s.check_failed {
                prev.identities
                    .iter()
                    .find(|e| e.did == s.did)
                    .and_then(|e| e.last_verified_at.clone())
            } else {
                Some(at_iso.clone())
            },
        })
        .collect();

    let mut sweeps = prev.sweeps;
    if coalesces_into(sweeps.first(), &record, at) {
        sweeps[0] = record;
    } else {
        sweeps.insert(0, record);
        sweeps.truncate(MAX_SWEEP_RECORDS);
    }

    MonitorHistory {
        sweeps,
        identities,
        interval_secs: MONITOR_INTERVAL_SECS,
    }
}

/// Whether `next` is a repeat of the newest entry close enough in time to replace it
/// rather than be listed beside it. Identical outcome and trigger only — a sweep that
/// found something new, or failed where the last one didn't, is a different event and is
/// always listed, however quickly it followed.
fn coalesces_into(newest: Option<&SweepRecord>, next: &SweepRecord, at: DateTime<Utc>) -> bool {
    let Some(newest) = newest else { return false };
    if newest.trigger != next.trigger
        || newest.identities_checked != next.identities_checked
        || newest.identities_failed != next.identities_failed
        || newest.unauthorized_found != next.unauthorized_found
    {
        return false;
    }
    // An unparseable stored timestamp is treated as too old to coalesce with: listing one
    // extra line is the harmless direction, silently swallowing a sweep is not.
    match DateTime::parse_from_rfc3339(&newest.at) {
        Ok(prev_at) => (at - prev_at.with_timezone(&Utc)).num_seconds() < COALESCE_SECS,
        Err(_) => false,
    }
}

/// Read the stored history. Best-effort by design.
///
/// A missing, unreadable, or corrupt record reads as empty. This is the opposite of the
/// fail-closed contract on `ceremony-staging` and `recovery-epilogue`, and deliberately so:
/// those records may hold the only copy of recovery material, so refusing to proceed
/// protects the user. This one holds counts and timestamps. Erroring on it would cost the
/// user the sweep that is running right now to preserve a readout of sweeps already past.
fn load_history() -> MonitorHistory {
    match crate::keychain::get_item(HISTORY_ACCOUNT) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "monitor history unreadable, starting a fresh log");
            MonitorHistory::default()
        }),
        Err(_) => MonitorHistory::default(),
    }
}

/// Serializes the load → fold → store round trip.
///
/// The unattended timer and a foreground check are separate tasks on a multi-threaded
/// runtime, and each resumes from an awaited `check_all` — so two passes can reach this
/// function at the same moment. Interleaved, the later store would be built from a history
/// read before the earlier one landed, silently dropping a pass from the log and rolling an
/// identity's `last_verified_at` backwards. Fail-soft is right for a write that *fails*; a
/// lost update leaves no trace at all, which on the surface that exists to evidence the
/// background sweep is the one loss worth a lock.
///
/// Same unit-of-global shape as `pds_capabilities` and `diagnostics`. Nothing awaits while
/// it is held, so a `std::sync::Mutex` is the right primitive.
static HISTORY_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Fold a completed sweep into the stored history. Never fails a sweep: a write failure is
/// logged and dropped, because losing the readout must not lose the protection.
fn record_sweep(statuses: &[IdentityStatus], trigger: SweepTrigger) {
    // A poisoned lock guards no invariant worth preserving here — the record is rebuilt
    // from the Keychain on every call — so recover rather than propagate a panic into the
    // monitor.
    let _guard = HISTORY_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let next = fold_sweep(load_history(), statuses, trigger, Utc::now());
    match serde_json::to_vec(&next) {
        Ok(bytes) => {
            if let Err(e) = crate::keychain::store_item(HISTORY_ACCOUNT, &bytes) {
                tracing::warn!(error = %e, "failed to store monitor history");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize monitor history"),
    }
}

/// Tauri IPC command: what the monitor has been doing.
///
/// Synchronous and stateless like the other `IdentityStore`-adjacent reads — the Keychain
/// is a blocking API and there is no network here.
#[tauri::command]
pub fn get_monitor_history() -> MonitorHistory {
    MonitorHistory {
        interval_secs: MONITOR_INTERVAL_SECS,
        ..load_history()
    }
}

/// Run a single monitoring cycle. Extracted from the loop for testability.
/// Returns the list of identity statuses with any alerts.
pub async fn run_monitoring_cycle(monitor: &PlcMonitor<'_>) -> Vec<IdentityStatus> {
    match monitor.check_all().await {
        Ok(statuses) => {
            // Recorded only on a completed pass. A `check_all` that could not even list the
            // managed identities did not sweep anything, and logging it as a zero-identity
            // sweep would read as "nothing to check" — the reassuring inverse of the truth.
            record_sweep(&statuses, SweepTrigger::Background);
            statuses
        }
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
    record_sweep(&statuses, SweepTrigger::Foreground);
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

    // ── Sweep history (pure fold) ──────────────────────────────────────────

    fn at(iso: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(iso)
            .expect("test timestamp")
            .with_timezone(&Utc)
    }

    fn status(did: &str, check_failed: bool, alerts: usize) -> IdentityStatus {
        IdentityStatus {
            did: did.to_string(),
            check_failed,
            unauthorized_changes: (0..alerts)
                .map(|n| UnauthorizedChange {
                    cid: format!("bafy{n}"),
                    created_at: "2026-07-26T00:00:00Z".to_string(),
                    signing_key: None,
                    operation: serde_json::json!({}),
                })
                .collect(),
        }
    }

    #[test]
    fn fold_records_counts_and_verification_times() {
        let history = fold_sweep(
            MonitorHistory::default(),
            &[
                status("did:plc:a", false, 0),
                status("did:plc:b", true, 0),
                status("did:plc:c", false, 2),
            ],
            SweepTrigger::Background,
            at("2026-07-26T10:00:00Z"),
        );

        assert_eq!(history.sweeps.len(), 1);
        let sweep = &history.sweeps[0];
        assert_eq!(sweep.identities_checked, 3);
        assert_eq!(sweep.identities_failed, 1);
        assert_eq!(sweep.unauthorized_found, 2);
        assert_eq!(sweep.trigger, SweepTrigger::Background);
        assert_eq!(sweep.at, "2026-07-26T10:00:00Z");

        assert_eq!(
            history.identities[0].last_verified_at.as_deref(),
            Some("2026-07-26T10:00:00Z")
        );
        // The directory did not answer for B, so B has never been verified.
        assert_eq!(history.identities[1].last_verified_at, None);
        assert_eq!(history.interval_secs, MONITOR_INTERVAL_SECS);
    }

    /// A failed check must not erase the identity's last successful verification — that
    /// timestamp is still true, and dropping it would make a transient outage look like an
    /// identity the wallet has never checked.
    #[test]
    fn failed_check_preserves_the_previous_verification_time() {
        let first = fold_sweep(
            MonitorHistory::default(),
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Background,
            at("2026-07-26T10:00:00Z"),
        );
        let second = fold_sweep(
            first,
            &[status("did:plc:a", true, 0)],
            SweepTrigger::Background,
            at("2026-07-26T10:15:00Z"),
        );

        assert_eq!(
            second.identities[0].last_verified_at.as_deref(),
            Some("2026-07-26T10:00:00Z")
        );
    }

    /// A removed identity leaves the log on the next sweep: only DIDs the sweep actually
    /// covered are carried forward.
    #[test]
    fn identities_absent_from_a_sweep_are_dropped() {
        let first = fold_sweep(
            MonitorHistory::default(),
            &[status("did:plc:a", false, 0), status("did:plc:b", false, 0)],
            SweepTrigger::Background,
            at("2026-07-26T10:00:00Z"),
        );
        let second = fold_sweep(
            first,
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Background,
            at("2026-07-26T10:15:00Z"),
        );

        assert_eq!(second.identities.len(), 1);
        assert_eq!(second.identities[0].did, "did:plc:a");
    }

    /// A burst of identical foreground checks — the app opening, then two screens asking —
    /// is one event in the log, not three. Otherwise ordinary navigation evicts every
    /// background sweep and the log stops answering "is the unattended check running?".
    #[test]
    fn identical_foreground_checks_coalesce() {
        let mut history = MonitorHistory::default();
        for minute in ["10:00:00", "10:00:20", "10:01:00"] {
            history = fold_sweep(
                history,
                &[status("did:plc:a", false, 0)],
                SweepTrigger::Foreground,
                at(&format!("2026-07-26T{minute}Z")),
            );
        }

        assert_eq!(history.sweeps.len(), 1);
        assert_eq!(history.sweeps[0].at, "2026-07-26T10:01:00Z");
    }

    /// Coalescing is bounded by time, by trigger, and by outcome — each of these is a
    /// distinct event the user is entitled to see listed.
    #[test]
    fn distinct_sweeps_are_never_coalesced() {
        let base = fold_sweep(
            MonitorHistory::default(),
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Foreground,
            at("2026-07-26T10:00:00Z"),
        );

        // Same trigger and outcome, but past the window.
        let later = fold_sweep(
            base.clone(),
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Foreground,
            at("2026-07-26T10:06:00Z"),
        );
        assert_eq!(later.sweeps.len(), 2);

        // Within the window, but the background timer is a different kind of event.
        let other_trigger = fold_sweep(
            base.clone(),
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Background,
            at("2026-07-26T10:00:30Z"),
        );
        assert_eq!(other_trigger.sweeps.len(), 2);

        // Within the window and the same trigger, but this pass found something.
        let new_finding = fold_sweep(
            base,
            &[status("did:plc:a", false, 1)],
            SweepTrigger::Foreground,
            at("2026-07-26T10:00:30Z"),
        );
        assert_eq!(new_finding.sweeps.len(), 2);
        assert_eq!(new_finding.sweeps[0].unauthorized_found, 1);
    }

    #[test]
    fn sweep_log_is_capped_newest_first() {
        let mut history = MonitorHistory::default();
        for n in 0..(MAX_SWEEP_RECORDS + 5) {
            history = fold_sweep(
                history,
                &[status("did:plc:a", false, 0)],
                SweepTrigger::Background,
                at("2026-07-26T00:00:00Z") + chrono::Duration::minutes(15 * n as i64),
            );
        }

        assert_eq!(history.sweeps.len(), MAX_SWEEP_RECORDS);
        let newest = at(&history.sweeps[0].at);
        let oldest = at(&history.sweeps[MAX_SWEEP_RECORDS - 1].at);
        assert!(newest > oldest, "sweeps must be ordered newest first");
    }

    /// The wire shape the Protection surface reads.
    #[test]
    fn monitor_history_serializes_camel_case() {
        let history = fold_sweep(
            MonitorHistory::default(),
            &[status("did:plc:a", false, 0)],
            SweepTrigger::Foreground,
            at("2026-07-26T10:00:00Z"),
        );

        let json = serde_json::to_value(&history).expect("serialize");
        assert_eq!(json["sweeps"][0]["trigger"], "foreground");
        assert_eq!(json["sweeps"][0]["identitiesChecked"], 1);
        assert_eq!(json["sweeps"][0]["identitiesFailed"], 0);
        assert_eq!(json["sweeps"][0]["unauthorizedFound"], 0);
        assert_eq!(json["identities"][0]["did"], "did:plc:a");
        assert_eq!(
            json["identities"][0]["lastVerifiedAt"],
            "2026-07-26T10:00:00Z"
        );
        assert_eq!(json["intervalSecs"], MONITOR_INTERVAL_SECS);
    }

    /// A record written before `interval_secs` existed still loads; the reader supplies the
    /// current cadence.
    #[test]
    fn history_without_interval_deserializes() {
        let stored = serde_json::json!({ "sweeps": [], "identities": [] });
        let history: MonitorHistory = serde_json::from_value(stored).expect("deserialize");
        assert_eq!(history.interval_secs, 0);
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

    /// Only a did:plc has a PLC audit log to monitor.
    #[test]
    fn only_did_plc_is_monitorable() {
        assert!(is_monitorable("did:plc:abc123"));
        assert!(!is_monitorable("did:web:example.com"));
        // The prefix check is anchored, so a did:web whose domain merely mentions did:plc
        // is still not monitorable.
        assert!(!is_monitorable("did:web:did:plc:decoy.example"));
    }

    /// A did:web is omitted from the sweep rather than reported as a failed check, and no
    /// request is spent asking plc.directory about a DID it has never heard of.
    #[tokio::test]
    async fn did_web_identity_is_omitted_from_sweep() {
        use httpmock::prelude::*;

        let did = "did:web:monitor-skip.example";
        let store = IdentityStore;
        let _ = store.add_identity(did);

        let mock_server = MockServer::start();
        let client = PdsClient::new_for_test(mock_server.base_url());
        let monitor = PlcMonitor::new(&client);

        // Any audit-log fetch for this DID would land here. It must never be reached.
        let audit_mock = mock_server.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(404);
        });

        let statuses = monitor.check_all().await.expect("check_all failed");

        assert!(
            !statuses.iter().any(|s| s.did == did),
            "a did:web must not appear in the sweep at all, and above all not as check_failed"
        );
        audit_mock.assert_calls(0);
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
