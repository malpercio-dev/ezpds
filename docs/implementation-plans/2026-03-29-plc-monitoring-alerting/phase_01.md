# PLC Monitoring & Alerting Implementation Plan — Phase 1: PlcMonitor Backend Core

**Goal:** Build the core monitoring logic that detects unauthorized PLC operations on managed identities.

**Architecture:** A `PlcMonitor` struct in the identity-wallet Tauri backend that fetches audit logs from plc.directory, diffs against cached state, classifies new operations as authorized (signed by device key) or unauthorized (signed by any other key), and exposes the results via a Tauri IPC command.

**Tech Stack:** Rust, Tauri v2 IPC, crypto crate (audit log parsing/diffing/verification), identity_store (Keychain-backed per-DID storage), pds_client (plc.directory HTTP client)

**Scope:** 3 phases from design Phase 6. This is phase 1 of 3.

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC6: PLC monitoring and alerting
- **plc-key-management.AC6.1 Success:** Monitor detects a new PLC operation signed by the device key and updates cached log without alerting
- **plc-key-management.AC6.2 Success:** Monitor detects a new PLC operation signed by a different key and creates an `UnauthorizedChange` alert
- **plc-key-management.AC6.3 Success:** Alert includes correct recovery deadline (operation timestamp + 72 hours)
- **plc-key-management.AC6.7 Edge:** Monitor handles plc.directory being unreachable gracefully (logs error, retries next cycle, does not alert)
- **plc-key-management.AC6.8 Edge:** Monitor handles empty audit log (newly created identity, no operations yet)

---

## Deviations from Design

The design plan specifies a per-DID `check_for_changes(did)` command and particular field names on `UnauthorizedChange`. This implementation makes deliberate changes for simplicity:

| Design | Implementation | Rationale |
|--------|---------------|-----------|
| `checkIdentityStatus(did: string)` per-DID call | `checkIdentityStatus()` no-arg, returns all identities | Avoids N+1 IPC calls; frontend gets complete state in one call |
| `UnauthorizedChange.operationCid` | `UnauthorizedChange.cid` | Shorter, matches `AuditEntry.cid` field name from crypto crate |
| `UnauthorizedChange.signedBy` | `UnauthorizedChange.signingKey` | Clearer that this is a did:key URI, not a display name |
| `UnauthorizedChange.detectedAt` | Not included | `createdAt` (from plc.directory) is the authoritative timestamp; "detected" time adds no value since detection happens on poll |
| `UnauthorizedChange.recoveryDeadline` | Not included (computed by frontend) | Avoids adding `chrono` dependency; deadline is deterministic from `createdAt + 72h`; frontend computes it for countdown display |
| `UnauthorizedChange.description` | Not included | Raw `operation` JSON provides full details; frontend renders the relevant fields |
| `IdentityStatus.healthy` | Not included | Monitoring errors are gracefully handled (AC6.7: return empty, no alert); per-identity "health" would be ambiguous |

---

## Codebase Verification Findings

- ✓ `plc_monitor.rs` does NOT exist — new file to create
- ✓ `crypto::parse_audit_log(json: &str) -> Result<Vec<AuditEntry>, CryptoError>` exists at `crates/crypto/src/plc.rs:606`
- ✓ `crypto::diff_audit_logs(cached: &[AuditEntry], current: &[AuditEntry]) -> Vec<AuditEntry>` exists at `crates/crypto/src/plc.rs:614`
- ✓ `crypto::verify_plc_operation(signed_op_json: &str, authorized_rotation_keys: &[DidKeyUri]) -> Result<VerifiedPlcOp, CryptoError>` exists at `crates/crypto/src/plc.rs:463`
- ✓ `AuditEntry { did, cid, created_at, nullified, operation }` at `crates/crypto/src/plc.rs:585`
- ✓ `IdentityStore::list_identities() -> Result<Vec<String>, IdentityStoreError>` at `identity_store.rs:189`
- ✓ `IdentityStore::get_plc_log(did) -> Result<Option<String>, IdentityStoreError>` at `identity_store.rs:277`
- ✓ `IdentityStore::store_plc_log(did, json) -> Result<(), IdentityStoreError>` at `identity_store.rs:261`
- ✓ `IdentityStore::get_or_create_device_key(did) -> Result<DevicePublicKey, IdentityStoreError>` at `identity_store.rs:202`
- ✓ `PdsClient::fetch_audit_log(did) -> Result<String, PdsClientError>` at `pds_client.rs:452`
- ✓ `PdsClient` is in `AppState` (eagerly initialized), accessed via `state.pds_client()`
- ✓ `VerifiedPlcOp` does NOT include a signing key field — must iterate candidate keys to identify signer
- ✓ `DevicePublicKey.key_id` contains the full `did:key:...` URI
- ✓ Error pattern: `thiserror::Error` + `serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")`
- ✓ Testing: `#[cfg(test)]` modules, `httpmock::MockServer`, `#[tokio::test]`, in-memory Keychain mock
- ✓ No `chrono` dependency — `created_at` is raw ISO 8601 string; 72h deadline computed by frontend

## External Dependency Findings

- ✓ plc.directory audit log: JSON array of `{ operation, did, cid, createdAt, nullified }` entries
- ✓ Signing key not in operation JSON — must try each rotation key from previous op via `verify_plc_operation`
- ✓ 72-hour recovery window: defined in did:plc spec v0.1; higher-authority key can rewrite history within 72h of `createdAt`
- ✓ `createdAt` format: ISO 8601 `YYYY-MM-DDTHH:mm:ss.sssZ`

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Create PlcMonitor types and error enum

**Verifies:** None (infrastructure for subsequent tasks)

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/plc_monitor.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add `mod plc_monitor;` declaration)

**Implementation:**

Create `plc_monitor.rs` with the following types:

```rust
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
```

Add `mod plc_monitor;` to `lib.rs` alongside the other module declarations (near `mod claim;`, `mod identity_store;`, etc.).

**Verification:**

Run: `cd apps/identity-wallet/src-tauri && cargo check`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): add PlcMonitor types and error enum`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement PlcMonitor::check_for_changes

**Verifies:** plc-key-management.AC6.1, plc-key-management.AC6.2, plc-key-management.AC6.3, plc-key-management.AC6.7, plc-key-management.AC6.8

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/plc_monitor.rs`

**Implementation:**

Add `PlcMonitor` struct and `check_for_changes` method. The struct holds a cloned `PdsClient` (cheap — wraps `reqwest::Client` + URL string).

`check_for_changes` algorithm:
1. Fetch current audit log from plc.directory via `pds_client.fetch_audit_log(did)`. On network error, log with `tracing::warn!` and return `Ok(vec![])` (AC6.7 — graceful handling, no alert).
2. Parse current log via `crypto::parse_audit_log`. On parse error, log warning and return `Ok(vec![])`.
3. Load cached log from `IdentityStore::get_plc_log(did)`. If `None` (first check or empty — AC6.8), parse as empty `Vec<AuditEntry>`.
4. Diff via `crypto::diff_audit_logs(cached, current)` to get new entries.
5. If no new entries, return `Ok(vec![])`.
6. Get the device key's did:key URI via `IdentityStore::get_or_create_device_key(did)` → `DevicePublicKey.key_id`.
7. For each new `AuditEntry`:
   a. Serialize `entry.operation` to JSON string.
   b. Call `crypto::verify_plc_operation(op_json, &[DidKeyUri(device_key_uri)])` (wrapping String in DidKeyUri newtype).
   c. If `Ok(_)` → authorized, skip (AC6.1).
   d. If `Err(_)` → unauthorized (AC6.2). Attempt to identify the signing key by trying each key in the previous operation's `rotationKeys`. Build `UnauthorizedChange` with `created_at` from the entry (AC6.3 — frontend computes deadline from this timestamp).
8. Update cached log: `IdentityStore::store_plc_log(did, &current_log_json)` (stores the full fetched log for next diff).
9. Return the list of `UnauthorizedChange` entries.

To get the previous operation's `rotationKeys` for signing key identification (step 7d):
- The previous entry in the current audit log (the entry just before the new one) contains the authoritative `rotationKeys`.
- Parse its `operation` field to extract `rotationKeys` array.
- Try `verify_plc_operation` with each key individually. The one that succeeds is the signing key.
- If none succeed, set `signing_key: None`.

```rust
use crate::identity_store::IdentityStore;
use crate::pds_client::PdsClient;
use crypto::{parse_audit_log, diff_audit_logs, verify_plc_operation, AuditEntry, DidKeyUri};

pub struct PlcMonitor {
    pds_client: PdsClient,
}

impl PlcMonitor {
    pub fn new(pds_client: PdsClient) -> Self {
        Self { pds_client }
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
                return Err(MonitorError::IdentityStoreError { message: e.to_string() });
            }
        };

        // Step 4: Diff
        let new_entries = diff_audit_logs(&cached_entries, &current_entries);

        // Step 5: If no new entries, return
        if new_entries.is_empty() {
            return Ok(vec![]);
        }

        // Step 6: Get device key
        let device_key = store.get_or_create_device_key(did)
            .map_err(|e| MonitorError::IdentityStoreError { message: e.to_string() })?;
        let device_key_uri = DidKeyUri(device_key.key_id);

        // Step 7: Classify each new entry
        let mut unauthorized = Vec::new();
        for entry in &new_entries {
            let op_json = serde_json::to_string(&entry.operation)
                .map_err(|e| MonitorError::ParseError { message: e.to_string() })?;

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
        store.store_plc_log(did, &current_log_json)
            .map_err(|e| MonitorError::IdentityStoreError { message: e.to_string() })?;

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
    let prev_entry = all_entries.iter()
        .take_while(|e| e.cid != target.cid)
        .last()?;

    // Extract rotationKeys from previous operation
    let rotation_keys: Vec<String> = prev_entry.operation
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
```

**Testing:**

Tests must verify each AC listed above:
- plc-key-management.AC6.1: Mock plc.directory returning a log with a new entry signed by the device key. Verify `check_for_changes` returns empty `Vec` and cached log is updated.
- plc-key-management.AC6.2: Mock plc.directory returning a log with a new entry signed by a different key. Verify `check_for_changes` returns one `UnauthorizedChange` with the correct signing key.
- plc-key-management.AC6.3: Verify `UnauthorizedChange.created_at` matches the operation's `createdAt` from the audit log (frontend uses this + 72h for deadline).
- plc-key-management.AC6.7: Mock plc.directory returning a network error. Verify `check_for_changes` returns `Ok(vec![])` (no error, no alert).
- plc-key-management.AC6.8: Start with no cached log and mock plc.directory returning an empty audit log. Verify `check_for_changes` returns `Ok(vec![])`.

Follow existing test patterns in the codebase:
- Use `#[tokio::test]` for async tests
- Use `httpmock::MockServer` for plc.directory HTTP mocking
- Use `PdsClient::new_for_test(mock_server.base_url())` to inject mock URL
- In-memory Keychain mock is automatically active under `#[cfg(test)]`
- Reference files for patterns: `pds_client.rs:705+` (HTTP mocking), `identity_store.rs:493+` (Keychain test helpers), `claim.rs:1101+` (error mapping tests)

**Note on test data:** Tests will need realistic PLC operation JSON that can be verified by `verify_plc_operation`. The simplest approach is to use `crypto::build_did_plc_genesis_op` or `build_did_plc_genesis_op_with_external_signer` to generate a signed operation in the test, then wrap it in an `AuditEntry` structure. This ensures the signature is valid and verifiable.

**Verification:**

Run: `cd apps/identity-wallet/src-tauri && cargo test plc_monitor`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement PlcMonitor::check_for_changes`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Implement PlcMonitor::check_all

**Verifies:** plc-key-management.AC6.1, plc-key-management.AC6.2 (multi-identity variant)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/plc_monitor.rs`

**Implementation:**

Add `check_all` method to `PlcMonitor`:

```rust
impl PlcMonitor {
    // ... existing methods ...

    pub async fn check_all(&self) -> Result<Vec<IdentityStatus>, MonitorError> {
        let store = IdentityStore;
        let dids = store.list_identities()
            .map_err(|e| MonitorError::IdentityStoreError { message: e.to_string() })?;

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
}
```

Note: Sequential iteration over DIDs is intentional for v1 — avoids concurrent Keychain access issues. Concurrent fetches can be added later if monitoring many identities becomes slow.

**Testing:**

Tests must verify:
- plc-key-management.AC6.1 (multi-identity): Register two DIDs, mock plc.directory for both. One has a new authorized op, one has no changes. Verify `check_all` returns two `IdentityStatus` entries both with `alert_count: 0`.
- plc-key-management.AC6.2 (multi-identity): Register two DIDs, one with an unauthorized op. Verify `check_all` returns correct alert counts per identity.

Follow same patterns as Task 2 tests but with multiple mock DID endpoints.

**Verification:**

Run: `cd apps/identity-wallet/src-tauri && cargo test plc_monitor`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement PlcMonitor::check_all`

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Register check_identity_status Tauri IPC command

**Verifies:** None (infrastructure — wires PlcMonitor to frontend IPC)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (add Tauri command)
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (register command in `invoke_handler`)

**Implementation:**

Add a Tauri IPC command in `plc_monitor.rs`:

```rust
/// Tauri IPC command: check all managed identities for unauthorized PLC operations.
/// Returns a list of IdentityStatus, one per managed DID.
#[tauri::command]
pub async fn check_identity_status(
    state: tauri::State<'_, crate::oauth::AppState>,
) -> Result<Vec<IdentityStatus>, MonitorError> {
    let monitor = PlcMonitor::new(state.pds_client().clone());
    monitor.check_all().await
}
```

In `lib.rs`, add `plc_monitor::check_identity_status` to the `invoke_handler` builder alongside existing commands:

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands ...
    plc_monitor::check_identity_status,
])
```

**Verification:**

Run: `cd apps/identity-wallet/src-tauri && cargo check`
Expected: Compiles without errors (Tauri command registration is compile-time verified)

**Commit:** `feat(identity-wallet): register check_identity_status IPC command`

<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->
