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

## Phase 1: Recovery module — types, error types, and fork-point identification

This phase creates the `recovery.rs` module with types, error enum, and the core fork-point identification logic. No Tauri commands yet — just the internal building blocks.

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Create recovery.rs with types and error enum

**Verifies:** None (infrastructure — types only)

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/recovery.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add `pub mod recovery;`)

**Implementation:**

Create `recovery.rs` with these types, following the existing patterns from `claim.rs` and `plc_monitor.rs`:

```rust
use serde::Serialize;
use std::collections::BTreeMap;

use crate::claim::{ClaimResult, OpDiff};

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
```

Add `pub mod recovery;` to `lib.rs` alongside the other module declarations (after `pub mod plc_monitor;`).

Note: These types are consumed by Tasks 2-3 in this phase and by later phases. If `cargo clippy -- -D warnings` reports dead_code warnings after this task, add `#[allow(dead_code)]` temporarily on unused items — they will be consumed by subsequent tasks.

**Verification:**
Run: `cargo build -p identity-wallet 2>&1 | head -5`
Expected: Build succeeds (no errors)

**Commit:** `feat(identity-wallet): add recovery module with types and error enum`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement find_fork_point function

**Verifies:** plc-key-management.AC7.1 (fork point identification is prerequisite), plc-key-management.AC7.7 (earliest fork point for multiple unauthorized ops)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`

**Implementation:**

Add the fork-point identification function. This walks the audit log backwards from the unauthorized operation to find the last operation signed by the device key. For multiple sequential unauthorized ops (AC7.7), it targets the earliest fork point.

```rust
use crypto::{AuditEntry, DidKeyUri};

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
```

**Testing:**

Tests must verify:
- plc-key-management.AC7.1: Fork point identification returns the correct entry (the one whose CID becomes `prev`)
- plc-key-management.AC7.7: With multiple sequential unauthorized ops, the function returns the earliest fork point (last device-key-signed op before the first unauthorized one)

Test scenarios:
1. Single unauthorized op after a device-key-signed genesis → fork point is the genesis
2. Two unauthorized ops in sequence → fork point is the last device-key-signed op before both
3. Target CID not found in audit log → returns `UnauthorizedChangeNotFound`
4. Target CID is the genesis op (index 0) → returns error

Follow the existing test pattern in `plc_monitor.rs`: use `#[cfg(test)] mod tests { }`, generate real keys via `crypto::generate_p256_keypair()`, build real signed operations via the crypto crate, and construct `AuditEntry` values from the signed ops.

**Verification:**
Run: `cargo test -p identity-wallet find_fork_point`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement fork-point identification for recovery override`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Implement check_recovery_window function

**Verifies:** plc-key-management.AC7.5 (RECOVERY_WINDOW_EXPIRED when 72h deadline passed)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`

**Implementation:**

Add the recovery window check. The 72-hour window is computed from the unauthorized operation's `created_at` timestamp.

```rust
use chrono::{DateTime, Duration, Utc};

const RECOVERY_WINDOW_HOURS: i64 = 72;

/// Checks whether the 72-hour recovery window is still open for an unauthorized operation.
///
/// Returns `Ok(())` if recovery is still possible, or `Err(RecoveryWindowExpired)` if
/// the 72-hour deadline has passed.
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
```

Note: Add `chrono` following the workspace dependency convention:
1. In the root `Cargo.toml`, add to `[workspace.dependencies]`:
```toml
chrono = { version = "0.4", default-features = false, features = ["clock", "std"] }
```
2. In `apps/identity-wallet/src-tauri/Cargo.toml`, add to `[dependencies]`:
```toml
chrono = { workspace = true }
```

**Testing:**

Tests must verify:
- plc-key-management.AC7.5: Timestamps older than 72 hours return `RecoveryWindowExpired`
- Timestamps within 72 hours return `Ok(())`
- Invalid timestamp strings return an appropriate error

Test approach: construct ISO 8601 timestamps relative to `Utc::now()` (e.g., `Utc::now() - Duration::hours(73)` for expired, `Utc::now() - Duration::hours(1)` for valid).

**Verification:**
Run: `cargo test -p identity-wallet check_recovery_window`
Expected: All tests pass

**Commit:** `feat(identity-wallet): add recovery window expiry check`

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
