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
- **plc-key-management.AC7.4 Success:** `submit_recovery_override` POSTs to plc.directory and updates cached log

---

## Phase 3: submit_recovery_override, command registration, IPC wrappers

This phase adds PdsClient accessor methods, the submission function, exposes both recovery functions as Tauri IPC commands, and adds TypeScript wrappers.

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add PdsClient accessor methods

**Verifies:** None (infrastructure — prerequisite for submit function)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs`

**Implementation:**

The `submit_recovery_override` function needs `PdsClient::plc_directory_url()` and `PdsClient::client()` accessors to construct the DID document fetch URL. These do not currently exist as public methods.

Add these two public getters to `PdsClient`:

```rust
/// Returns the plc.directory base URL.
pub fn plc_directory_url(&self) -> &str {
    &self.plc_directory_url
}

/// Returns a reference to the inner HTTP client.
pub fn client(&self) -> &reqwest::Client {
    &self.client
}
```

**Verification:**
Run: `cargo build -p identity-wallet`
Expected: Build succeeds

**Commit:** `refactor(identity-wallet): expose PdsClient accessor methods for recovery module`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement submit_recovery_override and Tauri commands

**Verifies:** plc-key-management.AC7.4

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/recovery.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (register commands in `generate_handler![]`)

**Implementation:**

Add the submission function and two `#[tauri::command]` wrappers to `recovery.rs`:

```rust
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
        .post_plc_operation(did, signed_op.clone())
        .await
        .map_err(|e| RecoveryError::PlcDirectoryError {
            message: format!("PLC directory rejected the operation: {e}"),
        })?;

    // 2. Re-fetch the audit log to update the cache.
    let updated_log = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to fetch updated audit log: {e}"),
        })?;

    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to update cached log: {e}"),
        })?;

    // 3. Re-fetch the DID document (it should now reflect the recovered state).
    // Use the raw plc.directory endpoint, not the audit log.
    let did_doc_url = format!("{}/{}", pds_client.plc_directory_url(), did);
    let did_doc: serde_json::Value = pds_client
        .client()
        .get(&did_doc_url)
        .send()
        .await
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to fetch DID document: {e}"),
        })?
        .json()
        .await
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to parse DID document: {e}"),
        })?;

    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| RecoveryError::NetworkError {
            message: format!("Failed to update cached DID doc: {e}"),
        })?;

    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}
```

Add two Tauri command wrappers:

```rust
/// Tauri command: Build a recovery override operation.
///
/// Stores the built operation in RecoveryState for subsequent submission.
#[tauri::command]
pub async fn build_recovery_override_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    operation_cid: String,
) -> Result<SignedRecoveryOp, RecoveryError> {
    let result = build_recovery_override(
        state.pds_client(),
        &did,
        &operation_cid,
    )
    .await?;

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

    let result = submit_recovery_override(
        state.pds_client(),
        &did,
        &signed_op,
    )
    .await?;

    // Clear recovery state on success.
    let mut recovery = state.recovery_state.lock().await;
    *recovery = None;

    Ok(result)
}
```

In `apps/identity-wallet/src-tauri/src/lib.rs`, add the two commands to the `generate_handler![]` macro (after `plc_monitor::check_identity_status`):

```rust
recovery::build_recovery_override_cmd,
recovery::submit_recovery_override_cmd,
```

**Testing:**

Tests must verify:
- plc-key-management.AC7.4: `submit_recovery_override` POSTs to plc.directory (mock server receives the signed op) and updates the cached PLC log in Keychain

Test approach: Use `httpmock::MockServer` to mock both plc.directory endpoints (`POST /{did}` for submission, `GET /{did}/log/audit` for re-fetch, `GET /{did}` for DID doc). Verify the mock received the correct signed operation JSON. Verify `IdentityStore::get_plc_log(did)` returns the updated log after submission.

**Verification:**
Run: `cargo test -p identity-wallet submit_recovery`
Expected: All tests pass

Run: `cargo build -p identity-wallet`
Expected: Build succeeds with new commands registered

**Commit:** `feat(identity-wallet): implement submit_recovery_override and register Tauri commands`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Add TypeScript IPC wrappers

**Verifies:** None (infrastructure — TypeScript types only)

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Implementation:**

Add the recovery override types and IPC wrappers at the end of `ipc.ts`, following the existing pattern:

```typescript
// ── recovery_override ─────────────────────────────────────────────────────────

/**
 * Error returned by recovery override commands.
 * Matches RecoveryError enum in recovery.rs with #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")].
 */
export type RecoveryError =
  | { code: 'RECOVERY_WINDOW_EXPIRED' }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'UNAUTHORIZED_CHANGE_NOT_FOUND' };

/**
 * Signed recovery operation ready for review and submission.
 * Matches SignedRecoveryOp struct in recovery.rs with #[serde(rename_all = "camelCase")].
 */
export interface SignedRecoveryOp {
  /** Human-readable diff of what the recovery operation changes. */
  diff: OpDiff;
  /** The signed PLC operation JSON, ready to POST to plc.directory. */
  signedOp: Record<string, unknown>;
}

/**
 * Build a recovery override operation for an unauthorized PLC change.
 *
 * Fetches the audit log, identifies the fork point, builds a counter-operation
 * that restores the pre-unauthorized state, and signs it with the device key.
 *
 * The built operation is stored in RecoveryState for subsequent submission
 * via submitRecoveryOverride().
 */
export const buildRecoveryOverride = (did: string, operationCid: string): Promise<SignedRecoveryOp> =>
  invoke('build_recovery_override_cmd', { did, operationCid });

/**
 * Submit the pending recovery override operation to plc.directory.
 *
 * Must be called after buildRecoveryOverride() — submits the stored signed
 * operation, updates the cached PLC audit log, and returns the updated DID document.
 */
export const submitRecoveryOverride = (did: string): Promise<ClaimResult> =>
  invoke('submit_recovery_override_cmd', { did });
```

Note: `OpDiff` and `ClaimResult` are already exported from `ipc.ts` (defined in the claim section).

**Verification:**
Run: `cd apps/identity-wallet && npx tsc --noEmit`
Expected: No type errors (or only pre-existing ones unrelated to this change)

**Commit:** `feat(identity-wallet): add recovery override IPC wrappers`

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
