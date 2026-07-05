# Claim Flow Backend — Phase 4: submit_claim, Command Registration, and IPC Wrappers

**Goal:** Complete the claim flow with `submit_claim` (posts to plc.directory + persists identity), register all five claim commands in Tauri's handler, and add typed TypeScript IPC wrappers.

**Architecture:** `submit_claim` reads the verified signed operation from `ClaimState`, POSTs it to plc.directory, registers the identity in `IdentityStore`, stores the DID document and audit log, then clears claim state. Command registration adds all five claim commands to `generate_handler![]` in `lib.rs`. IPC wrappers in `ipc.ts` follow the existing typed function pattern with discriminated union error types.

**Tech Stack:** Rust, serde, reqwest, TypeScript, Tauri IPC

**Scope:** 4 phases from design Phase 4 (this is phase 4 of 4)

**Codebase verified:** 2026-03-28

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC4: Claim flow executes end-to-end
- **plc-key-management.AC4.8 Success:** `submit_claim` POSTs the signed operation to plc.directory and persists the identity to IdentityStore
- **plc-key-management.AC4.9 Failure:** `submit_claim` returns `PLC_DIRECTORY_ERROR` when plc.directory rejects the operation

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add post_plc_operation to PdsClient

**Verifies:** None (infrastructure — enables submit_claim)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs`

**Implementation:**

Add a method to `PdsClient` that submits a signed PLC operation to plc.directory:

```rust
/// Submit a signed PLC operation to plc.directory.
///
/// Calls `POST {plc_directory_url}/{did}` with the signed operation as JSON body.
pub async fn post_plc_operation(
    &self,
    did: &str,
    operation: &serde_json::Value,
) -> Result<(), PdsClientError> {
    let url = format!("{}/{}", self.plc_directory_url, did);
    let resp = self.client.post(&url)
        .json(operation)
        .send()
        .await
        .map_err(|e| PdsClientError::NetworkError { message: e.to_string() })?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(PdsClientError::InvalidResponse {
            message: format!("plc.directory rejected operation: {}", body),
        })
    }
}
```

Add tests:
- Mock POST `/{did}` returning 200. Assert method returns Ok(()).
- Mock POST `/{did}` returning 409. Assert method returns error with body text.

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- pds_client::tests::post_plc`
Expected: Tests pass

**Commit:** `feat(identity-wallet): add post_plc_operation to PdsClient`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement submit_claim command with tests

**Verifies:** plc-key-management.AC4.8, plc-key-management.AC4.9

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs`

**Implementation:**

Add `submit_claim` Tauri command. Extract testable core logic into a helper:

```rust
pub(crate) async fn submit_claim_impl(
    pds_client: &PdsClient,
    claim_state: &ClaimState,
) -> Result<ClaimResult, ClaimError>
```

**Note:** `IdentityStore` is a stateless unit struct (no fields, all state lives in Keychain). It can be instantiated inline as `let store = IdentityStore;` — no need to pass it as a parameter or extract it from AppState.

The function:

1. Read `verified_signed_op` from `ClaimState`. Return `ClaimError::Unauthorized` if `None` (user hasn't completed verification).
2. POST the signed operation to plc.directory:
   - Parse the stored JSON string back to `serde_json::Value`
   - Call `pds_client.post_plc_operation(&claim_state.did, &operation)` (implemented in Task 1)
   - Map `PdsClientError::InvalidResponse` → `ClaimError::PlcDirectoryError { message }`
3. Persist the claimed identity to `IdentityStore`:
   - `IdentityStore.add_identity(&did)` — registers DID in managed-dids index. If already exists (`IdentityAlreadyExists`), this is fine — the user may have a partially completed prior claim.
   - `IdentityStore.get_or_create_device_key(&did)` — ensure device key exists.
   - Re-fetch the DID document from plc.directory: `pds_client.discover_pds(&did)` → get updated `PlcDidDocument`.
   - `IdentityStore.store_did_doc(&did, &serde_json::to_string(&did_doc)?)` — persist updated DID doc.
   - `pds_client.fetch_audit_log(&did)` → `IdentityStore.store_plc_log(&did, &log_json)` — persist updated audit log.
4. Clear `ClaimState` (set `AppState.claim_state` to `None`).
5. Return `ClaimResult { updated_did_doc: serde_json::to_value(&did_doc) }`.

The Tauri command wrapper:

```rust
#[tauri::command]
pub async fn submit_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ClaimResult, ClaimError>
```

**Testing:**

Tests must verify each AC:

1. **AC4.8 — success:** Mock plc.directory POST `/{did}` returning 200. Set up ClaimState with a verified signed op. Assert: mock was hit with correct body, `IdentityStore.list_identities()` includes the DID, `IdentityStore.get_did_doc()` returns the updated doc, `IdentityStore.get_plc_log()` returns the stored log. Also mock the re-fetch of DID doc and audit log after submission.

2. **AC4.9 — plc.directory rejects operation:** Mock plc.directory POST returning 409 with error body. Assert `ClaimError::PlcDirectoryError` with message from response body.

3. **No verified op — unauthorized:** Call with ClaimState that has `verified_signed_op: None`. Assert `ClaimError::Unauthorized`.

Follow existing test patterns: `#[tokio::test]`, `httpmock::MockServer` for plc.directory, in-memory Keychain mock for IdentityStore.

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- claim::tests::submit`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement submit_claim command (AC4.8, AC4.9)`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Register claim commands in lib.rs

**Verifies:** None (infrastructure — wiring)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (the `generate_handler![]` macro invocation)

**Implementation:**

Add all five claim commands to the `generate_handler![]` macro (search for `tauri::generate_handler!`):

```rust
.invoke_handler(tauri::generate_handler![
    create_account,
    get_or_create_device_key,
    sign_with_device_key,
    perform_did_ceremony,
    register_handle,
    check_handle_resolution,
    get_relay_url,
    save_relay_url,
    home::load_home_data,
    home::log_out,
    oauth::start_oauth_flow,
    claim::resolve_identity,
    claim::start_pds_auth,
    claim::request_claim_verification,
    claim::sign_and_verify_claim,
    claim::submit_claim,
])
```

**Verification:**

Run: `cargo check -p identity-wallet-tauri`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): register claim commands in Tauri handler`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add TypeScript IPC wrappers

**Verifies:** None (infrastructure — frontend IPC contract)

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Implementation:**

Add typed TypeScript wrappers following the existing pattern. All new types and functions go after the existing exports.

**Types to add:**

```typescript
// --- Claim flow types ---

export interface IdentityInfo {
  did: string;
  handle: string;
  pdsUrl: string;
  currentRotationKeys: string[];
  deviceKeyIsRoot: boolean;
}

export interface VerifiedClaimOp {
  diff: OpDiff;
  signedOp: string;
  warnings: string[];
}

export interface OpDiff {
  addedKeys: string[];
  removedKeys: string[];
  changedServices: ServiceChange[];
  prevCid: string;
}

export interface ServiceChange {
  id: string;
  changeType: string;
  oldEndpoint: string | null;
  newEndpoint: string | null;
}

export interface ClaimResult {
  updatedDidDoc: Record<string, unknown>;
}

// --- Claim flow error types ---

export type ResolveError =
  | { code: 'HANDLE_NOT_FOUND' }
  | { code: 'DID_NOT_FOUND' }
  | { code: 'PDS_UNREACHABLE' }
  | { code: 'NETWORK_ERROR'; message: string };

export type ClaimError =
  | { code: 'INVALID_TOKEN' }
  | { code: 'VERIFICATION_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'UNAUTHORIZED' }
  | { code: 'NETWORK_ERROR'; message: string };
```

**Functions to add:**

```typescript
export const resolveIdentity = (handleOrDid: string): Promise<IdentityInfo> =>
  invoke('resolve_identity', { handleOrDid });

export const startPdsAuth = (pdsUrl: string): Promise<void> =>
  invoke('start_pds_auth', { pdsUrl });

export const requestClaimVerification = (did: string): Promise<void> =>
  invoke('request_claim_verification', { did });

export const signAndVerifyClaim = (did: string, token: string): Promise<VerifiedClaimOp> =>
  invoke('sign_and_verify_claim', { did, token });

export const submitClaim = (did: string): Promise<ClaimResult> =>
  invoke('submit_claim', { did });
```

**Verification:**

Run: `cd apps/identity-wallet && pnpm exec tsc --noEmit`
Expected: TypeScript compiles without errors

**Commit:** `feat(identity-wallet): add TypeScript IPC wrappers for claim commands`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
