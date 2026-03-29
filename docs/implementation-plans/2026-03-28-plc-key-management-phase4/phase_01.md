# Claim Flow Backend — Phase 1: Types, Errors, and resolve_identity

**Goal:** Create the claim module with all shared types, error enums, ClaimState for cross-command state, and the `resolve_identity` command that resolves a handle/DID to identity information.

**Architecture:** A new `claim.rs` module in the identity-wallet Tauri backend. Types follow the existing `{ code: "SCREAMING_SNAKE_CASE" }` error serialization pattern. `resolve_identity` delegates to `PdsClient` for resolution and discovery, and checks `IdentityStore` for existing device key status. A `ClaimState` struct persists across the multi-step claim flow via a new `Mutex<Option<ClaimState>>` field on `AppState`.

**Tech Stack:** Rust, serde, tauri, tokio

**Scope:** 4 phases from design Phase 4 (this is phase 1 of 4)

**Codebase verified:** 2026-03-28

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC4: Claim flow executes end-to-end
- **plc-key-management.AC4.1 Success:** `resolve_identity` returns correct `IdentityInfo` including current rotation keys and PDS URL

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Create claim.rs with types and error enums

**Verifies:** None (infrastructure — types verified by compiler)

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/claim.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add `pub mod claim;` declaration)

**Implementation:**

Create `claim.rs` with all types needed across the claim flow. These types map to the IPC contracts in the design plan (lines 184-280).

**Note:** The `ServiceChange` type is not explicitly defined in the design's TypeScript IPC contracts (only referenced as `ServiceChange[]` in `OpDiff`). The definition below is inferred from the design context — it represents a change to a service entry between the current DID doc and the proposed operation.

**Types to create:**

```rust
use serde::Serialize;

// --- Output types ---

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub did: String,
    pub handle: String,
    pub pds_url: String,
    pub current_rotation_keys: Vec<String>,
    pub device_key_is_root: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedClaimOp {
    pub diff: OpDiff,
    pub signed_op: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpDiff {
    pub added_keys: Vec<String>,
    pub removed_keys: Vec<String>,
    pub changed_services: Vec<ServiceChange>,
    pub prev_cid: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChange {
    pub id: String,
    pub change_type: String, // "added", "removed", "modified"
    pub old_endpoint: Option<String>,
    pub new_endpoint: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    pub updated_did_doc: serde_json::Value,
}
```

**Error types:**

```rust
#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveError {
    HandleNotFound,
    DidNotFound,
    PdsUnreachable,
    NetworkError { message: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimError {
    InvalidToken,
    VerificationFailed { message: String },
    PlcDirectoryError { message: String },
    Unauthorized,
    NetworkError { message: String },
}
```

**ClaimState** (cross-command state persisted in AppState):

```rust
use crate::oauth_client::OAuthClient;
use crate::pds_client::PlcDidDocument;

pub struct ClaimState {
    pub did: String,
    pub pds_url: String,
    pub did_doc: PlcDidDocument,
    pub pds_oauth_client: Option<OAuthClient>,
    pub verified_signed_op: Option<String>,
}
```

Also add `Clone` derive to `PlcDidDocument` in `pds_client.rs` (line ~60). `ClaimState` stores a `PlcDidDocument` inside a `tokio::Mutex`, and downstream commands need to read fields while holding the lock guard. Adding `Clone` prevents issues if the implementer needs to extract data outside the lock scope.

Add `pub mod claim;` to `lib.rs` module declarations (alongside existing `pub mod device_key;`, `pub mod home;`, etc.).

**Verification:**

Run: `cargo check -p identity-wallet-tauri`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): add claim module types and error enums`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add ClaimState to AppState

**Verifies:** None (infrastructure — wiring)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (AppState struct definition and `new()` method)

**Implementation:**

Add a new field to `AppState`:

```rust
pub claim_state: tokio::sync::Mutex<Option<crate::claim::ClaimState>>,
```

Use `tokio::sync::Mutex` (not `std::sync::Mutex`) because claim commands are async and hold the lock across `.await` points (e.g., `resolve_identity` locks claim_state, does async PDS calls, then writes to it before releasing).

**Important:** The existing `AppState` fields (`pending_auth`, `oauth_session`) use `std::sync::Mutex`. This mixing is intentional and correct — those fields are locked briefly for non-async operations (take/replace of `Option` values with no `.await` while locked). `claim_state` is different: commands hold the lock across multiple async calls. Using `std::sync::Mutex` here would deadlock the Tokio runtime. Do NOT "harmonize" by changing either direction.

Update `AppState::new()` to initialize the field:

```rust
claim_state: tokio::sync::Mutex::new(None),
```

**Verification:**

Run: `cargo check -p identity-wallet-tauri`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): add claim_state to AppState`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Implement resolve_identity command

**Verifies:** plc-key-management.AC4.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs` (add resolve_identity function)

**Implementation:**

Add a `resolve_identity` Tauri command to `claim.rs`. Follow the existing pattern of a thin Tauri wrapper calling testable core logic.

The function:
1. Determines if input is a DID (starts with `"did:"`) or a handle
2. If handle: calls `PdsClient::resolve_handle(handle)` to get DID
3. Calls `PdsClient::discover_pds(did)` to fetch DID doc from plc.directory and extract PDS endpoint
4. Extracts handle from `also_known_as` entries (format: `at://handle`, strip `at://` prefix). **Edge case:** if `also_known_as` is empty or contains no `at://` entries, fall back to the original `handle_or_did` input if it was a handle, or use `"unknown"` if it was a DID
5. Checks if DID is in `IdentityStore::list_identities()`; if so, calls `get_or_create_device_key(did)` and compares `key.key_id` against `did_doc.rotation_keys[0]` to determine `device_key_is_root`
6. Stores `did`, `pds_url`, and `did_doc` in `AppState.claim_state` for use by subsequent commands
7. Returns `IdentityInfo`

Map `PdsClientError` variants to `ResolveError`:
- `HandleNotFound` → `ResolveError::HandleNotFound`
- `DidNotFound` → `ResolveError::DidNotFound`
- `PdsUnreachable { .. }` → `ResolveError::PdsUnreachable`
- `NetworkError { message }` / `InvalidResponse { message }` → `ResolveError::NetworkError { message }`

The Tauri command signature:

```rust
#[tauri::command]
pub async fn resolve_identity(
    state: tauri::State<'_, crate::oauth::AppState>,
    handle_or_did: String,
) -> Result<IdentityInfo, ResolveError> {
    // ...
}
```

**Testing:**
Tests must verify AC4.1:
- plc-key-management.AC4.1: resolve_identity returns correct IdentityInfo including current rotation keys and PDS URL

Specific test cases:
1. **Handle input → correct IdentityInfo:** Mock DNS/HTTP handle resolution returning a DID, mock plc.directory returning a DID doc with known rotation keys and PDS service. Assert returned `IdentityInfo` has correct `did`, `handle`, `pds_url`, `current_rotation_keys`, and `device_key_is_root: false` (unregistered DID).
2. **DID input → skips handle resolution:** Pass a `did:plc:...` string directly. Mock only plc.directory. Assert correct IdentityInfo without handle resolution mock being hit.
3. **Handle not found → ResolveError::HandleNotFound:** Mock both DNS and HTTP fallback to fail. Assert `HandleNotFound` error code.
4. **DID not found → ResolveError::DidNotFound:** Mock plc.directory to return 404. Assert `DidNotFound` error code.

Follow existing pds_client.rs test patterns: `#[tokio::test]` with `httpmock::MockServer`, `PdsClient::new_for_test(mock_server.base_url())`.

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- claim`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement resolve_identity command (AC4.1)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Serialization tests for claim types

**Verifies:** None (infrastructure — ensures IPC contract correctness)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs` (add `#[cfg(test)]` module)

**Implementation:**

Add serialization tests following the pattern in `lib.rs` (60+ serialization tests). Each test constructs a Rust type, serializes to `serde_json::Value`, and asserts field names and values match the TypeScript IPC contract.

Tests to write:
1. **IdentityInfo serializes camelCase:** Assert `pdsUrl` (not `pds_url`), `currentRotationKeys`, `deviceKeyIsRoot`
2. **VerifiedClaimOp serializes camelCase:** Assert `signedOp`, `diff`, `warnings`
3. **OpDiff serializes camelCase:** Assert `addedKeys`, `removedKeys`, `changedServices`, `prevCid`
4. **ServiceChange serializes camelCase:** Assert `changeType`, `oldEndpoint`, `newEndpoint`
5. **ClaimResult serializes camelCase:** Assert `updatedDidDoc`
6. **ResolveError::HandleNotFound serializes correctly:** Assert `{"code": "HANDLE_NOT_FOUND"}`
7. **ResolveError::NetworkError serializes correctly:** Assert `{"code": "NETWORK_ERROR", "message": "..."}`
8. **ClaimError::VerificationFailed serializes correctly:** Assert `{"code": "VERIFICATION_FAILED", "message": "..."}`
9. **ClaimError::InvalidToken serializes correctly:** Assert `{"code": "INVALID_TOKEN"}`
10. **ClaimError::PlcDirectoryError serializes correctly:** Assert `{"code": "PLC_DIRECTORY_ERROR", "message": "..."}`

Follow the exact pattern from `lib.rs` tests (e.g., `error_expired_code_serializes_correctly`).

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- claim`
Expected: All tests pass

**Commit:** `test(identity-wallet): add serialization tests for claim types`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
