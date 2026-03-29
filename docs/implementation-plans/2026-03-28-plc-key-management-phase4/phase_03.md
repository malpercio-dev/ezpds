# Claim Flow Backend — Phase 3: sign_and_verify_claim

**Goal:** Implement the core claim verification command — call `signPlcOperation` on the old PDS, then verify the returned signed operation locally using the crypto crate before allowing submission.

**Architecture:** `sign_and_verify_claim` coordinates three systems: (1) old PDS via XRPC for the signed operation, (2) plc.directory for the current audit log, and (3) the crypto crate for local verification. The local verification ensures the wallet never submits an operation it hasn't inspected. A new `fetch_audit_log` method on `PdsClient` fetches the audit log. Diffs between the proposed operation and the current DID document are computed to produce an `OpDiff` for the frontend.

**Tech Stack:** Rust, serde, crypto crate (verify_plc_operation, parse_audit_log), tokio

**Scope:** 4 phases from design Phase 4 (this is phase 3 of 4)

**Codebase verified:** 2026-03-28

**Prerequisite:** This phase depends on `crypto::build_did_plc_rotation_op` and `crypto::verify_plc_operation` from design Phase 1 (already implemented in `crates/crypto/src/plc.rs`). Tests in this phase use `build_did_plc_rotation_op` to construct valid/invalid mock PLC operations for verification testing.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC4: Claim flow executes end-to-end
- **plc-key-management.AC4.3 Success:** `sign_and_verify_claim` returns a verified operation with the device key at `rotationKeys[0]`
- **plc-key-management.AC4.4 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when the old PDS returns an operation with a different key at `rotationKeys[0]`
- **plc-key-management.AC4.5 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when `prev` does not chain from the current audit log
- **plc-key-management.AC4.6 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when unexpected keys or services are altered
- **plc-key-management.AC4.7 Success:** `sign_and_verify_claim` populates `warnings` for non-blocking concerns (e.g., old PDS added an extra service)
- **plc-key-management.AC4.10 Failure:** `sign_and_verify_claim` returns `INVALID_TOKEN` when the email verification token is wrong

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add fetch_audit_log to PdsClient

**Verifies:** None (infrastructure — enables prev chain verification)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs`

**Implementation:**

Add a method to `PdsClient` that fetches the audit log from plc.directory:

```rust
/// Fetch the PLC operation audit log for a DID.
///
/// Calls `GET {plc_directory_url}/{did}/log/audit` and returns the raw JSON string.
pub async fn fetch_audit_log(&self, did: &str) -> Result<String, PdsClientError> {
    let url = format!("{}/{}/log/audit", self.plc_directory_url, did);
    let resp = self.client.get(&url).send().await
        .map_err(|e| PdsClientError::NetworkError { message: e.to_string() })?;
    if !resp.status().is_success() {
        return Err(PdsClientError::DidNotFound);
    }
    resp.text().await
        .map_err(|e| PdsClientError::NetworkError { message: e.to_string() })
}
```

Add a test:
- Mock `GET /{did}/log/audit` returning a JSON array of audit entries. Assert the method returns the raw JSON string.

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- pds_client::tests::audit`
Expected: Test passes

**Commit:** `feat(identity-wallet): add fetch_audit_log to PdsClient`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement sign_and_verify_claim command with tests

**Verifies:** plc-key-management.AC4.3, plc-key-management.AC4.4, plc-key-management.AC4.5, plc-key-management.AC4.6, plc-key-management.AC4.7, plc-key-management.AC4.10

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs`

**Implementation:**

Add `sign_and_verify_claim` Tauri command. Extract testable core logic into a helper function:

```rust
pub(crate) async fn sign_and_verify_claim_impl(
    pds_client: &PdsClient,
    claim_state: &ClaimState,
    device_key_id: &str,
    token: &str,
) -> Result<(VerifiedClaimOp, String), ClaimError>
```

The function performs these steps:

**Step 1: Get recommended credentials from old PDS**
- Call `pds_client::get_recommended_did_credentials(oauth_client)` using the `pds_oauth_client` from `ClaimState`.
- This returns the PDS's recommended `rotation_keys`, `also_known_as`, `verification_methods`, `services`.

**Step 2: Build the sign request**
- Construct `SignPlcOperationRequest` with:
  - `token`: the email verification token from the user
  - `rotation_keys`: `Some(vec![device_key_id, ...recommended.rotation_keys])` — device key prepended at position [0]
  - `also_known_as`: from recommended credentials (keep existing)
  - `verification_methods`: from recommended credentials (keep existing)
  - `services`: from recommended credentials (keep existing)

**Step 3: Call signPlcOperation on old PDS**
- Call `pds_client::sign_plc_operation(oauth_client, &request)`.
- On error: inspect the HTTP error. If the PDS returns a 400-level error indicating an invalid token (check response body for `"InvalidToken"` or `"ExpiredToken"` error strings), return `ClaimError::InvalidToken`. Otherwise return `ClaimError::NetworkError`.
- On success: get `SignPlcOperationResponse.operation` (a `serde_json::Value`).

**Step 4: Serialize operation for verification**
- Convert to JSON string: `serde_json::to_string(&response.operation)`.

**Step 5: Fetch current audit log**
- Call `pds_client.fetch_audit_log(&claim_state.did)`.
- Parse via `crypto::parse_audit_log(&log_json)`.
- Get the last entry's CID as `expected_prev`.

**Step 6: Verify operation signature**
- Build authorized rotation keys from the current DID document: `claim_state.did_doc.rotation_keys.iter().map(|k| crypto::DidKeyUri(k.clone())).collect()`.
- Call `crypto::verify_plc_operation(&op_json_str, &authorized_keys)`.
- On `CryptoError`: return `ClaimError::VerificationFailed { message }`.
- On success: get `VerifiedPlcOp`.

**Step 7: Local verification checks**

Check 1 — **rotationKeys[0] is our device key** (AC4.3, AC4.4):
```rust
if verified_op.rotation_keys.first() != Some(&device_key_id.to_string()) {
    return Err(ClaimError::VerificationFailed {
        message: format!(
            "Expected device key at rotationKeys[0], found: {:?}",
            verified_op.rotation_keys.first()
        ),
    });
}
```

Check 2 — **prev chains correctly** (AC4.5):
```rust
match (&verified_op.prev, expected_prev.as_deref()) {
    (Some(op_prev), Some(expected)) if op_prev == expected => { /* OK */ }
    (prev, expected) => {
        return Err(ClaimError::VerificationFailed {
            message: format!(
                "prev mismatch: operation has {:?}, expected {:?}",
                prev, expected
            ),
        });
    }
}
```

Check 3 — **no unexpected key mutations** (AC4.6):
Compare `verified_op.rotation_keys[1..]` against `claim_state.did_doc.rotation_keys`. Any key removed from the original set (other than natural reordering from our key insertion) is an error.

Check 4 — **no unexpected service mutations** (AC4.6):
Compare `verified_op.services` against `claim_state.did_doc.services`. Any service endpoint changed or service removed from the original set is an error.

**Type conversion note:** `verified_op.services` is `BTreeMap<String, crypto::PlcService>` (from the crypto crate), while `claim_state.did_doc.services` is `HashMap<String, pds_client::PlcService>` (from pds_client). Both `PlcService` types have identical fields (`service_type: String`, `endpoint: String`). Compare by iterating the maps and matching on `service_type` and `endpoint` field values rather than comparing the types directly.

**Step 8: Compute diff and warnings**

Build `OpDiff`:
- `added_keys`: keys in `verified_op.rotation_keys` not in `did_doc.rotation_keys` (should be just our device key)
- `removed_keys`: keys in `did_doc.rotation_keys` not in `verified_op.rotation_keys`
- `changed_services`: compare services maps — identify added, removed, modified services → `Vec<ServiceChange>`
- `prev_cid`: `verified_op.prev.unwrap_or_default()`

Build `warnings: Vec<String>` (AC4.7):
- If the PDS added an extra service not in the original DID doc → add warning like `"Old PDS added service: {id}"`
- If the PDS added extra `also_known_as` entries → add warning
- These are non-blocking (not errors) because PDS may legitimately add auxiliary services.

**Step 9: Store verified operation**
- Store the signed operation JSON string in `ClaimState.verified_signed_op` for `submit_claim`.
- Return `VerifiedClaimOp { diff, signed_op: op_json_str, warnings }`.

The Tauri command wrapper:

```rust
#[tauri::command]
pub async fn sign_and_verify_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    token: String,
) -> Result<VerifiedClaimOp, ClaimError>
```

**Testing:**

Each test sets up a `httpmock::MockServer` mocking both the PDS XRPC endpoints and plc.directory audit log. Create a test helper that builds a valid signed PLC rotation operation using the crypto crate's `build_did_plc_rotation_op` with a test keypair.

Tests must verify each AC listed above:

1. **AC4.3 — success path:** Mock PDS returning a valid signed operation with test device key at `rotationKeys[0]`. Mock plc.directory audit log with matching `prev`. Assert returns `VerifiedClaimOp` with correct `diff.addedKeys` containing the device key.

2. **AC4.4 — wrong key at rotationKeys[0]:** Mock PDS returning operation with a DIFFERENT key at `rotationKeys[0]`. Assert `ClaimError::VerificationFailed` with message about wrong key.

3. **AC4.5 — prev chain mismatch:** Mock PDS returning operation with `prev` CID that doesn't match the last audit log entry's CID. Assert `ClaimError::VerificationFailed` with message about prev mismatch.

4. **AC4.6 — unexpected key removal:** Mock PDS returning operation that removes a rotation key from the original set. Assert `ClaimError::VerificationFailed`.

5. **AC4.6 — unexpected service change:** Mock PDS returning operation that changes an existing service endpoint. Assert `ClaimError::VerificationFailed`.

6. **AC4.7 — warnings for benign additions:** Mock PDS returning operation that adds an extra service not in original DID doc. Assert success with `warnings` non-empty.

7. **AC4.10 — invalid token:** Mock PDS returning 400 error for signPlcOperation. Assert `ClaimError::InvalidToken`.

Follow existing test patterns: `#[tokio::test]`, `httpmock::MockServer`, test helper functions for constructing mock PLC operations using the crypto crate.

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- claim::tests::sign_and_verify`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement sign_and_verify_claim with local verification (AC4.3-AC4.7, AC4.10)`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
