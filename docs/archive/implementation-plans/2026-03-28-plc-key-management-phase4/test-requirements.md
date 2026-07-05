# Test Requirements: PLC Key Management Phase 4

Phase 4 covers **plc-key-management.AC4: Claim flow executes end-to-end** (AC4.1 through AC4.10). All automated tests live in colocated `#[cfg(test)]` modules within the source files. Tests use `#[tokio::test]`, `httpmock::MockServer` for HTTP mocking, and the in-memory Keychain test double from `keychain.rs`.

## Automated Test Coverage

| AC | Description | Test Type | Test Location | Test Name Pattern |
|----|------------|-----------|---------------|-------------------|
| AC4.1 | `resolve_identity` returns correct `IdentityInfo` including current rotation keys and PDS URL | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_identity_handle_returns_correct_info` |
| AC4.1 | `resolve_identity` with DID input skips handle resolution | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_identity_did_input_skips_handle_resolution` |
| AC4.1 | `resolve_identity` returns `HandleNotFound` when resolution fails | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_identity_handle_not_found` |
| AC4.1 | `resolve_identity` returns `DidNotFound` when plc.directory 404s | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_identity_did_not_found` |
| AC4.2 | `request_claim_verification` calls `requestPlcOperationSignature` on the old PDS | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_request_claim_verification_calls_xrpc` |
| AC4.2 | `request_claim_verification` returns `Unauthorized` when no claim state exists | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_request_claim_verification_no_claim_state` |
| AC4.2 | `request_claim_verification` returns `Unauthorized` when no OAuth client exists | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_request_claim_verification_no_oauth_client` |
| AC4.2 | `request_claim_verification` returns `NetworkError` when PDS returns 500 | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_request_claim_verification_pds_error` |
| AC4.3 | `sign_and_verify_claim` returns a verified operation with the device key at `rotationKeys[0]` | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_success` |
| AC4.4 | `sign_and_verify_claim` returns `VERIFICATION_FAILED` when a different key is at `rotationKeys[0]` | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_wrong_key_at_position_zero` |
| AC4.5 | `sign_and_verify_claim` returns `VERIFICATION_FAILED` when `prev` does not chain from the current audit log | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_prev_chain_mismatch` |
| AC4.6 | `sign_and_verify_claim` returns `VERIFICATION_FAILED` when unexpected keys are removed | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_unexpected_key_removal` |
| AC4.6 | `sign_and_verify_claim` returns `VERIFICATION_FAILED` when unexpected services are altered | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_unexpected_service_change` |
| AC4.7 | `sign_and_verify_claim` populates `warnings` for non-blocking concerns | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_warnings_for_benign_additions` |
| AC4.8 | `submit_claim` POSTs the signed operation to plc.directory and persists the identity to IdentityStore | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_submit_claim_success` |
| AC4.9 | `submit_claim` returns `PLC_DIRECTORY_ERROR` when plc.directory rejects the operation | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_submit_claim_plc_directory_rejects` |
| AC4.10 | `sign_and_verify_claim` returns `INVALID_TOKEN` when the email verification token is wrong | Integration | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_sign_and_verify_claim_invalid_token` |

### Supplementary Tests (infrastructure, not tied to a specific AC)

| Description | Test Type | Test Location | Test Name Pattern |
|------------|-----------|---------------|-------------------|
| `IdentityInfo` serializes with camelCase field names | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_identity_info_serializes_camel_case` |
| `VerifiedClaimOp` serializes with camelCase field names | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_verified_claim_op_serializes_camel_case` |
| `OpDiff` serializes with camelCase field names | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_op_diff_serializes_camel_case` |
| `ServiceChange` serializes with camelCase field names | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_service_change_serializes_camel_case` |
| `ClaimResult` serializes with camelCase field names | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_claim_result_serializes_camel_case` |
| `ResolveError::HandleNotFound` serializes to `{"code":"HANDLE_NOT_FOUND"}` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_error_handle_not_found_serializes` |
| `ResolveError::NetworkError` serializes to `{"code":"NETWORK_ERROR","message":"..."}` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_resolve_error_network_error_serializes` |
| `ClaimError::VerificationFailed` serializes to `{"code":"VERIFICATION_FAILED","message":"..."}` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_claim_error_verification_failed_serializes` |
| `ClaimError::InvalidToken` serializes to `{"code":"INVALID_TOKEN"}` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_claim_error_invalid_token_serializes` |
| `ClaimError::PlcDirectoryError` serializes to `{"code":"PLC_DIRECTORY_ERROR","message":"..."}` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_claim_error_plc_directory_error_serializes` |
| `submit_claim` returns `Unauthorized` when `verified_signed_op` is `None` | Unit | `apps/identity-wallet/src-tauri/src/claim.rs` `#[cfg(test)]` | `test_submit_claim_no_verified_op` |
| `fetch_audit_log` returns raw JSON from plc.directory | Integration | `apps/identity-wallet/src-tauri/src/pds_client.rs` `#[cfg(test)]` | `test_fetch_audit_log_success` |
| `post_plc_operation` POSTs operation and returns Ok on 200 | Integration | `apps/identity-wallet/src-tauri/src/pds_client.rs` `#[cfg(test)]` | `test_post_plc_operation_success` |
| `post_plc_operation` returns error with body on rejection (409) | Integration | `apps/identity-wallet/src-tauri/src/pds_client.rs` `#[cfg(test)]` | `test_post_plc_operation_rejected` |

## Human Verification

| AC | Description | Why Not Automated | Verification Approach |
|----|------------|-------------------|----------------------|
| AC4.2 | `request_claim_verification` calls `requestPlcOperationSignature` on the old PDS (live PDS round-trip) | The XRPC call to a live PDS (e.g., bsky.social) requires real OAuth tokens obtained via Safari deep-link, which is unavailable in `cargo test`. The automated test mocks the PDS with httpmock. | 1. Build and run on an iOS simulator or device. 2. Complete the claim flow through PDS auth (OAuth via Safari). 3. On the email verification screen, tap "Send code." 4. Confirm the PDS sends a verification email to the account's registered address. 5. Confirm no errors appear in the Tauri console log. |
| AC4.3 | `sign_and_verify_claim` returns a verified operation with the device key at `rotationKeys[0]` (live PDS) | The automated test constructs mock PLC operations using the crypto crate. A live PDS (bsky.social) may produce operation structures with subtle differences from the mock (field ordering, extra fields, PDS-specific key formats). | 1. Continue from AC4.2 verification. 2. Enter the verification token received by email. 3. Confirm the review screen shows the device key as the first added rotation key. 4. Confirm `diff.addedKeys` on the review screen contains the device's `did:key` URI. 5. Confirm `diff.prevCid` is non-empty. |
| AC4.8 | `submit_claim` POSTs the signed operation to plc.directory and persists the identity (live plc.directory) | Automated tests mock plc.directory. Verifying that plc.directory accepts a real signed operation and that the DID document updates correctly requires submitting to the live service, which permanently mutates the DID's state. | 1. **Use a test DID** (not a production identity). 2. Continue from AC4.3 verification. 3. Tap "Confirm" on the review screen. 4. Confirm success screen appears with updated DID document. 5. Verify at `https://plc.directory/{did}` that `rotationKeys[0]` is the device key. 6. Verify `https://plc.directory/{did}/log/audit` shows the new operation. 7. Restart the app and confirm the identity appears in the identity list. |

## Test Implementation Notes

### Test helpers and shared fixtures

- **`ClaimState` construction:** Tests for `request_claim_verification_impl`, `sign_and_verify_claim_impl`, and `submit_claim_impl` all need a `ClaimState` with varying levels of completeness. Create a helper function like `make_test_claim_state(mock_server: &MockServer) -> ClaimState` that builds a fully populated state, and let individual tests override fields (e.g., set `pds_oauth_client` to `None` for unauthorized tests).

- **Mock PLC operations:** Tests for AC4.3 through AC4.7 need valid signed PLC operations as mock PDS responses. Use `crypto::build_did_plc_rotation_op` with a test P-256 keypair to construct operations. This ensures the crypto crate's own verification accepts them, isolating the test to the claim module's logic (key position checks, prev chain validation, service mutation detection).

- **`OAuthClient::new_for_test(base_url)`:** The existing test constructor on `OAuthClient` creates a client pointing at an httpmock server. Use this for all tests that need an authenticated PDS client in `ClaimState.pds_oauth_client`.

- **`PdsClient::new_for_test(base_url)`:** The existing test constructor sets both the PDS base URL and the plc.directory URL to the mock server. Tests that need different URLs for PDS vs. plc.directory may need two mock servers or conditional URL routing via mock path patterns.

- **In-memory Keychain:** The `#[cfg(test)]` Keychain implementation in `keychain.rs` uses a thread-local `HashMap`. `submit_claim` tests that verify IdentityStore persistence automatically use this in-memory backend. Call `keychain::tests::clear_test_keychain()` in test setup if isolation between tests is needed.

### Testable core logic pattern

Each Tauri command extracts its core logic into a `_impl` helper that takes explicit parameters instead of `tauri::State`. This avoids constructing a full Tauri app context in tests:

- `resolve_identity` -> core logic tested directly by constructing `PdsClient::new_for_test()` and calling the helper with mock server URLs
- `request_claim_verification_impl(claim_state)` -> takes a `&ClaimState` reference
- `sign_and_verify_claim_impl(pds_client, claim_state, device_key_id, token)` -> takes all dependencies explicitly
- `submit_claim_impl(pds_client, claim_state)` -> takes PDS client and claim state

### Test execution

```bash
# Run all Phase 4 claim tests
cargo test -p identity-wallet-tauri -- claim

# Run specific AC group
cargo test -p identity-wallet-tauri -- claim::tests::resolve_identity
cargo test -p identity-wallet-tauri -- claim::tests::request_claim
cargo test -p identity-wallet-tauri -- claim::tests::sign_and_verify
cargo test -p identity-wallet-tauri -- claim::tests::submit

# Run PdsClient infrastructure tests added in Phase 4
cargo test -p identity-wallet-tauri -- pds_client::tests::audit
cargo test -p identity-wallet-tauri -- pds_client::tests::post_plc
```
