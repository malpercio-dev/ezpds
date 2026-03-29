# Human Test Plan: PLC Key Management Phase 4 — Claim Flow Backend

## Prerequisites

- macOS with Xcode and iOS Simulator installed
- Nix dev shell active (`nix develop --impure --accept-flake-config` from workspace root)
- `pnpm install` completed in `apps/identity-wallet/`
- `cargo tauri ios init` completed with PATH and sandbox patches applied (see `apps/identity-wallet/CLAUDE.md` First-Time Setup)
- All automated tests passing:
  ```bash
  cargo test -p identity-wallet -- claim
  cargo test -p identity-wallet -- pds_client::tests::audit
  cargo test -p identity-wallet -- pds_client::tests::post_plc
  ```
- A **test Bluesky account** (not a production identity) with:
  - A known handle (e.g., `test-claim.bsky.social`)
  - Access to the registered email address (for receiving the verification code)
  - The account hosted on a PDS that supports `requestPlcOperationSignature` (e.g., bsky.social)

## Phase 1: Identity Resolution

| Step | Action | Expected |
|------|--------|----------|
| 1.1 | Launch the app in iOS Simulator via `cargo tauri ios dev`. Navigate to the claim flow entry point. | App launches successfully; claim flow screen is presented. |
| 1.2 | Enter the test account's handle (e.g., `test-claim.bsky.social`) into the identity input field and submit. | The app resolves the handle, displays the DID (`did:plc:...`), the handle, the PDS URL, and the current rotation keys. No error banner appears. |
| 1.3 | Go back and enter the test account's DID directly (e.g., `did:plc:abc123`) into the identity input field and submit. | The app skips handle resolution, fetches the DID document from plc.directory, and displays the same identity info as step 1.2. |
| 1.4 | Enter a nonexistent handle (e.g., `this-handle-definitely-does-not-exist-12345.test`) and submit. | The app displays a `HANDLE_NOT_FOUND` error message. No crash, no unhandled exception in the Tauri console log. |
| 1.5 | Enter a nonexistent DID (e.g., `did:plc:zzzzzzzzzzzzzzzzzzzzzzzz`) and submit. | The app displays a `DID_NOT_FOUND` error message. |

## Phase 2: PDS Authentication

| Step | Action | Expected |
|------|--------|----------|
| 2.1 | Continue from step 1.2 (resolved identity displayed). Tap the button to authenticate with the old PDS. | Safari opens to the PDS's OAuth authorization page. |
| 2.2 | Complete OAuth login in Safari (enter credentials for the test account). | Safari redirects back to the app via deep-link. The app receives the callback and transitions to the email verification screen. Check Tauri console for `pds_auth_ready` event. |

## Phase 3: Email Verification Request (AC4.2)

| Step | Action | Expected |
|------|--------|----------|
| 3.1 | On the email verification screen, tap "Send code" (or equivalent button that triggers `requestClaimVerification`). | No error appears in the app UI. Check the Tauri console log for a successful POST to `/xrpc/com.atproto.identity.requestPlcOperationSignature`. |
| 3.2 | Check the email inbox for the test account's registered email address. | A verification email arrives from the PDS containing a numeric or alphanumeric token/code. |
| 3.3 | Verify that tapping "Send code" again does not produce an error (idempotent). | A second verification email may arrive; no error in the UI or console. |

## Phase 4: Sign and Verify Claim (AC4.3, AC4.10)

| Step | Action | Expected |
|------|--------|----------|
| 4.1 | Enter the verification token from the email into the token input field and submit. | The app calls `signAndVerifyClaim`. A review screen appears showing: the device's `did:key` URI as an added rotation key, the `prevCid`, and any warnings. No `VERIFICATION_FAILED` or `INVALID_TOKEN` error. |
| 4.2 | Verify the review screen content: inspect `diff.addedKeys`. | The device key's `did:key` URI appears in the added keys list. |
| 4.3 | Verify `diff.prevCid` is a non-empty CID string (starts with `bag` or `baf`). | The `prevCid` field is populated and looks like a valid CID. |
| 4.4 | Verify `diff.removedKeys` is empty (claim-only flow should not remove any existing rotation keys). | No keys appear in the removed keys section. |
| 4.5 | Verify `diff.changedServices` is empty (claim-only flow should not alter services). | No service changes appear. |
| 4.6 | If `warnings` is non-empty, review each warning. | Warnings describe benign additions (e.g., PDS adding extra services) -- not blocking errors. |
| 4.7 | (Negative test) Go back, enter an incorrect token (e.g., `000000`), and submit. | The app displays an `INVALID_TOKEN` error. The review screen does not appear. |

## Phase 5: Submit Claim (AC4.8)

| Step | Action | Expected |
|------|--------|----------|
| 5.1 | From the review screen (step 4.1), tap "Confirm" to submit the claim. | The app calls `submitClaim`. A success screen appears with the updated DID document. |
| 5.2 | On the success screen, verify the updated DID document shows the device key in `rotationKeys`. | The device's `did:key` URI appears as `rotationKeys[0]` in the displayed document. |
| 5.3 | Open a browser and navigate to `https://plc.directory/{did}` (using the test account's DID). | The DID document JSON shows `rotationKeys[0]` is the device's `did:key` URI. |
| 5.4 | Navigate to `https://plc.directory/{did}/log/audit` in the browser. | The audit log shows a new entry at the end with the rotation operation. The `prev` field in the newest entry matches the CID of the second-to-last entry. |
| 5.5 | Force-quit and restart the app in the Simulator. | The app loads, and the claimed identity appears in the identity list (persisted via IdentityStore to Keychain). |

## End-to-End: Complete Claim Flow

**Purpose:** Validates that all 5 commands execute in sequence without state corruption, from handle resolution through plc.directory submission.

1. Launch fresh app (clear Keychain test data if needed via Simulator reset).
2. Configure relay URL on the RelayConfigScreen.
3. Navigate to claim flow.
4. Enter test handle, submit. Verify identity info screen appears (Phase 1).
5. Tap "Authenticate with PDS". Complete OAuth in Safari. Verify deep-link callback returns to app (Phase 2).
6. Tap "Send code". Wait for verification email (Phase 3).
7. Enter token from email. Verify review screen shows correct diff (Phase 4).
8. Tap "Confirm". Verify success screen and plc.directory update (Phase 5).
9. Restart app. Verify identity persists.
10. Check Tauri console throughout for unexpected errors or warnings.

## End-to-End: Claim Flow Retry After PLC Directory Rejection

**Purpose:** Validates that `ClaimState` is preserved on failure, allowing retry without restarting the entire flow.

1. Begin a claim flow through step 4.1 (review screen visible).
2. While the review screen is displayed, use a separate tool (e.g., `curl`) to submit a conflicting PLC operation for the same DID to plc.directory (simulating a race condition).
3. Tap "Confirm" on the review screen.
4. Verify `PLC_DIRECTORY_ERROR` is displayed with the rejection message.
5. Verify the app allows going back to re-enter the verification token and re-submit (the claim state was not cleared on failure).

## Human Verification Required

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| AC4.2: Live PDS XRPC round-trip | OAuth tokens from Safari deep-link are unavailable in `cargo test`; automated tests mock the PDS with httpmock. | Steps 3.1-3.2 |
| AC4.3: Live PDS operation structure | Mock PLC operations may differ subtly from live PDS output. | Steps 4.1-4.6 |
| AC4.8: Live plc.directory submission | Automated tests mock plc.directory; real submission permanently mutates the DID's state. | Steps 5.1-5.5 |
| AC4.2 (guard): No claim state Unauthorized | The `_impl` test pattern cannot exercise the Tauri command wrapper's `claim_state.is_none()` guard. | Implicit in Phase 3: if `requestClaimVerification` is called before `resolveIdentity`, the app shows Unauthorized. |

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC4.1: `resolve_identity` returns correct `IdentityInfo` | `test_resolve_identity_handle_input_builds_correct_response` | 1.2 |
| AC4.1: DID input skips handle resolution | `test_resolve_identity_did_input_skips_handle_resolution` | 1.3 |
| AC4.1: `HandleNotFound` on failed resolution | `test_resolve_identity_handle_not_found_returns_error` | 1.4 |
| AC4.1: `DidNotFound` on plc.directory 404 | `test_resolve_identity_did_not_found_returns_error` | 1.5 |
| AC4.2: Calls `requestPlcOperationSignature` on old PDS | `test_request_claim_verification_success` | 3.1, 3.2 |
| AC4.2: Unauthorized when no OAuth client | `test_request_claim_verification_unauthorized_no_oauth_client` | -- |
| AC4.2: `NetworkError` on PDS 500 | `test_request_claim_verification_pds_returns_500` | -- |
| AC4.3: Device key at `rotationKeys[0]` | `test_sign_and_verify_claim_success` | 4.1, 4.2 |
| AC4.4: `VERIFICATION_FAILED` wrong key at [0] | `test_sign_and_verify_claim_wrong_key_at_rotation_keys_0` | -- |
| AC4.5: `VERIFICATION_FAILED` prev chain mismatch | `test_sign_and_verify_claim_prev_mismatch` | -- |
| AC4.6: `VERIFICATION_FAILED` unexpected key removal | `test_sign_and_verify_claim_unexpected_key_removal` | -- |
| AC4.6: `VERIFICATION_FAILED` unexpected service change | `test_sign_and_verify_claim_unexpected_service_change` | -- |
| AC4.7: Warnings for benign additions | `test_sign_and_verify_claim_warnings_for_added_service` | 4.6 |
| AC4.8: `submit_claim` POSTs and persists | `test_submit_claim_success` | 5.1-5.5 |
| AC4.9: `PLC_DIRECTORY_ERROR` on rejection | `test_submit_claim_plc_directory_error` | -- |
| AC4.10: `INVALID_TOKEN` on wrong token | `test_sign_and_verify_claim_invalid_token` | 4.7 |
