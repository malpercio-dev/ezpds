# MM-146 Test Requirements

Maps every acceptance criterion from the MM-146 design plan to either an automated test or a documented human verification step. Rationalized against implementation decisions made during phase planning.

---

## Automated Tests

### MM-146.AC1: GET /v1/relay/keys returns active signing key

All AC1 criteria are covered by integration tests in Phase 1, Task 3. Tests use `test_state()` (in-memory SQLite) and axum's `oneshot()` to exercise the full handler stack without a running server.

| Criterion | Test Type | Test File | Test Function | Run Command |
|---|---|---|---|---|
| **AC1.1** Returns 200 with `{ keyId, publicKey, algorithm }` when a signing key is provisioned | Integration | `crates/relay/src/routes/get_relay_signing_key.rs` | `get_relay_keys_returns_200_with_active_key` | `cargo test -p relay get_relay` |
| **AC1.2** Returns the most recently created key when multiple keys exist | Integration | `crates/relay/src/routes/get_relay_signing_key.rs` | `get_relay_keys_returns_most_recently_created_key` | `cargo test -p relay get_relay` |
| **AC1.3** Returns 503 when no signing key is provisioned | Integration | `crates/relay/src/routes/get_relay_signing_key.rs` | `get_relay_keys_returns_503_when_no_key_provisioned` | `cargo test -p relay get_relay` |
| **AC1.4** Endpoint requires no authentication (public, no Bearer token) | Integration | `crates/relay/src/routes/get_relay_signing_key.rs` | `get_relay_keys_requires_no_authentication` | `cargo test -p relay get_relay` |

**Implementation rationale:** These are standard axum handler integration tests following the pattern established by `create_signing_key.rs` and other route files. Each test inserts test data directly via sqlx and sends a request through the full router. AC1.4 is verified by the absence of an Authorization header in the request builder (`get_keys()` sends no auth header) combined with an assertion that the response is 200, not 401.

---

### MM-146.AC2: build_did_plc_genesis_op_with_external_signer produces valid genesis op

All AC2 criteria are covered by unit tests in Phase 2, Task 4. Tests are appended to the existing `#[cfg(test)] mod tests` block in `plc.rs`. These are pure function tests with no I/O.

| Criterion | Test Type | Test File | Test Function | Run Command |
|---|---|---|---|---|
| **AC2.1** Callback receives CBOR-encoded unsigned op bytes; returned `PlcGenesisOp` passes `verify_genesis_op` | Unit | `crates/crypto/src/plc.rs` | `external_signer_callback_produces_valid_genesis_op` | `cargo test -p crypto` |
| **AC2.2** Callback returning `Err` propagates as `CryptoError::PlcOperation` | Unit | `crates/crypto/src/plc.rs` | `external_signer_callback_error_propagates_as_plc_operation` | `cargo test -p crypto` |
| **AC2.3** Existing `build_did_plc_genesis_op` (now a wrapper) produces identical output to before | Unit (existing) | `crates/crypto/src/plc.rs` | *(all pre-existing tests in mod tests)* | `cargo test -p crypto` |

**Implementation rationale:** AC2.1 generates a real P-256 keypair, passes a signing callback that uses the private key, and then verifies the resulting genesis op via `verify_genesis_op` -- the same verification function used in production. AC2.2 passes a callback that returns `Err(CryptoError::PlcOperation(...))` and asserts the error propagates unchanged. AC2.3 requires no new test code: the existing tests for `build_did_plc_genesis_op` exercise the refactored wrapper path implicitly. If the wrapper delegation introduces a regression, those existing tests fail.

---

### MM-146.AC3: perform_did_ceremony completes the full ceremony (partial automated coverage)

AC3 criteria are split between automated serialization tests and human verification. The `perform_did_ceremony` Tauri command orchestrates Keychain (Apple system API), Secure Enclave (hardware), and HTTP calls to a real relay. These I/O boundaries cannot be meaningfully mocked in `cargo test` because:

1. Keychain APIs (`Security.framework`) require a running app context with entitlements.
2. Secure Enclave signing (`device_key::sign`) requires physical or simulated Apple hardware.
3. The `RelayClient` uses a compile-time `LazyLock<RelayClient>` singleton -- no dependency injection seam exists to substitute a mock HTTP client, and introducing one would add complexity beyond the scope of this feature.

Phase 3, Task 3 explicitly acknowledges this gap and provides serialization-contract tests as the automated layer.

| Criterion | Test Type | Test File | Test Function | Run Command |
|---|---|---|---|---|
| **AC3.4** `NoRelaySigningKey` serializes as `{ code: "NO_RELAY_SIGNING_KEY" }` | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_no_relay_signing_key_serializes_correctly` | `cargo test -p identity-wallet` |
| **AC3.5** `RelayKeyFetchFailed` serializes correctly | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_relay_key_fetch_failed_serializes_correctly` | `cargo test -p identity-wallet` |
| **AC3.6** `SigningFailed` serializes correctly | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_signing_failed_serializes_correctly` | `cargo test -p identity-wallet` |
| **AC3.7** `DidCreationFailed` serializes correctly | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_did_creation_failed_serializes_correctly` | `cargo test -p identity-wallet` |
| *(supporting)* `DIDCeremonyResult` serializes `did` field in camelCase | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_result_serializes_did_in_camel_case` | `cargo test -p identity-wallet` |
| *(supporting)* `KeyNotFound` serializes correctly | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_key_not_found_serializes_correctly` | `cargo test -p identity-wallet` |
| *(supporting)* `KeychainError` serializes correctly | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_keychain_error_serializes_correctly` | `cargo test -p identity-wallet` |
| *(supporting)* `NetworkError` serializes with message field | Unit | `apps/identity-wallet/src-tauri/src/lib.rs` | `did_ceremony_error_network_error_serializes_with_message` | `cargo test -p identity-wallet` |

**Implementation rationale:** The 8 serde tests verify the contract between Rust and TypeScript. If a variant's serialized `code` string changes, the TypeScript `DIDCeremonyError.code` discriminated union in `ipc.ts` will silently fail to match it. These tests catch that at compile/test time. The behavioral outcomes (AC3.1 through AC3.3, and the runtime error paths of AC3.4 through AC3.7) require human verification on an iOS simulator -- see the next section.

---

## Human Verification

### MM-146.AC3: perform_did_ceremony behavioral outcomes

The following criteria require manual testing on an iOS Simulator (or device) with a running relay instance. They cannot be automated because they depend on Keychain persistence, Secure Enclave hardware signing, and live HTTP round-trips to a relay that has been provisioned with a signing key.

| Criterion | Verification Approach | Justification |
|---|---|---|
| **AC3.1** Given a valid pending session token and provisioned relay key, returns `DIDCeremonyResult { did }` with a valid `did:plc` identifier | **iOS Simulator end-to-end flow:** (1) Start a local relay with a provisioned signing key. (2) Launch the app on the iOS Simulator. (3) Complete the account creation flow (claim code, email, handle). (4) Observe that the DID ceremony screen transitions to the DID success screen. (5) Verify the displayed DID starts with `did:plc:` and is 32 characters long. | The Tauri command touches Keychain, SE, and HTTP in sequence. No mock seam exists for any of these in the current architecture. |
| **AC3.2** Keychain `"session-token"` is overwritten with the full session token from `POST /v1/dids` response | **Post-ceremony Keychain inspection:** After a successful ceremony in the simulator, use `security find-generic-password -s "ezpds-identity-wallet" -a "session-token" -w` in Terminal (or restart the app and verify it reads the upgraded token). Alternatively, add a temporary `tracing::info!` log in the `keychain::store_item` call and inspect Xcode console output. | Keychain writes require a running app with the correct entitlements. The value is set by `keychain::store_item`, which is an opaque `Security.framework` call. |
| **AC3.3** Keychain `"did"` is populated with the resulting DID | **Post-ceremony Keychain inspection:** Same approach as AC3.2, using key `"did"` instead of `"session-token"`. Verify the stored value matches the DID shown on the success screen. | Same justification as AC3.2. |
| **AC3.4** Returns `NoRelaySigningKey` when relay has no key (runtime behavior) | **iOS Simulator with empty relay:** (1) Start a local relay without provisioning a signing key. (2) Complete account creation. (3) Observe the DID ceremony screen shows the error message "The relay hasn't been configured yet. Please try again later." and a Retry button. | The serialization contract is tested automatically; this verifies the runtime HTTP 503 detection path. |
| **AC3.5** Returns `RelayKeyFetchFailed` when `GET /v1/relay/keys` is unreachable (runtime behavior) | **iOS Simulator with relay stopped:** (1) Complete account creation with relay running. (2) Stop the relay process. (3) Observe the DID ceremony screen shows "Couldn't reach the server. Check your connection." and a Retry button. | Requires actual network failure -- cannot be simulated in a unit test without an HTTP mock layer. |
| **AC3.6** Returns `SigningFailed` when SE signing fails (runtime behavior) | **Difficult to trigger intentionally.** SE signing failures are rare and hardware-dependent (e.g., key access revoked, biometric failure on a key with biometric policy). Verify indirectly: the error enum variant exists, serializes correctly (automated test), and the UI maps it to "Device signing failed. Please try again." (code review of `DIDCeremonyScreen.svelte`). | Secure Enclave failures cannot be reliably triggered in the simulator. The code path is verified via code review and the serialization unit test. |
| **AC3.7** Returns `DidCreationFailed` when `POST /v1/dids` returns non-2xx (runtime behavior) | **iOS Simulator with relay returning errors:** (1) Provision the relay signing key. (2) Start the ceremony. (3) Cause `POST /v1/dids` to fail (e.g., use an already-promoted session token, or modify the relay to return 400). (4) Observe the DID ceremony screen shows "Couldn't create your identity. Please try again." and a Retry button. | Requires a specific relay state that produces a non-2xx response. Could also be verified with a proxy (e.g., mitmproxy) that intercepts and returns an error. |

---

### MM-146.AC4: DID ceremony UI

No frontend test framework (Vitest, Playwright, etc.) is configured in the `apps/identity-wallet/` project. All UI criteria are verified manually on the iOS Simulator. The only automated frontend check is `pnpm check` (TypeScript/Svelte type-checking), which validates component props and IPC types at build time but does not render or interact with components.

| Criterion | Verification Approach | Justification |
|---|---|---|
| **AC4.1** App shows loading screen with status text while ceremony is in flight | **iOS Simulator observation:** (1) Launch the app and complete account creation. (2) Observe that a loading screen appears with the text "Setting up your identity..." while the ceremony network calls are in progress. For slow-network testing, use Network Link Conditioner on the simulator to add latency. | UI rendering requires the Tauri runtime and a mobile WebView. `LoadingScreen.svelte` is a pre-existing component; this test confirms it is wired up correctly with the `statusText` prop. |
| **AC4.2** On success, transitions to success screen showing truncated DID and a "Continue" button | **iOS Simulator observation:** (1) Complete a successful ceremony. (2) Verify the success screen appears with the heading "Identity Created!", a truncated DID in `did:plc:xxxxx...xxxx` format, and a "Continue" button. | Requires Tauri IPC round-trip to get a real DID and the Svelte rendering pipeline. |
| **AC4.3** On failure, shows inline error message and a Retry button (does not rewind to previous screen) | **iOS Simulator with relay stopped or unconfigured:** (1) Trigger a ceremony failure (e.g., relay not running). (2) Verify the error message appears inline (red text) with a Retry button. (3) Verify the app does NOT navigate back to the handle or account creation screen. | Tests the error UI path end-to-end including the `catch` block in `DIDCeremonyScreen.svelte`. |
| **AC4.4** Retry button re-invokes the ceremony from the beginning | **iOS Simulator retry flow:** (1) Trigger a failure (relay down). (2) Start the relay and provision a signing key. (3) Tap Retry. (4) Observe the loading screen reappears and the ceremony completes successfully, transitioning to the success screen. | Verifies that `runCeremony()` is called again from scratch (re-fetches device key, relay key, etc.) rather than resuming from a partial state. |
| **AC4.5** "Continue" button transitions to `shamir_backup` placeholder step | **iOS Simulator observation:** (1) Complete a successful ceremony. (2) On the success screen, tap "Continue". (3) Verify the app transitions to a placeholder screen with the heading "Backup" and text "Shamir backup coming soon..." | Simple navigation check. Verifies the `oncontinue` callback in `DIDSuccessScreen.svelte` sets `step = 'shamir_backup'` in `+page.svelte`. |

---

## Coverage Summary

| AC Group | Total Criteria | Automated | Human Verification | Notes |
|---|---|---|---|---|
| AC1 (Relay endpoint) | 4 | 4 | 0 | Full automated coverage via axum integration tests |
| AC2 (Crypto external signer) | 3 | 3 | 0 | Full automated coverage; AC2.3 is implicit via existing tests |
| AC3 (Tauri ceremony command) | 7 | 4 (serde) | 7 (behavioral) | Serialization contracts automated; behavioral outcomes require iOS Simulator. Four criteria have both automated (serde) and human (behavioral) verification. |
| AC4 (Frontend UI) | 5 | 0 | 5 | No frontend test framework configured; all verified on iOS Simulator |
| **Total** | **19** | **11** | **12** | Every criterion has at least one verification method |

**Note on overlapping coverage:** AC3.4 through AC3.7 each appear in both the automated and human columns. The automated tests verify the serde serialization contract (the `code` string matches what TypeScript expects). The human verification confirms the runtime behavior (the correct error variant is produced when the real failure condition occurs). Both layers are necessary: a serialization-only test would miss a bug in the HTTP status code check, while a manual-only test would miss a serialization rename that breaks the TypeScript error handler.
