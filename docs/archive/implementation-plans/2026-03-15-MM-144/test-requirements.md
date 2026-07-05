# MM-144 Test Requirements

## Coverage Summary

| Category | Automated | Human Verification |
|---|---|---|
| AC1 (UI rendering) | 0 | 6 |
| AC2 (account creation) | 3 | 2 |
| AC3 (error handling) | 5 | 5 |
| AC4 (Keychain storage) | 0 | 3 |
| AC5 (build passes) | 2 | 0 |
| **Total** | **10** | **16** |

Note: Several AC3 criteria appear in both sections. The Rust error-mapping logic (HTTP status code + relay error code -> `CreateAccountError` variant) is unit-testable. The full user-facing flow (error message text displayed on the correct screen) requires iOS Simulator verification because the frontend has no test framework.

---

## Automated Tests

### AC2: Account creation succeeds end-to-end

| Criterion | Test Type | File | What to Verify |
|---|---|---|---|
| MM-144.AC2.2: The Rust command POSTs to `POST /v1/accounts/mobile` with `email`, `handle`, `claimCode`, `devicePublicKey`, and `platform: "ios"` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateMobileAccountRequest` serializes with the correct camelCase field names and includes all five fields. Construct a `CreateMobileAccountRequest`, serialize to `serde_json::Value`, assert keys are `email`, `handle`, `claimCode`, `devicePublicKey`, `platform` and that `platform` value is `"ios"`. |
| MM-144.AC2.5: On success, the frontend receives `{ nextStep: "did_creation" }` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountResult` serializes correctly. Construct `CreateAccountResult { next_step: "did_creation".into() }`, serialize to JSON, assert the output is `{ "nextStep": "did_creation" }`. |

### AC3: Error handling (Rust error variant mapping)

| Criterion | Test Type | File | What to Verify |
|---|---|---|---|
| MM-144.AC3.1: A relay 404 response maps to `ExpiredCode` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountError::ExpiredCode` serializes as `{ "code": "EXPIRED_CODE" }`. Construct the variant, serialize to `serde_json::Value`, assert `value["code"] == "EXPIRED_CODE"`. |
| MM-144.AC3.2: A relay 409/`CLAIM_CODE_REDEEMED` maps to `RedeemedCode` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountError::RedeemedCode` serializes as `{ "code": "REDEEMED_CODE" }`. Same pattern as above. |
| MM-144.AC3.3: A relay 409/`ACCOUNT_EXISTS` maps to `EmailTaken` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountError::EmailTaken` serializes as `{ "code": "EMAIL_TAKEN" }`. Same pattern. |
| MM-144.AC3.4: A relay 409/`HANDLE_TAKEN` maps to `HandleTaken` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountError::HandleTaken` serializes as `{ "code": "HANDLE_TAKEN" }`. Same pattern. |
| MM-144.AC3.5: A network or server error maps to `NetworkError` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` (in `#[cfg(test)] mod tests`) | `CreateAccountError::NetworkError { message: "..." }` serializes as `{ "code": "NETWORK_ERROR", "message": "..." }`. Construct the variant with a test message, serialize, assert both fields. |

### AC5: Build passes

| Criterion | Test Type | File | What to Verify |
|---|---|---|---|
| MM-144.AC5.1: `cargo build --workspace` succeeds after adding new Rust dependencies | integration (CI) | N/A (CI pipeline command) | Run `cargo build --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all --check`. Exit code 0 for all three commands. This is a build-level gate, not a test file. |
| MM-144.AC5.2: `pnpm build` in `apps/identity-wallet/` succeeds after adding new frontend components | integration (CI) | N/A (CI pipeline command) | Run `cd apps/identity-wallet && pnpm build`. Exit code 0. Verifies TypeScript compilation and Svelte component validity. |

### Existing relay-side coverage (already written, not new work)

The relay's `POST /v1/accounts/mobile` endpoint already has comprehensive integration tests in `crates/relay/src/routes/create_mobile_account.rs`. These tests cover the server-side behavior that the mobile client depends on:

| Relay Behavior | Existing Test | Relevant AC |
|---|---|---|
| 201 response with correct shape | `returns_201_with_correct_shape` | AC2.2, AC2.3 |
| 404 for invalid/expired claim code | `invalid_claim_code_returns_404`, `expired_claim_code_returns_404` | AC3.1 |
| 409 `CLAIM_CODE_REDEEMED` for redeemed code | `already_redeemed_claim_code_returns_409` | AC3.2 |
| 409 `ACCOUNT_EXISTS` for duplicate email | `duplicate_email_in_pending_returns_409`, `duplicate_email_in_accounts_returns_409` | AC3.3 |
| 409 `HANDLE_TAKEN` for duplicate handle | `duplicate_handle_in_pending_returns_409`, `duplicate_handle_in_handles_returns_409` | AC3.4 |
| `nextStep: "did_creation"` in success response | `returns_201_with_correct_shape` (asserts `json["nextStep"] == "did_creation"`) | AC2.5 |

These tests validate that the relay produces the exact HTTP status codes and error envelope shapes that the Tauri client's error-mapping logic depends on. No new relay tests are needed for MM-144.

---

## Human Verification

### AC1: Onboarding screens render correctly

| Criterion | Justification | Verification Steps |
|---|---|---|
| MM-144.AC1.1: Welcome screen shows app branding and a "Get Started" CTA button that advances to Claim Code step | No frontend test framework configured (Svelte 5 components, no Vitest/Playwright/Testing Library setup). Visual/interactive behavior requires rendering in a browser or iOS Simulator. | 1. Run `cd apps/identity-wallet && cargo tauri ios dev` to launch in iOS Simulator. 2. Verify the Welcome screen displays "Identity Wallet" heading and "Your self-sovereign identity, in your pocket." tagline. 3. Verify a "Get Started" button is visible. 4. Tap "Get Started" and verify the app advances to the Claim Code screen. |
| MM-144.AC1.2: Claim Code screen shows a 6-character alphanumeric input; the Next button is disabled until exactly 6 characters are entered | Same as above -- input validation behavior (disabled state, character filtering) is DOM-level and requires a rendering context. | 1. From the Welcome screen, tap "Get Started" to reach the Claim Code screen. 2. Verify an input field is displayed with placeholder "ABC123". 3. Verify the "Next" button is disabled (grayed out, not tappable). 4. Type "abc" (3 characters) -- verify the input auto-uppercases to "ABC" and the button remains disabled. 5. Type "12#$34" -- verify non-alphanumeric characters are stripped, leaving "ABC123" (6 chars), and the button becomes enabled. 6. Delete one character -- verify the button disables again. |
| MM-144.AC1.3: Email screen shows an email input; the Next button is disabled until a valid email format is entered | Same as above -- regex-based email validation tied to DOM input state. | 1. Advance to the Email screen (Welcome -> Claim Code with valid 6-char code -> Email). 2. Verify an email input field is displayed with placeholder "you@example.com". 3. Verify the "Next" button is disabled. 4. Type "notanemail" -- verify the button remains disabled. 5. Type "user@example.com" -- verify the button becomes enabled. 6. Clear the field and type "user@" -- verify the button is disabled (incomplete email). |
| MM-144.AC1.4: Handle screen shows a handle input; the Next button is disabled until the handle is non-empty | Same as above -- non-empty validation on a text input. | 1. Advance to the Handle screen (Welcome -> Claim Code -> Email -> Handle). 2. Verify a handle input field is displayed with placeholder "alice". 3. Verify the "Create Account" button is disabled. 4. Type "myhandle" -- verify the button becomes enabled. 5. Clear the field -- verify the button disables again. 6. Type a single space and then delete it -- verify the button remains disabled (trims whitespace). |
| MM-144.AC1.5: Loading screen shows a spinner and status message while account creation is in progress | Loading screen is transient (visible only during the async HTTP call). Requires a running relay or a slow/intercepted network to observe. | 1. Set up a running relay (`cargo run -p relay`) with a valid claim code seeded in the database. 2. Run `cargo tauri ios dev`. 3. Complete all onboarding steps with valid data. 4. On submitting the Handle screen, verify the Loading screen appears with a spinning animation and the text "Creating your account...". 5. (Optional: use Network Link Conditioner on the Simulator to add latency and make the loading screen visible for longer.) |
| MM-144.AC1.6: Each screen's Next/Submit button only advances when its validation condition is met | Aggregate criterion covering all per-screen validation. Fully covered by AC1.2-AC1.4 verification steps above. | 1. Perform all verification steps for AC1.2, AC1.3, and AC1.4. 2. On each screen, attempt to tap the disabled button and verify no navigation occurs. 3. Verify that entering valid data and tapping the button advances to the next screen. |

### AC2: Account creation succeeds end-to-end

| Criterion | Justification | Verification Steps |
|---|---|---|
| MM-144.AC2.1: Valid email, handle, and claim code submission invokes the `create_account` Rust command via Tauri IPC | The IPC bridge between the Svelte frontend and Rust backend requires a running Tauri app in the iOS Simulator. The `invoke()` call cannot be tested without the Tauri runtime. | 1. Start the relay with a seeded claim code: `cargo run -p relay`. 2. Run `cargo tauri ios dev`. 3. Complete the onboarding flow with valid claim code, email, and handle. 4. Verify the app does not remain stuck on the Loading screen (successful IPC call means it either advances to success or shows an error). 5. Check relay logs to confirm a `POST /v1/accounts/mobile` request was received with the correct fields. |
| MM-144.AC2.3: On 201 response, `device_token` and `session_token` are stored in the iOS Keychain | Keychain writes use `security-framework` calling real iOS Security.framework APIs. These APIs are unavailable outside of an Apple platform runtime (no mock framework is configured). | 1. Complete a successful onboarding flow in the iOS Simulator (relay returns 201). 2. After the "Account Created!" placeholder appears, use Xcode's Keychain debugging or `security` CLI in the Simulator shell to verify: `xcrun simctl keychain <device-id> dump` (or attach a debugger and call `SecItemCopyMatching` with service `"ezpds-identity-wallet"` and account `"device-token"`). 3. Verify `device-token` and `session-token` entries exist under service `"ezpds-identity-wallet"`. |

### AC3: Error handling (frontend message display and screen navigation)

| Criterion | Justification | Verification Steps |
|---|---|---|
| MM-144.AC3.1: Expired claim code surfaces as "This claim code has expired. Please request a new one." and returns user to Claim Code screen | The error message text and screen-reversion logic live in the Svelte `+page.svelte` state machine. No frontend test framework is configured to verify DOM content or navigation state. | 1. Start the relay. Do NOT seed a claim code (or seed one that is already expired). 2. Run `cargo tauri ios dev`. 3. Enter a non-existent or expired 6-character claim code, a valid email, and a valid handle. 4. Submit and wait for the loading screen to resolve. 5. Verify the app returns to the Claim Code screen. 6. Verify the error message "This claim code has expired. Please request a new one." is displayed in red below the input. |
| MM-144.AC3.2: Redeemed claim code surfaces as "This claim code has already been used." and returns user to Claim Code screen | Same as above -- frontend error message rendering. | 1. Start the relay and seed a claim code. 2. Use the claim code once (complete a full successful onboarding). 3. Restart the app (kill and relaunch via `cargo tauri ios dev`). 4. Enter the same (now-redeemed) claim code with a different email and handle. 5. Submit and verify the app returns to the Claim Code screen with the message "This claim code has already been used." |
| MM-144.AC3.3: Email taken surfaces as "An account with that email already exists." and returns user to Email screen | Same as above. | 1. Start the relay. Seed two claim codes. 2. Complete onboarding with claim code 1, email "alice@example.com", and handle "alice". 3. Restart the app. 4. Begin onboarding with claim code 2, email "alice@example.com" (same email), and handle "bob". 5. Submit and verify the app returns to the Email screen with the message "An account with that email already exists." |
| MM-144.AC3.4: Handle taken surfaces as "That handle is taken. Please choose another." and returns user to Handle screen | Same as above. | 1. Start the relay. Seed two claim codes. 2. Complete onboarding with claim code 1, email "alice@example.com", and handle "alice.ezpds.com". 3. Restart the app. 4. Begin onboarding with claim code 2, email "bob@example.com", and handle "alice.ezpds.com" (same handle). 5. Submit and verify the app returns to the Handle screen with the message "That handle is taken. Please choose another." |
| MM-144.AC3.5: Network/server error surfaces as "Couldn't reach the server. Check your connection." and returns user to Handle screen | Same as above. | 1. Do NOT start the relay (no server running). 2. Run `cargo tauri ios dev`. 3. Complete all onboarding steps with any valid-looking inputs. 4. Submit and verify the app returns to the Handle screen with the message "Couldn't reach the server. Check your connection." |

### AC4: iOS Keychain storage

| Criterion | Justification | Verification Steps |
|---|---|---|
| MM-144.AC4.1: `device_token` stored under service `"ezpds-identity-wallet"`, account `"device-token"` | Keychain APIs (`security-framework::passwords::set_generic_password`) call real iOS Security.framework. No mock framework is set up; unit testing Keychain operations requires an Apple runtime. The `store_item` function is a thin wrapper with no branching logic worth isolating. | 1. Complete a successful onboarding flow in the iOS Simulator. 2. Pause execution after success (add a breakpoint in `create_account` after the `store_item("device-token", ...)` call, or inspect post-hoc). 3. In the Xcode debugger console, call `SecItemCopyMatching` with query dict `{ kSecClass: kSecClassGenericPassword, kSecAttrService: "ezpds-identity-wallet", kSecAttrAccount: "device-token", kSecReturnData: true }`. 4. Verify data is returned and its base64url-decoded length is 43 characters (base64url encoding of 32 bytes). |
| MM-144.AC4.2: `session_token` stored under service `"ezpds-identity-wallet"`, account `"session-token"` | Same as above. | 1. Same setup as AC4.1. 2. Query the Keychain with account `"session-token"`. 3. Verify data is returned and matches the expected format. |
| MM-144.AC4.3: Device P-256 private key stored under service `"ezpds-identity-wallet"`, account `"device-private-key"` | Same as above. The private key is stored before the HTTP request (AC2.4 ordering), but verifying ordering requires stepping through with a debugger. | 1. Same setup as AC4.1 (or even a failed HTTP request -- the private key is stored before the POST). 2. Query the Keychain with account `"device-private-key"`. 3. Verify data is returned and its length is 32 bytes (raw P-256 private key scalar). 4. (Ordering verification) Set a breakpoint on the `http::RelayClient::new().post(...)` call in `create_account`. When hit, query the Keychain for `"device-private-key"` -- it must already exist, confirming the key was stored before the HTTP request (AC2.4). |

---

## Test Implementation Notes

### Unit tests in `src-tauri/src/lib.rs`

All automated tests for AC2 and AC3 are serde serialization tests that verify the IPC contract between Rust and TypeScript. They should be added to the existing `#[cfg(test)] mod tests` block in `apps/identity-wallet/src-tauri/src/lib.rs`. These tests do not require any external dependencies (no network, no Keychain, no Tauri runtime).

Example test structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // -- AC2.2: Request serialization --
    #[test]
    fn create_mobile_account_request_serializes_camel_case() {
        let req = CreateMobileAccountRequest {
            email: "test@example.com".into(),
            handle: "alice".into(),
            device_public_key: "pubkey123".into(),
            platform: "ios".into(),
            claim_code: "ABC123".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["handle"], "alice");
        assert_eq!(json["devicePublicKey"], "pubkey123");
        assert_eq!(json["platform"], "ios");
        assert_eq!(json["claimCode"], "ABC123");
    }

    // -- AC2.5: Result serialization --
    #[test]
    fn create_account_result_serializes_camel_case() {
        let result = CreateAccountResult { next_step: "did_creation".into() };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["nextStep"], "did_creation");
    }

    // -- AC3.1-AC3.5: Error variant serialization --
    #[test]
    fn error_expired_code_serializes_correctly() {
        let err = CreateAccountError::ExpiredCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EXPIRED_CODE");
    }

    // ... (one test per error variant)
}
```

### What is NOT testable without additional infrastructure

1. **Frontend component rendering** (AC1.*): Requires a frontend test framework (Vitest + Testing Library, or Playwright). Not configured in this project.
2. **Tauri IPC bridge** (AC2.1): Requires the Tauri runtime to broker `invoke()` calls between the WebView and Rust. Cannot be unit-tested.
3. **iOS Keychain operations** (AC4.*): Requires Apple Security.framework at runtime. The `keychain.rs` functions are thin wrappers over `security-framework` crate calls with no branching logic.
4. **End-to-end HTTP flow** (AC2.3, AC2.4): The `create_account` command calls real Keychain APIs and real HTTP endpoints in sequence. Mocking either would require adding `mockall` or a similar framework plus trait-based dependency injection, which is not set up.

### Future automation opportunities

- **Frontend tests**: Adding Vitest + `@testing-library/svelte` would allow testing component validation logic (AC1.2-AC1.4, AC1.6) and error message display (AC3.1-AC3.5 frontend side).
- **Playwright e2e**: Adding Playwright with `@playwright/test` would allow full browser-based testing of the state machine transitions.
- **Keychain mocking**: Extracting the Keychain operations behind a trait and using `mockall` would allow unit-testing the `create_account` command's orchestration logic (key storage ordering, token storage after HTTP success) without an Apple runtime.
