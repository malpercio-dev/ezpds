# MM-150: Test Requirements

**Ticket:** MM-150 — Wallet Home Screen: Identity Overview + Session Status
**Design plan:** `docs/design-plans/2026-03-27-MM-150.md`
**Last verified:** 2026-03-27

---

## Acceptance Criteria Index

Every acceptance criterion from the design plan, mapped to its implementing phase and test strategy.

### MM-150.AC1: Identity card displays correctly

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| MM-150.AC1.1 | Home screen shows the user's handle from `getSession` response | Phase 3 | Human Verification |
| MM-150.AC1.2 | DID is displayed truncated as `did:plc:XXXXXXXX...XXXXXX` (first 8 + last 6 of method-specific part) | Phase 3 | Human Verification |
| MM-150.AC1.3 | Copy button copies the full untruncated DID to clipboard | Phase 3 | Human Verification |
| MM-150.AC1.4 | Email from `getSession` is shown | Phase 3 | Human Verification |
| MM-150.AC1.5 | DID-derived avatar circle is visible with a stable hue derived from the DID hash | Phase 2 | Human Verification |
| MM-150.AC1.6 | Avatar shows the first letter of the handle as its initial | Phase 2 | Human Verification |
| MM-150.AC1.7 | Avatar shows `?` when handle is `handle.invalid` | Phase 2 | Human Verification |
| MM-150.AC1.8 | Loading spinner is shown while `loadHomeData()` is in flight | Phase 3 | Human Verification |

### MM-150.AC2: Status indicators are accurate

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| MM-150.AC2.1 | Relay status shows Connected when `_health` returns 200 | Phase 1 | Automated Test Coverage Required |
| MM-150.AC2.2 | Relay status shows Error when `_health` returns non-200 or network fails | Phase 1 | Automated Test Coverage Required |
| MM-150.AC2.3 | Session status shows Active when `getSession` succeeds | Phase 1 | Automated Test Coverage Required |
| MM-150.AC2.4 | Session status shows Error when `getSession` fails after OAuthClient refresh attempt | Phase 1 | Automated Test Coverage Required |
| MM-150.AC2.5 | Relay and session statuses are independent (one can be error while other is active) | Phase 1 | Automated Test Coverage Required |

### MM-150.AC3: Three action flows work

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| MM-150.AC3.1 | Log out clears `oauth-access-token`, `oauth-refresh-token`, and `did` from Keychain | Phase 1 | Automated Test Coverage Required |
| MM-150.AC3.2 | Log out navigates to the welcome screen | Phase 3, 4 | Human Verification |
| MM-150.AC3.3 | Device key and DPoP key remain in Keychain after logout | Phase 1 | Automated Test Coverage Required |
| MM-150.AC3.4 | Tapping View DID Document navigates to `did_document` step | Phase 4 | Human Verification |
| MM-150.AC3.5 | DID document view shows `id`, `alsoKnownAs`, `verificationMethod`, and `service` fields | Phase 5 | Human Verification |
| MM-150.AC3.6 | Raw JSON toggle reveals the full DID document as a monospace block | Phase 5 | Human Verification |
| MM-150.AC3.7 | Key copy button copies `publicKeyMultibase` value to clipboard | Phase 5 | Human Verification |
| MM-150.AC3.8 | View DID Document button is hidden when `session.didDoc` is null | Phase 3 | Human Verification |
| MM-150.AC3.9 | Back from DID document returns to home | Phase 4, 5 | Human Verification |
| MM-150.AC3.10 | Tapping Recovery Info navigates to `recovery_info` step | Phase 4 | Human Verification |
| MM-150.AC3.11 | Share 1 shows checkmark when `recovery-share-1` exists in Keychain | Phase 6 | Human Verification |
| MM-150.AC3.12 | Share 1 shows X when `recovery-share-1` is absent from Keychain | Phase 6 | Human Verification |
| MM-150.AC3.13 | Share 2 always shows checkmark (static relay custody fact) | Phase 6 | Human Verification |
| MM-150.AC3.14 | Back from recovery info returns to home | Phase 4, 6 | Human Verification |

### MM-150.AC4: Tauri commands and IPC wrappers

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| MM-150.AC4.1 | `load_home_data` returns `relayHealthy: true` when `_health` returns 200 | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.2 | `load_home_data` returns populated `session` when `getSession` succeeds | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.3 | `load_home_data` returns `relayHealthy: false` (with `session` still populated) when `_health` fails | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.4 | `load_home_data` returns `session: null` and `sessionError` populated when `getSession` fails | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.5 | `load_home_data` always returns `Ok(HomeData)` — never `Err` | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.6 | `log_out` deletes OAuth tokens and DID from Keychain | Phase 1 | Automated Test Coverage Required |
| MM-150.AC4.7 | `log_out` always returns `Ok(())` even if Keychain delete partially fails | Phase 1 | Automated Test Coverage Required |

### MM-150.AC5: App launches to home when already onboarded

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| MM-150.AC5.1 | App starts at the `home` step when OAuth tokens exist in Keychain on launch | Phase 4 | Human Verification |
| MM-150.AC5.2 | `homeData` is loaded on mount of `HomeScreen` regardless of entry path | Phase 3, 4 | Human Verification |

---

## Automated Test Coverage Required

Tests are in `apps/identity-wallet/src-tauri/src/home.rs` (Phase 1, Task 4). All automated criteria target Rust unit tests with `httpmock` for HTTP endpoint mocking.

| Criterion | Test File | Test Function | Verifies |
|-----------|-----------|---------------|----------|
| MM-150.AC2.1 | `home.rs` | `load_home_data_relay_healthy_true_when_health_returns_200` | `relay_healthy` is `true` when mock `_health` returns 200 |
| MM-150.AC2.2 | `home.rs` | `load_home_data_relay_healthy_false_when_health_fails` | `relay_healthy` is `false` when mock `_health` returns 503 |
| MM-150.AC2.3 | `home.rs` | `load_home_data_session_populated_when_get_session_succeeds` | `session` is `Some` with correct fields when mock `getSession` returns 200 |
| MM-150.AC2.4 | `home.rs` | `load_home_data_session_null_when_get_session_fails` | `session` is `None` and `session_error` is `Some` when mock `getSession` returns 401 |
| MM-150.AC2.5 | `home.rs` | `load_home_data_relay_healthy_false_when_health_fails` | `session` is populated even when relay health fails (independence verified) |
| MM-150.AC2.5 | `home.rs` | `load_home_data_session_null_when_get_session_fails` | `relay_healthy` is `true` even when session fails (independence verified) |
| MM-150.AC3.1 | `home.rs` | `log_out_deletes_oauth_and_did_from_keychain` | `oauth-access-token`, `oauth-refresh-token`, and `did` are absent after logout |
| MM-150.AC3.3 | `home.rs` | `log_out_preserves_device_and_dpop_keys` | `oauth-dpop-key-priv` and `device-rotation-key-priv` remain after logout |
| MM-150.AC4.1 | `home.rs` | `load_home_data_relay_healthy_true_when_health_returns_200` | `HomeData.relay_healthy == true` when `_health` returns 200 |
| MM-150.AC4.2 | `home.rs` | `load_home_data_session_populated_when_get_session_succeeds` | `HomeData.session` contains correct `did`, `handle`, `email`, `emailConfirmed` |
| MM-150.AC4.3 | `home.rs` | `load_home_data_relay_healthy_false_when_health_fails` | `relay_healthy == false` while `session` is still populated |
| MM-150.AC4.4 | `home.rs` | `load_home_data_session_null_when_get_session_fails` | `session == None`, `session_error == Some(...)` when `getSession` returns 401 |
| MM-150.AC4.5 | `home.rs` | `load_home_data_no_session_returns_not_authenticated` | Function returns `HomeData` (not `Err`) when no session exists in AppState |
| MM-150.AC4.6 | `home.rs` | `log_out_deletes_oauth_and_did_from_keychain` | Three Keychain items deleted, AppState cleared |
| MM-150.AC4.7 | `home.rs` | `log_out_succeeds_when_keychain_items_absent` | Function completes without panic when items are already absent |

Additional serialization tests (not mapped to specific ACs but validate the IPC contract):

| Test Function | Verifies |
|---------------|----------|
| `home_data_serializes_camel_case` | `HomeData` and `SessionInfo` serialize to camelCase keys matching TypeScript types |
| `home_data_session_null_serializes_error_code` | `session: null` + `sessionError` serialization matches frontend expectations |

---

## Human Verification Required

All UI component criteria (Phases 2-6) and navigation wiring (Phase 4) require human verification on the iOS Simulator because this project has no browser-based component test harness. The Svelte components render inside a Tauri WKWebView on iOS, so DOM-level testing frameworks are not available.

### Phase 2: DIDAvatar Component

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| MM-150.AC1.5 | Visual rendering: hue derived from DID hash produces a colored circle | 1. Complete onboarding so the app reaches the home screen. 2. Observe the avatar circle in the identity card. 3. Verify it shows a solid-color circle (not white, not black). 4. Force-quit and relaunch the app. 5. Verify the avatar color is identical to step 3 (stable hue). |
| MM-150.AC1.6 | Visual rendering: handle initial displayed inside avatar | 1. On the home screen, check the letter inside the avatar circle. 2. Verify it matches the first character of the handle shown below it (uppercased). For example, if handle is `alice.test`, the avatar shows `A`. |
| MM-150.AC1.7 | Edge case requiring relay to return `handle.invalid` | 1. Create an account without registering a handle (if possible), or mock the relay to return `handle.invalid` as the handle. 2. Navigate to the home screen. 3. Verify the avatar shows `?` instead of a letter. |

### Phase 3: HomeScreen Component

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| MM-150.AC1.1 | UI rendering of session data | 1. Complete onboarding with handle `testuser.test`. 2. On the home screen, verify the identity card shows `@testuser.test`. |
| MM-150.AC1.2 | DID truncation display | 1. On the home screen, read the DID string in the identity card. 2. Verify it shows `did:plc:` followed by 8 characters, an ellipsis, and 6 characters (e.g., `did:plc:abcdefgh...uvwxyz`). 3. The full prefix `did:plc:` must be visible. |
| MM-150.AC1.3 | Clipboard interaction on iOS | 1. On the home screen, tap the DID copy button (labeled "Copy"). 2. Verify the button text changes to "Copied!" for approximately 2 seconds. 3. Open Notes or another app and paste. 4. Verify the pasted text is the full untruncated DID (e.g., `did:plc:abcdefghijklmnopqrstuvwx`). |
| MM-150.AC1.4 | UI rendering of email | 1. On the home screen, verify the email address displayed in the identity card matches the email used during registration. |
| MM-150.AC1.8 | Loading spinner timing | 1. Launch the app (or tap the refresh button on the home screen). 2. Observe that a spinner with "Loading..." text appears briefly before the identity card renders. On a fast connection this may be very brief. |
| MM-150.AC3.2 | Navigation after logout | 1. On the home screen, tap "Log Out". 2. Verify the app navigates to the welcome screen (the initial onboarding entry point). 3. Verify no identity data is visible on the welcome screen. |
| MM-150.AC3.8 | Conditional button visibility | 1. If the relay has not published a DID document for the account, the home screen should NOT show a "View DID Document" button. 2. If a DID document exists (standard onboarding flow), the button should be visible. |

### Phase 4: State Machine Wiring

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| MM-150.AC3.4 | Navigation to DID document screen | 1. On the home screen, verify the "View DID Document" button is present (requires `didDoc` to be non-null). 2. Tap "View DID Document". 3. Verify the app transitions to the DID Document screen (header says "DID Document"). |
| MM-150.AC3.9 | Back navigation from DID document | 1. On the DID Document screen, tap the "Back" button. 2. Verify the app returns to the home screen with identity card intact. |
| MM-150.AC3.10 | Navigation to recovery info screen | 1. On the home screen, tap "Recovery Info". 2. Verify the app transitions to the Recovery Info screen (header says "Recovery Info"). |
| MM-150.AC3.14 | Back navigation from recovery info | 1. On the Recovery Info screen, tap the "Back" button. 2. Verify the app returns to the home screen. |
| MM-150.AC5.1 | App startup with existing tokens | 1. Complete full onboarding so OAuth tokens are stored in Keychain. 2. Force-quit the app completely. 3. Relaunch the app. 4. Verify the app opens directly to the home screen (not the welcome screen). |
| MM-150.AC5.2 | `homeData` loads regardless of entry path | 1. Complete onboarding (app should navigate to home after the `complete` step). Verify identity card is populated. 2. Force-quit and relaunch. Verify identity card is populated again (loaded on mount). |

### Phase 5: DIDDocumentScreen Component

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| MM-150.AC3.5 | Structured DID document rendering | 1. Navigate to the DID Document screen. 2. Verify the "Identifier" section shows the full DID. 3. Verify "Also Known As" shows `at://handle` entries (if present). 4. Verify "Verification Keys" shows one or more key cards with type (e.g., "Multikey") and truncated `publicKeyMultibase`. 5. Verify "Services" shows service type and endpoint URL. |
| MM-150.AC3.6 | Raw JSON toggle | 1. On the DID Document screen, tap "Show Raw JSON". 2. Verify a monospace code block appears showing the full JSON document with proper indentation. 3. Tap "Hide Raw JSON". 4. Verify the raw block disappears. |
| MM-150.AC3.7 | Key copy button | 1. On the DID Document screen, find a verification key card. 2. Tap the "Copy" button next to the `publicKeyMultibase` value. 3. Verify the button text changes to "Copied!" for approximately 2 seconds. 4. Paste in Notes or another app. 5. Verify the pasted text is the full `publicKeyMultibase` string (not the truncated display). |

### Phase 6: RecoveryInfoScreen Component

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| MM-150.AC3.11 | Share 1 present indicator | 1. Complete onboarding (which stores `recovery-share-1` in Keychain). 2. Navigate to Recovery Info. 3. Verify Share 1 row shows a green checkmark icon and text "Saved to iCloud Keychain". |
| MM-150.AC3.12 | Share 1 absent indicator | 1. Manually delete `recovery-share-1` from the Keychain (requires Xcode Keychain debugging or a test helper). 2. Return to the home screen and tap refresh. 3. Navigate to Recovery Info. 4. Verify Share 1 row shows a red X icon and text "Not found in Keychain". |
| MM-150.AC3.13 | Share 2 static indicator | 1. Navigate to Recovery Info. 2. Verify Share 2 row always shows a green checkmark icon and text "Held by the relay". |

---

## End-to-End Scenarios

### E2E-1: Full onboarding to home screen

**Purpose:** Validates the complete user journey from first launch through account creation to the home screen, exercising Phases 1-4.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Launch the app on a fresh iOS Simulator (no prior Keychain data) | Welcome screen appears |
| 2 | Complete the full onboarding flow (claim code, email, handle, password, DID ceremony, Shamir backup) | Each step transitions correctly |
| 3 | After the `complete` step, observe the transition | App navigates to the home screen |
| 4 | Verify identity card | Handle, truncated DID, email, and colored avatar are all displayed |
| 5 | Verify status indicators | Relay shows "Connected" (green dot), Session shows "Active" (green dot) |
| 6 | Verify action buttons | "View DID Document", "Recovery Info", and "Log Out" buttons are visible |

### E2E-2: Home screen to DID document and back

**Purpose:** Validates DID Document navigation round-trip, exercising Phases 4-5.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen, tap "View DID Document" | DID Document screen appears with "DID Document" header |
| 2 | Verify structured content | Identifier, verification keys, and services sections are populated |
| 3 | Tap "Show Raw JSON" | Monospace JSON block appears below the structured view |
| 4 | Tap "Hide Raw JSON" | JSON block disappears |
| 5 | Tap the "Copy" button on a verification key | Button text changes to "Copied!" |
| 6 | Tap "Back" | Returns to the home screen with all data intact |

### E2E-3: Home screen to recovery info and back

**Purpose:** Validates Recovery Info navigation round-trip, exercising Phases 4 and 6.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen, tap "Recovery Info" | Recovery Info screen appears with "Recovery Info" header |
| 2 | Verify Share 1 | Green checkmark, "Saved to iCloud Keychain" |
| 3 | Verify Share 2 | Green checkmark, "Held by the relay" |
| 4 | Verify Share 3 | Clipboard icon, "Your manual backup" |
| 5 | Tap "Back" | Returns to the home screen with all data intact |

### E2E-4: Logout and re-authentication

**Purpose:** Validates that logout clears tokens and the app returns to a clean state, exercising Phases 1, 3, and 4.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen, tap "Log Out" | App navigates to the welcome screen |
| 2 | Force-quit and relaunch the app | Welcome screen appears (not home screen), confirming tokens were cleared |
| 3 | Complete the OAuth login flow again | App navigates to the home screen with fresh session data |

### E2E-5: App relaunch with existing session

**Purpose:** Validates AC5.1 — the app launches to home when already onboarded.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start from a state where onboarding is complete and OAuth tokens exist | Home screen is showing |
| 2 | Force-quit the app completely | App is terminated |
| 3 | Relaunch the app | App opens directly to the home screen (not welcome) |
| 4 | Verify identity card is populated | Handle, DID, email, and avatar are all displayed |

### E2E-6: Refresh button

**Purpose:** Validates that the refresh button re-fetches data without navigating away.

| Step | Action | Expected |
|------|--------|----------|
| 1 | On the home screen, note the current identity card data | Data is displayed |
| 2 | Tap the refresh button (top-right corner) | Loading spinner appears briefly, then data re-renders |
| 3 | Verify data is unchanged | Same handle, DID, email, and status indicators |

---

## Traceability Matrix

Every acceptance criterion mapped to its automated test and/or manual verification step.

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| MM-150.AC1.1 | -- | Phase 3: verify handle in identity card |
| MM-150.AC1.2 | -- | Phase 3: verify DID truncation format |
| MM-150.AC1.3 | -- | Phase 3: tap copy, paste in another app |
| MM-150.AC1.4 | -- | Phase 3: verify email in identity card |
| MM-150.AC1.5 | -- | Phase 2: verify colored circle, stable across relaunches |
| MM-150.AC1.6 | -- | Phase 2: verify handle initial in avatar |
| MM-150.AC1.7 | -- | Phase 2: verify `?` for `handle.invalid` |
| MM-150.AC1.8 | -- | Phase 3: observe spinner during load |
| MM-150.AC2.1 | `load_home_data_relay_healthy_true_when_health_returns_200` | -- |
| MM-150.AC2.2 | `load_home_data_relay_healthy_false_when_health_fails` | -- |
| MM-150.AC2.3 | `load_home_data_session_populated_when_get_session_succeeds` | -- |
| MM-150.AC2.4 | `load_home_data_session_null_when_get_session_fails` | -- |
| MM-150.AC2.5 | `load_home_data_relay_healthy_false_when_health_fails` + `load_home_data_session_null_when_get_session_fails` | -- |
| MM-150.AC3.1 | `log_out_deletes_oauth_and_did_from_keychain` | -- |
| MM-150.AC3.2 | -- | Phase 3/4: tap Log Out, verify welcome screen |
| MM-150.AC3.3 | `log_out_preserves_device_and_dpop_keys` | -- |
| MM-150.AC3.4 | -- | Phase 4: tap View DID Document, verify navigation |
| MM-150.AC3.5 | -- | Phase 5: verify structured sections |
| MM-150.AC3.6 | -- | Phase 5: toggle raw JSON |
| MM-150.AC3.7 | -- | Phase 5: copy key, paste to verify |
| MM-150.AC3.8 | -- | Phase 3: verify button hidden when `didDoc` is null |
| MM-150.AC3.9 | -- | Phase 4/5: tap Back from DID document |
| MM-150.AC3.10 | -- | Phase 4: tap Recovery Info, verify navigation |
| MM-150.AC3.11 | -- | Phase 6: verify green checkmark for Share 1 |
| MM-150.AC3.12 | -- | Phase 6: verify red X for Share 1 absent |
| MM-150.AC3.13 | -- | Phase 6: verify green checkmark for Share 2 |
| MM-150.AC3.14 | -- | Phase 4/6: tap Back from recovery info |
| MM-150.AC4.1 | `load_home_data_relay_healthy_true_when_health_returns_200` | -- |
| MM-150.AC4.2 | `load_home_data_session_populated_when_get_session_succeeds` | -- |
| MM-150.AC4.3 | `load_home_data_relay_healthy_false_when_health_fails` | -- |
| MM-150.AC4.4 | `load_home_data_session_null_when_get_session_fails` | -- |
| MM-150.AC4.5 | `load_home_data_no_session_returns_not_authenticated` | -- |
| MM-150.AC4.6 | `log_out_deletes_oauth_and_did_from_keychain` | -- |
| MM-150.AC4.7 | `log_out_succeeds_when_keychain_items_absent` | -- |
| MM-150.AC5.1 | -- | Phase 4: force-quit, relaunch, verify home |
| MM-150.AC5.2 | -- | Phase 3/4: verify data loads on mount from both entry paths |

---

## Summary

- **Total acceptance criteria:** 33
- **Automated test coverage:** 14 criteria (all in Phase 1, Rust unit tests in `home.rs`)
- **Human verification required:** 19 criteria (UI rendering, clipboard, navigation, iOS Keychain state)
- **End-to-end scenarios:** 6

### Prerequisites for Human Verification

- macOS with Xcode installed
- iOS Simulator available (iPhone target)
- `cargo tauri ios dev` running successfully
- A relay instance accessible from the simulator (local or remote)
- `cargo test -p identity-wallet` passing (all Phase 1 automated tests green)
