# relay-url-config: Test Requirements

**Feature:** relay-url-config -- Relay URL Configuration
**Design plan:** `docs/design-plans/2026-03-27-relay-url-config.md`
**Last verified:** 2026-03-27

---

## Acceptance Criteria Index

Every acceptance criterion from the design plan, mapped to its implementing phase and test strategy.

### relay-url-config.AC1: Relay config screen shown on first launch

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC1.1 | On first launch (no saved relay URL), the relay config screen appears before the welcome screen | Phase 4 | Human Verification |
| relay-url-config.AC1.2 | User can accept the pre-filled default URL and proceed to welcome | Phase 4 | Human Verification |
| relay-url-config.AC1.3 | User can enter a custom URL and proceed if the relay is healthy | Phase 4 | Human Verification |
| relay-url-config.AC1.4 | User cannot advance past the config screen without a valid, reachable URL | Phase 4 | Human Verification |

### relay-url-config.AC2: Default URL pre-filled

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC2.1 | URL input is pre-filled with `https://relay.ezpds.com` on first launch | Phase 4 | Human Verification |

### relay-url-config.AC3: URL persists across restarts

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC3.1 | After saving a URL and relaunching the app, the relay config screen is not shown | Phase 3, 4 | Human Verification |
| relay-url-config.AC3.2 | All relay IPC commands on subsequent launches use the saved URL | Phase 3 | Automated Test Coverage Required |

### relay-url-config.AC4: Relay reachability verified before saving

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC4.1 | A URL whose `/xrpc/_health` returns HTTP 200 is accepted | Phase 3 | Human Verification |
| relay-url-config.AC4.2 | An unreachable host surfaces an `UNREACHABLE` inline error | Phase 3, 4 | Human Verification |
| relay-url-config.AC4.3 | A malformed URL (not `http`/`https`, empty host) surfaces an `INVALID_URL` error before any network call | Phase 3 | Automated Test Coverage Required |
| relay-url-config.AC4.4 | A URL with a trailing slash is accepted and normalized (slash stripped) before saving | Phase 3 | Automated Test Coverage Required |

### relay-url-config.AC5: Returning users skip config screen

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC5.1 | When a relay URL is already in Keychain on launch, the app starts at the welcome step (or home if authenticated) | Phase 3, 4 | Human Verification |
| relay-url-config.AC5.2 | The saved URL is used for relay calls on the same launch it was saved (no restart required) | Phase 3 | Human Verification |

### relay-url-config.AC6: Error and loading states

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| relay-url-config.AC6.1 | A loading/spinner state is shown while the health check is in flight | Phase 4 | Human Verification |
| relay-url-config.AC6.2 | `INVALID_URL` error is shown inline on the config screen (user stays on screen) | Phase 4 | Human Verification |
| relay-url-config.AC6.3 | `UNREACHABLE` error is shown inline on the config screen (user stays on screen) | Phase 4 | Human Verification |

---

## Automated Test Coverage Required

Tests are in `apps/identity-wallet/src-tauri/src/lib.rs` (Phase 3, Task 3). All automated criteria target Rust unit tests exercising the `normalize_relay_url` helper and the `keychain::store_relay_url` / `keychain::load_relay_url` round-trip.

| Criterion | Test File | Test Function | Verifies |
|-----------|-----------|---------------|----------|
| relay-url-config.AC4.3 | `lib.rs` | `normalize_relay_url_rejects_non_http_schemes` | `ftp://` and `ws://` URLs return `RelayConfigError::InvalidUrl` |
| relay-url-config.AC4.3 | `lib.rs` | `normalize_relay_url_rejects_malformed_input` | Empty string and non-URL string return `RelayConfigError::InvalidUrl` |
| relay-url-config.AC4.3 | `lib.rs` | `normalize_relay_url_accepts_http_and_https` | `https://` and `http://` URLs are accepted without error |
| relay-url-config.AC4.4 | `lib.rs` | `normalize_relay_url_strips_trailing_slash` | `https://relay.example.com/` becomes `https://relay.example.com` |
| relay-url-config.AC3.2 | `lib.rs` | `relay_url_round_trips_through_keychain` | A URL stored via `store_relay_url` is retrieved unchanged by `load_relay_url` |
| relay-url-config.AC3.2 | `lib.rs` | `get_relay_url_returns_none_before_save` | `get_relay_url()` returns `None` when no URL has been saved to Keychain |

---

## Human Verification Required

All UI component criteria (Phase 4) and integration behaviors that require a live relay (Phase 3 health check, Phase 4 screen navigation) require human verification on the iOS Simulator. This project has no browser-based component test harness; Svelte components render inside a Tauri WKWebView on iOS, so DOM-level testing frameworks are not available. The `save_relay_url` command makes live HTTP calls and is not unit-tested.

### Phase 3: IPC Commands (live relay required)

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| relay-url-config.AC4.1 | Health check requires a live relay returning HTTP 200 | 1. Start a local relay (`cargo run -p relay`). 2. In the iOS Simulator, enter the local relay URL (e.g., `http://localhost:2583`) on the config screen. 3. Tap Connect. 4. Verify the spinner appears, then the app advances to the welcome screen. |
| relay-url-config.AC4.2 | Unreachable host requires network-level failure, not mockable in unit tests | 1. On the relay config screen, enter `https://does-not-exist.example.com`. 2. Tap Connect. 3. Verify the spinner appears, then an inline error reads "Could not reach the relay. Check the URL and try again." 4. Verify you remain on the config screen. |
| relay-url-config.AC5.2 | Requires verifying runtime state across IPC commands within a single app session | 1. On the config screen, enter a valid relay URL and tap Connect. 2. Proceed through onboarding (claim code, email, handle, password). 3. Verify that account creation succeeds (it uses the relay URL saved moments ago, not the compile-time default). |

### Phase 4: Frontend Relay Configuration Screen

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| relay-url-config.AC1.1 | Navigation gating requires iOS Simulator observation | 1. Reset the iOS Simulator (Erase All Content and Settings). 2. Launch the app via `cargo tauri ios dev`. 3. Verify the first screen shown is the relay configuration screen (header says "Connect to Relay"), not the welcome screen. |
| relay-url-config.AC1.2 | Requires tapping through the default pre-filled URL | 1. On the relay config screen (fresh state), do not modify the URL. 2. Verify the input field shows `https://relay.ezpds.com`. 3. Tap Connect. 4. If the production relay is reachable, verify the app advances to the welcome screen. |
| relay-url-config.AC1.3 | Requires entering a custom URL and verifying navigation | 1. On the relay config screen, clear the input field. 2. Enter a custom URL pointing to a running relay (e.g., `http://localhost:2583`). 3. Tap Connect. 4. Verify the app advances to the welcome screen. |
| relay-url-config.AC1.4 | Requires confirming the screen blocks advancement on error | 1. On the relay config screen, enter `https://does-not-exist.example.com`. 2. Tap Connect. 3. Verify an error message appears and you remain on the config screen. 4. Clear the field, enter `notaurl`, and tap Connect. 5. Verify an error message appears and you remain on the config screen. |
| relay-url-config.AC2.1 | Visual inspection of the pre-filled input value | 1. Reset the iOS Simulator. 2. Launch the app. 3. On the relay config screen, verify the URL text input contains exactly `https://relay.ezpds.com`. |
| relay-url-config.AC3.1 | Requires app relaunch to verify Keychain persistence | 1. On the relay config screen, accept the default URL (or enter a valid one) and tap Connect. 2. Force-quit the app completely. 3. Relaunch the app. 4. Verify the relay config screen does NOT appear; the app starts at the welcome screen (or home if previously authenticated). |
| relay-url-config.AC5.1 | Requires app relaunch with pre-existing Keychain state | 1. Complete the relay configuration step so a URL is saved. 2. Force-quit and relaunch the app. 3. Verify the app starts at the welcome screen (or home if OAuth tokens exist). The relay config screen is skipped. |
| relay-url-config.AC6.1 | Visual rendering of loading state | 1. On the relay config screen, enter a valid relay URL. 2. Tap Connect. 3. Observe that the Connect button is replaced by a spinning indicator while the health check is in flight. 4. Verify the input field is disabled during loading. |
| relay-url-config.AC6.2 | Visual rendering of inline error | 1. On the relay config screen, enter `notaurl`. 2. Tap Connect. 3. Verify an inline error message appears below the input field reading "Invalid URL -- must start with http:// or https://". 4. Verify the input field border turns red. 5. Verify you remain on the config screen. |
| relay-url-config.AC6.3 | Visual rendering of inline error | 1. On the relay config screen, enter `https://does-not-exist.example.com`. 2. Tap Connect. 3. Verify an inline error message appears reading "Could not reach the relay. Check the URL and try again." 4. Verify you remain on the config screen. |

---

## End-to-End Scenarios

### E2E-1: First launch -- configure relay and begin onboarding

**Purpose:** Validates the complete first-launch path from relay configuration through the start of onboarding, exercising Phases 3-4.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator (Erase All Content and Settings) | Simulator is clean |
| 2 | Launch the app via `cargo tauri ios dev` | Relay config screen appears with "Connect to Relay" header |
| 3 | Verify the URL input is pre-filled | Input contains `https://relay.ezpds.com` |
| 4 | Tap Connect (with a reachable relay) | Spinner appears, then app advances to the welcome screen |
| 5 | Verify the welcome screen is functional | "Get Started" button is visible and tappable |

### E2E-2: First launch -- invalid URL then recovery

**Purpose:** Validates error handling and recovery on the relay config screen, exercising Phases 3-4.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Relay config screen appears |
| 3 | Clear the URL field and type `notaurl` | Connect button is disabled (URL does not start with http/https) |
| 4 | Clear the field and type `https://does-not-exist.example.com` | Connect button is enabled |
| 5 | Tap Connect | Spinner appears, then inline error: "Could not reach the relay..." |
| 6 | Clear the field and enter a valid relay URL (e.g., `https://relay.ezpds.com` or `http://localhost:2583`) | Connect button is enabled, error text clears on next tap |
| 7 | Tap Connect | Spinner appears, then app advances to the welcome screen |

### E2E-3: Returning user -- relay config screen skipped

**Purpose:** Validates that returning users bypass the relay configuration screen entirely, exercising the Keychain persistence path from Phase 3 and the mount-time check from Phase 4.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start from a state where the relay URL has been saved (E2E-1 completed) | App is on the welcome screen or further |
| 2 | Force-quit the app completely | App is terminated |
| 3 | Relaunch the app | App opens directly to the welcome screen (not the relay config screen) |
| 4 | If OAuth tokens also exist in Keychain, verify the app opens to the home screen instead | Home screen with identity card is displayed |

### E2E-4: Full journey -- relay config through account creation

**Purpose:** Validates that the relay URL configured on the config screen is used for all subsequent IPC commands (account creation, DID ceremony, handle registration), exercising all four phases.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Relay config screen appears |
| 3 | Enter a valid relay URL and tap Connect | App advances to the welcome screen |
| 4 | Proceed through full onboarding (claim code, email, handle, password, DID ceremony, Shamir backup, handle registration) | Each step completes successfully using the saved relay URL |
| 5 | After the `complete` step, verify the home screen | Identity card shows handle, DID, email; relay status is "Connected" |
| 6 | Force-quit and relaunch | App opens to home screen (both relay URL and OAuth tokens are restored from Keychain) |

### E2E-5: Custom relay URL -- self-hosted deployment

**Purpose:** Validates that a non-default relay URL works end-to-end for self-hosted deployments.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start a local relay instance (`cargo run -p relay`) | Relay is listening on `http://localhost:2583` |
| 2 | Reset the iOS Simulator and launch the app | Relay config screen appears |
| 3 | Clear the default URL, enter `http://localhost:2583`, and tap Connect | Spinner, then app advances to the welcome screen |
| 4 | Proceed through onboarding | All commands succeed against the local relay |
| 5 | Force-quit and relaunch | App opens to home; relay status shows "Connected" (to the local relay) |

---

## Traceability Matrix

Every acceptance criterion mapped to its automated test and/or manual verification step.

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| relay-url-config.AC1.1 | -- | Phase 4: verify config screen appears first on fresh launch |
| relay-url-config.AC1.2 | -- | Phase 4: accept default URL, verify advancement to welcome |
| relay-url-config.AC1.3 | -- | Phase 4: enter custom URL, verify advancement to welcome |
| relay-url-config.AC1.4 | -- | Phase 4: enter invalid/unreachable URL, verify screen blocks advancement |
| relay-url-config.AC2.1 | -- | Phase 4: verify input pre-filled with `https://relay.ezpds.com` |
| relay-url-config.AC3.1 | -- | Phase 4: save URL, force-quit, relaunch, verify config screen is skipped |
| relay-url-config.AC3.2 | `relay_url_round_trips_through_keychain` + `get_relay_url_returns_none_before_save` | -- |
| relay-url-config.AC4.1 | -- | Phase 3: connect to a live relay, verify acceptance |
| relay-url-config.AC4.2 | -- | Phase 3/4: enter unreachable URL, verify inline error |
| relay-url-config.AC4.3 | `normalize_relay_url_rejects_non_http_schemes` + `normalize_relay_url_rejects_malformed_input` + `normalize_relay_url_accepts_http_and_https` | -- |
| relay-url-config.AC4.4 | `normalize_relay_url_strips_trailing_slash` | -- |
| relay-url-config.AC5.1 | -- | Phase 4: relaunch with saved URL, verify config screen skipped |
| relay-url-config.AC5.2 | -- | Phase 3: save URL, then proceed through onboarding in same session |
| relay-url-config.AC6.1 | -- | Phase 4: verify spinner during health check |
| relay-url-config.AC6.2 | -- | Phase 4: verify `INVALID_URL` inline error display |
| relay-url-config.AC6.3 | -- | Phase 4: verify `UNREACHABLE` inline error display |

---

## Summary

- **Total acceptance criteria:** 16
- **Automated test coverage:** 3 criteria (AC3.2, AC4.3, AC4.4 -- Rust unit tests in `lib.rs`)
- **Human verification required:** 13 criteria (UI rendering, navigation gating, live relay health check, Keychain persistence across restarts)
- **End-to-end scenarios:** 5

### Prerequisites for Human Verification

- macOS with Xcode installed
- iOS Simulator available (iPhone target)
- `cargo tauri ios dev` running successfully
- A relay instance accessible from the simulator (local via `cargo run -p relay` or remote production)
- `cargo test -p identity-wallet` passing (all Phase 3 automated tests green)
