# Test Plan: Relay URL Configuration

**Feature:** relay-url-config
**Implementation plan:** docs/implementation-plans/2026-03-27-relay-url-config/
**Base SHA:** 50df3fa05b5a83fe9bbc475745358095cfa70dc0
**Head SHA:** 34b49276acda0ec11d7ddfc1b7280ad8d9775d42
**Generated:** 2026-03-27

---

## Automated Test Coverage

All 6 automatable criteria pass. Run with:

```bash
cargo test --manifest-path apps/identity-wallet/src-tauri/Cargo.toml -- normalize_relay_url get_relay_url relay_url
```

| Test | Criterion |
|------|-----------|
| `normalize_relay_url_rejects_non_http_schemes` | AC4.3 — `ftp://` and `ws://` rejected |
| `normalize_relay_url_rejects_malformed_input` | AC4.3 — empty string and non-URL rejected |
| `normalize_relay_url_accepts_http_and_https` | AC4.3 — `http://` and `https://` accepted |
| `normalize_relay_url_strips_trailing_slash` | AC4.4 — trailing slash normalized |
| `relay_url_round_trips_through_keychain` | AC3.2 — store/load round-trip |
| `get_relay_url_returns_none_before_save` | AC3.2 — `None` before any save |

---

## Prerequisites

- macOS with Xcode installed (Ventura 13 or later)
- iOS Simulator available (iPhone target)
- Nix dev shell entered from the workspace root: `nix develop --impure --accept-flake-config`
- Frontend dependencies installed: `cd apps/identity-wallet && pnpm install`
- Xcode project generated: `cargo tauri ios init`
- `cargo test -p identity-wallet` passes (all 6 automated tests green)
- A relay instance accessible from the simulator (local via `cargo run -p relay`, or the remote relay at `https://relay.ezpds.com`)

---

## Phase 3: IPC Commands (live relay required)

| Step | Action | Expected |
|------|--------|----------|
| 3.1 | Start a local relay: from the workspace root, run `cargo run -p relay` | Relay starts and listens on `http://localhost:2583` |
| 3.2 | In a second terminal, launch the app: `cd apps/identity-wallet && cargo tauri ios dev` | App builds and opens in the iOS Simulator |
| 3.3 | On the relay config screen, clear the pre-filled URL and type `http://localhost:2583` | The URL input shows `http://localhost:2583` |
| 3.4 | Tap the "Connect" button | A spinner appears briefly, then the app advances to the welcome screen. Verifies AC4.1. |
| 3.5 | Force-quit the app in the Simulator | App is terminated |
| 3.6 | Relaunch the app | The relay config screen does NOT appear; the app starts at the welcome screen. Verifies AC3.1. |
| 3.7 | Reset the simulator, relaunch, enter `https://does-not-exist.example.com` | The input shows the unreachable URL |
| 3.8 | Tap "Connect" | A spinner appears, then an inline error: "Could not reach the relay. Check the URL and try again." You remain on the config screen. Verifies AC4.2. |
| 3.9 | Reset the simulator, configure with a valid relay URL, tap Connect | App advances to the welcome screen |
| 3.10 | Proceed through full onboarding (claim code, email, handle, password, DID ceremony, Shamir backup, handle registration) | Each step completes successfully. All relay IPC commands use the URL saved in step 3.9. Verifies AC5.2. |

---

## Phase 4: Frontend Relay Configuration Screen

| Step | Action | Expected |
|------|--------|----------|
| 4.1 | Reset the iOS Simulator (Device > Erase All Content and Settings) | Simulator state is clean |
| 4.2 | Launch the app via `cargo tauri ios dev` | The first screen shown is the relay configuration screen with header "Connect to Relay". Verifies AC1.1. |
| 4.3 | Inspect the URL input field without modifying it | Input contains exactly `https://relay.ezpds.com`. Verifies AC2.1. |
| 4.4 | Tap Connect without modifying the URL (production relay must be reachable) | A spinner appears, then the app advances to the welcome screen. Verifies AC1.2. |
| 4.5 | Reset the simulator, relaunch the app | Relay config screen appears again |
| 4.6 | Clear the URL input, type `http://localhost:2583` (local relay must be running) | Input shows the custom URL |
| 4.7 | Tap "Connect" | Spinner appears, then app advances to the welcome screen. Verifies AC1.3. |
| 4.8 | Reset the simulator, relaunch the app | Relay config screen appears |
| 4.9 | Enter `https://does-not-exist.example.com` and tap "Connect" | An inline error message appears; you remain on the config screen |
| 4.10 | Clear the field, type `notaurl`, and observe the Connect button | Connect button is disabled (format check fails). Verifies AC1.4. |
| 4.11 | Configure with a valid URL and tap Connect, then force-quit the app | App advances past relay config, then is terminated |
| 4.12 | Relaunch the app | The relay config screen does NOT appear; the app starts at the welcome screen (or home if previously authenticated). Verifies AC3.1 and AC5.1. |
| 4.13 | On the relay config screen (fresh state), enter a valid relay URL and tap "Connect" | The "Connect" button is replaced by a spinning indicator. The URL input field is disabled during loading. Verifies AC6.1. |
| 4.14 | On the relay config screen, type `notaurl` and tap "Connect" | An inline error appears: "Invalid URL — must start with http:// or https://". The input border turns red. You remain on the config screen. Verifies AC6.2. |
| 4.15 | Clear the field, enter `https://does-not-exist.example.com`, and tap "Connect" | A spinner appears, then inline error: "Could not reach the relay. Check the URL and try again." You remain on the config screen. Verifies AC6.3. |

---

## End-to-End Scenarios

### E2E-1 — First launch, configure relay, begin onboarding

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Relay config screen appears with "Connect to Relay" header |
| 3 | Verify the URL input is pre-filled | Input contains `https://relay.ezpds.com` |
| 4 | Tap Connect (with a reachable relay) | Spinner, then app advances to the welcome screen |
| 5 | Verify the welcome screen | "Get Started" button is visible and tappable |

### E2E-2 — Invalid URL, then recovery

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Relay config screen appears |
| 3 | Type `notaurl` in the URL field | Connect button is disabled (format check prevents submission) |
| 4 | Type `https://does-not-exist.example.com` and tap Connect | Spinner, then inline error: "Could not reach the relay. Check the URL and try again." |
| 5 | Clear the field, enter a valid relay URL, tap Connect | Previous error clears; spinner, then app advances to welcome screen |

### E2E-3 — Returning user, relay config screen skipped

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start from a state where relay URL is saved (E2E-1 completed) | App is on welcome screen or further |
| 2 | Force-quit the app | App is terminated |
| 3 | Relaunch the app | App opens directly to the welcome screen (not the relay config screen) |
| 4 | If OAuth tokens exist in Keychain, verify home screen | Home screen with identity card is displayed |

### E2E-4 — Full journey, relay config through account creation

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Relay config screen appears |
| 3 | Enter a valid relay URL and tap Connect | App advances to the welcome screen |
| 4 | Proceed through full onboarding (claim code, email, handle, password, DID ceremony, Shamir backup, handle registration) | Each step completes successfully using the saved relay URL |
| 5 | After the `complete` step, verify the home screen | Identity card shows handle, DID, email |
| 6 | Force-quit and relaunch | App opens to home screen (both relay URL and OAuth tokens restored from Keychain) |

### E2E-5 — Custom relay URL, self-hosted deployment

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start a local relay: `cargo run -p relay` | Relay listening on `http://localhost:2583` |
| 2 | Reset the iOS Simulator and launch the app | Relay config screen appears |
| 3 | Clear default URL, enter `http://localhost:2583`, tap Connect | Spinner, then app advances to welcome screen |
| 4 | Proceed through onboarding | All commands succeed against the local relay |
| 5 | Force-quit and relaunch | App opens to home; local relay is still used |

---

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| relay-url-config.AC1.1 | — | Phase 4: 4.2 |
| relay-url-config.AC1.2 | — | Phase 4: 4.3–4.4 |
| relay-url-config.AC1.3 | — | Phase 4: 4.6–4.7 |
| relay-url-config.AC1.4 | — | Phase 4: 4.9–4.10 |
| relay-url-config.AC2.1 | — | Phase 4: 4.3 |
| relay-url-config.AC3.1 | — | Phase 4: 4.12 |
| relay-url-config.AC3.2 | `relay_url_round_trips_through_keychain`, `get_relay_url_returns_none_before_save` | — |
| relay-url-config.AC4.1 | — | Phase 3: 3.4 |
| relay-url-config.AC4.2 | — | Phase 3: 3.7–3.8 |
| relay-url-config.AC4.3 | `normalize_relay_url_rejects_non_http_schemes`, `normalize_relay_url_rejects_malformed_input`, `normalize_relay_url_accepts_http_and_https` | — |
| relay-url-config.AC4.4 | `normalize_relay_url_strips_trailing_slash` | — |
| relay-url-config.AC5.1 | — | Phase 4: 4.12 |
| relay-url-config.AC5.2 | — | Phase 3: 3.9–3.10 |
| relay-url-config.AC6.1 | — | Phase 4: 4.13 |
| relay-url-config.AC6.2 | — | Phase 4: 4.14 |
| relay-url-config.AC6.3 | — | Phase 4: 4.15 |
