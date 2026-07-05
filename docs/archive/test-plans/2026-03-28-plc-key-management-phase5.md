# Human Test Plan: Claim Flow Frontend (Import Screens + Multi-Identity)

**Implementation plan:** `docs/implementation-plans/2026-03-28-plc-key-management/` (phases 1-5)
**Generated:** 2026-03-29

## Prerequisites

- macOS with Xcode installed (latest stable)
- iOS Simulator available (iPhone target)
- Nix dev shell active from workspace root: `nix develop --impure --accept-flake-config`
- Frontend dependencies installed: `cd apps/identity-wallet && pnpm install`
- Xcode project generated: `cargo tauri ios init` (with PATH patch and sandbox disabling per `apps/identity-wallet/CLAUDE.md`)
- TypeScript types compiling: `cd apps/identity-wallet && pnpm check`
- Rust compiling: `cargo build -p identity-wallet --lib`
- An existing AT Protocol identity on a reachable PDS (e.g., a Bluesky account) for the import flow
- Access to the email address associated with that identity (for the verification code)
- App launched via `cd apps/identity-wallet && cargo tauri ios dev`

---

## Phase 1: Mode Selector and Identity-Aware Routing

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator: Device > Erase All Content and Settings | Simulator is clean; no Keychain entries |
| 2 | Launch the app via `cd apps/identity-wallet && cargo tauri ios dev` | App compiles and opens in the Simulator |
| 3 | Observe the first screen | The mode selector screen is displayed (NOT the relay config screen). Heading reads "Identity Wallet" with tagline "Your self-sovereign identity, in your pocket." |
| 4 | Verify two buttons are visible | "Create new identity" button (primary/prominent styling) and "I have an identity" button (secondary styling) are both visible |
| 5 | Tap each button area to confirm interactivity | Both buttons respond to taps (visual feedback on press); neither is disabled or grayed out |

**Covers:** plc-key-management.AC5.1

---

## Phase 2: Identity Input and Resolution

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the mode selector, tap "I have an identity" | Identity input screen appears with: a text input field, a "Resolve" button, and a "Back" button |
| 2 | Enter a handle that does not exist: `this-handle-definitely-does-not-exist-12345.test` | Text appears in the input field |
| 3 | Tap "Resolve" | A loading indicator appears briefly |
| 4 | Observe the screen after loading | Inline error message: "Handle not found. Check the spelling and try again." The user remains on the identity input screen. No "Continue" button is visible |
| 5 | Clear the text input completely | Input field is empty |
| 6 | Enter your valid AT Protocol handle (e.g., `yourname.bsky.social`) | Handle text appears in the input field |
| 7 | Tap "Resolve" | A loading indicator appears while resolution is in progress |
| 8 | Observe the resolved identity card | Card displays: Handle (e.g., `@yourname.bsky.social`), DID (truncated `did:plc:...`), PDS URL (e.g., `https://morel.us-east.host.bsky.network`), Rotation key status (either "Your device is the root key" in green or "Device key is not the root key" in neutral styling) |
| 9 | Verify "Continue" button appeared | A "Continue" button is visible below the identity card |
| 10 | Verify error message cleared | The previous "Handle not found" error is no longer displayed |
| 11 | Tap "Back" | Navigation returns to the mode selector screen with both buttons visible |

**Covers:** plc-key-management.AC5.3, plc-key-management.AC5.4

---

## Phase 3: PDS Authentication and Email Verification

| Step | Action | Expected |
|------|--------|----------|
| 1 | From mode selector, tap "I have an identity", enter your valid handle, tap "Resolve", then tap "Continue" | PDS auth screen appears showing the PDS URL and an "Authenticate with PDS" button. A "Back" button is visible |
| 2 | Tap "Authenticate with PDS" | A spinner appears with text "Opening browser for PDS authentication..." then Safari opens with the PDS OAuth authorization page |
| 3 | Complete the OAuth authorization in Safari (approve the request) | Safari redirects back to the app via deep link. The app advances to the email verification screen |
| 4 | Observe the email verification screen on mount | A spinner appears with "Sending verification email..." |
| 5 | Wait for the email sending to complete | The screen shows: instruction text ("A verification code has been sent to your email..."), a text input for the token, and a "Verify" button |
| 6 | Enter an invalid token: `000000` | Text appears in the token input |
| 7 | Tap "Verify" | An inline error message appears: "Invalid or expired verification code. Check your email and try again." The user remains on the email verification screen. The token input is still editable |
| 8 | Clear the input and enter the correct verification code from your email | Correct code is in the input field |
| 9 | Tap "Verify" | The error clears. A loading state appears. On success, the app navigates to the review operation screen |

**Covers:** plc-key-management.AC5.5, plc-key-management.AC5.6, plc-key-management.AC5.7

---

## Phase 4: Review Operation and Claim Submission

| Step | Action | Expected |
|------|--------|----------|
| 1 | Observe the review operation screen | The screen displays: **Keys section** showing keys being added (green, `+` prefix) and/or keys being removed (red, `-` prefix), or "No key changes". **Services section** showing service changes or "No service changes" |
| 2 | Verify key display formatting | Key values are in monospace font, truncated for mobile (first 20 characters + "...") |
| 3 | Verify color coding | Added items use green (`#22c55e`), removed items use red (`#ef4444`), modified items use amber (`#f59e0b`) |
| 4 | Verify buttons at bottom | "Confirm & Submit" (primary) and "Cancel" (secondary) buttons are visible |
| 5a | **If warnings are present:** observe warning display | Warning messages appear in amber/yellow highlighted boxes. "Confirm & Submit" button is disabled (grayed out). A checkbox appears: "I understand these warnings and want to proceed" |
| 5b | **If warnings present:** tap the acknowledgment checkbox | "Confirm & Submit" button becomes enabled/tappable |
| 5c | **If warnings present:** untap the checkbox | Button becomes disabled again |
| 5d | **If warnings present:** re-tap checkbox to enable, then tap "Confirm & Submit" | Submission proceeds (see step 6) |
| 5e | **If no warnings:** verify no warning section or checkbox is shown | "Confirm & Submit" button is enabled by default |
| 6 | Tap "Confirm & Submit" (with checkbox acknowledged if warnings present) | A loading state appears |
| 7 | Observe the claim success screen | Screen shows: green checkmark icon/circle, heading "Identity Claimed Successfully", description text about rotation key control, DID document summary card showing DID, handle, and PDS endpoint |
| 8 | Verify "Done" button | A "Done" button is visible |
| 9 | Tap "Done" | App navigates to the home screen (IdentityListHome). The claimed identity appears as a card on the home screen |

**Covers:** plc-key-management.AC5.8, plc-key-management.AC5.9, plc-key-management.AC5.10

---

## Phase 5: Multi-Identity Home and Add Identity

| Step | Action | Expected |
|------|--------|----------|
| 1 | Observe the home screen after completing the import flow | IdentityListHome displays one identity card |
| 2 | Verify identity card content | Card shows: DID avatar (colored circle), handle (e.g., `@yourname.bsky.social`) or "Unknown handle", truncated DID, PDS endpoint |
| 3 | Verify rotation key status badge on the card | Green "Root Key" badge if device key is `rotationKeys[0]`, amber "Not Root" if not primary, or gray "Unknown" if undetermined |
| 4 | Tap the identity card | Navigates to identity detail view (DIDDocumentScreen) showing the full DID document |
| 5 | Tap "Back" on detail view | Returns to the home screen |
| 6 | Verify "Add Identity" button | An "Add Identity" button is visible at the bottom of the identity list |
| 7 | Tap "Add Identity" | The mode selector screen appears with both "Create new identity" and "I have an identity" options |

**Covers:** plc-key-management.AC5.11, plc-key-management.AC5.12

---

## Phase 6: Returning User and Onboarding Regression

### AC5.2 -- Returning user skips mode selector

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen with at least one identity claimed (from Phase 4) | Home screen is visible |
| 2 | Force-quit the app (swipe up from app switcher, or stop the dev server) | App is terminated |
| 3 | Relaunch the app via `cargo tauri ios dev` | App opens. The mode selector does NOT appear. The home screen (IdentityListHome) is displayed directly with the previously claimed identity card(s) |

**Covers:** plc-key-management.AC5.2

### AC5.13 -- Onboarding regression

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator (Erase All Content and Settings) | Clean state |
| 2 | Launch the app via `cargo tauri ios dev` | Mode selector screen appears |
| 3 | Tap "Create new identity" | Relay config screen appears (or is skipped if a relay URL is saved) |
| 4 | Enter a valid relay URL (e.g., `https://relay.ezpds.com` or `http://localhost:2583`) and tap Connect | Welcome screen appears with "Get Started" button |
| 5 | Proceed through the full onboarding flow: Welcome > Claim Code > Email > Handle > Password > Loading > DID Ceremony > DID Success > Shamir Backup > Handle Registration > Complete > Authenticating | Each screen renders correctly with proper inputs, buttons, and transitions |
| 6 | Observe the final screen | Onboarding completes; app arrives at IdentityListHome |
| 7 | Verify the identity card | The newly created identity appears as a card with correct handle and DID |
| 8 | Force-quit and relaunch the app | App opens directly to the home screen (mode selector skipped) |

**Covers:** plc-key-management.AC5.13

---

## End-to-End Scenarios

### E2E-1: First Launch Import Existing Identity

Validates the complete import flow from fresh install through claim submission to home screen.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app | Mode selector appears with two options |
| 3 | Tap "I have an identity" | Identity input screen appears |
| 4 | Enter a valid handle and tap "Resolve" | Identity info card displays DID, handle, PDS, rotation key status |
| 5 | Tap "Continue" | PDS auth screen appears with PDS URL |
| 6 | Tap "Authenticate with PDS" | Safari opens for OAuth |
| 7 | Complete OAuth in Safari | App returns to email verification screen |
| 8 | Wait for "Sending verification email..." to complete | Token input form appears |
| 9 | Enter verification code from email, tap "Verify" | Review operation screen appears with diff |
| 10 | Tap "Confirm & Submit" (acknowledge warnings if present) | Claim success screen appears with DID doc summary |
| 11 | Tap "Done" | Home screen shows the claimed identity card with status badge |

### E2E-2: Multiple Identities (Create Then Import)

Validates that both identity creation paths coexist and multi-identity home correctly displays cards from different flows.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app, tap "Create new identity" | Relay config screen appears |
| 3 | Complete full onboarding (relay config through auth) | Home screen shows one identity card |
| 4 | Tap "Add Identity" button | Mode selector appears |
| 5 | Tap "I have an identity" | Identity input screen appears |
| 6 | Complete import flow (resolve handle, PDS auth, email verification, review, submit) | Claim success screen appears |
| 7 | Tap "Done" | Home screen shows two identity cards with status badges |
| 8 | Force-quit and relaunch | Home screen appears directly with both cards |

### E2E-3: Import Flow Error Recovery

Validates that all error states in the import flow are recoverable.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From mode selector, tap "I have an identity" | Identity input screen appears |
| 2 | Enter an invalid handle (`this-handle-definitely-does-not-exist-12345.test`), tap "Resolve" | Inline error: "Handle not found. Check the spelling and try again." |
| 3 | Clear input, enter a valid handle, tap "Resolve" | Identity card appears; error clears |
| 4 | Tap "Continue", then tap "Authenticate with PDS" | Safari opens |
| 5 | Cancel or deny OAuth in Safari | Error message on PDS auth screen |
| 6 | Tap "Authenticate with PDS" again | Safari reopens for retry |
| 7 | Complete OAuth successfully | Email verification screen appears |
| 8 | Enter wrong verification code (`000000`), tap "Verify" | Inline error: "Invalid or expired verification code. Check your email and try again." |
| 9 | Enter correct code, tap "Verify" | Review operation screen appears; error clears |
| 10 | Tap "Cancel" on review screen | Returns to identity input screen |

### E2E-4: Returning User Skips Mode Selector

Validates that Keychain-persisted identity state survives app restart.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Complete E2E-1 (at least one identity claimed) | Home screen visible |
| 2 | Force-quit the app completely | App terminated |
| 3 | Relaunch the app | Home screen appears directly (mode selector skipped) |
| 4 | Verify identity cards are displayed | All previously claimed identities shown with correct data |

---

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| plc-key-management.AC5.1 | -- | Phase 1: Mode selector with two buttons on fresh launch |
| plc-key-management.AC5.2 | `IdentityStore::list_identities()` tests | Phase 6: Relaunch with existing identities skips to home |
| plc-key-management.AC5.3 | `resolve_identity()` tests | Phase 2: Enter handle, tap Resolve, verify identity card |
| plc-key-management.AC5.4 | `resolve_identity()` error path tests | Phase 2: Enter bad handle, verify inline error |
| plc-key-management.AC5.5 | `start_pds_auth()` tests | Phase 3: Tap Authenticate, verify Safari opens, complete OAuth |
| plc-key-management.AC5.6 | `sign_and_verify_claim()` tests | Phase 3: Enter correct token, verify flow advances |
| plc-key-management.AC5.7 | `sign_and_verify_claim()` INVALID_TOKEN test | Phase 3: Enter wrong token, verify inline error |
| plc-key-management.AC5.8 | -- | Phase 4: Inspect diff display with color coding |
| plc-key-management.AC5.9 | -- | Phase 4: Verify button disabled with warnings, checkbox enables it |
| plc-key-management.AC5.10 | `submit_claim()` tests | Phase 4: Verify success screen content, tap Done |
| plc-key-management.AC5.11 | `get_did_doc()` + `get_or_create_device_key()` tests | Phase 5: Verify multi-identity cards with status badges |
| plc-key-management.AC5.12 | -- | Phase 5: Tap "Add Identity", verify mode selector appears |
| plc-key-management.AC5.13 | -- | Phase 6: Full onboarding regression |
