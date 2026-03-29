# plc-key-management.AC5: Test Requirements

**Feature:** plc-key-management -- Import Flow Frontend (AC5)
**Design plan:** `docs/design-plans/2026-03-28-plc-key-management.md`
**Implementation plan:** `docs/implementation-plans/2026-03-28-plc-key-management/` (Phases 1--5)
**Last verified:** 2026-03-29

---

## Acceptance Criteria Index

Every AC5 acceptance criterion from the design plan, mapped to its implementing phase and test strategy.

### plc-key-management.AC5: Import flow frontend

| ID | Criterion | Phase | Test Strategy |
|----|-----------|-------|---------------|
| plc-key-management.AC5.1 | Mode selector on first launch shows "Create new identity" and "I have an identity" options | Phase 1 | Human Verification |
| plc-key-management.AC5.2 | App skips mode selector and goes to home when `listIdentities()` returns non-empty | Phase 1 | Human Verification |
| plc-key-management.AC5.3 | Identity input screen resolves a handle and displays current PDS + rotation key state | Phase 2 | Human Verification |
| plc-key-management.AC5.4 | Identity input screen shows inline error for unresolvable handle | Phase 2 | Human Verification |
| plc-key-management.AC5.5 | PDS auth screen triggers OAuth and proceeds after `auth_ready` event | Phase 3 | Human Verification |
| plc-key-management.AC5.6 | Email verification screen sends token and shows verified operation diff | Phase 3 | Human Verification |
| plc-key-management.AC5.7 | Email verification screen shows inline error for invalid token and stays on same screen | Phase 3 | Human Verification |
| plc-key-management.AC5.8 | Review operation screen displays added/removed keys and changed services clearly | Phase 4 | Human Verification |
| plc-key-management.AC5.9 | Review operation screen blocks submission and shows warning when verification detects suspicious changes | Phase 4 | Human Verification |
| plc-key-management.AC5.10 | Claim success screen shows updated DID doc and navigates to home | Phase 4 | Human Verification |
| plc-key-management.AC5.11 | Multi-identity home shows all claimed identities as cards with rotation key status badges | Phase 5 | Human Verification |
| plc-key-management.AC5.12 | "+" button on home navigates back to mode selector to add another identity | Phase 5 | Human Verification |
| plc-key-management.AC5.13 | Existing onboarding flow (create new identity) remains functional and unchanged | Phase 1, 5 | Human Verification |

---

## Automated Test Coverage

No new automated tests are required for AC5. The three Tauri commands introduced across these phases (`list_identities`, `get_stored_did_doc`, `get_device_key_id`) are thin wrappers around `IdentityStore` methods that are already covered by unit tests in `apps/identity-wallet/src-tauri/src/identity_store.rs`. The claim flow IPC commands (`resolveIdentity`, `startPdsAuth`, `requestClaimVerification`, `signAndVerifyClaim`, `submitClaim`) are tested by their respective AC groups (AC1--AC4) and are not retested at the frontend integration layer.

All frontend changes are Svelte 5 screen components rendered inside a Tauri WKWebView on iOS. The project has no browser-based component test harness (no Vitest, Playwright, or similar), so UI behavior is verified manually on the iOS Simulator.

**Existing automated tests that support AC5 (run with `cargo test -p identity-wallet`):**

| Method | Test File | Verifies |
|--------|-----------|----------|
| `IdentityStore::list_identities()` | `identity_store.rs` | Round-trip of managed-dids array; empty and populated cases |
| `IdentityStore::get_did_doc()` | `identity_store.rs` | DID doc storage and retrieval; `None` for missing docs |
| `IdentityStore::get_or_create_device_key()` | `identity_store.rs` | Per-DID key generation; idempotency; cross-DID isolation |
| `resolve_identity()` | `claim.rs` | Identity resolution with PDS discovery and rotation key extraction |
| `sign_and_verify_claim()` | `claim.rs` | Claim signing, diff generation, warning population, verification failures |
| `submit_claim()` | `claim.rs` | PLC directory submission and identity persistence |

---

## Human Verification Required

All 13 AC5 criteria require human verification on the iOS Simulator. These criteria cover UI rendering, screen transitions, user interaction, and state machine wiring that cannot be exercised without the Tauri runtime and WKWebView.

### Prerequisites

- macOS with Xcode installed
- iOS Simulator available (iPhone target)
- `cargo tauri ios dev` running successfully from `apps/identity-wallet/`
- An existing AT Protocol identity on a reachable PDS (e.g., a Bluesky account) for the import flow
- Access to the email address associated with that identity (for verification code)
- `cargo test -p identity-wallet` passing (all existing Rust tests green)

---

### plc-key-management.AC5.1: Mode selector on first launch

**Criterion:** Mode selector on first launch shows "Create new identity" and "I have an identity" options.

**Why manual:** UI rendering in WKWebView; requires fresh app state with no Keychain entries.

**Steps:**
1. Reset the iOS Simulator (Device > Erase All Content and Settings).
2. Launch the app via `cd apps/identity-wallet && cargo tauri ios dev`.
3. **Verify:** The first screen displayed is the mode selector (not the relay config screen).
4. **Verify:** The screen shows the heading "Identity Wallet" and tagline "Your self-sovereign identity, in your pocket."
5. **Verify:** Two buttons are visible: "Create new identity" (primary) and "I have an identity" (secondary).
6. **Verify:** Both buttons are tappable and not disabled.

---

### plc-key-management.AC5.2: App skips mode selector when identities exist

**Criterion:** App skips mode selector and goes to home when `listIdentities()` returns non-empty.

**Why manual:** Requires Keychain state from a previously completed claim or identity creation flow. The `listIdentities()` Tauri command reads from the iOS Keychain, which is not available in `cargo test`.

**Steps:**
1. Start from a state where at least one identity has been claimed or created (complete the full onboarding or import flow first).
2. Force-quit the app (swipe up from app switcher or stop the dev server).
3. Relaunch the app via `cargo tauri ios dev`.
4. **Verify:** The mode selector screen does NOT appear.
5. **Verify:** The app navigates directly to the home screen (IdentityListHome showing identity cards).

---

### plc-key-management.AC5.3: Identity input screen resolves a handle

**Criterion:** Identity input screen resolves a handle and displays current PDS + rotation key state.

**Why manual:** Requires network call to resolve a real handle via DNS/HTTP and fetch the DID document from plc.directory, plus visual inspection of the resolved identity card.

**Steps:**
1. From the mode selector (AC5.1 state), tap "I have an identity".
2. **Verify:** The identity input screen appears with a text input, "Resolve" button, and "Back" button.
3. Enter a valid AT Protocol handle (e.g., your Bluesky handle like `yourname.bsky.social`).
4. Tap "Resolve".
5. **Verify:** A loading state appears while resolution is in progress.
6. **Verify:** On success, an identity info card appears showing:
   - Handle: `@yourname.bsky.social`
   - DID: truncated `did:plc:...`
   - PDS URL: the PDS endpoint (e.g., `https://morel.us-east.host.bsky.network`)
   - Rotation key status: either "Your device is the root key" (green) or "Device key is not the root key" (neutral)
7. **Verify:** A "Continue" button appears below the identity card.
8. Tap "Back" and verify navigation returns to the mode selector.

---

### plc-key-management.AC5.4: Identity input screen shows error for unresolvable handle

**Criterion:** Identity input screen shows inline error for unresolvable handle.

**Why manual:** Requires network call that fails, plus visual inspection of error display and screen retention.

**Steps:**
1. From the mode selector, tap "I have an identity".
2. Enter a handle that does not exist (e.g., `this-handle-definitely-does-not-exist-12345.test`).
3. Tap "Resolve".
4. **Verify:** A loading state appears briefly.
5. **Verify:** An inline error message appears: "Handle not found. Check the spelling and try again."
6. **Verify:** The user remains on the identity input screen (no navigation occurred).
7. **Verify:** The "Continue" button does NOT appear (no resolved identity).
8. Clear the input, enter a valid handle, and tap "Resolve".
9. **Verify:** The error clears and the identity info card appears (recovery works).

---

### plc-key-management.AC5.5: PDS auth screen triggers OAuth and proceeds

**Criterion:** PDS auth screen triggers OAuth and proceeds after `auth_ready` event.

**Why manual:** Requires PDS OAuth flow via Safari, deep-link callback routing through iOS, and visual observation of screen transitions.

**Steps:**
1. Complete AC5.3 (resolve a handle successfully).
2. Tap "Continue" on the identity input screen.
3. **Verify:** The PDS auth screen appears, showing the PDS URL and an "Authenticate with PDS" button.
4. **Verify:** A "Back" button is visible to return to identity input.
5. Tap "Authenticate with PDS".
6. **Verify:** A spinner appears with text "Opening browser for PDS authentication..."
7. **Verify:** Safari opens with the PDS OAuth authorization page.
8. Complete the OAuth authorization in Safari (approve the request).
9. **Verify:** Safari redirects back to the app via deep link.
10. **Verify:** The app advances to the email verification screen.

---

### plc-key-management.AC5.6: Email verification screen sends token and shows verified operation diff

**Criterion:** Email verification screen sends token and shows verified operation diff.

**Why manual:** Requires a live PDS to send the verification email, user interaction to enter the token received via email, and visual inspection of the verified operation diff display.

**Steps:**
1. Complete AC5.5 (PDS auth succeeded, now on the email verification screen).
2. **Verify:** On mount, a spinner appears with "Sending verification email..."
3. **Verify:** After the email is sent, the screen shows: instruction text ("A verification code has been sent to your email..."), a text input for the token, and a "Verify" button.
4. Check your email for the verification code from the PDS.
5. Enter the verification code in the token input field.
6. Tap "Verify".
7. **Verify:** A loading state appears while verification is in progress.
8. **Verify:** On success, the app navigates to the review operation screen (AC5.8).

---

### plc-key-management.AC5.7: Email verification screen shows error for invalid token

**Criterion:** Email verification screen shows inline error for invalid token and stays on same screen.

**Why manual:** Requires a live PDS to reject an invalid token, plus visual inspection of error display and screen retention.

**Steps:**
1. Complete AC5.5 (PDS auth succeeded, now on the email verification screen).
2. Wait for the "Sending verification email..." step to complete.
3. Enter an obviously invalid token (e.g., `000000` or `invalid`).
4. Tap "Verify".
5. **Verify:** An inline error message appears: "Invalid or expired verification code. Check your email and try again."
6. **Verify:** The user remains on the email verification screen (no navigation occurred).
7. **Verify:** The token input field is still editable.
8. Clear the input, enter the correct token from your email, and tap "Verify".
9. **Verify:** The error clears and the flow advances to the review operation screen (recovery works).

---

### plc-key-management.AC5.8: Review operation screen displays operation diff clearly

**Criterion:** Review operation screen displays added/removed keys and changed services clearly.

**Why manual:** Requires visual inspection of the color-coded diff display (green for added, red for removed, yellow for modified) and layout of the operation summary.

**Steps:**
1. Complete AC5.6 (email verification succeeded, now on the review operation screen).
2. **Verify:** The review screen displays the following sections:
   - **Keys section:** Shows keys being added (green, `+` prefix -- this should include your device's key) and keys being removed (red, `-` prefix), or "No key changes" if none.
   - **Services section:** Shows service changes (added/removed/modified) or "No service changes" if none.
3. **Verify:** Key values are displayed in monospace font, truncated for mobile (first 20 characters + "...").
4. **Verify:** Color coding is correct: added items in green (`#22c55e`), removed items in red (`#ef4444`), modified items in amber (`#f59e0b`).
5. **Verify:** A "Confirm & Submit" primary button and "Cancel" secondary button are visible at the bottom.

---

### plc-key-management.AC5.9: Review operation screen blocks submission on warnings

**Criterion:** Review operation screen blocks submission and shows warning when verification detects suspicious changes.

**Why manual:** Requires a claim operation that produces warnings. This scenario is difficult to trigger with a production PDS, so this may require a controlled test environment where the PDS returns an operation with unexpected changes.

**Steps (if warnings are present in the operation):**
1. Arrive at the review operation screen with a `VerifiedClaimOp` that contains warnings (non-empty `warnings` array).
2. **Verify:** Warning messages are displayed in amber/yellow highlighted boxes with distinct styling from regular info.
3. **Verify:** The "Confirm & Submit" button is disabled (grayed out, not tappable).
4. **Verify:** A checkbox appears below the warnings: "I understand these warnings and want to proceed."
5. Tap the checkbox to acknowledge the warnings.
6. **Verify:** The "Confirm & Submit" button becomes enabled (tappable).
7. Untap the checkbox.
8. **Verify:** The button becomes disabled again.

**Steps (if no warnings are present):**
1. Arrive at the review operation screen with a `VerifiedClaimOp` that has an empty `warnings` array.
2. **Verify:** No warning section or checkbox is displayed.
3. **Verify:** The "Confirm & Submit" button is enabled by default (not blocked).

**Note:** Both paths should be tested. If a controlled PDS environment is not available to produce warnings, verify the no-warnings path on a production PDS and visually inspect the code to confirm the warnings path is correctly wired.

---

### plc-key-management.AC5.10: Claim success screen shows updated DID doc and navigates to home

**Criterion:** Claim success screen shows updated DID doc and navigates to home.

**Why manual:** Requires the full claim submission to plc.directory to succeed, then visual inspection of the success screen and navigation to the home screen.

**Steps:**
1. Complete AC5.8 (on the review operation screen with no warnings, or acknowledge warnings per AC5.9).
2. Tap "Confirm & Submit".
3. **Verify:** A loading state appears while the claim is being submitted to plc.directory.
4. **Verify:** On success, the claim success screen appears with:
   - A green checkmark icon or circle
   - Heading: "Identity Claimed Successfully"
   - Description text about rotation key control
   - A DID document summary card showing: DID, handle, and PDS endpoint
5. **Verify:** A "Done" button is visible.
6. Tap "Done".
7. **Verify:** The app navigates to the home screen (IdentityListHome).
8. **Verify:** The claimed identity appears as a card on the home screen.

---

### plc-key-management.AC5.11: Multi-identity home shows identity cards with status badges

**Criterion:** Multi-identity home shows all claimed identities as cards with rotation key status badges.

**Why manual:** Requires multiple identities in the Keychain (from both onboarding and import flows), plus visual inspection of identity cards with rotation key status badges.

**Steps:**
1. Claim at least two identities (one via "Create new identity" and one via "I have an identity", or two via import).
2. Navigate to or relaunch to the home screen.
3. **Verify:** The home screen (IdentityListHome) displays one card per identity.
4. **Verify:** Each card shows:
   - A DID avatar
   - Handle (e.g., `@yourname.bsky.social`) or "Unknown handle" if unavailable
   - Truncated DID
   - PDS endpoint
5. **Verify:** Each card has a rotation key status badge:
   - Green "Root Key" badge if the device key is the primary rotation key (`rotationKeys[0]`)
   - Amber "Not Root" badge if the device key is not the primary rotation key
   - Gray "Unknown" badge if status could not be determined
6. **Verify:** Tapping a card navigates to the identity detail view (DIDDocumentScreen) for that identity.
7. **Verify:** The detail view shows the full DID document with a "Back" button that returns to the home screen.

---

### plc-key-management.AC5.12: "+" button navigates to mode selector

**Criterion:** "+" button on home navigates back to mode selector to add another identity.

**Why manual:** Requires visual inspection of the "+" button and navigation to the mode selector.

**Steps:**
1. From the home screen (IdentityListHome) with at least one identity.
2. **Verify:** An "Add Identity" button is visible at the bottom of the identity list.
3. Tap the "Add Identity" button.
4. **Verify:** The app navigates to the mode selector screen.
5. **Verify:** Both options ("Create new identity" and "I have an identity") are available.
6. Tap "I have an identity" and begin a second import flow.
7. **Verify:** The import flow works correctly (the previous identity is not affected).
8. After completing the second import, verify the home screen shows both identities.

---

### plc-key-management.AC5.13: Existing onboarding flow remains functional

**Criterion:** Existing onboarding flow (create new identity) remains functional and unchanged.

**Why manual:** Regression test requiring the full onboarding flow through all existing screens, verifying no behavioral changes from the import flow additions.

**Steps:**
1. Reset the iOS Simulator (Erase All Content and Settings).
2. Launch the app via `cargo tauri ios dev`.
3. **Verify:** The mode selector screen appears (AC5.1).
4. Tap "Create new identity".
5. **Verify:** The relay config screen appears (or is skipped if a relay URL is already saved).
6. Enter a valid relay URL (e.g., `https://relay.ezpds.com` or `http://localhost:2583`) and tap Connect.
7. **Verify:** The welcome screen appears with the "Get Started" button.
8. Proceed through the full onboarding flow:
   - Welcome > Claim Code > Email > Handle > Password > Loading > DID Ceremony > DID Success > Shamir Backup > Handle Registration > Complete > Authenticating
9. **Verify:** Each screen renders correctly with proper inputs, buttons, and transitions.
10. **Verify:** The onboarding completes and the app arrives at the home screen (IdentityListHome).
11. **Verify:** The newly created identity appears as a card on the home screen with the correct handle and DID.
12. Force-quit and relaunch the app.
13. **Verify:** The app opens directly to the home screen (skips mode selector per AC5.2).

---

## End-to-End Scenarios

### E2E-1: First launch -- import existing identity

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

### E2E-2: Multiple identities -- create then import

| Step | Action | Expected |
|------|--------|----------|
| 1 | Reset the iOS Simulator | Simulator is clean |
| 2 | Launch the app, tap "Create new identity" | Relay config screen appears |
| 3 | Complete full onboarding (relay config through auth) | Home screen shows one identity card |
| 4 | Tap "Add Identity" button | Mode selector appears |
| 5 | Tap "I have an identity" | Identity input screen appears |
| 6 | Complete import flow (steps 4--10 from E2E-1) | Claim success screen appears |
| 7 | Tap "Done" | Home screen shows two identity cards with status badges |
| 8 | Force-quit and relaunch | Home screen appears directly with both cards |

### E2E-3: Import flow error recovery

| Step | Action | Expected |
|------|--------|----------|
| 1 | From mode selector, tap "I have an identity" | Identity input screen appears |
| 2 | Enter an invalid handle, tap "Resolve" | Inline error: "Handle not found..." |
| 3 | Clear input, enter a valid handle, tap "Resolve" | Identity card appears; error clears |
| 4 | Tap "Continue", then tap "Authenticate with PDS" | Safari opens |
| 5 | Cancel or deny OAuth in Safari | Error message on PDS auth screen |
| 6 | Tap "Authenticate with PDS" again | Safari reopens for retry |
| 7 | Complete OAuth successfully | Email verification screen appears |
| 8 | Enter wrong verification code, tap "Verify" | Inline error: "Invalid or expired verification code..." |
| 9 | Enter correct code, tap "Verify" | Review operation screen appears; error clears |
| 10 | Tap "Cancel" on review screen | Returns to identity input screen |

### E2E-4: Returning user skips mode selector

| Step | Action | Expected |
|------|--------|----------|
| 1 | Complete E2E-1 (at least one identity claimed) | Home screen visible |
| 2 | Force-quit the app completely | App terminated |
| 3 | Relaunch the app | Home screen appears directly (mode selector skipped) |
| 4 | Verify identity cards are displayed | All previously claimed identities shown with correct data |

---

## Traceability Matrix

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| plc-key-management.AC5.1 | -- | Mode selector with two buttons on fresh launch |
| plc-key-management.AC5.2 | `IdentityStore::list_identities()` tests (underlying method) | Relaunch with existing identities skips to home |
| plc-key-management.AC5.3 | `resolve_identity()` tests (underlying method) | Enter handle, tap Resolve, verify identity card |
| plc-key-management.AC5.4 | `resolve_identity()` error path tests (underlying method) | Enter bad handle, verify inline error, verify screen retention |
| plc-key-management.AC5.5 | `start_pds_auth()` tests (underlying method) | Tap Authenticate, verify Safari opens, complete OAuth |
| plc-key-management.AC5.6 | `sign_and_verify_claim()` tests (underlying method) | Enter correct token, verify flow advances |
| plc-key-management.AC5.7 | `sign_and_verify_claim()` INVALID_TOKEN test (underlying method) | Enter wrong token, verify inline error, verify screen retention |
| plc-key-management.AC5.8 | -- | Inspect diff display: added/removed keys, changed services, color coding |
| plc-key-management.AC5.9 | -- | Verify button disabled with warnings, checkbox enables it |
| plc-key-management.AC5.10 | `submit_claim()` tests (underlying method) | Verify success screen content, tap Done, verify home navigation |
| plc-key-management.AC5.11 | `IdentityStore::get_did_doc()` + `get_or_create_device_key()` tests | Verify multi-identity cards with rotation key status badges |
| plc-key-management.AC5.12 | -- | Tap "+" button, verify mode selector appears |
| plc-key-management.AC5.13 | -- | Full onboarding regression: mode selector > create > relay > onboarding > home |

---

## Summary

- **Total acceptance criteria:** 13 (AC5.1 through AC5.13)
- **Automated test coverage:** 0 new tests required (all Tauri commands are thin wrappers around already-tested `IdentityStore` and claim module methods)
- **Human verification required:** 13 criteria (all are UI-level behaviors requiring iOS Simulator)
- **End-to-end scenarios:** 4

### Test Execution Commands

```bash
# Verify all existing Rust backend tests pass (prerequisite for human verification)
cargo test -p identity-wallet

# Verify TypeScript types compile
cd apps/identity-wallet && pnpm check

# Verify Rust compiles
cargo build -p identity-wallet --lib

# Launch for manual testing
cd apps/identity-wallet && cargo tauri ios dev
```
