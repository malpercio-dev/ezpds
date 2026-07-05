# Claim Flow Frontend — Phase 3: PdsAuthScreen + EmailVerificationScreen

**Goal:** Create screens for PDS authentication (OAuth to the user's old PDS) and email verification (token input + claim signing). These are the middle steps of the import flow.

**Architecture:** PdsAuthScreen follows the AuthenticatingScreen pattern — calls `startPdsAuth()` on user action, shows spinner while Safari handles OAuth, navigates on promise resolution. EmailVerificationScreen sends the verification email on mount, accepts a token input, and calls `signAndVerifyClaim()` to produce a `VerifiedClaimOp`.

**Tech Stack:** Svelte 5 (runes), TypeScript, Tauri v2 IPC

**Scope:** 3 of 5 implementation phases

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.5 Success:** PdsAuthScreen shows PDS endpoint, user taps Authenticate, Safari opens, and on successful deep-link callback the flow advances to email verification
- **plc-key-management.AC5.6 Failure:** PdsAuthScreen shows error message when PDS auth fails (UNAUTHORIZED, NETWORK_ERROR)
- **plc-key-management.AC5.7 Success:** EmailVerificationScreen sends verification email on mount, accepts token input, and produces a VerifiedClaimOp on successful signAndVerifyClaim
- **plc-key-management.AC5.8 Failure:** EmailVerificationScreen shows error when token is invalid (INVALID_TOKEN) or verification fails (VERIFICATION_FAILED)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Create PdsAuthScreen component

**Verifies:** plc-key-management.AC5.5, plc-key-management.AC5.6

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/PdsAuthScreen.svelte`

**Implementation:**

Create a screen component following the AuthenticatingScreen pattern but with a user-initiated action instead of auto-start on mount.

**Props interface:**
```typescript
let {
  pdsUrl,
  onnext,
  onback,
}: {
  pdsUrl: string;
  onnext: () => void;
  onback: () => void;
} = $props();
```

**Internal state:**
```typescript
let authenticating = $state(false);
let error = $state<string | null>(null);
```

**Behavior:**
1. **Initial state:** Display PDS info and an "Authenticate with PDS" button
   - Show: "Connect to your PDS at `{pdsUrl}` to verify your identity."
   - Show back button to return to identity input
2. **On button press:** Set `authenticating = true`, call `startPdsAuth(pdsUrl)` from `$lib/ipc`
   - While authenticating: show spinner + "Opening browser for PDS authentication…" (matching AuthenticatingScreen style)
   - Disable back button while authenticating
3. **On success** (promise resolves): call `onnext()` — parent navigates to `email_verification`
4. **On error:** Set `authenticating = false`, map `ClaimError.code` to user-friendly messages:
   - `UNAUTHORIZED` → "Authentication was denied. Please try again."
   - `NETWORK_ERROR` → "Network error. Check your connection and try again."
   - Any other code → "Authentication failed. Please try again."
   - Show error text + retry button (re-click "Authenticate with PDS")

**Styling:** Follow existing screen patterns. Use the spinner from AuthenticatingScreen (`.spinner` with border-top animation). Use `.error-text` pattern for errors.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add PdsAuthScreen component`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire PdsAuthScreen into +page.svelte

**Verifies:** plc-key-management.AC5.5, plc-key-management.AC5.6

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1: Import PdsAuthScreen**
```typescript
import PdsAuthScreen from '$lib/components/onboarding/PdsAuthScreen.svelte';
```

**Step 2: Add rendering block** (after the `identity_input` block from Phase 2)

```svelte
{:else if step === 'pds_auth'}
  <PdsAuthScreen
    pdsUrl={identityInfo!.pdsUrl}
    onnext={() => goTo('email_verification')}
    onback={() => goTo('identity_input')}
  />
```

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): wire PdsAuthScreen into page state machine`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-5) -->
<!-- START_TASK_3 -->
### Task 3: Create EmailVerificationScreen component

**Verifies:** plc-key-management.AC5.7, plc-key-management.AC5.8

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/EmailVerificationScreen.svelte`

**Implementation:**

Create a screen component that sends the verification email on mount and collects the token.

**Props interface:**
```typescript
let {
  did,
  onnext,
  onback,
}: {
  did: string;
  onnext: (result: VerifiedClaimOp) => void;
  onback: () => void;
} = $props();
```

Import `requestClaimVerification`, `signAndVerifyClaim`, `type VerifiedClaimOp`, `type ClaimError` from `$lib/ipc`.

**Internal state:**
```typescript
let token = $state('');
let sending = $state(true);       // true while sending verification email
let sendError = $state<string | null>(null);
let verifying = $state(false);    // true while verifying token
let verifyError = $state<string | null>(null);
```

**Behavior:**

1. **On mount:** Call `requestClaimVerification(did)` to trigger the verification email
   - While sending: show spinner + "Sending verification email…"
   - On success: show token input form
   - On error: show error + "Retry" button that re-calls `requestClaimVerification`

2. **Token input form:** (shown after email sent)
   - Instruction text: "A verification code has been sent to your email. Enter the code below."
   - Text input for `token` (text type, autocomplete off)
   - "Verify" button (disabled while `verifying` or when `token` is empty)

3. **On verify button press:** Call `signAndVerifyClaim(did, token.trim())`
   - While verifying: show spinner or disable button
   - On success: call `onnext(result)` with the `VerifiedClaimOp`
   - On error: map `ClaimError.code` to user-friendly messages:
     - `INVALID_TOKEN` → "Invalid or expired verification code. Check your email and try again."
     - `VERIFICATION_FAILED` → "Verification failed: {message}"
     - `NETWORK_ERROR` → "Network error. Check your connection and try again."
     - Any other → "An error occurred. Please try again."

4. **Back button:** calls `onback()` — navigates back to PDS auth

**Styling:** Follow existing input screen patterns (HandleScreen): centered layout, input with `.error` class on validation failure, `.error-text` for error messages.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add EmailVerificationScreen component`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Wire EmailVerificationScreen into +page.svelte

**Verifies:** plc-key-management.AC5.7, plc-key-management.AC5.8

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1: Import EmailVerificationScreen**
```typescript
import EmailVerificationScreen from '$lib/components/onboarding/EmailVerificationScreen.svelte';
```

**Step 2: Add rendering block** (after the `pds_auth` block)

```svelte
{:else if step === 'email_verification'}
  <EmailVerificationScreen
    did={identityInfo!.did}
    onnext={(result) => {
      verifiedClaim = result;
      goTo('review_operation');
    }}
    onback={() => goTo('pds_auth')}
  />
```

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): wire EmailVerificationScreen into page state machine`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Verify build and existing flow

**Files:**
- No file changes — verification only

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

Run: `cargo test -p identity-wallet`
Expected: All existing Rust tests pass

**Commit:** No commit — verification only
<!-- END_TASK_5 -->
<!-- END_SUBCOMPONENT_B -->
