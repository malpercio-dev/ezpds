# Claim Flow Frontend — Phase 4: ReviewOperationScreen + ClaimSuccessScreen

**Goal:** Create the review screen that displays the PLC operation diff and warnings before submission, and the success screen shown after claim submission.

**Architecture:** ReviewOperationScreen displays the `OpDiff` from `VerifiedClaimOp`, shows warnings, and on confirm calls `submitClaim()`. ClaimSuccessScreen displays the updated DID document summary and provides navigation to home. Both follow the established component patterns.

**Tech Stack:** Svelte 5 (runes), TypeScript, Tauri v2 IPC

**Scope:** 4 of 5 implementation phases

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.9 Success:** ReviewOperationScreen displays added/removed keys, changed services, and warnings from VerifiedClaimOp
- **plc-key-management.AC5.10 Success:** User confirms operation, `submitClaim` is called, and success screen shows updated DID document
- **plc-key-management.AC5.11 Failure:** ReviewOperationScreen shows error when `submitClaim` fails (PLC_DIRECTORY_ERROR, NETWORK_ERROR)
- **plc-key-management.AC5.12 Success:** ClaimSuccessScreen displays confirmation with DID doc summary and navigates to home

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Create ReviewOperationScreen component

**Verifies:** plc-key-management.AC5.9, plc-key-management.AC5.10, plc-key-management.AC5.11

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/ReviewOperationScreen.svelte`

**Implementation:**

Create a screen that displays the operation diff and handles claim submission.

**Props interface:**
```typescript
let {
  did,
  verifiedClaim,
  onnext,
  oncancel,
}: {
  did: string;
  verifiedClaim: VerifiedClaimOp;
  onnext: (result: ClaimResult) => void;
  oncancel: () => void;
} = $props();
```

Import `submitClaim`, `type VerifiedClaimOp`, `type ClaimResult`, `type ClaimError`, `type OpDiff`, `type ServiceChange`, `type ChangeType` from `$lib/ipc`.

**Internal state:**
```typescript
let submitting = $state(false);
let error = $state<string | null>(null);
let warningsAcknowledged = $state(false);
```

**Behavior:**

1. **Display OpDiff sections** (from `verifiedClaim.diff`):

   **Keys section:**
   - "Keys being added" → list each key in `diff.addedKeys` (green highlight, `+` prefix)
   - "Keys being removed" → list each key in `diff.removedKeys` (red highlight, `−` prefix)
   - If both arrays are empty, show "No key changes"

   **Services section:**
   - For each `ServiceChange` in `diff.changedServices`:
     - `changeType === 'added'`: green — "Adding service: {id} → {newEndpoint}"
     - `changeType === 'removed'`: red — "Removing service: {id} (was: {oldEndpoint})"
     - `changeType === 'modified'`: yellow — "Modifying service: {id}: {oldEndpoint} → {newEndpoint}"
   - If array is empty, show "No service changes"

   Display key values truncated for mobile (first 20 chars + "…"), monospace font. Use the `.section` and `.key-card` styling patterns from `DIDDocumentScreen.svelte`.

2. **Warnings section (blocks submission per AC5.9):**
   - If `verifiedClaim.warnings.length > 0`: display each warning in a yellow/amber highlighted box
   - Use icon or colored border to distinguish from regular info
   - Add internal state: `let warningsAcknowledged = $state(false);`
   - Below the warnings, show a checkbox: "I understand these warnings and want to proceed"
   - The "Confirm & Submit" button is **disabled** until `warningsAcknowledged` is `true`
   - If no warnings, the checkbox is not shown and `warningsAcknowledged` defaults to effectively `true` (no blocking)

3. **Action buttons** (at bottom, `margin-top: auto`):
   - "Confirm & Submit" primary button → calls `handleSubmit()`
   - Disabled while `submitting` OR when warnings exist and `warningsAcknowledged` is `false`
   - "Cancel" secondary button → calls `oncancel()`
   - Disabled while `submitting`

4. **handleSubmit:**
   - Set `submitting = true`, clear `error`
   - Call `submitClaim(did)`
   - On success: call `onnext(result)` with the `ClaimResult`
   - On error: map `ClaimError.code`:
     - `PLC_DIRECTORY_ERROR` → "PLC directory rejected the operation: {message}"
     - `NETWORK_ERROR` → "Network error. Check your connection and try again."
     - `UNAUTHORIZED` → "Authorization expired. Please restart the import flow."
     - Any other → "Submission failed. Please try again."
   - Set `submitting = false`

**Styling:** Follow DIDDocumentScreen patterns for section cards. Use color-coded diff entries:
- Added: `#22c55e` (green-500) text/border
- Removed: `#ef4444` (red-500) text/border
- Modified: `#f59e0b` (amber-500) text/border
- Warnings: amber background (`#fffbeb`), amber border (`#f59e0b`)

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add ReviewOperationScreen component`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create ClaimSuccessScreen component

**Verifies:** plc-key-management.AC5.12

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/ClaimSuccessScreen.svelte`

**Implementation:**

Create a success screen that shows the updated DID document summary.

**Props interface:**
```typescript
let {
  claimResult,
  ondone,
}: {
  claimResult: ClaimResult;
  ondone: () => void;
} = $props();
```

Import `type ClaimResult` from `$lib/ipc`.

**Behavior:**

1. **Success header:**
   - Checkmark icon or "✓" in a green circle
   - "Identity Claimed Successfully"
   - Brief description: "Your rotation key has been updated. You are now in control of this identity."

2. **DID document summary** (from `claimResult.updatedDidDoc`):
   - Extract `id` (DID), `alsoKnownAs` (handle), `service` (PDS endpoint) from the `Record<string, unknown>` — use the same extraction pattern as `DIDDocumentScreen.svelte` (`Array.isArray()` checks + type assertions)
   - Show: DID, handle, PDS endpoint in a summary card

3. **"Done" button** → calls `ondone()` — parent navigates to home

**Styling:** Follow WelcomeScreen-like centered layout. Green checkmark circle, success messaging, summary card using `.section` pattern from DIDDocumentScreen.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add ClaimSuccessScreen component`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Wire ReviewOperationScreen + ClaimSuccessScreen into +page.svelte

**Verifies:** plc-key-management.AC5.9, plc-key-management.AC5.10, plc-key-management.AC5.11, plc-key-management.AC5.12

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1: Add imports**
```typescript
import ReviewOperationScreen from '$lib/components/onboarding/ReviewOperationScreen.svelte';
import ClaimSuccessScreen from '$lib/components/onboarding/ClaimSuccessScreen.svelte';
```

**Step 2: Add rendering blocks** (after the `email_verification` block from Phase 3)

```svelte
{:else if step === 'review_operation'}
  <ReviewOperationScreen
    did={identityInfo!.did}
    verifiedClaim={verifiedClaim!}
    onnext={(result) => {
      claimResult = result;
      goTo('claim_success');
    }}
    oncancel={() => goTo('identity_input')}
  />
{:else if step === 'claim_success'}
  <ClaimSuccessScreen
    claimResult={claimResult!}
    ondone={() => goTo('home')}
  />
```

**Note on `!` assertions:** `verifiedClaim` and `claimResult` are guaranteed non-null at their respective steps because the preceding screens set them before navigating. The `!` assertion is safe here and matches how the codebase handles similar state (e.g., `homeData!` in HomeScreen action handlers).

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): wire ReviewOperationScreen and ClaimSuccessScreen into page state machine`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Verify full import flow compiles

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
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
