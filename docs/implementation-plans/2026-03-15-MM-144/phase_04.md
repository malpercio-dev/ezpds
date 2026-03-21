# MM-144 Onboarding Flow — Phase 4: State Machine Orchestrator + ipc.ts

**Goal:** Wire up `+page.svelte` as the five-screen onboarding state machine. Add `createAccount()` to `ipc.ts`. Handle all success and error paths. Replace the `greet` demo entirely.

**Architecture:** `+page.svelte` owns `step: OnboardingStep` and `form` state. It renders the active screen component, invokes `createAccount()` when the user reaches the loading step, maps typed errors to user-facing messages and step reversions, and advances to a DID ceremony placeholder on success. `ipc.ts` gains the typed `createAccount()` wrapper.

**Tech Stack:** Svelte 5 runes, TypeScript strict, `@tauri-apps/api/core` `invoke()`

**Scope:** Phase 4 of 4

**Codebase verified:** 2026-03-15

---

## Acceptance Criteria Coverage

### MM-144.AC1: Onboarding screens render correctly
- **MM-144.AC1.1 Success:** Welcome screen shows app branding and a "Get Started" CTA button that advances to Claim Code step
- **MM-144.AC1.2 Success:** Claim Code screen shows a 6-character alphanumeric input; the Next button is disabled until exactly 6 characters are entered
- **MM-144.AC1.3 Success:** Email screen shows an email input; the Next button is disabled until a valid email format is entered
- **MM-144.AC1.4 Success:** Handle screen shows a handle input; the Next button is disabled until the handle is non-empty
- **MM-144.AC1.5 Success:** Loading screen shows a spinner and status message while account creation is in progress
- **MM-144.AC1.6 Success:** Each screen's Next/Submit button only advances when its validation condition is met

### MM-144.AC2: Account creation succeeds end-to-end
- **MM-144.AC2.1 Success:** Valid email, handle, and claim code submission invokes the `create_account` Rust command via Tauri IPC
- **MM-144.AC2.5 Success:** On success, the frontend receives `{ nextStep: "did_creation" }` and advances past the loading screen

### MM-144.AC3: Error handling
- **MM-144.AC3.1 Failure:** A relay 404 (expired claim code) surfaces as "This claim code has expired. Please request a new one." and returns to Claim Code screen
- **MM-144.AC3.2 Failure:** A relay 409/`CLAIM_CODE_REDEEMED` surfaces as "This claim code has already been used." and returns to Claim Code screen
- **MM-144.AC3.3 Failure:** A relay 409/`ACCOUNT_EXISTS` surfaces as "An account with that email already exists." and returns to Email screen
- **MM-144.AC3.4 Failure:** A relay 409/`HANDLE_TAKEN` surfaces as "That handle is taken. Please choose another." and returns to Handle screen
- **MM-144.AC3.5 Failure:** A network or server error surfaces as "Couldn't reach the server. Check your connection." and returns to Handle screen

### MM-144.AC5: Build passes
- **MM-144.AC5.2 Success:** `pnpm build` in `apps/identity-wallet/` succeeds after adding new frontend components

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add `createAccount` to `ipc.ts`

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Verifies:** MM-144.AC2.1

**Step 1: Add the types and wrapper to the existing `ipc.ts`**

The current file contains only the `greet` wrapper. Add the following below the existing `greet` export:

```typescript
// ── create_account ──────────────────────────────────────────────────────────

export interface CreateAccountParams {
  claimCode: string;
  email: string;
  handle: string;
}

export interface CreateAccountResult {
  nextStep: string;
}

/**
 * Error returned by the `create_account` Rust command.
 *
 * Serialized as `{ code: "EXPIRED_CODE" }` etc. by the Rust backend.
 * The `message` field is present only on NETWORK_ERROR and UNKNOWN variants.
 */
export interface CreateAccountError {
  code:
    | 'EXPIRED_CODE'
    | 'REDEEMED_CODE'
    | 'EMAIL_TAKEN'
    | 'HANDLE_TAKEN'
    | 'NETWORK_ERROR'
    | 'UNKNOWN';
  message?: string;
}

/**
 * Create a new account via the relay.
 *
 * On success, tokens are stored in the iOS Keychain by the Rust backend.
 * On failure, the Promise rejects with a `CreateAccountError`.
 */
export const createAccount = (
  params: CreateAccountParams
): Promise<CreateAccountResult> =>
  invoke('create_account', params);
```

**Why `invoke('create_account', params)` passes camelCase:** Tauri v2 automatically maps camelCase JavaScript argument keys to snake_case Rust parameter names (`claimCode` → `claim_code`, etc.) during IPC deserialization. The `CreateAccountParams` interface uses camelCase to match JavaScript convention.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/ipc.ts
git commit -m "feat(identity-wallet): add createAccount IPC wrapper to ipc.ts"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Replace `+page.svelte` with the onboarding state machine

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Verifies:** MM-144.AC1.1–1.6, MM-144.AC2.1, MM-144.AC2.5, MM-144.AC3.1–3.5

**Step 1: Replace the entire content of `+page.svelte`**

The current file contains the `greet` demo. Replace it entirely with:

```svelte
<script lang="ts">
  import WelcomeScreen from '$lib/components/onboarding/WelcomeScreen.svelte';
  import ClaimCodeScreen from '$lib/components/onboarding/ClaimCodeScreen.svelte';
  import EmailScreen from '$lib/components/onboarding/EmailScreen.svelte';
  import HandleScreen from '$lib/components/onboarding/HandleScreen.svelte';
  import LoadingScreen from '$lib/components/onboarding/LoadingScreen.svelte';
  import { createAccount, type CreateAccountError } from '$lib/ipc';

  // ── Onboarding step type ─────────────────────────────────────────────────

  type OnboardingStep =
    | 'welcome'
    | 'claim_code'
    | 'email'
    | 'handle'
    | 'loading'
    | 'did_ceremony';

  // ── State ────────────────────────────────────────────────────────────────

  let step = $state<OnboardingStep>('welcome');
  let form = $state({ claimCode: '', email: '', handle: '' });

  /**
   * Per-field error messages displayed by each screen.
   * Cleared when the user navigates forward to the next step.
   */
  let errors = $state<{ claimCode?: string; email?: string; handle?: string }>(
    {}
  );

  // ── Navigation helpers ───────────────────────────────────────────────────

  function goTo(next: OnboardingStep) {
    errors = {};
    step = next;
  }

  // ── Account creation ─────────────────────────────────────────────────────

  async function submitAccount() {
    step = 'loading';
    errors = {};

    try {
      const result = await createAccount({
        claimCode: form.claimCode,
        email: form.email,
        handle: form.handle,
      });

      if (result.nextStep === 'did_creation') {
        step = 'did_ceremony';
      } else {
        // Unexpected nextStep value — treat as success and advance anyway.
        step = 'did_ceremony';
      }
    } catch (raw: unknown) {
      // Guard against non-CreateAccountError shapes (e.g. JS runtime errors).
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as CreateAccountError).code === 'string'
      ) {
        handleError(raw as CreateAccountError);
      } else {
        errors.handle = "Couldn't reach the server. Check your connection.";
        step = 'handle';
      }
    }
  }

  function handleError(err: CreateAccountError) {
    switch (err.code) {
      case 'EXPIRED_CODE':
        errors.claimCode = 'This claim code has expired. Please request a new one.';
        step = 'claim_code';
        break;
      case 'REDEEMED_CODE':
        errors.claimCode = 'This claim code has already been used.';
        step = 'claim_code';
        break;
      case 'EMAIL_TAKEN':
        errors.email = 'An account with that email already exists.';
        step = 'email';
        break;
      case 'HANDLE_TAKEN':
        errors.handle = 'That handle is taken. Please choose another.';
        step = 'handle';
        break;
      case 'NETWORK_ERROR':
      case 'UNKNOWN':
      default:
        errors.handle = "Couldn't reach the server. Check your connection.";
        step = 'handle';
        break;
    }
  }
</script>

<div class="app">
  {#if step === 'welcome'}
    <WelcomeScreen onstart={() => goTo('claim_code')} />
  {:else if step === 'claim_code'}
    <ClaimCodeScreen
      bind:value={form.claimCode}
      error={errors.claimCode}
      onnext={() => goTo('email')}
    />
  {:else if step === 'email'}
    <EmailScreen
      bind:value={form.email}
      error={errors.email}
      onnext={() => goTo('handle')}
    />
  {:else if step === 'handle'}
    <HandleScreen
      bind:value={form.handle}
      error={errors.handle}
      onnext={submitAccount}
    />
  {:else if step === 'loading'}
    <LoadingScreen statusText="Creating your account…" />
  {:else if step === 'did_ceremony'}
    <div class="placeholder">
      <h2>Account Created!</h2>
      <p>DID ceremony coming soon…</p>
    </div>
  {/if}
</div>

<style>
  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 1rem;
    text-align: center;
    padding: 2rem;
  }
</style>
```

**Why `errors` is a `$state` object with optional fields:** Each screen only cares about its own error. Storing errors by field name keeps the state flat and avoids a separate `errorMessage` string that would need context about which screen it belongs to.

**Why `HandleScreen onnext={submitAccount}`:** The Handle screen is the last data-entry step. Clicking "Create Account" on it directly triggers submission (step transitions to `loading` inside `submitAccount`). There is no separate "submit" step — the transition is handled by `submitAccount` itself.

**Why `catch (raw: unknown)` cast:** Tauri IPC errors arrive as `unknown` from TypeScript's perspective. Casting to `CreateAccountError` is safe because the Rust backend guarantees the `code` field is always present on error. The `default` case in `handleError` catches any unexpected shape.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/routes/+page.svelte
git commit -m "feat(identity-wallet): implement onboarding state machine in +page.svelte"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Verify build and run in iOS simulator

**Files:** No changes.

**Step 1: TypeScript build check**

```bash
cd apps/identity-wallet && pnpm build
```

Expected: build succeeds with zero TypeScript errors and zero Svelte errors.

**Step 2: svelte-check**

```bash
cd apps/identity-wallet && pnpm exec svelte-check
```

Expected: zero errors.

**Step 3: Rust workspace build**

```bash
cargo build --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all --check
```

Expected: all three pass.

**Step 4: Manual end-to-end verification in iOS simulator (manual)**

```bash
cd apps/identity-wallet && cargo tauri ios dev
```

Walk through each step manually to verify:

| Step | Verify |
|------|--------|
| Welcome screen | App name + "Get Started" button visible |
| Claim Code screen | Input auto-uppercases; Next disabled until 6 chars |
| Email screen | Next disabled until valid email format |
| Handle screen | Next disabled when empty; button reads "Create Account" |
| Loading screen | Spinner visible during submission |
| Error on expired code | Error message on Claim Code screen, correct text |
| Error on handle taken | Error message on Handle screen, correct text |
| Success | Transitions to "Account Created!" placeholder |

This step requires a running relay instance (`cargo run -p relay`) with a valid claim code seeded in the database.

**Step 5: Commit any fixes**

```bash
git add -p
git commit -m "fix(identity-wallet): address issues found during simulator testing"
```

Skip if no fixes were needed.
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
