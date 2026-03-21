# MM-146 DID Ceremony Implementation Plan

**Goal:** Wire the `perform_did_ceremony` Tauri command into the TypeScript IPC layer and implement the loading, success, and retry UI screens.

**Architecture:** Four changes: (1) add types + `performDIDCeremony` to `ipc.ts`, (2) create `DIDCeremonyScreen.svelte` that auto-starts the ceremony and handles retry, (3) create `DIDSuccessScreen.svelte` showing the truncated DID, (4) update `+page.svelte` to wire up both new screens and add `'did_success'` + `'shamir_backup'` steps.

**Tech Stack:** TypeScript, Svelte 5 (runes: `$state`, `$derived`, `$props`, `onMount`), `@tauri-apps/api/core` invoke

**Scope:** Phase 4 of 4 from the MM-146 design plan.

**Codebase verified:** 2026-03-20

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-146.AC4: DID ceremony UI
- **MM-146.AC4.1 Success:** App shows loading screen with status text while ceremony is in flight
- **MM-146.AC4.2 Success:** On success, transitions to success screen showing truncated DID and a "Continue" button
- **MM-146.AC4.3 Failure:** On failure, shows inline error message and a Retry button (does not rewind to previous screen)
- **MM-146.AC4.4 Success:** Retry button re-invokes the ceremony from the beginning
- **MM-146.AC4.5 Success:** "Continue" button transitions to `shamir_backup` placeholder step

---

<!-- START_SUBCOMPONENT_A (tasks 1-5) -->

<!-- START_TASK_1 -->
### Task 1: Add DID ceremony types and performDIDCeremony to ipc.ts

**Verifies:** MM-146.AC4.1 (prerequisite IPC layer)

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts` — append at the end of the file

**Implementation:**

Append the following block to the end of `ipc.ts`:

```typescript
// ── perform_did_ceremony ─────────────────────────────────────────────────────

/**
 * Successful result from the `perform_did_ceremony` Rust command.
 * This is a pure data shape returned on success.
 */
export type DIDCeremonyResult = {
  did: string;
};

/**
 * Error returned by the `perform_did_ceremony` Rust command.
 *
 * Serialized as `{ code: "NO_RELAY_SIGNING_KEY" }` etc. by the Rust backend.
 * The `message` field is present only on the NETWORK_ERROR variant.
 * This is a pure data shape used for error handling.
 */
export type DIDCeremonyError = {
  code:
    | 'KEY_NOT_FOUND'
    | 'RELAY_KEY_FETCH_FAILED'
    | 'NO_RELAY_SIGNING_KEY'
    | 'SIGNING_FAILED'
    | 'DID_CREATION_FAILED'
    | 'KEYCHAIN_ERROR'
    | 'NETWORK_ERROR';
  message?: string;
};

/**
 * Perform the DID ceremony: fetch relay key, build signed genesis op, post to relay,
 * persist DID and upgraded session token in Keychain.
 *
 * On success, the DID and new session token are stored in Keychain by the Rust backend.
 * On failure, the Promise rejects with a `DIDCeremonyError`.
 */
export const performDIDCeremony = (handle: string): Promise<DIDCeremonyResult> =>
  invoke('perform_did_ceremony', { handle });
```

**Verification:**

Run from `apps/identity-wallet/`:
```bash
pnpm check
```
Expected: TypeScript type-check passes with no errors.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create DIDCeremonyScreen.svelte

**Verifies:** MM-146.AC4.1, MM-146.AC4.3, MM-146.AC4.4

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/DIDCeremonyScreen.svelte`

**Implementation:**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import LoadingScreen from './LoadingScreen.svelte';
  import { performDIDCeremony, type DIDCeremonyError } from '$lib/ipc';

  let {
    handle,
    onsuccess,
  }: {
    handle: string;
    onsuccess: (did: string) => void;
  } = $props();

  let loading = $state(true);
  let error = $state<DIDCeremonyError | null>(null);

  async function runCeremony() {
    loading = true;
    error = null;
    try {
      const result = await performDIDCeremony(handle);
      loading = false;
      onsuccess(result.did);
    } catch (raw: unknown) {
      loading = false;
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as DIDCeremonyError).code === 'string'
      ) {
        error = raw as DIDCeremonyError;
      } else {
        error = { code: 'NETWORK_ERROR', message: 'An unexpected error occurred.' };
      }
    }
  }

  function errorMessage(err: DIDCeremonyError): string {
    switch (err.code) {
      case 'NO_RELAY_SIGNING_KEY':
        return "The relay hasn't been configured yet. Please try again later.";
      case 'RELAY_KEY_FETCH_FAILED':
      case 'NETWORK_ERROR':
        return "Couldn't reach the server. Check your connection.";
      case 'SIGNING_FAILED':
        return 'Device signing failed. Please try again.';
      case 'DID_CREATION_FAILED':
        return "Couldn't create your identity. Please try again.";
      case 'KEYCHAIN_ERROR':
        return "Couldn't save to your device. Please try again.";
      case 'KEY_NOT_FOUND':
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  onMount(() => runCeremony());
</script>

{#if loading}
  <LoadingScreen statusText="Setting up your identity…" />
{:else if error}
  <div class="screen">
    <p class="error-text">{errorMessage(error)}</p>
    <button class="retry" onclick={() => runCeremony()}>Retry</button>
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 1.5rem;
    text-align: center;
  }

  .error-text {
    font-size: 1rem;
    color: #ef4444;
    margin: 0;
  }

  .retry {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create DIDSuccessScreen.svelte

**Verifies:** MM-146.AC4.2, MM-146.AC4.5

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/DIDSuccessScreen.svelte`

**Implementation:**

The DID format is `did:plc:` (8 chars) + 24 lowercase base32 chars = 32 total. Truncate for display: show the `did:plc:` prefix plus first 5 suffix chars + `…` + last 4 suffix chars.

```svelte
<script lang="ts">
  let {
    did,
    oncontinue,
  }: {
    did: string;
    oncontinue: () => void;
  } = $props();

  // Truncate the DID suffix for display on a narrow mobile screen.
  // "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcde…uvwx"
  let displayDid = $derived(
    did.startsWith('did:plc:') && did.length > 20
      ? `did:plc:${did.slice(8, 13)}…${did.slice(-4)}`
      : did
  );
</script>

<div class="screen">
  <div class="success-icon" aria-hidden="true">✓</div>
  <h2>Identity Created!</h2>
  <p class="label">Your decentralized identifier</p>
  <code class="did">{displayDid}</code>
  <button class="cta" onclick={oncontinue}>Continue</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 1.25rem;
    text-align: center;
  }

  .success-icon {
    width: 64px;
    height: 64px;
    background: #007aff;
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: 700;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .label {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0;
  }

  .did {
    font-family: monospace;
    font-size: 0.9rem;
    background: #f3f4f6;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    word-break: break-all;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Update +page.svelte to wire up new screens

**Verifies:** MM-146.AC4.2, MM-146.AC4.5

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1:** Add two new imports after the existing `LoadingScreen` import (line 6):

```svelte
  import DIDCeremonyScreen from '$lib/components/onboarding/DIDCeremonyScreen.svelte';
  import DIDSuccessScreen from '$lib/components/onboarding/DIDSuccessScreen.svelte';
```

**Step 2:** Expand `OnboardingStep` to include the two new steps (currently lines 19-25):

```typescript
  type OnboardingStep =
    | 'welcome'
    | 'claim_code'
    | 'email'
    | 'handle'
    | 'loading'
    | 'did_ceremony'
    | 'did_success'
    | 'shamir_backup';
```

**Step 3:** Add `did` field to `form` (currently line 30):

```typescript
  let form = $state({ claimCode: '', email: '', handle: '', did: '' });
```

**Step 4:** Replace the `did_ceremony` placeholder block (currently lines 137-141) with the wired-up screens:

Replace:
```svelte
  {:else if step === 'did_ceremony'}
    <div class="placeholder">
      <h2>Account Created!</h2>
      <p>DID ceremony coming soon…</p>
    </div>
```

With:
```svelte
  {:else if step === 'did_ceremony'}
    <DIDCeremonyScreen
      handle={form.handle}
      onsuccess={(did) => { form.did = did; step = 'did_success'; }}
    />
  {:else if step === 'did_success'}
    <DIDSuccessScreen
      did={form.did}
      oncontinue={() => { step = 'shamir_backup'; }}
    />
  {:else if step === 'shamir_backup'}
    <div class="placeholder">
      <h2>Backup</h2>
      <p>Shamir backup coming soon…</p>
    </div>
```

**Note:** The existing `.placeholder` CSS class in `+page.svelte` (lines 152-160) already applies the correct styling for the `shamir_backup` placeholder. No new CSS needed.

**Verification:**

Run from `apps/identity-wallet/`:
```bash
pnpm check
```
Expected: TypeScript type-check passes with no errors.

Run from workspace root:
```bash
cargo build -p identity-wallet
```
Expected: Rust backend compiles without errors. (This validates the Tauri command registration from Phase 3 is intact.)
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Commit

```bash
git add apps/identity-wallet/src/lib/ipc.ts \
        apps/identity-wallet/src/lib/components/onboarding/DIDCeremonyScreen.svelte \
        apps/identity-wallet/src/lib/components/onboarding/DIDSuccessScreen.svelte \
        apps/identity-wallet/src/routes/+page.svelte
git commit -m "feat(identity-wallet): add DID ceremony UI screens and IPC wrapper"
```
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_A -->
