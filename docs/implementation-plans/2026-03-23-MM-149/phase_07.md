# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Add post-onboarding authentication screens and startup token restoration so the app auto-advances to OAuth after DID ceremony and skips onboarding on relaunch.

**Architecture:** SvelteKit extends the 10-step onboarding state machine (Svelte 5 runes) with three new steps: `authenticating` (auto-invokes `start_oauth_flow` via `onMount`), `authenticated` (success), and `auth_failed` (retry/reset). The Rust `setup()` closure loads tokens from Keychain on startup and, if found, emits an `"auth_ready"` event to skip onboarding. A short async delay (300 ms) before emitting lets the webview JS listener register first.

**Tech Stack:** Svelte 5 (runes), SvelteKit 2, Tauri v2 (`tauri::Emitter` trait, `tauri::async_runtime::spawn`), `@tauri-apps/api/event` `listen()`

**Scope:** 7 phases from original design (phase 7 of 7)

**Codebase verified:** 2026-03-24

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC7: Frontend authentication screens
- **MM-149.AC7.1 Success:** After onboarding step 10 completes, app auto-advances to `authenticating` step and calls `start_oauth_flow`
- **MM-149.AC7.2 Success:** On `start_oauth_flow` resolution, app transitions to `authenticated` state
- **MM-149.AC7.3 Success:** On app relaunch with stored tokens, app skips onboarding and shows `authenticated` state directly
- **MM-149.AC7.4 Failure:** `start_oauth_flow` error transitions app to `auth_failed` step

### MM-149.AC8: Failed auth recovery
- **MM-149.AC8.1 Success:** "Try again" button on `auth_failed` re-invokes `start_oauth_flow` cleanly (no stale state)
- **MM-149.AC8.2 Success:** "Start over" button resets to step 1 of onboarding

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add OAuthError type and startOAuthFlow to ipc.ts

**Verifies:** None (IPC infrastructure for AC7 and AC8)

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Step 1: Read the current ipc.ts**

Open `apps/identity-wallet/src/lib/ipc.ts`. Note:
- Line 1: `import { invoke } from '@tauri-apps/api/core';`
- The existing export pattern: `export const createAccount = (params): Promise<Result> => invoke('command_name', params);`
- Existing error type union pattern: each variant is `{ code: 'SCREAMING_SNAKE_CASE' }`

**Step 2: Add OAuthError type and startOAuthFlow**

Append to the bottom of `apps/identity-wallet/src/lib/ipc.ts`:

```typescript
// ── OAuth ─────────────────────────────────────────────────────────────────────
//
// These variants must exactly match the Rust `OAuthError` enum in oauth.rs.
// Rust serializes them as `{ "code": "SCREAMING_SNAKE_CASE" }` via:
//   #[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]

export type OAuthError =
  | { code: 'DPOP_KEY_GEN_FAILED' }
  | { code: 'DPOP_KEY_INVALID' }
  | { code: 'DPOP_PROOF_FAILED' }
  | { code: 'KEYCHAIN_ERROR' }
  | { code: 'STATE_MISMATCH' }
  | { code: 'CALLBACK_ABANDONED' }
  | { code: 'PAR_FAILED' }
  | { code: 'TOKEN_EXCHANGE_FAILED' }
  | { code: 'TOKEN_REFRESH_FAILED' }
  | { code: 'NOT_AUTHENTICATED' };

export const startOAuthFlow = (): Promise<void> => invoke('start_oauth_flow');
```

**Step 3: TypeScript check**

```bash
cd apps/identity-wallet && pnpm check
```

Expected: passes without errors.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update lib.rs setup() to restore tokens and emit auth_ready

**Verifies:** MM-149.AC7.3 (app relaunch with stored tokens → authenticated state directly)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add Emitter to the existing use import**

Find the existing `use tauri::Manager;` import and add `Emitter`:

Before:
```rust
use tauri::Manager;
```

After:
```rust
use tauri::{Emitter, Manager};
```

**Step 2: Read the existing setup() closure**

The existing `setup(|app| { ... })` from Phase 2 registers the deep-link `on_open_url` handler.
It ends with `Ok(())`. The new code goes between the `on_open_url` block and `Ok(())`.

**Step 3: Add Keychain restore + deferred auth_ready emission**

After the `app.deep_link().on_open_url(...)` block and before `Ok(())`, add:

```rust
        // On relaunch: restore persisted session from Keychain and notify frontend.
        // The 300 ms delay lets the SvelteKit app boot and register its event listener
        // before the event fires — emitting synchronously here would be dropped.
        if let Some((access, refresh)) = keychain::load_oauth_tokens() {
            {
                let state = app.state::<oauth::AppState>();
                *state.oauth_session.lock().unwrap() = Some(oauth::OAuthSession {
                    access_token: access,
                    refresh_token: refresh,
                    // expires_at = 0 ensures OAuthClient refreshes immediately on first use.
                    expires_at: 0,
                    dpop_nonce: None,
                });
            }
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                handle.emit("auth_ready", ()).ok();
            });
        }
```

Note: `keychain::load_oauth_tokens()` was added in Phase 3. `oauth::OAuthSession` with `expires_at: u64` and `dpop_nonce: Option<String>` fields was updated in Phase 5.

**Step 4: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Create AuthenticatingScreen.svelte

**Verifies:** MM-149.AC7.1 (authenticating step auto-invokes start_oauth_flow on mount)

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/AuthenticatingScreen.svelte`

**Step 1: Review the existing DIDCeremonyScreen.svelte pattern**

Open `apps/identity-wallet/src/lib/components/onboarding/DIDCeremonyScreen.svelte` and note:
- `$props()` for typed prop declarations (Svelte 5 runes)
- `onMount(() => runCeremony())` for auto-triggering the async operation on mount
- Callback props `onsuccess` / `onfailure` called from inside the async function
- `try/catch` with the error cast to the expected error type

`AuthenticatingScreen` follows this same pattern.

**Step 2: Create AuthenticatingScreen.svelte**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { startOAuthFlow, type OAuthError } from '$lib/ipc';

  let {
    onresolved,
    onfailed,
  }: {
    onresolved: () => void;
    onfailed: (err: OAuthError) => void;
  } = $props();

  async function authenticate() {
    try {
      await startOAuthFlow();
      onresolved();
    } catch (raw) {
      onfailed(raw as OAuthError);
    }
  }

  onMount(() => {
    authenticate();
  });
</script>

<div class="screen">
  <div class="spinner" aria-label="Loading"></div>
  <p class="status">Opening browser for authentication…</p>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 24px;
    padding: 32px;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .status {
    text-align: center;
    color: #6b7280;
    font-size: 1rem;
  }
</style>
```

**Step 3: TypeScript check**

```bash
cd apps/identity-wallet && pnpm check
```

Expected: passes without errors.

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Update +page.svelte with OAuth steps

**Verifies:** MM-149.AC7.1, MM-149.AC7.2, MM-149.AC7.3, MM-149.AC7.4, MM-149.AC8.1, MM-149.AC8.2

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Step 1: Read the full +page.svelte**

Open `apps/identity-wallet/src/routes/+page.svelte`. Locate:
- Lines 23-33: `OnboardingStep` union type (10 string literals, last is `'complete'`)
- Lines 37-38: `let step = $state<OnboardingStep>('welcome')` and `let form = $state(...)`
- Lines 44+: `let errors = $state(...)`
- Lines 50+: `goTo(next: OnboardingStep)` function
- Lines 123-173 (approx): The `{#if step === 'welcome'}...{:else if step === 'complete'}...{/if}` conditional chain
- The `{:else if step === 'complete'}` block — note whether it has a button with an onclick or ends automatically

**Step 2: Add imports**

At the top of the `<script>` block, add these imports (after the existing ones — do not duplicate `onMount` if it already exists):

```typescript
import { listen } from '@tauri-apps/api/event';
import { onMount } from 'svelte';
import AuthenticatingScreen from '$lib/components/onboarding/AuthenticatingScreen.svelte';
import type { OAuthError } from '$lib/ipc';
```

**Step 3: Extend the OnboardingStep type**

Find the `type OnboardingStep = ...` declaration. Add three new variants at the end:

```typescript
type OnboardingStep =
  | 'welcome'
  | 'claim_code'
  | 'email'
  | 'handle'
  | 'password'
  | 'loading'
  | 'did_ceremony'
  | 'did_success'
  | 'shamir_backup'
  | 'complete'
  | 'authenticating'
  | 'authenticated'
  | 'auth_failed';
```

**Step 4: Add authError state variable**

After the `let errors = $state(...)` declaration, add:

```typescript
let authError = $state<OAuthError | null>(null);
```

**Step 5: Add auth_ready event listener in onMount**

If `onMount` is not yet present in the file, add it after the state declarations. If it already exists (e.g., from Phase 2 deep-link testing), add the listener call inside the existing `onMount` block:

```typescript
onMount(() => {
  listen('auth_ready', () => {
    goTo('authenticated');
  });
  // Note: We intentionally don't await listen() or return a cleanup function here.
  // Svelte 5's onMount does not await async cleanup return values (it would receive a
  // Promise, not the unlisten function). Since +page.svelte is the root page and never
  // unmounts during the app lifecycle, the listener persists for the app's lifetime,
  // which is the correct behavior.
});
```

**Step 6: Update the complete step to transition to authenticating**

Find the `{:else if step === 'complete'}` rendering block. Inside it, locate the button or element that signals the user is done (e.g., a "Finish" or "Done" button). Change its onclick handler to call `goTo('authenticating')`.

If no such button exists and the `complete` step is a static terminal screen, add a "Continue" button using the same CSS classes as other action buttons in the file (look at the `welcome` or `password` step buttons for the class pattern):

```svelte
<button onclick={() => goTo('authenticating')}>
  Continue
</button>
```

**Step 7: Add rendering blocks for the three OAuth steps**

After the `{:else if step === 'complete'}` block, immediately before the closing `{/if}`, add:

```svelte
{:else if step === 'authenticating'}
  <AuthenticatingScreen
    onresolved={() => goTo('authenticated')}
    onfailed={(err) => {
      authError = err;
      goTo('auth_failed');
    }}
  />

{:else if step === 'authenticated'}
  <div class="oauth-screen">
    <div class="oauth-icon" aria-hidden="true">✓</div>
    <h2 class="oauth-title">Authenticated</h2>
    <p class="oauth-body">Your identity wallet is ready.</p>
  </div>

{:else if step === 'auth_failed'}
  <div class="oauth-screen">
    <div class="oauth-icon" aria-hidden="true">✗</div>
    <h2 class="oauth-title">Authentication Failed</h2>
    {#if authError}
      <p class="oauth-error-code">{authError.code}</p>
    {/if}
    <div class="oauth-actions">
      <button
        class="cta"
        onclick={() => {
          authError = null;
          goTo('authenticating');
        }}
      >
        Try again
      </button>
      <button
        class="cta cta--secondary"
        onclick={() => {
          authError = null;
          goTo('welcome');
        }}
      >
        Start over
      </button>
    </div>
  </div>
```

Add these CSS rules to the existing `<style>` block at the bottom of `+page.svelte` (alongside the existing `.screen`, `.cta`, etc. rules already present):

```css
.oauth-screen {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  gap: 24px;
  padding: 32px;
  text-align: center;
}

.oauth-icon {
  font-size: 3rem;
}

.oauth-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: #111827;
  margin: 0;
}

.oauth-body {
  color: #6b7280;
  font-size: 1rem;
  margin: 0;
}

.oauth-error-code {
  font-family: monospace;
  font-size: 0.875rem;
  color: #6b7280;
  margin: 0;
}

.oauth-actions {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
}

.cta--secondary {
  background: #f3f4f6;
  color: #374151;
}
```

**Step 8: TypeScript check**

```bash
cd apps/identity-wallet && pnpm check
```

Expected: passes without errors.

**Step 9: Build**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_TASK_5 -->
### Task 5: Operational verification and commit

**Verifies:** MM-149.AC7.1–4, MM-149.AC8.1–2 (manual test against running relay)

**Step 1: Fresh install test (AC7.1, AC7.2)**

Start the relay, then launch the app in the iOS Simulator:

```bash
cd apps/identity-wallet && cargo tauri ios dev
```

Complete the 10-step onboarding flow through DID ceremony and Shamir backup. On the `complete` step, tap "Continue". Verify:
- App transitions to `authenticating` (spinner visible, browser opens)
- After authenticating in Safari, app returns to `authenticated` state

**Step 1b: Keychain storage verification (AC7.3 prerequisite)**

After Step 1 completes successfully (app shows `authenticated`), verify that tokens were persisted to Keychain before testing relaunch. In Xcode, open the debug console and confirm no Keychain errors appear (the `store_oauth_tokens` call logs at `tracing::error` level on failure — no error lines means storage succeeded).

Alternatively, run the Keychain unit tests to confirm the helpers work correctly:

```bash
cargo test -p identity-wallet keychain
```

Expected: all keychain-related tests pass. This verifies the storage path used by `start_oauth_flow` after token exchange.

**Step 2: Relaunch test (AC7.3)**

Stop and relaunch the app (press Home then tap the icon). Verify:
- Onboarding is skipped entirely
- App shows `authenticated` state directly

**Step 3: Auth failure test (AC7.4, AC8.1, AC8.2)**

Kill the relay so the PAR call will fail. Launch the app fresh (first clear Keychain tokens by uninstalling the app). Complete onboarding and tap "Continue" on the `complete` step. Verify:
- App shows `auth_failed` step with error code
- "Try again" button returns to `authenticating` (spinner + opens browser again)
- "Start over" button resets to the `welcome` step

**Step 4: Commit**

```bash
git add apps/identity-wallet/src/lib/ipc.ts
git add apps/identity-wallet/src/lib/components/onboarding/AuthenticatingScreen.svelte
git add apps/identity-wallet/src/routes/+page.svelte
git add apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat(identity-wallet): SvelteKit OAuth screens and startup token restore (MM-149 phase 7)"
```

<!-- END_TASK_5 -->
