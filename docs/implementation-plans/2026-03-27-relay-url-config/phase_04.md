# Relay URL Configuration — Phase 4: Frontend Relay Configuration Screen

**Goal:** Show the relay URL configuration screen on first launch and skip it on subsequent launches.

**Architecture:** Add three IPC wrappers to `ipc.ts`, create `RelayConfigScreen.svelte`, and update `+page.svelte` to add the `relay_config` step and the mount-time check. `saveRelayUrl` performs validation, health check, Keychain persistence, and AppState initialization in a single IPC call; the screen simply calls it on tap.

**Tech Stack:** SvelteKit 2, Svelte 5 runes, TypeScript, Tauri IPC

**Scope:** 4 of 4 phases

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### relay-url-config.AC1: Relay config screen shown on first launch
- **relay-url-config.AC1.1 Success:** On first launch (no saved relay URL), the relay config screen appears before the welcome screen
- **relay-url-config.AC1.2 Success:** User can accept the pre-filled default URL and proceed to welcome
- **relay-url-config.AC1.3 Success:** User can enter a custom URL and proceed if the relay is healthy
- **relay-url-config.AC1.4 Failure:** User cannot advance past the config screen without a valid, reachable URL

### relay-url-config.AC2: Default URL pre-filled
- **relay-url-config.AC2.1 Success:** URL input is pre-filled with `https://relay.ezpds.com` on first launch

### relay-url-config.AC5: Returning users skip config screen
- **relay-url-config.AC5.1 Success:** When a relay URL is already in Keychain on launch, the app starts at the welcome step (or home if authenticated)
- **relay-url-config.AC5.2 Edge:** The saved URL is used for relay calls on the same launch it was saved (no restart required)

### relay-url-config.AC6: Error and loading states
- **relay-url-config.AC6.1 Success:** A loading/spinner state is shown while the health check is in flight
- **relay-url-config.AC6.2 Failure:** `INVALID_URL` error is shown inline on the config screen (user stays on screen)
- **relay-url-config.AC6.3 Failure:** `UNREACHABLE` error is shown inline on the config screen (user stays on screen)

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->
<!-- START_TASK_1 -->
### Task 1: Add IPC wrappers to `src/lib/ipc.ts`

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Step 1: Add the `RelayConfigError` type**

Add this type alongside the other error types in `ipc.ts`. Follow the discriminated union pattern used by the other error types in the file:

```typescript
/** Error from relay URL configuration commands. */
export type RelayConfigError = { code: 'INVALID_URL' | 'UNREACHABLE' | 'KEYCHAIN_ERROR' };
```

**Step 2: Add the two command wrappers**

Add these two exports at the bottom of `ipc.ts`, following the same arrow-function style used throughout the file:

```typescript
/**
 * Returns the saved relay base URL, or null if not yet configured.
 * Call this on app mount to decide whether to show the relay config screen.
 */
export const getRelayUrl = (): Promise<string | null> =>
  invoke('get_relay_url');

/**
 * Validates url, pings /xrpc/_health, saves to Keychain, and initializes the
 * runtime relay client. After this resolves, all relay IPC commands use url.
 * Throws RelayConfigError on failure.
 */
export const saveRelayUrl = (url: string): Promise<void> =>
  invoke('save_relay_url', { url });
```

**Step 3: Verify TypeScript compiles**

```bash
cd apps/identity-wallet && pnpm check 2>&1 | head -30
```

Expected: No type errors.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create `RelayConfigScreen.svelte`

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/RelayConfigScreen.svelte`

Create the file with the following contents:

```svelte
<script lang="ts">
  import { saveRelayUrl, type RelayConfigError } from '$lib/ipc';

  const DEFAULT_RELAY_URL = 'https://relay.ezpds.com';

  let { onnext }: { onnext: () => void } = $props();

  let url = $state(DEFAULT_RELAY_URL);
  let loading = $state(false);
  let error = $state<string | undefined>(undefined);

  let isValidFormat = $derived(
    url.trim().length > 0 &&
      (url.startsWith('http://') || url.startsWith('https://'))
  );

  async function handleConnect() {
    error = undefined;
    loading = true;
    try {
      await saveRelayUrl(url.trim());
      onnext();
    } catch (e) {
      const relayError = e as RelayConfigError;
      if (relayError.code === 'INVALID_URL') {
        error = 'Invalid URL — must start with http:// or https://';
      } else if (relayError.code === 'KEYCHAIN_ERROR') {
        error = 'Could not save the relay URL. Please try again.';
      } else {
        error = 'Could not reach the relay. Check the URL and try again.';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="screen">
  <div class="content">
    <h2>Connect to Relay</h2>
    <p class="hint">
      Your wallet connects to a relay to create your identity. Use the default
      or enter the address of your own relay.
    </p>

    <input
      type="url"
      class:error={!!error}
      disabled={loading}
      bind:value={url}
      placeholder="https://relay.ezpds.com"
      autocomplete="off"
      autocorrect="off"
      autocapitalize="off"
      spellcheck={false}
    />

    {#if error}
      <p class="error-text">{error}</p>
    {/if}
  </div>

  <div class="actions">
    {#if loading}
      <div class="spinner" role="status" aria-label="Connecting…"></div>
    {:else}
      <button disabled={!isValidFormat} onclick={handleConnect}>Connect</button>
    {/if}
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem;
    gap: 1.5rem;
  }

  .content {
    display: flex;
    flex-direction: column;
    align-items: center;
    flex: 1;
    justify-content: center;
    gap: 1rem;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
    text-align: center;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    max-width: 280px;
    line-height: 1.4;
    margin: 0;
  }

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
    outline: none;
    font-family: monospace;
    color: #111827;
  }

  input:focus {
    border-color: #007aff;
  }

  input.error {
    border-color: #ef4444;
  }

  input:disabled {
    opacity: 0.6;
  }

  .error-text {
    font-size: 0.875rem;
    color: #ef4444;
    margin: 0;
    text-align: center;
    max-width: 320px;
  }

  .actions {
    display: flex;
    justify-content: center;
    padding-bottom: env(safe-area-inset-bottom, 0);
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    font-weight: 600;
    background: #007aff;
    color: white;
    border: none;
    border-radius: 12px;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }

  .spinner {
    width: 48px;
    height: 48px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update `+page.svelte` — step type, mount logic, and renderer

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Step 1: Import `RelayConfigScreen` and `getRelayUrl`**

At the top of the `<script>` block, add:
```typescript
import RelayConfigScreen from '$lib/components/onboarding/RelayConfigScreen.svelte';
import { getRelayUrl, /* existing imports */ } from '$lib/ipc';
```

**Step 2: Add `relay_config` to `OnboardingStep`**

The `OnboardingStep` type union currently starts with `'welcome'`. Add `'relay_config'` at the beginning:

```typescript
type OnboardingStep =
  | 'relay_config'
  | 'welcome'
  | 'claim_code'
  | 'email'
  | 'handle'
  | 'password'
  | 'loading'
  | 'did_ceremony'
  | 'did_success'
  | 'shamir_backup'
  | 'handle_registration'
  | 'complete'
  | 'authenticating'
  | 'home'
  | 'did_document'
  | 'recovery_info'
  | 'auth_failed';
```

**Step 3: Change the initial step**

The `step` state variable currently initializes to `'welcome'`. Change it to `'relay_config'`:

```typescript
let step = $state<OnboardingStep>('relay_config');
```

**Step 4: Add relay URL check to `onMount`**

Update the existing `onMount` block. The current `onMount` only registers the `auth_ready` listener. Add the relay URL check at the start:

```typescript
onMount(async () => {
  // If the user has already configured a relay URL, skip the config screen.
  const savedUrl = await getRelayUrl();
  if (savedUrl) {
    step = 'welcome';
  }

  // Existing: listen for auth_ready deep-link callback from the OAuth flow.
  listen('auth_ready', () => {
    goTo('home');
  });
});
```

> The initial `step = 'relay_config'` means a first-launch user sees the config screen immediately. The `getRelayUrl()` IPC call is a fast Keychain read (~milliseconds), so returning users are redirected to `welcome` before the screen renders visibly.

**Step 5: Add the `relay_config` rendering block**

In the template section, add the `relay_config` case as the FIRST `{#if}` branch (before `step === 'welcome'`):

```svelte
{#if step === 'relay_config'}
  <RelayConfigScreen onnext={() => goTo('welcome')} />
{:else if step === 'welcome'}
  <!-- existing welcome block unchanged -->
```

**Step 6: Verify TypeScript**

```bash
cd apps/identity-wallet && pnpm check 2>&1 | head -30
```

Expected: No type errors.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Run the app and commit

**Step 1: Build the frontend**

```bash
cd apps/identity-wallet && pnpm build 2>&1 | tail -20
```

Expected: Builds without errors or warnings.

**Step 2: Verify TypeScript and Svelte**

```bash
cd apps/identity-wallet && pnpm check 2>&1
```

Expected: No errors.

**Step 3: Smoke test in Simulator (manual)**

Launch the app in the iOS Simulator:
```bash
cd apps/identity-wallet && cargo tauri ios dev
```

**Verify these behaviors manually:**

| Scenario | Expected |
|----------|----------|
| Fresh state (no saved URL) | Relay config screen appears first with `https://relay.ezpds.com` pre-filled |
| Enter invalid URL (e.g. `notaurl`) and tap Connect | Inline error: "Invalid URL — must start with http:// or https://" |
| Enter unreachable URL (e.g. `https://does-not-exist.example.com`) and tap Connect | Loading spinner appears, then inline error: "Could not reach the relay…" |
| Enter correct relay URL (or accept default with relay running) and tap Connect | Loading spinner, then advances to Welcome screen |
| Restart the app after saving URL | Relay config screen is NOT shown; Welcome screen appears directly |

**Step 4: Update `apps/identity-wallet/CLAUDE.md`**

The implementation plan's CLAUDE.md documents the app's key contracts and IPC commands. Update it to reflect the changes made across all four phases:

- Add `relay-base-url` to the Keychain accounts section (new account key added in Phase 3)
- Add `get_relay_url` and `save_relay_url` to the IPC commands list
- Note that `relay_client` is now runtime-configurable via `AppState::set_relay_client()` rather than a compile-time global static

**Step 5: Commit**

```bash
git add apps/identity-wallet/src/lib/ipc.ts \
        apps/identity-wallet/src/lib/components/onboarding/RelayConfigScreen.svelte \
        apps/identity-wallet/src/routes/+page.svelte \
        apps/identity-wallet/CLAUDE.md
git commit -m "feat: add relay URL configuration screen to onboarding"
```
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->
