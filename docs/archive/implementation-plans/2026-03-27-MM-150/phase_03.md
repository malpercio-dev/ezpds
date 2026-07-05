# MM-150 Implementation Plan — Phase 3: HomeScreen component

**Goal:** Main home screen displaying identity card, relay/session status indicators, and action buttons.

**Architecture:** Svelte 5 component. Calls `loadHomeData()` from `$lib/ipc` on mount and on refresh button tap. Shows a spinner from `LoadingScreen` during the load. Renders `DIDAvatar`, identity card, two status indicator cards, and three action buttons. Log out calls `logOut()` and signals parent via `onlogout`.

**Tech Stack:** Svelte 5, TypeScript, `$lib/ipc.ts` (Phase 1 types + functions)

**Scope:** Phase 3 of 6

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### MM-150.AC1: Identity card displays correctly
- **MM-150.AC1.1 Success:** Home screen shows the user's handle from `getSession` response
- **MM-150.AC1.2 Success:** DID is displayed truncated as `did:plc:XXXXXXXX…XXXXXX`
- **MM-150.AC1.3 Success:** Copy button copies the full untruncated DID to clipboard
- **MM-150.AC1.4 Success:** Email from `getSession` is shown
- **MM-150.AC1.5 Success:** DID-derived avatar circle is visible with a stable hue
- **MM-150.AC1.6 Success:** Avatar shows the first letter of the handle as its initial
- **MM-150.AC1.7 Edge:** Avatar shows `?` when handle is `handle.invalid`
- **MM-150.AC1.8 Edge:** Loading spinner is shown while `loadHomeData()` is in flight

### MM-150.AC2: Status indicators are accurate
- **MM-150.AC2.1 Success:** Relay status shows Connected when `relayHealthy` is true
- **MM-150.AC2.2 Failure:** Relay status shows Error when `relayHealthy` is false
- **MM-150.AC2.3 Success:** Session status shows Active when `session` is non-null
- **MM-150.AC2.4 Failure:** Session status shows Error when `session` is null
- **MM-150.AC2.5 Edge:** Relay and session statuses are independent

### MM-150.AC3: Three action flows work
- **MM-150.AC3.1 Success:** Log out clears `oauth-access-token`, `oauth-refresh-token`, and `did` from Keychain
- **MM-150.AC3.2 Success:** Log out navigates to the welcome screen
- **MM-150.AC3.3 Success:** Device key and DPoP key remain in Keychain after logout
- **MM-150.AC3.4 Success:** Tapping View DID Document navigates to `did_document` step
- **MM-150.AC3.8 Edge:** View DID Document button is hidden when `session.didDoc` is null
- **MM-150.AC3.10 Success:** Tapping Recovery Info navigates to `recovery_info` step

---

<!-- START_SUBCOMPONENT_A (tasks 1-1) -->
<!-- START_TASK_1 -->
### Task 1: Create `HomeScreen.svelte`

**Verifies:** MM-150.AC1.1–AC1.8, MM-150.AC2.1–AC2.5, MM-150.AC3.1–AC3.4, MM-150.AC3.8, MM-150.AC3.10

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/HomeScreen.svelte`

**DID truncation specification:**

The `did:plc:` prefix is always shown in full. The method-specific ID (everything after `did:plc:`) is truncated: first 8 chars + `…` + last 6 chars.

Examples:
- `did:plc:abcdefghijklmnopqrstuvwx` → `did:plc:abcdefgh…uvwx` (only works if ≥ 14 chars after prefix)
- `did:plc:abc` → `did:plc:abc` (too short, shown as-is)

```
displayDid: full DID when method-specific ID < 14 chars
         : "did:plc:" + first8 + "…" + last6 otherwise
```

**Implementation:**

Create `apps/identity-wallet/src/lib/components/home/HomeScreen.svelte`:

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { loadHomeData, logOut, type HomeData } from '$lib/ipc';
  import DIDAvatar from './DIDAvatar.svelte';

  let {
    onnavdiddoc,
    onnavrecovery,
    onlogout,
  }: {
    onnavdiddoc: (data: HomeData) => void;
    onnavrecovery: (data: HomeData) => void;
    onlogout: () => void;
  } = $props();

  let homeData = $state<HomeData | null>(null);
  let loading = $state(true);
  let didCopied = $state(false);

  async function loadData() {
    loading = true;
    homeData = await loadHomeData();
    loading = false;
  }

  onMount(() => {
    loadData();
  });

  // Truncate the DID for display on narrow mobile screens.
  // "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcdefgh…uvwxyz"
  let displayDid = $derived.by(() => {
    const did = homeData?.session?.did ?? '';
    const prefix = 'did:plc:';
    if (!did.startsWith(prefix)) return did;
    const specific = did.slice(prefix.length);
    if (specific.length < 14) return did;
    return `${prefix}${specific.slice(0, 8)}…${specific.slice(-6)}`;
  });

  async function copyDid() {
    const did = homeData?.session?.did;
    if (!did) return;
    try {
      await navigator.clipboard.writeText(did);
      didCopied = true;
      setTimeout(() => { didCopied = false; }, 2000);
    } catch (e) {
      console.error('clipboard write failed:', e);
    }
  }

  async function handleLogOut() {
    await logOut();
    onlogout();
  }
</script>

{#if loading}
  <div class="screen screen--center">
    <div class="spinner" aria-label="Loading"></div>
    <p class="status-text">Loading…</p>
  </div>
{:else}
  <div class="screen">
    <div class="header">
      <h1 class="title">Identity Wallet</h1>
      <button class="refresh-btn" onclick={loadData} aria-label="Refresh">↻</button>
    </div>

    {#if homeData?.session}
      <!-- Identity card -->
      <div class="identity-card">
        <DIDAvatar did={homeData.session.did} handle={homeData.session.handle} />
        <div class="identity-info">
          <p class="handle">@{homeData.session.handle}</p>
          <button class="did-btn" onclick={copyDid} title="Tap to copy full DID">
            <span class="did-text">{displayDid}</span>
            <span class="copy-hint">{didCopied ? 'Copied!' : 'Copy'}</span>
          </button>
          <p class="email">{homeData.session.email}</p>
        </div>
      </div>
    {:else}
      <div class="identity-card identity-card--empty">
        <p class="empty-text">Session unavailable</p>
        {#if homeData?.sessionError}
          <p class="error-code">{homeData.sessionError}</p>
        {/if}
      </div>
    {/if}

    <!-- Status indicators -->
    <div class="status-section">
      <div class="status-row">
        <span
          class="status-dot"
          class:status-dot--ok={homeData?.relayHealthy}
          class:status-dot--err={!homeData?.relayHealthy}
          aria-hidden="true"
        ></span>
        <div>
          <p class="status-label">Relay</p>
          <p class="status-value">{homeData?.relayHealthy ? 'Connected' : 'Error'}</p>
        </div>
      </div>
      <div class="status-row">
        <span
          class="status-dot"
          class:status-dot--ok={homeData?.session != null}
          class:status-dot--err={homeData?.session == null}
          aria-hidden="true"
        ></span>
        <div>
          <p class="status-label">Session</p>
          <p class="status-value">{homeData?.session != null ? 'Active' : 'Error'}</p>
        </div>
      </div>
    </div>

    <!-- Action buttons -->
    <div class="actions">
      {#if homeData?.session?.didDoc != null}
        <button class="action-btn" onclick={() => onnavdiddoc(homeData!)}>
          View DID Document
        </button>
      {/if}
      <button class="action-btn" onclick={() => onnavrecovery(homeData!)}>
        Recovery Info
      </button>
      <button class="action-btn action-btn--danger" onclick={handleLogOut}>
        Log Out
      </button>
    </div>
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 1.5rem;
    gap: 1.5rem;
    overflow-y: auto;
  }

  .screen--center {
    align-items: center;
    justify-content: center;
    gap: 1rem;
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
    to { transform: rotate(360deg); }
  }

  .status-text {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .title {
    font-size: 1.4rem;
    font-weight: 700;
    margin: 0;
    color: #111827;
  }

  .refresh-btn {
    background: none;
    border: none;
    font-size: 1.4rem;
    color: #007aff;
    cursor: pointer;
    padding: 0.25rem;
    line-height: 1;
  }

  .identity-card {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .identity-card--empty {
    flex-direction: column;
    align-items: flex-start;
  }

  .identity-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    min-width: 0;
  }

  .handle {
    font-size: 1.1rem;
    font-weight: 600;
    color: #111827;
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .did-btn {
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-align: left;
  }

  .did-text {
    font-family: monospace;
    font-size: 0.8rem;
    color: #374151;
  }

  .copy-hint {
    font-size: 0.7rem;
    color: #007aff;
    white-space: nowrap;
  }

  .email {
    font-size: 0.85rem;
    color: #6b7280;
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .empty-text {
    font-size: 0.95rem;
    color: #6b7280;
    margin: 0;
  }

  .error-code {
    font-family: monospace;
    font-size: 0.8rem;
    color: #ef4444;
    margin: 0;
  }

  .status-section {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .status-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .status-dot--ok {
    background: #22c55e;
  }

  .status-dot--err {
    background: #ef4444;
  }

  .status-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .status-value {
    font-size: 0.875rem;
    color: #111827;
    margin: 0;
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-top: auto;
  }

  .action-btn {
    width: 100%;
    padding: 0.9rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .action-btn--danger {
    background: #f3f4f6;
    color: #ef4444;
  }
</style>
```

**Verification:**
Run from `apps/identity-wallet/`: `pnpm check`
Expected: No TypeScript errors

**Commit:**
```bash
git add apps/identity-wallet/src/lib/components/home/HomeScreen.svelte
git commit -m "feat: add HomeScreen component with identity card and status indicators"
```
<!-- END_TASK_1 -->
<!-- END_SUBCOMPONENT_A -->
