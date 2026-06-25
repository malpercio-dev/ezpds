<script lang="ts">
  import { onMount } from 'svelte';
  import { loadHomeData, logOut, type HomeData } from '$lib/ipc';
  import DIDAvatar from './DIDAvatar.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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
  let didCopyFailed = $state(false);

  async function loadData() {
    loading = true;
    try {
      homeData = await loadHomeData();
    } catch {
      homeData = null;
    } finally {
      loading = false;
    }
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
    } catch {
      didCopyFailed = true;
      setTimeout(() => { didCopyFailed = false; }, 2000);
    }
  }

  async function handleLogOut() {
    try {
      await logOut();
    } catch {
      // logOut always succeeds on the Rust side; navigate away even if IPC fails
    }
    onlogout();
  }
</script>

{#if loading}
  <div class="screen screen--center">
    <Spinner size={48} label="Loading" />
    <p class="status-text">Loading…</p>
  </div>
{:else}
  <div class="screen">
    <div class="header">
      <h1 class="title">Obsign</h1>
      <button class="refresh" onclick={loadData} aria-label="Refresh">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /><path d="M3 21v-5h5" /></svg>
      </button>
    </div>

    {#if homeData?.session}
      <div class="identity-card">
        <DIDAvatar did={homeData.session.did} handle={homeData.session.handle} />
        <div class="identity-info">
          <p class="handle">@{homeData.session.handle}</p>
          <button class="did-btn" onclick={copyDid} title="Tap to copy full DID">
            <span class="did-text">{displayDid}</span>
            <span class="copy-hint">{didCopied ? 'Copied!' : didCopyFailed ? 'Failed' : 'Copy'}</span>
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

    <div class="status-section">
      <div class="status-row">
        <span class="status-dot" class:ok={homeData?.relayHealthy} class:err={!homeData?.relayHealthy} aria-hidden="true"></span>
        <div>
          <p class="status-label">Relay</p>
          <p class="status-value">{homeData?.relayHealthy ? 'Connected' : 'Error'}</p>
        </div>
      </div>
      <div class="status-row">
        <span class="status-dot" class:ok={homeData?.session != null} class:err={homeData?.session == null} aria-hidden="true"></span>
        <div>
          <p class="status-label">Session</p>
          <p class="status-value">{homeData?.session != null ? 'Active' : 'Error'}</p>
        </div>
      </div>
    </div>

    <div class="actions">
      {#if homeData?.session?.didDoc != null}
        <button class="action" onclick={() => onnavdiddoc(homeData!)}>View DID document</button>
      {/if}
      <button class="action" onclick={() => onnavrecovery(homeData!)}>Recovery info</button>
      <button class="action action--danger" onclick={handleLogOut}>Log out</button>
    </div>
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md);
    gap: var(--space-lg);
    overflow-y: auto;
  }
  .screen--center {
    align-items: center;
    justify-content: center;
    gap: var(--space-md);
  }
  .status-text {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .title {
    font-size: 1.4rem;
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }
  .refresh {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: none;
    border: none;
    color: var(--color-accent);
    cursor: pointer;
    padding: var(--space-xs);
  }

  .identity-card {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    align-items: center;
    gap: var(--space-md);
  }
  .identity-card--empty {
    flex-direction: column;
    align-items: flex-start;
  }
  .identity-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    min-width: 0;
  }
  .handle {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
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
    gap: var(--space-sm);
    text-align: left;
  }
  .did-text {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .copy-hint {
    font-size: var(--text-label);
    color: var(--color-accent);
    white-space: nowrap;
  }
  .email {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .empty-text {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
  }
  .error-code {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-critical);
    margin: 0;
  }

  .status-section {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .status-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .status-dot {
    width: 10px;
    height: 10px;
    border-radius: var(--radius-full);
    flex-shrink: 0;
    background: var(--color-muted);
  }
  .status-dot.ok {
    background: var(--color-safe);
  }
  .status-dot.err {
    background: var(--color-critical);
  }
  .status-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .status-value {
    font-size: var(--text-label);
    color: var(--color-ink);
    margin: 0;
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin-top: auto;
  }
  .action {
    width: 100%;
    padding: var(--space-md);
    background: var(--color-primary);
    color: var(--color-on-color);
    border: none;
    border-radius: var(--radius-md);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    cursor: pointer;
  }
  .action--danger {
    background: var(--color-surface);
    color: var(--color-critical);
    border: 1px solid var(--color-line);
  }
</style>
