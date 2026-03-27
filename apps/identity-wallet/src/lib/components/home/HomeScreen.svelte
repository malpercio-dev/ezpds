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
