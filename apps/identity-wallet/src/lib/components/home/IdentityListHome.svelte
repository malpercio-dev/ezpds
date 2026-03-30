<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { listIdentities, getStoredDidDoc, getDeviceKeyId, checkIdentityStatus, type UnauthorizedChange, type IdentityStatus } from '$lib/ipc';
  import { extractPdsFromPlcDoc, extractHandle, truncateDid } from '$lib/did-doc-utils';
  import DIDAvatar from './DIDAvatar.svelte';

  let {
    onadd,
    onselect,
    onalert,
  }: {
    onadd: () => void;
    onselect: (did: string, didDoc: Record<string, unknown>) => void;
    onalert?: (did: string, changes: UnauthorizedChange[]) => void;
  } = $props();

  interface IdentityCard {
    did: string;
    handle: string | null;
    pdsUrl: string | null;
    deviceKeyIsRoot: boolean | null;
  }

  let identities = $state<IdentityCard[]>([]);
  let didDocs = $state<Map<string, Record<string, unknown>>>(new Map());
  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let alertData = $state<Map<string, UnauthorizedChange[]>>(new Map());
  let unlisten: UnlistenFn | null = null;

  function isDeviceKeyRoot(
    didDoc: Record<string, unknown>,
    deviceKeyId: string
  ): boolean | null {
    const rotationKeys = didDoc.rotationKeys;
    if (!Array.isArray(rotationKeys) || rotationKeys.length === 0) return null;
    return rotationKeys[0] === deviceKeyId;
  }

  async function loadData() {
    loading = true;
    loadError = null;
    try {
      const dids = await listIdentities();
      identities = [];
      didDocs.clear();

      for (const did of dids) {
        try {
          const [docResult, keyIdResult] = await Promise.all([
            getStoredDidDoc(did),
            getDeviceKeyId(did),
          ]);

          const handle = docResult ? extractHandle(docResult) : null;
          const pdsUrl = docResult ? extractPdsFromPlcDoc(docResult) : null;
          const deviceKeyIsRoot = docResult ? isDeviceKeyRoot(docResult, keyIdResult) : null;

          if (docResult) {
            didDocs.set(did, docResult);
          }

          identities.push({
            did,
            handle,
            pdsUrl,
            deviceKeyIsRoot,
          });
        } catch (e) {
          console.error(`Failed to load identity ${did}:`, e);
          // Show degraded card instead of silently dropping the identity
          identities.push({
            did,
            handle: null,
            pdsUrl: null,
            deviceKeyIsRoot: null,
          });
        }
      }
    } catch (e) {
      console.error('Failed to load identities:', e);
      identities = [];
      didDocs.clear();
      loadError = 'Failed to load identities. Tap refresh to try again.';
    } finally {
      loading = false;
    }
  }

  onMount(async () => {
    loadData();

    // Fetch initial alert status
    checkIdentityStatus()
      .then((statuses) => {
        const data = new Map<string, UnauthorizedChange[]>();
        for (const s of statuses) {
          if (s.alertCount > 0) data.set(s.did, s.unauthorizedChanges);
        }
        alertData = data;
      })
      .catch((e) => console.warn('Alert check failed:', e));

    // Listen for plc_alert events from background monitoring timer
    unlisten = await listen<IdentityStatus[]>('plc_alert', (event) => {
      const data = new Map<string, UnauthorizedChange[]>();
      for (const s of event.payload) {
        if (s.alertCount > 0) data.set(s.did, s.unauthorizedChanges);
      }
      alertData = data;
    });
  });

  onDestroy(() => {
    unlisten?.();
  });

  function getBadgeLabel(deviceKeyIsRoot: boolean | null): string {
    if (deviceKeyIsRoot === true) {
      return 'Root Key';
    } else if (deviceKeyIsRoot === false) {
      return 'Not Root';
    }
    return 'Unknown';
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

    {#if loadError}
      <div class="empty-state">
        <p class="error-text">{loadError}</p>
        <button class="add-btn" onclick={loadData}>Refresh</button>
      </div>
    {:else if identities.length === 0}
      <div class="empty-state">
        <p class="empty-text">No identities yet</p>
        <button class="add-btn" onclick={onadd}>+ Add Identity</button>
      </div>
    {:else}
      <div class="identity-cards">
        {#each identities as card (card.did)}
          <button
            class="identity-card"
            onclick={() => onselect(card.did, didDocs.get(card.did) ?? {})}
          >
            <div class="card-content">
              <DIDAvatar did={card.did} handle={card.handle ?? 'Unknown'} />
              <div class="identity-info">
                <p class="handle">@{card.handle ?? 'Unknown handle'}</p>
                <p class="did">{truncateDid(card.did)}</p>
                {#if card.pdsUrl}
                  <p class="pds">{card.pdsUrl}</p>
                {/if}
              </div>
            </div>
            <div class="card-badge">
              {#if alertData.get(card.did)?.length}
                <div
                  class="badge badge--alert"
                  role="button"
                  tabindex="0"
                  onkeydown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); onalert?.(card.did, alertData.get(card.did) ?? []); } }}
                  onclick={(e) => { e.stopPropagation(); onalert?.(card.did, alertData.get(card.did) ?? []); }}
                >
                  <span class="badge-dot"></span>
                  {alertData.get(card.did)?.length} {alertData.get(card.did)?.length === 1 ? 'Alert' : 'Alerts'}
                </div>
              {/if}
              <span
                class="badge"
                class:badge--root={card.deviceKeyIsRoot === true}
                class:badge--not-root={card.deviceKeyIsRoot === false}
                class:badge--unknown={card.deviceKeyIsRoot === null}
              >
                <span class="badge-dot"></span>
                {getBadgeLabel(card.deviceKeyIsRoot)}
              </span>
            </div>
          </button>
        {/each}
      </div>

      <button class="add-btn" onclick={onadd}>+ Add Identity</button>
    {/if}
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

  .identity-cards {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .identity-card {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    cursor: pointer;
    width: 100%;
    text-align: left;
    transition: background 0.2s, border-color 0.2s;
  }

  .identity-card:active {
    background: #f3f4f6;
    border-color: #9ca3af;
  }

  .card-content {
    display: flex;
    align-items: center;
    gap: 1rem;
    min-width: 0;
    flex: 1;
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

  .did {
    font-family: monospace;
    font-size: 0.8rem;
    color: #374151;
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .pds {
    font-size: 0.8rem;
    color: #6b7280;
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .card-badge {
    flex-shrink: 0;
  }

  .badge {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .badge-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .badge--root {
    background: #dcfce7;
    color: #166534;
  }

  .badge--root .badge-dot {
    background: #16a34a;
  }

  .badge--not-root {
    background: #fef3c7;
    color: #92400e;
  }

  .badge--not-root .badge-dot {
    background: #f59e0b;
  }

  .badge--unknown {
    background: #f3f4f6;
    color: #374151;
  }

  .badge--unknown .badge-dot {
    background: #9ca3af;
  }

  .badge--alert {
    background: #fef2f2;
    color: #991b1b;
    cursor: pointer;
    transition: background 0.2s, color 0.2s;
  }

  .badge--alert:active {
    background: #fecaca;
    color: #7f1d1d;
  }

  .badge--alert .badge-dot {
    background: #ef4444;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1.5rem;
    padding: 2rem 1rem;
  }

  .empty-text {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
  }

  .error-text {
    font-size: 1rem;
    color: #ef4444;
    margin: 0;
    text-align: center;
  }

  .add-btn {
    width: 100%;
    padding: 0.9rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    margin-top: auto;
  }

  .add-btn:active {
    background: #0051d5;
  }
</style>
