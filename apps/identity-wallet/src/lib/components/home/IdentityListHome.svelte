<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { listIdentities, getStoredDidDoc,
    refreshDidDoc, getDeviceKeyId, checkIdentityStatus, type UnauthorizedChange, type IdentityStatus } from '$lib/ipc';
  import {
    extractPdsFromPlcDoc,
    extractHandle,
    truncateDid,
    docNeedsRotationKeysRefresh,
  } from '$lib/did-doc-utils';
  import DIDAvatar from './DIDAvatar.svelte';

  let {
    onadd,
    onselect,
    onalert,
    onagents,
    onsettings,
  }: {
    onadd: () => void;
    onselect: (did: string, didDoc: Record<string, unknown>, deviceKeyIsRoot: boolean | null) => void;
    onalert?: (did: string, changes: UnauthorizedChange[]) => void;
    /** Open the "My agents" management screen (agent consent + audit). */
    onagents?: () => void;
    /** Open the Settings screen. */
    onsettings?: () => void;
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

  // Total unauthorized changes across all identities, for the monitoring banner.
  let alertCount = $derived(
    Array.from(alertData.values()).reduce((n, changes) => n + changes.length, 0)
  );

  function isDeviceKeyRoot(
    didDoc: Record<string, unknown>,
    deviceKeyId: string
  ): boolean | null {
    const rotationKeys = didDoc.rotationKeys;
    if (!Array.isArray(rotationKeys) || rotationKeys.length === 0) return null;
    return rotationKeys[0] === deviceKeyId;
  }

  // Display the PDS host rather than the full URL ("bsky.social", not "https://bsky.social").
  function hostOf(url: string): string {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
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
          let [docResult, keyIdResult] = await Promise.all([
            getStoredDidDoc(did),
            getDeviceKeyId(did),
          ]);

          // Cache self-heal: earlier builds cached DID docs without rotationKeys
          // (the W3C shape), which starves the custody badge and hides the migrate
          // entry. Re-fetch the PLC data document once and re-store it; on failure
          // keep whatever the cache had.
          if (docNeedsRotationKeysRefresh(docResult)) {
            try {
              docResult = await refreshDidDoc(did);
            } catch (e) {
              console.warn(`DID doc refresh failed for ${did}:`, e);
            }
          }

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
          if (s.unauthorizedChanges.length > 0) data.set(s.did, s.unauthorizedChanges);
        }
        alertData = data;
      })
      .catch((e) => console.warn('Alert check failed:', e));

    // Listen for plc_alert events from background monitoring timer
    unlisten = await listen<IdentityStatus[]>('plc_alert', (event) => {
      if (!Array.isArray(event.payload)) return;
      const data = new Map<string, UnauthorizedChange[]>();
      for (const s of event.payload) {
        if (s.unauthorizedChanges.length > 0) data.set(s.did, s.unauthorizedChanges);
      }
      alertData = data;
    });
  });

  onDestroy(() => {
    unlisten?.();
  });

  function getBadgeLabel(deviceKeyIsRoot: boolean | null): string {
    if (deviceKeyIsRoot === true) return 'Root key';
    if (deviceKeyIsRoot === false) return 'Not root';
    return 'Unknown';
  }
</script>

{#if loading}
  <div class="screen">
    <div class="header"><h1 class="title">Identities</h1></div>
    <div class="cards" aria-hidden="true">
      {#each [0, 1] as i (i)}
        <div class="skel">
          <div class="skel-seal"></div>
          <div class="skel-lines">
            <span class="skel-line w55"></span>
            <span class="skel-line w80"></span>
          </div>
        </div>
      {/each}
    </div>
  </div>
{:else}
  <div class="screen">
    <div class="header">
      <h1 class="title">Identities</h1>
      <span class="header-actions">
        <button class="icon-btn" onclick={loadData} aria-label="Refresh">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>
        </button>
        {#if onsettings}
          <button class="icon-btn icon-btn--settings" onclick={onsettings} aria-label="Settings">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        {/if}
      </span>
    </div>

    {#if loadError}
      <div class="notice">
        <p class="notice-text">{loadError}</p>
        <button class="btn btn-secondary" onclick={loadData}>Try again</button>
      </div>
    {:else if identities.length === 0}
      <div class="empty">
        <span class="empty-seal" aria-hidden="true">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </span>
        <p class="empty-title">No identities yet</p>
        <p class="empty-sub">Create a new identity, or import one you already control.</p>
        <button class="btn btn-primary" onclick={onadd}>Create or import</button>
      </div>
    {:else}
      {#if alertCount === 0}
        <div class="monitor monitor--safe">
          <span class="monitor-ic" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          </span>
          <span class="monitor-body">
            <span class="monitor-t">All identities secure</span>
            <span class="monitor-s"><span class="pulse" aria-hidden="true"></span>Watching the public record</span>
          </span>
        </div>
      {:else}
        <div class="monitor monitor--alert">
          <span class="monitor-ic" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          </span>
          <span class="monitor-body">
            <span class="monitor-t">{alertCount} unauthorized {alertCount === 1 ? 'change' : 'changes'} need your attention</span>
            <span class="monitor-s">Open the flagged {alertData.size === 1 ? 'identity' : 'identities'} below to review</span>
          </span>
        </div>
      {/if}

      <p class="section-label">Your seals</p>

      <div class="cards">
        {#each identities as card (card.did)}
          {@const alerts = alertData.get(card.did)}
          <div class="card-group">
          <button class="card" class:card--alert={alerts?.length} onclick={() => onselect(card.did, didDocs.get(card.did) ?? {}, card.deviceKeyIsRoot)}>
            <DIDAvatar did={card.did} handle={card.handle ?? 'Unknown'} />
            <span class="info">
              <span class="handle">{card.handle ? '@' + card.handle : 'Unknown handle'}</span>
              <span class="did">{truncateDid(card.did)}</span>
              {#if card.pdsUrl}<span class="pds">on {hostOf(card.pdsUrl)}</span>{/if}
              <span class="badges">
                <span
                  class="badge"
                  class:badge--root={card.deviceKeyIsRoot === true}
                  class:badge--notroot={card.deviceKeyIsRoot === false}
                  class:badge--unknown={card.deviceKeyIsRoot === null}
                >
                  {#if card.deviceKeyIsRoot === true}
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>
                  {:else if card.deviceKeyIsRoot === false}
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
                  {:else}
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 4.5 1.5c0 1.5-2 2-2 3"/><path d="M12 17h.01"/></svg>
                  {/if}
                  {getBadgeLabel(card.deviceKeyIsRoot)}
                </span>
              </span>
            </span>
            <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
          </button>
          {#if alerts?.length}
            <button class="alert-strip" onclick={() => onalert?.(card.did, alerts ?? [])}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
              Review {alerts.length} unauthorized {alerts.length === 1 ? 'change' : 'changes'}
              <svg class="strip-chev" width="8" height="14" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {/if}
          </div>
        {/each}
      </div>

      <button class="add-card" onclick={onadd}>
        <span class="add-plus" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
        </span>
        <span class="add-body">
          <span class="add-t">Add an identity</span>
          <span class="add-s">Create new, or import an existing one</span>
        </span>
      </button>

      {#if onagents}
        <button class="agents-row" onclick={onagents}>
          <span class="agents-ic" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><path d="M9 14h.01M15 14h.01"/></svg>
          </span>
          <span class="agents-body">
            <span class="agents-t">My agents</span>
            <span class="agents-s">See and control what acts on your behalf</span>
          </span>
          <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
        </button>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-lg);
    overflow-y: auto;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .title {
    font-family: var(--font-sans);
    font-size: 1.875rem;
    font-weight: var(--weight-bold);
    letter-spacing: -0.02em;
    color: var(--color-ink);
    margin: 0;
  }

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 44px;
    height: 44px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    color: var(--color-ink);
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard);
  }
  .icon-btn:active {
    background: var(--color-surface-sunk);
  }

  .header-actions {
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
  }

  /* The gear is the "reveal the machinery" affordance — aubergine, like links
     and advanced-detail disclosures, not a status or a primary action. */
  .icon-btn--settings {
    color: var(--color-accent);
  }

  /* Monitoring banner — derived from real alert state, never decorative. */
  .monitor {
    display: flex;
    align-items: center;
    gap: 13px;
    border-radius: var(--radius-lg);
    padding: 15px 16px;
  }
  .monitor-ic {
    width: 38px;
    height: 38px;
    border-radius: var(--radius-full);
    background: var(--color-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .monitor-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .monitor-t {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
  }
  .monitor-s {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-label);
  }
  .monitor--safe {
    background: var(--color-safe-surface);
  }
  .monitor--safe .monitor-ic {
    color: var(--color-safe);
  }
  .monitor--safe .monitor-t {
    color: var(--color-safe);
  }
  .monitor--safe .monitor-s {
    color: var(--color-safe-soft);
  }
  .monitor--alert {
    background: var(--color-critical-surface);
  }
  .monitor--alert .monitor-ic {
    color: var(--color-critical);
  }
  .monitor--alert .monitor-t {
    color: var(--color-critical);
  }
  .monitor--alert .monitor-s {
    color: var(--color-critical-soft);
  }

  .pulse {
    width: 7px;
    height: 7px;
    border-radius: var(--radius-full);
    background: var(--color-safe-solid);
    flex-shrink: 0;
    position: relative;
  }
  .pulse::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: var(--radius-full);
    background: var(--color-safe-solid);
    animation: pulse 2.4s ease-out infinite;
  }
  @keyframes pulse {
    0% { transform: scale(1); opacity: 0.55; }
    70% { transform: scale(3.2); opacity: 0; }
    100% { opacity: 0; }
  }

  .section-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    letter-spacing: 0.01em;
    margin: 0 0 calc(-1 * var(--space-xs));
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .card {
    display: flex;
    align-items: center;
    gap: 14px;
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: 15px 14px 15px 15px;
    width: 100%;
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard), border-color var(--duration-base) var(--ease-standard);
  }
  .card:active {
    background: var(--color-surface);
    border-color: var(--color-line-strong);
  }

  .info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .handle {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .did {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pds {
    font-size: var(--text-label);
    color: var(--color-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 5px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: var(--radius-full);
    font-size: 11.5px;
    font-weight: var(--weight-semibold);
    white-space: nowrap;
  }
  .badge--root {
    background: var(--color-safe-surface);
    color: var(--color-safe);
  }
  .badge--notroot {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .badge--unknown {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
  }
  .card-group {
    display: flex;
    flex-direction: column;
  }
  /* An identity under attack fuses its card with the review strip below it. */
  .card--alert {
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  .alert-strip {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: 44px;
    padding: 10px 15px;
    background: var(--color-critical-surface);
    color: var(--color-critical);
    border: 1px solid var(--color-line);
    border-top: none;
    border-bottom-left-radius: var(--radius-xl);
    border-bottom-right-radius: var(--radius-xl);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    text-align: left;
    cursor: pointer;
    transition: border-color var(--duration-base) var(--ease-standard);
  }
  .alert-strip:active {
    border-color: var(--color-critical);
  }
  .strip-chev {
    margin-left: auto;
    color: var(--color-critical-soft);
    flex-shrink: 0;
  }

  .chev {
    color: var(--color-ink-faint);
    flex-shrink: 0;
  }

  /* Quiet row into the agent-management surface. */
  .agents-row {
    display: flex;
    align-items: center;
    gap: 13px;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: 14px 15px;
    width: 100%;
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard);
  }
  .agents-row:active {
    background: var(--color-surface-sunk);
  }
  .agents-ic {
    width: 42px;
    height: 42px;
    border-radius: var(--radius-full);
    background: var(--color-bg);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .agents-body {
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
    min-width: 0;
  }
  .agents-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .agents-s {
    font-size: var(--text-label);
    color: var(--color-muted);
  }

  .add-card {
    display: flex;
    align-items: center;
    gap: 13px;
    background: transparent;
    border: 1.5px dashed var(--color-line);
    border-radius: var(--radius-xl);
    padding: 16px 15px;
    width: 100%;
    text-align: left;
    cursor: pointer;
    transition: border-color var(--duration-base) var(--ease-standard), background var(--duration-base) var(--ease-standard);
  }
  .add-card:active {
    border-color: var(--color-primary);
    background: var(--color-seal-tint);
  }
  .add-plus {
    width: 42px;
    height: 42px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .add-body {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .add-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .add-s {
    font-size: var(--text-label);
    color: var(--color-muted);
  }

  /* Empty + error */
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-sm);
    flex: 1;
    padding: var(--space-xl) var(--space-md);
  }
  .empty-seal {
    width: 64px;
    height: 64px;
    border-radius: var(--radius-full);
    background: var(--color-seal-pale);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: var(--space-sm);
  }
  .empty-title {
    font-size: var(--text-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .empty-sub {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    max-width: 32ch;
  }
  .notice {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    background: var(--color-critical-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    text-align: center;
  }
  .notice-text {
    font-size: var(--text-body);
    color: var(--color-critical);
    margin: 0;
  }

  .btn {
    border: none;
    border-radius: var(--radius-md);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    padding: 14px 24px;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard);
  }
  .btn-primary {
    background: var(--color-primary);
    color: var(--color-on-color);
  }
  .btn-primary:active {
    background: var(--color-primary-deep);
  }
  .btn-secondary {
    background: var(--color-bg);
    color: var(--color-ink);
    border: 1px solid var(--color-line);
  }

  /* Loading skeleton */
  .skel {
    display: flex;
    align-items: center;
    gap: 14px;
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: 15px;
  }
  .skel-seal {
    width: 52px;
    height: 52px;
    border-radius: var(--radius-full);
    background: var(--color-surface-sunk);
    flex-shrink: 0;
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skel-lines {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
  }
  .skel-line {
    height: 12px;
    border-radius: var(--radius-sm);
    background: var(--color-surface-sunk);
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skel-line.w55 { width: 55%; }
  .skel-line.w80 { width: 80%; }
  @keyframes shimmer {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
