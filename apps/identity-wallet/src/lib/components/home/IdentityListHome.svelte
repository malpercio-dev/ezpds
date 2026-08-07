<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { checkIdentityStatus, getMonitorHistory, rekeyInProgress,
    type UnauthorizedChange, type IdentityStatus, type MonitorHistory } from '$lib/ipc';
  import {
    truncateDid,
    isDidWeb,
    isOldModelRecovery,
  } from '$lib/did-doc-utils';
  import { loadIdentityCards, type IdentityCard } from '$lib/identity-cards';
  import { toRow, summarize, type ProtectionSummary } from '$lib/protection';
  import { hostOf } from '$lib/url';
  import Button from '$lib/components/ui/Button.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';
  import DIDAvatar from './DIDAvatar.svelte';

  let {
    onadd,
    onselect,
    onalert,
    onprotection,
    onsettings,
    onrekey,
    onrecover,
  }: {
    onadd: () => void;
    onselect: (
      did: string,
      didDoc: Record<string, unknown>,
      deviceKeyIsRoot: boolean | null,
      deviceKeyUnusable: boolean
    ) => void;
    onalert?: (did: string, changes: UnauthorizedChange[]) => void;
    /**
     * Open the app-level Protection surface. The strip is a door, not a readout: the
     * monitor's work is the wallet's central trust-building claim, and a claim with no way
     * to inspect the evidence behind it is just an assertion.
     */
    onprotection?: () => void;
    /** Open the Settings screen. */
    onsettings?: () => void;
    /** Start the old-model re-key upgrade for a did:plc identity. */
    onrekey?: (did: string) => void;
    /**
     * Enter the recovery ceremony for an identity this device can no longer sign for.
     * Offered, never auto-launched: the identity is not in danger, only this device's
     * control of it, and an unprompted ceremony on app open would read as an alarm.
     */
    onrecover?: (did: string) => void;
  } = $props();

  let identities = $state<IdentityCard[]>([]);
  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let alertData = $state<Map<string, UnauthorizedChange[]>>(new Map());
  /**
   * The DIDs the last sweep actually verified — an allowlist, not a failure list.
   *
   * The sweep omits an identity it has no business asking about (a did:web), so absence
   * cannot mean success; and before the first sweep answers, absence means "not asked
   * yet". Deriving verification from the *presence* of a good reading is what keeps the
   * strip from showing the all-clear green it has not earned, the same reason
   * `IdentityScreen` starts at `plcVerified = false`.
   */
  let sweptOk = $state<Set<string>>(new Set());
  /** False until a sweep result has been absorbed, so "not yet" never reads as "failed". */
  let sweepAnswered = $state(false);
  let history = $state<MonitorHistory | null>(null);
  // Advances on a minute's tick so "checked N min ago" ages in place rather than freezing
  // at whatever it said when the screen mounted.
  let now = $state(Date.now());
  let ticker: ReturnType<typeof setInterval> | null = null;
  // DIDs eligible for the old-model re-key upgrade (old-model doc OR an interrupted re-key with a
  // staged set). Drives the calm per-identity "Add a recovery key" strip. Reassigned wholesale
  // after each load so the map stays reactive (per the `$state(new Map())` reactivity rule).
  let rekeyEligible = $state<Map<string, boolean>>(new Map());
  let unlisten: UnlistenFn | null = null;
  /**
   * Set synchronously by `onDestroy`, which runs before this component's async `onMount`
   * can finish. Svelte does not treat an async `onMount`'s return value as a cleanup hook,
   * so a subscription that resolves after teardown has to disarm itself.
   */
  let destroyed = false;

  // PLC monitoring only watches did:plc identities (a did:web has no plc.directory audit
  // log, so `plc_monitor` is a no-op for it). An all-did:web wallet gets the honest note
  // and neither the watch pulse nor the verified shield.
  let allWeb = $derived(identities.length > 0 && identities.every((c) => isDidWeb(c.did)));

  /**
   * The one statement the strip renders — derived by `$lib/protection`, the same function
   * the Protection surface's panel uses, so the door and what is behind it can never
   * disagree about the state of the wallet.
   */
  let summary = $derived<ProtectionSummary>(
    summarize(
      identities.map((c) =>
        toRow(
          {
            did: c.did,
            handle: c.handle,
            changes: alertData.get(c.did) ?? [],
            deviceKeyUnusable: c.deviceKeyUnusable,
            plcCheckSucceeded: sweptOk.has(c.did),
            lastVerifiedAt: null,
            degraded: c.degraded,
          },
          now
        )
      ),
      history,
      now,
      !sweepAnswered
    )
  );

  /**
   * Which tone the strip wears. `safe` splits in two, exactly as `StatusPanel` does: the
   * verified all-clear earns the green, an unreached directory takes the calm informational
   * slate, and an all-did:web wallet takes the seal tint — it is neither a check that
   * passed nor one that failed.
   */
  let stripTone = $derived(
    summary.urgency !== 'safe'
      ? summary.urgency
      : !summary.verified
        ? 'unverified'
        : allWeb
          ? 'web'
          : 'safe'
  );

  async function loadData() {
    loading = true;
    loadError = null;
    const rekeyMap = new Map<string, boolean>();
    try {
      const cards = await loadIdentityCards();

      for (const card of cards) {
        // Old-model identities (and interrupted re-keys with a staged set) are offered the
        // recovery-key upgrade. The in-progress check resurfaces a re-key whose PLC op already
        // landed (so the doc reads as new-model) but whose escrow/Share 1 did not finish.
        let eligible = isOldModelRecovery(card.did, card.didDoc);
        if (!eligible && !isDidWeb(card.did)) {
          try {
            eligible = await rekeyInProgress(card.did);
          } catch (e) {
            console.warn(`Re-key in-progress check failed for ${card.did}:`, e);
          }
        }
        rekeyMap.set(card.did, eligible);
      }

      identities = cards;
    } catch (e) {
      console.error('Failed to load identities:', e);
      identities = [];
      loadError = 'Couldn’t load your identities. Tap refresh to try again.';
    } finally {
      rekeyEligible = rekeyMap;
      loading = false;
    }
  }

  // Index identity statuses by DID, keeping only those with unauthorized changes.
  // Shared by the foreground check and the background plc_alert event so both build
  // the alert map the same way.
  function toAlertMap(statuses: IdentityStatus[]): Map<string, UnauthorizedChange[]> {
    const data = new Map<string, UnauthorizedChange[]>();
    for (const s of statuses) {
      if (s.unauthorizedChanges.length > 0) data.set(s.did, s.unauthorizedChanges);
    }
    return data;
  }

  /** Absorb a sweep's answer: what it found, and which identities it actually verified. */
  function absorb(statuses: IdentityStatus[]) {
    alertData = toAlertMap(statuses);
    sweptOk = new Set(statuses.filter((s) => !s.checkFailed).map((s) => s.did));
    sweepAnswered = true;
  }

  /** Re-read the monitor's own log, which the check that just ran has appended to. */
  function refreshHistory() {
    getMonitorHistory()
      .then((h) => (history = h))
      .catch((e) => console.warn('Monitor history read failed:', e));
  }

  onMount(async () => {
    loadData();
    refreshHistory();

    checkIdentityStatus()
      .then((statuses) => {
        absorb(statuses);
        // The check the wallet just ran is itself a sweep; read the log back so the strip
        // says "checked just now" rather than reporting the previous pass.
        refreshHistory();
      })
      .catch((e) => console.warn('Alert check failed:', e));

    // Listen for plc_alert events from background monitoring timer
    const off = await listen<IdentityStatus[]>('plc_alert', (event) => {
      if (!Array.isArray(event.payload)) return;
      absorb(event.payload);
      refreshHistory();
    });
    // Home unmounts on every step into an identity, so the await above can resolve after
    // teardown — by which point `onDestroy` has already run with nothing to release.
    if (destroyed) {
      off();
      return;
    }
    unlisten = off;

    // A minute is the resolution of the only readout the clock feeds ("checked N min ago").
    ticker = setInterval(() => {
      now = Date.now();
    }, 60_000);
  });

  onDestroy(() => {
    destroyed = true;
    if (ticker !== null) clearInterval(ticker);
    unlisten?.();
  });

  function getBadgeLabel(deviceKeyIsRoot: boolean | null): string {
    if (deviceKeyIsRoot === true) return 'Root key';
    if (deviceKeyIsRoot === false) return 'Not root';
    return 'Unknown';
  }

  /**
   * Which single strip a card shows beneath it. Only one is offered at a time so the
   * card never presents two competing calls to action.
   *
   * `unusable` outranks `alert` deliberately: the alert strip's destination is the
   * recovery-override flow, which signs a counter-operation with this device's key —
   * the exact key that is gone. Offering it first would send the user into a flow that
   * cannot complete. Recovery restores signing, and the alert is still there afterwards.
   *
   * The share-recovery ceremony is structurally did:plc-only — it works by rotating a
   * fresh key into `rotationKeys[0]` via a PLC operation, and a did:web has no rotation
   * keys (`start_share_recovery` refuses a non-`did:plc:` identifier outright). A did:web
   * whose key is gone therefore gets its own state rather than an offer that dead-ends —
   * and rather than nothing, which is the very failure this whole change exists to fix.
   */
  function activeStrip(
    card: IdentityCard,
    alerts: UnauthorizedChange[] | undefined,
    rekeyOffered: boolean
  ): 'unusable' | 'unusable-web' | 'alert' | 'rekey' | null {
    if (card.deviceKeyUnusable) {
      if (isDidWeb(card.did)) return 'unusable-web';
      if (onrecover) return 'unusable';
    }
    if (alerts?.length) return 'alert';
    if (rekeyOffered) return 'rekey';
    return null;
  }
</script>

{#if loading}
  <div class="screen">
    <ScreenHeader title="Identities" size="home" />
    <div class="cards" aria-hidden="true">
      {#each [0, 1] as i (i)}
        <SkeletonCard seal />
      {/each}
    </div>
  </div>
{:else}
  <div class="screen">
    <ScreenHeader title="Identities" size="home">
      {#snippet actions()}
        <button class="icon-btn" onclick={loadData} aria-label="Refresh">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>
        </button>
        {#if onsettings}
          <button class="icon-btn icon-btn--settings" onclick={onsettings} aria-label="Settings">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        {/if}
      {/snippet}
    </ScreenHeader>

    {#if loadError}
      <div class="notice">
        <p class="notice-text">{loadError}</p>
        <Button variant="secondary" onclick={loadData}>Try again</Button>
      </div>
    {:else if identities.length === 0}
      <div class="empty">
        <span class="empty-seal" aria-hidden="true">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </span>
        <p class="empty-title">No identities yet</p>
        <p class="empty-sub">Create a new identity, or import one you already control.</p>
        <Button onclick={onadd}>Create or import</Button>
      </div>
    {:else}
      <!-- The protection strip. A door, not a readout: the sweep is the wallet's one
           continuously-running defence, and until it could be inspected the app could only
           assert that it was happening. Rendered from the same `summarize` the Protection
           surface's panel uses, so the door can never state something the room contradicts. -->
      {#snippet stripBody()}
        <span class="monitor-ic" aria-hidden="true">
          {#if summary.urgency === 'critical'}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          {:else if summary.urgency === 'expired'}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          {:else if summary.urgency === 'warning'}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
          {:else if !summary.verified}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M10 9.5a2.2 2.2 0 0 1 4 1.2c0 1.4-1.9 1.8-1.9 2.8"/><path d="M12 16.5h.01"/></svg>
          {:else if allWeb}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          {:else}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          {/if}
        </span>
        <span class="monitor-body">
          <span class="monitor-t">{summary.headline}</span>
          <span class="monitor-s">
            <!-- The pulse marks a live watch, so it appears only where one is actually
                 running and answering: never over an unreached directory, an alarm, or an
                 all-did:web wallet that has no public record to watch. -->
            {#if summary.urgency === 'safe' && summary.verified && !allWeb}
              <span class="pulse" aria-hidden="true"></span>
            {/if}
            {summary.detail}
          </span>
        </span>
      {/snippet}

      {#if onprotection}
        <button class="monitor monitor--{stripTone} monitor--door" onclick={onprotection}>
          {@render stripBody()}
          <svg class="monitor-chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
        </button>
      {:else}
        <div class="monitor monitor--{stripTone}">{@render stripBody()}</div>
      {/if}

      <p class="section-label">Your seals</p>

      <div class="cards">
        {#each identities as card (card.did)}
          {@const alerts = alertData.get(card.did)}
          {@const strip = activeStrip(card, alerts, Boolean(onrekey && rekeyEligible.get(card.did)))}
          <div class="card-group">
          <button class="card" class:card--alert={strip === 'alert'} class:card--rekey={strip === 'rekey'} class:card--unusable={strip === 'unusable' || strip === 'unusable-web'} onclick={() => onselect(card.did, card.didDoc ?? {}, card.deviceKeyIsRoot, card.deviceKeyUnusable)}>
            <DIDAvatar did={card.did} handle={card.handle ?? 'Unknown'} />
            <span class="info">
              <span class="handle">{card.handle ? '@' + card.handle : 'Unknown handle'}</span>
              <span class="did">{truncateDid(card.did)}</span>
              {#if card.pdsUrl}<span class="pds">on {hostOf(card.pdsUrl)}</span>{/if}
              <span class="badges">
                {#if isDidWeb(card.did)}
                  <!-- did:web has no rotation keys, so "root key" doesn't apply. Name the method
                       honestly instead of showing an "Unknown" root-key badge that reads as a fault. -->
                  <span class="badge badge--web">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13 13 0 0 1 3.4 9A13 13 0 0 1 12 21a13 13 0 0 1-3.4-9A13 13 0 0 1 12 3z"/></svg>
                    did:web
                  </span>
                  {#if card.deviceKeyUnusable}
                    <!-- The method badge names what the identity is, not whether this device
                         can act for it. A did:web with a dead key must say so too. -->
                    <span class="badge badge--unusable">
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
                      Can't sign
                    </span>
                  {/if}
                {:else if card.deviceKeyUnusable}
                  <!-- Not "Unknown" (which reads as a lookup that failed) and not "Not root"
                       (the DID document still lists this device's key first). The key is gone
                       from this device: name that, and never colour alone. -->
                  <span class="badge badge--unusable">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
                    Can't sign
                  </span>
                {:else}
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
                {/if}
              </span>
            </span>
            <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
          </button>
          {#if strip === 'unusable'}
            <!-- The honest degraded state: this device's key for the identity is gone, so
                 nothing it does can sign. Recovery mints a fresh Secure Enclave key and
                 rotates it into rotationKeys[0] — the right destination, offered rather
                 than launched. Seal-toned, not the critical palette: the identity itself
                 is intact; only this device's control of it is not. -->
            <button class="unusable-strip" onclick={() => onrecover?.(card.did)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
              <span class="strip-body">
                <span class="strip-t">This device can no longer sign for this identity</span>
                <span class="strip-s">Recover to restore control</span>
              </span>
              <svg class="strip-chev" width="8" height="14" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {:else if strip === 'unusable-web'}
            <!-- No ceremony to offer: a did:web has no rotation keys to rotate into. The
                 remedy is domain-side, so this opens the identity where it is explained. -->
            <button
              class="unusable-strip"
              onclick={() => onselect(card.did, card.didDoc ?? {}, card.deviceKeyIsRoot, card.deviceKeyUnusable)}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
              <span class="strip-body">
                <span class="strip-t">This device can no longer sign for this identity</span>
                <span class="strip-s">See what to do</span>
              </span>
              <svg class="strip-chev" width="8" height="14" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {:else if strip === 'alert' && alerts}
            <button class="alert-strip" onclick={() => onalert?.(card.did, alerts)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
              Review {alerts.length} unauthorized {alerts.length === 1 ? 'change' : 'changes'}
              <svg class="strip-chev" width="8" height="14" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {:else if strip === 'rekey'}
            <!-- Calm, non-alarmist upgrade prompt (this is an improvement, not an incident): a
                 seal-toned strip, deliberately NOT the critical/alert palette. Yields to an active
                 alert strip, which takes priority for the same card. -->
            <button class="rekey-strip" onclick={() => onrekey?.(card.did)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 11.5 2 2 4-4"/></svg>
              Add a recovery key
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
<!-- The door names the question behind it rather than pre-empting it with two of the
               four answers — the situation screen is what sorts create from claim from
               recovery, and listing a subset here would send the other two away. -->
          <span class="add-s">Whatever your situation — we'll work out the rest</span>
        </span>
      </button>

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

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--size-tap-target);
    height: var(--size-tap-target);
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

  /* The gear is the "reveal the machinery" affordance — aubergine, like links
     and advanced-detail disclosures, not a status or a primary action. */
  .icon-btn--settings {
    color: var(--color-accent);
  }

  /* The protection strip — derived from real monitor state, never decorative, and a door
     into the Protection surface rather than a readout that dead-ends. */
  .monitor {
    display: flex;
    align-items: center;
    gap: 13px;
    width: 100%;
    /* Carried by both branches, not just the door, so the button and the div occupy
       identical space — a strip that shifted by 2px depending on whether it was tappable
       would be a layout tell for a state difference the user is not being shown. */
    border: 1px solid transparent;
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    text-align: left;
  }
  .monitor--door {
    min-height: var(--size-tap-target);
    cursor: pointer;
    transition: border-color var(--duration-base) var(--ease-standard);
  }
  .monitor--door:active {
    border-color: currentColor;
  }
  .monitor-chev {
    margin-left: auto;
    flex-shrink: 0;
    opacity: 0.65;
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
    gap: var(--space-3xs);
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
  /* did:web informational banner — neutral aubergine "reveal the machinery" tone, never the green
     safe shield (which would imply active monitoring the wallet does not do for did:web). */
  .monitor--web {
    background: var(--color-seal-tint);
  }
  .monitor--web .monitor-ic {
    color: var(--color-accent);
  }
  .monitor--web .monitor-t {
    color: var(--color-ink);
  }
  .monitor--web .monitor-s {
    color: var(--color-muted);
  }
  /* A state needing action, not an incident on the identity: the warning tone, matching the
     card's badge and strip, never the critical/alert palette. Follows the same per-part
     colouring as the other banner variants. */
  .monitor--warning {
    background: var(--color-warning-surface);
  }
  .monitor--warning .monitor-ic {
    color: var(--color-warning);
  }
  .monitor--warning .monitor-t {
    color: var(--color-warning);
  }
  .monitor--warning .monitor-s {
    color: var(--color-ink-soft);
  }
  .monitor--critical {
    background: var(--color-critical-surface);
  }
  .monitor--critical .monitor-ic {
    color: var(--color-critical);
  }
  .monitor--critical .monitor-t {
    color: var(--color-critical);
  }
  .monitor--critical .monitor-s {
    color: var(--color-critical-soft);
  }
  /* Ashen and closed — the moment to act has passed, a different fact from "act now" and
     deliberately not sharing the alarm's colour. */
  .monitor--expired {
    background: var(--color-expired-surface);
  }
  .monitor--expired .monitor-ic,
  .monitor--expired .monitor-t,
  .monitor--expired .monitor-s {
    color: var(--color-expired);
  }
  /* No fresh reading: calm slate, claiming nothing. Not green (which would assert a check
     that failed) and not amber (nothing is wrong with the identities). */
  .monitor--unverified {
    background: var(--color-info-surface);
  }
  .monitor--unverified .monitor-ic,
  .monitor--unverified .monitor-t,
  .monitor--unverified .monitor-s {
    color: var(--color-info);
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
    padding: var(--space-md);
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
    gap: var(--space-2xs);
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
    font-size: var(--text-label);
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
  /* A definite loss of local signing ability, not an incident on the identity — the warning
     tone, not the critical one. The label and the struck-lock icon carry the meaning; the
     colour only reinforces it. */
  .badge--unusable {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  /* Neutral method badge for did:web — not a status, so it borrows the aubergine accent, not a
     safe/warning color. */
  .badge--web {
    background: var(--color-seal-tint);
    color: var(--color-accent);
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
  /* Same fuse for the calm re-key upgrade strip. */
  .card--rekey,
  .card--unusable {
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  .alert-strip {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--size-tap-target);
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

  /* Calm upgrade strip: seal-toned, deliberately NOT the critical/alert palette — a re-key is an
     improvement, not an incident. Fuses to the bottom of the card like the alert strip. */
  .rekey-strip {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--size-tap-target);
    padding: 10px 15px;
    background: var(--color-seal-tint);
    color: var(--color-accent);
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
  .rekey-strip:active {
    border-color: var(--color-accent);
  }
  .rekey-strip .strip-chev {
    color: var(--color-accent);
  }

  /* Two-line strip: the state, then what to do about it. Seal-toned like the re-key strip
     rather than the alert palette — the identity is intact, only this device's control of
     it is not, and an alarm here would misstate the stakes. */
  .unusable-strip {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--size-tap-target);
    padding: 10px 15px;
    background: var(--color-seal-tint);
    color: var(--color-accent);
    border: 1px solid var(--color-line);
    border-top: none;
    border-bottom-left-radius: var(--radius-xl);
    border-bottom-right-radius: var(--radius-xl);
    text-align: left;
    cursor: pointer;
    transition: border-color var(--duration-base) var(--ease-standard);
  }
  .unusable-strip:active {
    border-color: var(--color-accent);
  }
  .unusable-strip .strip-chev {
    color: var(--color-accent);
    margin-left: auto;
  }
  .unusable-strip > svg:first-child {
    flex-shrink: 0;
  }
  .strip-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .strip-t {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
  }
  .strip-s {
    font-size: var(--text-caption);
    color: var(--color-muted);
  }

  .chev {
    color: var(--color-ink-faint);
    flex-shrink: 0;
  }

  .add-card {
    display: flex;
    align-items: center;
    gap: 13px;
    background: transparent;
    border: 1.5px dashed var(--color-line);
    border-radius: var(--radius-xl);
    padding: var(--space-md);
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

</style>
