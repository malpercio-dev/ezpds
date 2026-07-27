<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    checkIdentityStatus,
    getMonitorHistory,
    type IdentityStatus,
    type MonitorHistory,
    type UnauthorizedChange,
  } from '$lib/ipc';
  import { loadIdentityCards, type IdentityCard } from '$lib/identity-cards';
  import { truncateDid } from '$lib/did-doc-utils';
  import { formatCountdown } from '$lib/deadline';
  import { panelLabel } from '$lib/identity-status';
  import {
    toRow,
    orderRows,
    summarize,
    formatLastVerified,
    describeSweep,
    describeInterval,
    formatClockTime,
    type ProtectionRow,
  } from '$lib/protection';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import StatusPanel from '$lib/components/ui/StatusPanel.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';

  // The app-level Defend surface. Its job is to give the PLC monitor a visible face: the
  // sweep runs unattended every fifteen minutes and, until this screen existed, produced
  // nothing a user could look at — so the wallet's central trust claim rested entirely on
  // the user believing an assertion. Here the evidence is the screen.
  //
  // Two halves, in that order: what is true of each identity right now, then the log of
  // how the wallet came to know it. State leads, evidence follows.
  let {
    onback,
    onselect,
    onalert,
  }: {
    onback: () => void;
    /** Open an identity's instrument panel. */
    onselect: (
      did: string,
      didDoc: Record<string, unknown>,
      deviceKeyIsRoot: boolean | null,
      deviceKeyUnusable: boolean
    ) => void;
    /**
     * Open an identity's alarm surface directly. Taken instead of `onselect` for a row in
     * an alarm state: with a countdown running, the one clear action is the override, and
     * routing through the panel first would spend the user's attention on a screen whose
     * only offer is the same button.
     */
    onalert: (did: string, changes: UnauthorizedChange[]) => void;
  } = $props();

  let cards = $state<IdentityCard[]>([]);
  let alertData = $state<Map<string, UnauthorizedChange[]>>(new Map());
  /**
   * The DIDs the last sweep actually verified — an allowlist, not a failure list, because
   * the sweep omits identities it has no business asking about and absence before the first
   * pass means "not asked yet". See the same reasoning on `IdentityListHome`.
   */
  let sweptOk = $state<Set<string>>(new Set());
  /** False until a sweep result has been absorbed, so "not yet" never reads as "failed". */
  let sweepAnswered = $state(false);
  let history = $state<MonitorHistory | null>(null);
  let loading = $state(true);
  let checking = $state(false);
  let now = $state(Date.now());
  let ticker: ReturnType<typeof setInterval> | null = null;
  let unlisten: UnlistenFn | null = null;
  /**
   * Set synchronously by `onDestroy`, which runs before an async `onMount` can finish.
   * Svelte does not treat an async `onMount`'s return value as a cleanup hook, so a
   * subscription that resolves after teardown has to disarm itself.
   */
  let destroyed = false;

  let rows = $derived<ProtectionRow[]>(
    orderRows(
      cards.map((c) =>
        toRow(
          {
            did: c.did,
            handle: c.handle,
            changes: alertData.get(c.did) ?? [],
            deviceKeyUnusable: c.deviceKeyUnusable,
            plcCheckSucceeded: sweptOk.has(c.did),
            lastVerifiedAt: lastVerifiedFor(c.did),
            degraded: c.degraded,
          },
          now
        )
      )
    )
  );

  let summary = $derived(summarize(rows, history, now, !sweepAnswered));

  function lastVerifiedFor(did: string): string | null {
    return history?.identities.find((e) => e.did === did)?.lastVerifiedAt ?? null;
  }

  function cardFor(did: string): IdentityCard | undefined {
    return cards.find((c) => c.did === did);
  }

  /** What each row says beneath the handle: its state, then the evidence behind it. */
  function rowDetail(row: ProtectionRow): string {
    // Tested first: nothing below this line is a reading for a degraded identity, so any
    // of it would be describing placeholder values as though they were facts.
    if (row.degraded) return "Couldn't read this identity on this device";
    if (row.urgency === 'critical' && row.deadline) return formatCountdown(row.deadline, now);
    if (row.urgency === 'expired') return 'The window to reverse it has closed';
    if (row.urgency === 'warning') {
      // The share-recovery ceremony is structurally did:plc-only — it works by rotating a
      // fresh key into `rotationKeys[0]`, and a did:web has none. Offering "recover" here
      // would name a flow that does not exist for this identity, so the row points at the
      // identity screen, where the domain-side remedy is spelled out.
      return row.isWeb
        ? 'Its remedy is at your domain — open to see what to do'
        : 'Recover to restore control from this device';
    }
    if (row.isWeb) return 'Held at your own domain — no public record to watch';
    if (!row.verified) {
      // Before the first sweep answers there is no failure to report, only a question in
      // flight. The row's last-verified time, if the log has one, is still true meanwhile.
      if (!sweepAnswered) {
        return row.lastVerifiedAt
          ? `Checking now · last ${formatLastVerified(row.lastVerifiedAt, now).toLowerCase()}`
          : 'Checking the public record…';
      }
      return "Couldn't reach the public record";
    }
    return formatLastVerified(row.lastVerifiedAt, now);
  }

  function absorb(statuses: IdentityStatus[]) {
    alertData = new Map(
      statuses.filter((s) => s.unauthorizedChanges.length > 0).map((s) => [s.did, s.unauthorizedChanges])
    );
    sweptOk = new Set(statuses.filter((s) => !s.checkFailed).map((s) => s.did));
    sweepAnswered = true;
  }

  async function refreshHistory() {
    try {
      history = await getMonitorHistory();
    } catch (e) {
      console.warn('Monitor history read failed:', e);
    }
  }

  /** Run a sweep now. The result lands in the log below, which is the point of the button. */
  async function checkNow() {
    checking = true;
    try {
      absorb(await checkIdentityStatus());
    } catch (e) {
      // The sweep's own failure is not hidden: the identities it could not reach keep their
      // unverified rows, and the log simply gains no new entry. Surfacing a toast on top of
      // that would say the same thing twice.
      console.warn('Status check failed:', e);
    } finally {
      await refreshHistory();
      now = Date.now();
      checking = false;
    }
  }

  onMount(async () => {
    try {
      cards = await loadIdentityCards();
    } catch (e) {
      console.error('Failed to load identities:', e);
    } finally {
      loading = false;
    }

    await refreshHistory();
    void checkNow();

    const off = await listen<IdentityStatus[]>('plc_alert', (event) => {
      if (!Array.isArray(event.payload)) return;
      absorb(event.payload);
      void refreshHistory();
    });
    if (destroyed) {
      off();
      return;
    }
    unlisten = off;

    // A minute is the resolution of every readout the clock feeds: countdowns render whole
    // minutes, and "checked N min ago" cannot move faster than that.
    ticker = setInterval(() => {
      now = Date.now();
    }, 60_000);
  });

  onDestroy(() => {
    destroyed = true;
    if (ticker !== null) clearInterval(ticker);
    unlisten?.();
  });
</script>

<div class="screen">
  <ScreenHeader title="Protection" {onback} backLabel="Back to identities">
    {#snippet actions()}
      <button
        class="icon-btn"
        onclick={checkNow}
        disabled={checking}
        aria-label="Check now"
        aria-busy={checking}
      >
        <svg class:spin={checking} width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>
      </button>
    {/snippet}
  </ScreenHeader>

  {#if loading}
    <!-- The shimmer is decoration and stays hidden, but the *fact* that the screen is
         loading is content: without it a screen-reader user hears an empty Protection
         surface and cannot tell "still loading" from "nothing to protect" — the worst
         possible ambiguity on this particular screen. -->
    <div class="loading" role="status" aria-busy="true">
      <span class="sr-only">Loading your identities and the monitor's history…</span>
      <div class="rows" aria-hidden="true">
        {#each [0, 1] as i (i)}
          <SkeletonCard seal />
        {/each}
      </div>
    </div>
  {:else}
    <StatusPanel
      urgency={summary.urgency}
      verified={summary.verified}
      label={summary.headline}
      detail={summary.detail}
      {now}
    />

    {#if rows.length > 0}
      <section class="zone">
        <h2 class="zone-label">Identities</h2>
        <div class="rows">
          {#each rows as row (row.did)}
            {@const alerts = alertData.get(row.did) ?? []}
            <button
              class="row row--{row.urgency === 'safe' && !row.verified ? 'unverified' : row.urgency}"
              onclick={() => {
                if ((row.urgency === 'critical' || row.urgency === 'expired') && alerts.length > 0) {
                  onalert(row.did, alerts);
                  return;
                }
                const card = cardFor(row.did);
                onselect(row.did, card?.didDoc ?? {}, card?.deviceKeyIsRoot ?? null, row.deviceKeyUnusable);
              }}
            >
              <span class="row-ic" aria-hidden="true">
                {#if row.urgency === 'critical'}
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                {:else if row.urgency === 'expired'}
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                {:else if row.urgency === 'warning'}
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
                {:else if !row.verified}
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M10 9.5a2.2 2.2 0 0 1 4 1.2c0 1.4-1.9 1.8-1.9 2.8"/><path d="M12 16.5h.01"/></svg>
                {:else}
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                {/if}
              </span>
              <span class="row-body">
                <span class="row-t">{row.handle ? '@' + row.handle : truncateDid(row.did)}</span>
                <!-- The state is spelled out in words on every row, never carried by the
                     icon and colour alone — the same rule the badge and panel follow. -->
                <span class="row-state">{panelLabel(row.urgency, row.verified)}</span>
                <span class="row-s">{rowDetail(row)}</span>
              </span>
              <svg class="row-chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {/each}
        </div>
      </section>
    {/if}

    <section class="zone">
      <h2 class="zone-label">Monitor history</h2>
      <p class="zone-note">
        {describeInterval(history?.intervalSecs ?? null)}. Each pass compares every identity's
        public record against the copy this wallet holds, and raises the alarm if anything
        changed without your key.
      </p>

      {#if history && history.sweeps.length > 0}
        <ol class="log">
          <!-- Keyed by position, not by content: `at` is second-resolution, so two passes
               of the same trigger in one second that did NOT coalesce (their outcomes
               differed, which is exactly when both must be listed) would collide, and a
               duplicate key is a fatal error in Svelte rather than a render glitch. The log
               is a wholesale-replaced snapshot with no per-item state to preserve, so
               position is the honest key. -->
          {#each history.sweeps as sweep, i (i)}
            <li class="log-item">
              <span class="log-ic" aria-hidden="true">
                {#if sweep.trigger === 'background'}
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                {:else}
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="m10 17 5-5-5-5"/><path d="M15 12H3"/></svg>
                {/if}
              </span>
              <span class="log-body">
                <span class="log-t">
                  {sweep.trigger === 'background' ? 'Background check' : 'Checked on opening'}
                  {#if sweep.unauthorizedFound > 0}
                    <span class="log-flag">flagged</span>
                  {/if}
                </span>
                <span class="log-s">{describeSweep(sweep)}</span>
              </span>
              <time class="log-at" datetime={sweep.at}>{formatClockTime(sweep.at)}</time>
            </li>
          {/each}
        </ol>
      {:else}
        <p class="log-empty">
          No checks recorded yet. The first one runs as soon as the wallet can reach the
          public record.
        </p>
      {/if}
    </section>
  {/if}
</div>

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
  .icon-btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .spin {
    animation: spin 1.1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .spin {
      animation: none;
    }
  }

  .zone {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .zone-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    letter-spacing: 0.01em;
    margin: 0;
  }
  .zone-note {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .rows {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 13px;
    width: 100%;
    min-height: var(--size-tap-target);
    padding: var(--space-md);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard),
      border-color var(--duration-base) var(--ease-standard);
  }
  .row:active {
    background: var(--color-surface);
    border-color: var(--color-line-strong);
  }
  .row-ic {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .row-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .row-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .row-state {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
  }
  .row-s {
    font-size: var(--text-caption);
    color: var(--color-muted);
  }
  .row-chev {
    color: var(--color-ink-faint);
    flex-shrink: 0;
  }

  .row--safe .row-ic {
    background: var(--color-safe-surface);
    color: var(--color-safe);
  }
  .row--safe .row-state {
    color: var(--color-safe);
  }
  .row--unverified .row-ic {
    background: var(--color-info-surface);
    color: var(--color-info);
  }
  .row--unverified .row-state {
    color: var(--color-info);
  }
  .row--warning .row-ic {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .row--warning .row-state {
    color: var(--color-warning);
  }
  .row--critical {
    border-color: var(--color-critical);
  }
  .row--critical .row-ic {
    background: var(--color-critical-surface);
    color: var(--color-critical);
  }
  .row--critical .row-state,
  .row--critical .row-s {
    color: var(--color-critical);
  }
  .row--expired .row-ic {
    background: var(--color-expired-surface);
    color: var(--color-expired);
  }
  .row--expired .row-state {
    color: var(--color-expired);
  }

  /* The log is a receipt, so it reads as records rather than as destinations: no chevrons,
     no tap targets, mono timestamps. Nothing here is actionable — the actions are upstairs
     on the rows, where the state that earns them lives. */
  .log {
    display: flex;
    flex-direction: column;
    gap: 1px;
    list-style: none;
    margin: 0;
    padding: 0;
    background: var(--color-line);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .log-item {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 11px var(--space-md);
    background: var(--color-bg);
  }
  .log-ic {
    color: var(--color-muted);
    display: flex;
    flex-shrink: 0;
  }
  .log-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .log-t {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .log-flag {
    padding: 1px 7px;
    border-radius: var(--radius-full);
    background: var(--color-critical-surface);
    color: var(--color-critical);
    font-size: var(--text-caption);
    font-weight: var(--weight-semibold);
  }
  .log-s {
    font-size: var(--text-caption);
    color: var(--color-muted);
  }
  .log-at {
    font-family: var(--font-mono);
    font-size: var(--text-caption);
    color: var(--color-muted);
    flex-shrink: 0;
  }
  .log-empty {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
    padding: var(--space-md);
    background: var(--color-surface);
    border-radius: var(--radius-lg);
  }
</style>
