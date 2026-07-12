<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { SvelteMap } from 'svelte/reactivity';
  import {
    listPairings,
    listTransfers,
    cancelTransfer,
    type TransferEntry,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { accountLabel, chipFor, timelineLine } from '$lib/transfers';
  import { shortenId } from '$lib/format';
  import { serverIdentity } from '$lib/server-identity';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // In-flight device transfers: every planned device swap on ONE relay that can still
  // advance — a security-relevant pending state (from initiate onward a live code can
  // hand out device credentials; once accepted, the target device already holds a
  // working token). Cancelling interrupts the swap without touching the account's
  // sessions. Pinned to a single pairing at entry (`?server=<pairingId>`, else the
  // active pairing) — id-addressed like Devices, so a concurrent active switch on Home
  // can never redirect what this screen shows or signs.

  type TransfersState =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; transfers: TransferEntry[]; cursor?: string; paging: boolean };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let inflight = $state<TransfersState>({ kind: 'loading' });
  // A failed *page* fetch never clobbers the rows already shown — it renders
  // inline next to the paging button instead (mirrors the Accounts screen).
  let pagingError = $state<ErrorView | undefined>(undefined);
  let expandedId = $state<string | null>(null);
  let cancelingStates = $state<SvelteMap<string, boolean>>(new SvelteMap());
  let cancelErrors = $state<SvelteMap<string, ErrorView | undefined>>(new SvelteMap());
  let gateHint = $state<string | undefined>(undefined);

  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  onMount(async () => {
    try {
      pairingsView = await listPairings();
    } catch {
      pairingsView = 'error';
      return;
    }
    const requested = page.url.searchParams.get('server');
    const targetId = requested ?? pairingsView.active;
    pairing = pairingsView.pairings.find((p) => p.id === targetId) ?? null;
    if (pairing) await loadTransfers(pairing.id);
  });

  async function loadTransfers(pairingId: string) {
    inflight = { kind: 'loading' };
    pagingError = undefined;
    try {
      const first = await listTransfers(pairingId);
      inflight = {
        kind: 'ready',
        transfers: first.transfers,
        cursor: first.cursor,
        paging: false,
      };
    } catch (e) {
      inflight = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  /** Fetch the next page and append — the accumulated list stays newest-first. */
  async function loadMore() {
    if (!pairing || inflight.kind !== 'ready' || !inflight.cursor || inflight.paging) return;
    inflight = { ...inflight, paging: true };
    pagingError = undefined;
    try {
      const next = await listTransfers(pairing.id, inflight.cursor);
      inflight = {
        kind: 'ready',
        transfers: [...inflight.transfers, ...next.transfers],
        cursor: next.cursor,
        paging: false,
      };
    } catch (e) {
      // A failed page keeps what is already shown; the error renders by the button.
      pagingError = classifyRelayError(e);
      inflight = { ...inflight, paging: false };
    }
  }

  async function doCancel(entry: TransferEntry) {
    if (!pairing) return;
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent cancels.
    if (cancelingStates.get(entry.id)) return;
    cancelingStates.set(entry.id, true);
    gateHint = undefined;
    cancelErrors.set(entry.id, undefined);

    try {
      // Cancelling kills a live swap (and an accepted device's credential) — gate it
      // on user presence.
      const presence = await requireUserPresence('Cancel a device transfer on this server');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to cancel this transfer.';
        return;
      }
      await cancelTransfer(pairing.id, entry.id);
      // Reload so the list reports the relay's post-cancel truth (the transfer leaves
      // the in-flight set) rather than an optimistic local edit.
      await loadTransfers(pairing.id);
    } catch (e) {
      cancelErrors.set(entry.id, classifyRelayError(e));
    } finally {
      cancelingStates.set(entry.id, false);
    }
  }

  function toggleExpanded(id: string) {
    expandedId = expandedId === id ? null : id;
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
</script>

{#snippet transferRow(entry: TransferEntry)}
  {@const chip = chipFor(entry.status)}
  <div class="transfer-item">
    <button
      class="transfer-row"
      type="button"
      aria-expanded={expandedId === entry.id}
      aria-controls={`transfer-panel-${entry.id}`}
      onclick={() => toggleExpanded(entry.id)}
    >
      <span class="transfer-account">{shortenId(accountLabel(entry))}</span>
      <span class="transfer-timeline">{timelineLine(entry)}</span>
      <StatusChip status={chip.chip} label={chip.label} />
    </button>

    {#if expandedId === entry.id}
      <div class="transfer-panel" id={`transfer-panel-${entry.id}`}>
        <dl class="facts">
          <dt>account</dt>
          <dd>{entry.did}</dd>
          {#if entry.handle}
            <dt>handle</dt>
            <dd>{entry.handle}</dd>
          {/if}
          <dt>opened</dt>
          <dd>{entry.createdAt}</dd>
          <dt>code expires</dt>
          <dd>{entry.expiresAt}</dd>
          {#if entry.acceptedAt}
            <dt>accepted</dt>
            <dd>{entry.acceptedAt}</dd>
          {/if}
          {#if entry.acceptedDevicePlatform}
            <dt>by device</dt>
            <dd>{entry.acceptedDevicePlatform}</dd>
          {/if}
        </dl>

        <p class="note">
          Cancelling stops this swap and revokes the accepting device's credential. The
          account's existing sessions are untouched.
        </p>
        <Button
          variant="destructive"
          loading={cancelingStates.get(entry.id) ?? false}
          onclick={() => doCancel(entry)}
        >
          Cancel this transfer
        </Button>
        {#if cancelErrors.get(entry.id)}
          <ErrorState
            view={cancelErrors.get(entry.id)!}
            server={identity}
            retrying={cancelingStates.get(entry.id) ?? false}
            onretry={() => doCancel(entry)}
          />
        {/if}
      </div>
    {/if}
  </div>
{/snippet}

<ScreenShell
  prompt="transfers"
  title="Device transfers in flight"
  onback={() => history.back()}
  server={identity}
>
  {#if pairingsView === 'loading'}
    <p class="resolving">checking servers…</p>
  {:else if pairingsView === 'error'}
    <section class="panel" aria-label="Server check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">Couldn't read this device's servers. Go back and retry.</p>
    </section>
  {:else if !pairing}
    <!-- Unpaired, or no active pick and no ?server pin — there is no relay to ask. -->
    <section class="panel" aria-label="No server selected">
      <StatusChip status="pending" label="no server" />
      <p class="note">
        No server is selected. Pick or pair one first — in-flight transfers are always
        read from a specific server.
      </p>
    </section>
  {:else if inflight.kind === 'loading'}
    <p class="resolving">reading in-flight transfers…</p>
  {:else if inflight.kind === 'error'}
    <ErrorState
      view={inflight.view}
      server={identity}
      onretry={() => pairing && loadTransfers(pairing.id)}
    />
  {:else}
    <p class="lede">
      Every planned device swap on this server that can still advance. A transfer whose
      code was accepted means a new device already holds a working credential — cancel
      it to interrupt the swap.
    </p>

    <section class="panel" aria-labelledby="inflight-label">
      <span id="inflight-label" class="label">In flight · {inflight.transfers.length}</span>
      {#if inflight.transfers.length === 0}
        <p class="note">
          No transfers in flight. A user starting a device swap from their old device
          appears here until the swap completes, expires, or is cancelled.
        </p>
      {:else}
        <div class="transfer-list">
          {#each inflight.transfers as entry (entry.id)}
            {@render transferRow(entry)}
          {/each}
        </div>
      {/if}
    </section>

    {#if inflight.cursor}
      <Button variant="secondary" loading={inflight.paging} onclick={loadMore}>
        Load more
      </Button>
      {#if pagingError}
        <ErrorState view={pagingError} server={identity} retrying={inflight.paging} onretry={loadMore} />
      {/if}
    {/if}

    {#if gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{gateHint}</span>
      </p>
    {/if}
  {/if}

  {#snippet actions()}
    {#if pairing && inflight.kind === 'ready'}
      <Button variant="secondary" onclick={() => pairing && loadTransfers(pairing.id)}>
        Refresh
      </Button>
    {/if}
  {/snippet}
</ScreenShell>

<style>
  .panel {
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .lede {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .note {
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .resolving {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .hint {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .transfer-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .transfer-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .transfer-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--control-min-height);
    padding: var(--space-sm);
    background: transparent;
    border: none;
    font: inherit;
    color: inherit;
    cursor: pointer;
    text-align: left;
  }
  .transfer-row:hover,
  .transfer-row:active {
    background: var(--color-surface);
  }
  /* The account under transfer is the row's identity: mono, like DeviceRow.
     Shortened with an explicit ellipsis in the markup — never clipped by CSS. */
  .transfer-account {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    max-width: 40%;
  }
  .transfer-timeline {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .transfer-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    padding-top: var(--space-sm);
    border-top: var(--border-hairline) solid var(--color-line);
  }
  /* The fact sheet: aligned label/value pairs, the legibility of a good `ls -l`. */
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2xs) var(--space-md);
    margin: 0;
  }
  /* Inside a raised well: ink-soft, per the tokens.css contrast rule for muted. */
  .facts dt {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink-soft);
  }
  .facts dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
</style>
