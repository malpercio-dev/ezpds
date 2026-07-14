<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    listTransfers,
    cancelTransfer,
    type TransferEntry,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { accountLabel, chipFor, timelineLine } from '$lib/transfers';
  import { shortenId } from '$lib/format';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createGuardedActions } from '$lib/guarded-action.svelte';
  import { createPagedList } from '$lib/paged-list.svelte';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // In-flight device transfers: every planned device swap on ONE relay that can still
  // advance — a security-relevant pending state (from initiate onward a live code can
  // hand out device credentials; once accepted, the target device already holds a
  // working token). Cancelling interrupts the swap without touching the account's
  // sessions. Pinned to a single pairing at entry (see $lib/pinned-pairing), id-addressed
  // like Devices; paged via the relay cursor.

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let expandedId = $state<string | null>(null);
  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  // The cursor-paged in-flight list, and the per-row busy/error + gate-hint state for
  // the biometric-gated cancel.
  const inflight = createPagedList<TransferEntry>((cursor) =>
    listTransfers(pairing!.id, cursor).then((r) => ({ items: r.transfers, cursor: r.cursor })),
  );
  const guarded = createGuardedActions();

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) await inflight.load();
  });

  async function doCancel(entry: TransferEntry) {
    if (!pairing) return;
    const target = pairing;
    await guarded.run({
      id: entry.id,
      reason: 'Cancel a device transfer on this server',
      deniedHint: 'Confirm with Face ID to cancel this transfer.',
      action: async () => {
        await cancelTransfer(target.id, entry.id);
        // Reload so the list reports the relay's post-cancel truth (the transfer leaves
        // the in-flight set) rather than an optimistic local edit.
        await inflight.load();
      },
    });
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
          loading={guarded.isBusy(entry.id)}
          onclick={() => doCancel(entry)}
        >
          Cancel this transfer
        </Button>
        {#if guarded.errorFor(entry.id)}
          <ErrorState
            view={guarded.errorFor(entry.id)!}
            server={identity}
            retrying={guarded.isBusy(entry.id)}
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
  <PinnedPairingGate view={pairingsView} {pairing} resource="in-flight transfers are always read from a specific server.">
    {#snippet children()}
    {#if inflight.kind === 'loading'}
    <p class="resolving">reading in-flight transfers…</p>
  {:else if inflight.kind === 'error'}
    <ErrorState view={inflight.errorView!} server={identity} onretry={() => inflight.load()} />
  {:else}
    <p class="lede">
      Every planned device swap on this server that can still advance. A transfer whose
      code was accepted means a new device already holds a working credential — cancel
      it to interrupt the swap.
    </p>

    <section class="panel" aria-labelledby="inflight-label">
      <span id="inflight-label" class="label">In flight · {inflight.items.length}</span>
      {#if inflight.items.length === 0}
        <p class="note">
          No transfers in flight. A user starting a device swap from their old device
          appears here until the swap completes, expires, or is cancelled.
        </p>
      {:else}
        <div class="transfer-list">
          {#each inflight.items as entry (entry.id)}
            {@render transferRow(entry)}
          {/each}
        </div>
      {/if}
    </section>

    {#if inflight.cursor}
      <Button variant="secondary" loading={inflight.paging} onclick={() => inflight.loadMore()}>
        Load more
      </Button>
      {#if inflight.pagingError}
        <ErrorState view={inflight.pagingError!} server={identity} retrying={inflight.paging} onretry={() => inflight.loadMore()} />
      {/if}
    {/if}

    {#if guarded.gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{guarded.gateHint}</span>
      </p>
    {/if}
  {/if}
    {/snippet}
  </PinnedPairingGate>

  {#snippet actions()}
    {#if pairing && inflight.kind === 'ready'}
      <Button variant="secondary" onclick={() => inflight.load()}>
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
