<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    listClaimCodes,
    revokeClaimCode,
    type ClaimCodeEntry,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { partitionCodes, chipFor, timelineLine } from '$lib/claim-codes';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createGuardedActions } from '$lib/guarded-action.svelte';
  import { createPagedList } from '$lib/paged-list.svelte';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The claim-code inventory: every code minted on ONE relay with its derived
  // lifecycle status, split into outstanding live credentials (revocable) and the
  // historical record. Pinned to a single pairing at entry (see $lib/pinned-pairing),
  // id-addressed like Devices; paged via the relay cursor.

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let expandedCode = $state<string | null>(null);
  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  // The cursor-paged inventory, and the per-row busy/error + gate-hint state for the
  // biometric-gated revoke.
  const inventory = createPagedList<ClaimCodeEntry>((cursor) =>
    listClaimCodes(pairing!.id, cursor).then((r) => ({ items: r.codes, cursor: r.cursor })),
  );
  const guarded = createGuardedActions();

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) await inventory.load();
  });

  async function doRevoke(entry: ClaimCodeEntry) {
    if (!pairing) return;
    const target = pairing;
    await guarded.run({
      id: entry.code,
      reason: 'Revoke a claim code on this server',
      deniedHint: 'Confirm with Face ID to revoke this code.',
      action: async () => {
        await revokeClaimCode(target.id, entry.code);
        // Reload so the row reports the relay's post-revoke truth (status flips to
        // revoked with its timestamp) rather than an optimistic local edit.
        await inventory.load();
      },
    });
  }

  function toggleExpanded(code: string) {
    expandedCode = expandedCode === code ? null : code;
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
  const grouped = $derived(
    inventory.kind === 'ready' ? partitionCodes(inventory.items) : null,
  );
</script>

{#snippet codeRow(entry: ClaimCodeEntry, revocable: boolean)}
  {@const chip = chipFor(entry.status)}
  <div class="code-item">
    <button
      class="code-row"
      type="button"
      aria-expanded={expandedCode === entry.code}
      aria-controls={`code-panel-${entry.code}`}
      onclick={() => toggleExpanded(entry.code)}
    >
      <span class="code-value">{entry.code}</span>
      <span class="code-timeline">{timelineLine(entry)}</span>
      <StatusChip status={chip.chip} label={chip.label} />
    </button>

    {#if expandedCode === entry.code}
      <div class="code-panel" id={`code-panel-${entry.code}`}>
        <dl class="facts">
          <dt>minted</dt>
          <dd>{entry.createdAt}</dd>
          <dt>expires</dt>
          <dd>{entry.expiresAt}</dd>
          {#if entry.redeemedAt}
            <dt>redeemed</dt>
            <dd>{entry.redeemedAt}</dd>
          {/if}
          {#if entry.revokedAt}
            <dt>revoked</dt>
            <dd>{entry.revokedAt}</dd>
          {/if}
        </dl>

        {#if revocable}
          <Button
            variant="destructive"
            loading={guarded.isBusy(entry.code)}
            onclick={() => doRevoke(entry)}
          >
            Revoke this code
          </Button>
          {#if guarded.errorFor(entry.code)}
            <ErrorState
              view={guarded.errorFor(entry.code)!}
              server={identity}
              retrying={guarded.isBusy(entry.code)}
              onretry={() => doRevoke(entry)}
            />
          {/if}
        {/if}
        <!-- A terminal code needs no action: the chip + timestamp already report it. -->
      </div>
    {/if}
  </div>
{/snippet}

<ScreenShell
  prompt="codes"
  title="Claim codes on this server"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="the code inventory is always read from a specific server.">
    {#snippet children()}
    {#if inventory.kind === 'loading'}
    <p class="resolving">reading code inventory…</p>
  {:else if inventory.kind === 'error'}
    <ErrorState view={inventory.errorView!} server={identity} onretry={() => inventory.load()} />
  {:else if grouped}
    <p class="lede">
      Every claim code minted on this server. An outstanding code is a live signup
      credential — revoke one to kill it before anyone redeems it.
    </p>

    <section class="panel" aria-labelledby="outstanding-label">
      <span id="outstanding-label" class="label">
        Outstanding · {grouped.outstanding.length}
      </span>
      {#if grouped.outstanding.length === 0}
        <p class="note">No live codes. Codes minted on Home appear here until redeemed.</p>
      {:else}
        <div class="code-list">
          {#each grouped.outstanding as entry (entry.code)}
            {@render codeRow(entry, true)}
          {/each}
        </div>
      {/if}
    </section>

    {#if grouped.history.length > 0}
      <section class="panel" aria-labelledby="history-label">
        <span id="history-label" class="label">History · {grouped.history.length}</span>
        <div class="code-list">
          {#each grouped.history as entry (entry.code)}
            {@render codeRow(entry, false)}
          {/each}
        </div>
      </section>
    {/if}

    {#if inventory.cursor}
      <Button variant="secondary" loading={inventory.paging} onclick={() => inventory.loadMore()}>
        Load more
      </Button>
      {#if inventory.pagingError}
        <ErrorState view={inventory.pagingError!} server={identity} retrying={inventory.paging} onretry={() => inventory.loadMore()} />
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
    {#if pairing && inventory.kind === 'ready'}
      <Button variant="secondary" onclick={() => inventory.load()}>
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
  .code-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .code-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .code-row {
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
  .code-row:hover,
  .code-row:active {
    background: var(--color-surface);
  }
  /* The code itself is the row's identity: mono, tracked out like CodeOutput. */
  .code-value {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    font-weight: var(--weight-medium);
    letter-spacing: 0.12em;
    color: var(--color-ink);
  }
  .code-timeline {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .code-panel {
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
