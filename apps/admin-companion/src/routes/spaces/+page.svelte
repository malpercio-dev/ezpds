<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    listHostedSpaces,
    setSpaceTakedown,
    type HostedSpaceEntry,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createArmedAction } from '$lib/armed-action.svelte';
  import { createPagedList } from '$lib/paged-list.svelte';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // Spaces: the permissioned-data inventory of ONE relay, and the per-space takedown.
  // Two kinds of row, and the distinction is the whole point — a space this server
  // governs, whose owner can delete it, and a space governed elsewhere that this server
  // only stores members' repos in, where takedown is the operator's ONLY lever. Pinned
  // to a single pairing at entry (see $lib/pinned-pairing) like Devices and Transfers;
  // paged via the relay cursor.
  //
  // Takedown carries the same friction as an account takedown: expanding a row is not
  // arming, the first tap ARMS an explicit confirmation restating the relay-returned URI,
  // and confirming runs the biometric gate before anything is signed. One armed action
  // for the screen rather than one per row, because only the expanded row can be armed —
  // collapsing or expanding another disarms it, so a confirm can never sit under a row
  // the operator is no longer looking at.

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let pairing = $state<Pairing | null>(null);
  let expandedUri = $state<string | null>(null);
  /** Narrow the listing to the spaces this server already refuses. */
  let refusedOnly = $state(false);

  const spaces = createPagedList<HostedSpaceEntry>((cursor) =>
    listHostedSpaces(pairing!.id, cursor, refusedOnly ? { status: 'takendown' } : {}).then((r) => ({
      items: r.spaces,
      cursor: r.cursor,
    })),
  );
  const takedown = createArmedAction();

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) await spaces.load();
  });

  function toggleExpanded(uri: string) {
    // Collapsing (or moving to another row) must never leave a confirm armed behind it.
    takedown.disarm();
    expandedUri = expandedUri === uri ? null : uri;
  }

  async function toggleFilter() {
    refusedOnly = !refusedOnly;
    takedown.disarm();
    expandedUri = null;
    await spaces.load();
  }

  /** Tap 2: gate on user presence, then sign the takedown (or the restore). */
  async function confirmWrite(entry: HostedSpaceEntry) {
    if (!pairing) return;
    const pinned = pairing;
    const uri = entry.uri;
    const applied = entry.takendownAt === undefined;
    await takedown.confirm({
      reason: applied
        ? 'Take down a space on this server'
        : 'Restore a space on this server',
      deniedHint: applied
        ? 'Confirm with Face ID to take down this space.'
        : 'Confirm with Face ID to restore this space.',
      // Re-checked here, not just in render, so no caller — including the error panel's
      // retry — can sign against a row the operator has since collapsed.
      precondition: () => expandedUri === uri,
      run: async () => {
        await setSpaceTakedown(pinned.id, uri, applied);
        // Reload so the list reports the relay's post-write truth (including a row
        // leaving the filtered set) rather than an optimistic local edit.
        await spaces.load();
      },
    });
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
</script>

{#snippet spaceRow(entry: HostedSpaceEntry)}
  {@const refused = entry.takendownAt !== undefined}
  <div class="space-item">
    <button
      class="space-row"
      type="button"
      aria-expanded={expandedUri === entry.uri}
      aria-controls={`space-panel-${entry.uri}`}
      onclick={() => toggleExpanded(entry.uri)}
    >
      <span class="space-uri">{entry.uri}</span>
      <span class="space-counts">
        {entry.repoCount} repo{entry.repoCount === 1 ? '' : 's'} ·
        {entry.recordCount} record{entry.recordCount === 1 ? '' : 's'}
      </span>
      <!-- Authority is stated in words on every row, not inferred from an icon: it is
           what decides whether the operator has any other option than takedown. -->
      <StatusChip
        status={refused ? 'revoked' : 'active'}
        label={refused ? 'refused' : 'serving'}
      />
    </button>

    {#if expandedUri === entry.uri}
      <div class="space-panel" id={`space-panel-${entry.uri}`}>
        <dl class="facts">
          <dt>authority</dt>
          <dd>{entry.authorityDid}</dd>
          <dt>governed by</dt>
          <dd>{entry.localAuthority ? 'this server' : 'another server'}</dd>
          <dt>first seen</dt>
          <dd>{entry.createdAt}</dd>
          <dt>repos stored</dt>
          <dd>{entry.repoCount}</dd>
          <dt>records stored</dt>
          <dd>{entry.recordCount}</dd>
          {#if entry.deletedAt}
            <dt>deleted by owner</dt>
            <dd>{entry.deletedAt}</dd>
          {/if}
          {#if entry.takendownAt}
            <dt>taken down</dt>
            <dd>{entry.takendownAt}</dd>
          {/if}
        </dl>

        {#if !entry.localAuthority}
          <p class="note">
            Another server governs this space, so its owner's delete is not available
            here. Taking it down is the only way to stop storing and serving these
            records.
          </p>
        {/if}

        {#if !takedown.armed}
          <Button
            variant={refused ? 'primary' : 'destructive'}
            loading={takedown.writing}
            onclick={takedown.arm}
          >
            {refused ? 'Restore this space' : 'Take down this space'}
          </Button>
        {:else}
          <div
            class="confirm"
            role="group"
            aria-label={refused ? 'Confirm restore' : 'Confirm takedown'}
          >
            <p class="confirm-text">
              {#if refused}
                Restore <span class="confirm-uri">{entry.uri}</span> on {identity?.host}?
                Reads, writes, and sync resume for everyone who was using it.
              {:else}
                Take down <span class="confirm-uri">{entry.uri}</span> on {identity?.host}?
                Reads, writes, and sync are refused until it is restored. Nothing stored is
                deleted — the {entry.recordCount} record{entry.recordCount === 1 ? '' : 's'}
                stay where they are.
              {/if}
            </p>
            <Button
              variant={refused ? 'primary' : 'destructive'}
              loading={takedown.writing}
              onclick={() => confirmWrite(entry)}
            >
              {refused ? 'Confirm restore' : 'Confirm takedown'}
            </Button>
            <Button variant="secondary" disabled={takedown.writing} onclick={takedown.disarm}>
              Cancel
            </Button>
          </div>
        {/if}

        {#if takedown.error}
          <ErrorState
            view={takedown.error}
            server={identity}
            retrying={takedown.writing}
            onretry={() => confirmWrite(entry)}
          />
        {/if}
        {#if takedown.gateHint}
          <p class="hint" role="status">
            <StatusChip status="info" label="confirm" />
            <span>{takedown.gateHint}</span>
          </p>
        {/if}
      </div>
    {/if}
  </div>
{/snippet}

<ScreenShell
  prompt="spaces"
  title="Spaces this server stores"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate
    view={pairingsView}
    {pairing}
    resource="spaces are always read from a specific server."
  >
    {#snippet children()}
      {#if spaces.kind === 'loading'}
        <p class="resolving">reading stored spaces…</p>
      {:else if spaces.kind === 'error'}
        <ErrorState view={spaces.errorView!} server={identity} onretry={() => spaces.load()} />
      {:else}
        <section class="panel" aria-labelledby="spaces-label">
          <span id="spaces-label" class="label">
            {refusedOnly ? 'Refused' : 'Stored'} · {spaces.items.length}
          </span>
          <Button variant="secondary" onclick={toggleFilter}>
            {refusedOnly ? 'Show every space' : 'Show only refused spaces'}
          </Button>

          {#if spaces.items.length === 0}
            <p class="note">
              {#if refusedOnly}
                No spaces are taken down on this server.
              {:else}
                This server stores no spaces. A row appears when one of its accounts
                creates a space, or first writes into a space another server governs.
              {/if}
            </p>
          {:else}
            <div class="space-list">
              {#each spaces.items as entry (entry.uri)}
                {@render spaceRow(entry)}
              {/each}
            </div>
          {/if}
        </section>

        {#if spaces.cursor}
          <Button variant="secondary" loading={spaces.paging} onclick={() => spaces.loadMore()}>
            Load more
          </Button>
          {#if spaces.pagingError}
            <ErrorState
              view={spaces.pagingError!}
              server={identity}
              retrying={spaces.paging}
              onretry={() => spaces.loadMore()}
            />
          {/if}
        {/if}
      {/if}
    {/snippet}
  </PinnedPairingGate>

  {#snippet actions()}
    {#if pairing && spaces.kind === 'ready'}
      <Button variant="secondary" onclick={() => spaces.load()}>Refresh</Button>
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
  .space-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .space-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .space-row {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2xs);
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
  .space-row:hover,
  .space-row:active {
    background: var(--color-surface);
  }
  /* The URI is the row's identity — mono, and wrapped rather than clipped: the
     authority DID sits in the middle, so a truncated URI would hide which server
     governs the space, the one fact that decides what the operator can do. */
  .space-uri {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    overflow-wrap: anywhere;
  }
  .space-counts {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .space-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding: var(--space-md);
    border-top: var(--border-hairline) solid var(--color-line);
  }
  /* The fact sheet: aligned label/value pairs, the legibility of a good `ls -l`. */
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2xs) var(--space-md);
    margin: 0;
  }
  .facts dt {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .facts dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  /* The armed confirmation: a visibly raised, critical-edged block — the screen state
     itself signals "you are one tap from a signed takedown", not color alone (the
     restated URI and button copy carry the meaning too). */
  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding: var(--space-md);
    border: var(--border-hairline) solid var(--color-critical);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .confirm-text {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink);
  }
  .confirm-uri {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    overflow-wrap: anywhere;
  }
</style>
