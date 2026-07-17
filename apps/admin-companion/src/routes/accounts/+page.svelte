<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import {
    listAccounts,
    type Pairing,
    type PairingsState,
    type AccountListEntry,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { quotaBar } from '$lib/format';
  import { loadPinnedPairing, pinnedHref } from '$lib/pinned-pairing';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import AccountRow from '$lib/components/ui/AccountRow.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The accounts screen: the hub for per-account operator work. Every account on ONE
  // relay — accounts flagged by a watched labeler first (the spam/abuse triage view),
  // DID order within each group, exactly as the relay sorts them — searchable
  // (handle/DID substring) and filterable by derived lifecycle, each row carrying the
  // blob-quota readout so capacity scans across accounts, plus its ⚑ flag lines when a
  // watched labeler has labeled it. Pinned to a single pairing at entry (see
  // $lib/pinned-pairing) like Devices/Moderation. Tapping a row hands the
  // relay-confirmed DID to the account-detail screen (identity facts + usage/storage,
  // with moderation one hop deeper) — replacing DID-pasting as the entry point for
  // per-account work.

  type StatusFilter = 'all' | AccountListEntry['status'];
  const FILTERS: { value: StatusFilter; label: string }[] = [
    { value: 'all', label: 'all' },
    { value: 'active', label: 'active' },
    { value: 'deactivated', label: 'deactivated' },
    { value: 'suspended', label: 'suspended' },
    { value: 'takendown', label: 'taken down' },
  ];

  type ListView =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | {
        kind: 'ready';
        accounts: AccountListEntry[];
        quotaBytes: number;
        flaggedTotal: number;
        cursor: string | null;
      };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let pairing = $state<Pairing | null>(null);
  let q = $state('');
  let statusFilter = $state<StatusFilter>('all');
  let listView = $state<ListView>({ kind: 'loading' });
  let loadingMore = $state(false);
  let moreError = $state<ErrorView | undefined>(undefined);

  // Every (re)load bumps the generation; a slow response for a superseded search or
  // filter must not land under a newer one.
  let generation = 0;

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) void loadFirstPage();
  });

  const identity = $derived(pairing ? serverIdentity(pairing) : null);

  function currentFilters(): { status?: AccountListEntry['status']; q?: string } {
    return {
      ...(statusFilter === 'all' ? {} : { status: statusFilter }),
      ...(q.trim() === '' ? {} : { q: q.trim() }),
    };
  }

  async function loadFirstPage() {
    if (!pairing) return;
    const gen = ++generation;
    listView = { kind: 'loading' };
    moreError = undefined;
    try {
      const pageResult = await listAccounts(pairing.id, currentFilters());
      if (gen !== generation) return;
      listView = {
        kind: 'ready',
        accounts: pageResult.accounts,
        quotaBytes: pageResult.quotaBytes,
        flaggedTotal: pageResult.flaggedTotal,
        cursor: pageResult.cursor,
      };
    } catch (e) {
      if (gen !== generation) return;
      listView = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  async function loadMore() {
    if (!pairing || listView.kind !== 'ready' || !listView.cursor || loadingMore) return;
    const gen = generation;
    loadingMore = true;
    moreError = undefined;
    try {
      const pageResult = await listAccounts(pairing.id, {
        ...currentFilters(),
        cursor: listView.cursor,
      });
      if (gen !== generation || listView.kind !== 'ready') return;
      listView = {
        kind: 'ready',
        accounts: [...listView.accounts, ...pageResult.accounts],
        quotaBytes: pageResult.quotaBytes,
        flaggedTotal: pageResult.flaggedTotal,
        cursor: pageResult.cursor,
      };
    } catch (e) {
      if (gen !== generation) return;
      moreError = classifyRelayError(e);
    } finally {
      loadingMore = false;
    }
  }

  function applyFilter(value: StatusFilter) {
    if (statusFilter === value) return;
    statusFilter = value;
    void loadFirstPage();
  }

  function search(event: SubmitEvent) {
    event.preventDefault();
    void loadFirstPage();
  }

  function openAccount(entry: AccountListEntry) {
    if (!pairing) return;
    void goto(pinnedHref('/account', pairing.id, { did: entry.did }));
  }
</script>

<ScreenShell
  prompt="accounts"
  title="Accounts on this server"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="the account list always reads from a specific server.">
    {#snippet children()}
    <p class="lede">
      Every account on this server — accounts flagged by a watched labeler first, then
      DID order. Tap an account for its detail — usage, storage, and moderation; the
      meter is each account's blob-storage quota.
    </p>

    <section class="panel" aria-labelledby="accounts-filter-label">
      <span id="accounts-filter-label" class="label">Search &amp; filter</span>
      <form class="search" onsubmit={search}>
        <TextField
          label="Handle or DID contains"
          bind:value={q}
          placeholder="alice, did:plc:…"
          mono
        />
        <Button variant="secondary" type="submit" loading={listView.kind === 'loading'}>
          Search
        </Button>
      </form>
      <div class="filters" role="group" aria-label="Filter by account status">
        {#each FILTERS as filter (filter.value)}
          <button
            type="button"
            class="filter"
            aria-pressed={statusFilter === filter.value}
            onclick={() => applyFilter(filter.value)}
          >
            {filter.label}
          </button>
        {/each}
      </div>
    </section>

    {#if listView.kind === 'loading'}
      <p class="resolving">reading accounts…</p>
    {:else if listView.kind === 'error'}
      <ErrorState view={listView.view} server={identity} onretry={loadFirstPage} />
    {:else if listView.accounts.length === 0}
      <section class="panel" aria-label="No accounts">
        <StatusChip status="info" label="none" />
        <p class="note">
          {q.trim() !== '' || statusFilter !== 'all'
            ? 'No accounts match this search and filter.'
            : 'This server has no accounts yet.'}
        </p>
      </section>
    {:else}
      <section class="panel" aria-label="Accounts">
        {#if listView.flaggedTotal > 0}
          <!-- The triage banner: the filter-consistent flagged count, stated up front
               because flagged rows sort first but can also sit on unloaded pages. -->
          <p class="flagged-summary" role="status">
            <StatusChip status="flagged" />
            <span>
              {listView.flaggedTotal} flagged
              {listView.flaggedTotal === 1 ? 'account' : 'accounts'} — sorted first
            </span>
          </p>
        {/if}
        <ul class="list">
          {#each listView.accounts as entry (entry.did)}
            <li>
              <AccountRow
                did={entry.did}
                handle={entry.handle}
                status={entry.status}
                quota={quotaBar(entry.quotaUsedPct)}
                flags={entry.flags}
                onclick={() => openAccount(entry)}
              />
            </li>
          {/each}
        </ul>
        <p class="count">
          {listView.accounts.length} shown{listView.cursor ? ' · more available' : ''}
        </p>
        {#if listView.cursor}
          <Button variant="secondary" loading={loadingMore} onclick={loadMore}>
            Load more
          </Button>
        {/if}
        {#if moreError}
          <ErrorState view={moreError} server={identity} retrying={loadingMore} onretry={loadMore} />
        {/if}
      </section>
    {/if}
    {/snippet}
  </PinnedPairingGate>
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
  .search {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  /* Filter chips: state by aria-pressed styling (border + fill + weight), the current
     pick never signalled by color alone — the pressed chip is also the only filled one. */
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-xs);
  }
  .filter {
    display: inline-flex;
    align-items: center;
    min-height: var(--control-min-height);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    background: transparent;
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--chip-radius);
    padding: var(--space-xs) var(--space-sm);
    cursor: pointer;
  }
  .filter[aria-pressed='true'] {
    color: var(--color-ink);
    font-weight: var(--weight-medium);
    background: var(--color-surface-raised);
    border-color: var(--color-primary);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
  }
  .list li + li {
    border-top: var(--border-hairline) solid var(--color-line);
  }
  .count {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .flagged-summary {
    margin: 0;
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
  }
</style>
