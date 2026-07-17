<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { listAudit, type AuditEventEntry, type Pairing, type PairingsState } from '$lib/ipc';
  import { AUDIT_ACTIONS, chipFor, detailEntries, summaryLine } from '$lib/audit';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createPagedList } from '$lib/paged-list.svelte';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The server-wide admin audit log: every privileged admin action on ONE relay,
  // newest first, attributed to the credential that signed it (master token vs. a
  // specific paired device). Pinned to a single pairing at entry (see
  // $lib/pinned-pairing), id-addressed like Devices; paged via the relay cursor.
  // Reads only — nothing here signs a mutation.

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let expandedId = $state<string | null>(null);
  // Pinned once at entry: the pairing this screen reads from.
  let pairing = $state<Pairing | null>(null);

  // Server-side exact-match filters. The action comes from the fixed chip row; actor
  // and subject are set by drilling in from an event's fact sheet.
  let actionFilter = $state<string | null>(null);
  let actorFilter = $state<string | null>(null);
  let subjectFilter = $state<string | null>(null);

  const log = createPagedList<AuditEventEntry>((cursor) =>
    listAudit(pairing!.id, {
      cursor,
      action: actionFilter ?? undefined,
      actor: actorFilter ?? undefined,
      subject: subjectFilter ?? undefined,
    }).then((r) => ({ items: r.events, cursor: r.cursor ?? undefined })),
  );

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) await log.load();
  });

  async function applyActionFilter(action: string | null) {
    actionFilter = action;
    expandedId = null;
    await log.load();
  }

  async function drillIn(kind: 'actor' | 'subject', value: string) {
    if (kind === 'actor') actorFilter = value;
    else subjectFilter = value;
    expandedId = null;
    await log.load();
  }

  async function clearDrillIn() {
    actorFilter = null;
    subjectFilter = null;
    expandedId = null;
    await log.load();
  }

  function toggleExpanded(id: string) {
    expandedId = expandedId === id ? null : id;
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
  const drilledIn = $derived(actorFilter !== null || subjectFilter !== null);
</script>

{#snippet eventRow(event: AuditEventEntry)}
  {@const chip = chipFor(event)}
  {@const facts = detailEntries(event.detail)}
  <div class="event-item">
    <button
      class="event-row"
      type="button"
      aria-expanded={expandedId === event.id}
      aria-controls={`event-panel-${event.id}`}
      onclick={() => toggleExpanded(event.id)}
    >
      <span class="event-main">
        <span class="event-action">{event.action}</span>
        <span class="event-summary">{summaryLine(event)}</span>
      </span>
      <StatusChip status={chip.chip} label={chip.label} />
    </button>

    {#if expandedId === event.id}
      <div class="event-panel" id={`event-panel-${event.id}`}>
        <dl class="facts">
          <dt>at</dt>
          <dd>{event.createdAt}</dd>
          <dt>actor</dt>
          <dd>{event.actor}</dd>
          {#if event.subject}
            <dt>subject</dt>
            <dd>{event.subject}</dd>
          {/if}
          <dt>outcome</dt>
          <dd>{event.outcome}</dd>
          {#each facts as [key, value] (key)}
            <dt>{key}</dt>
            <dd>{value}</dd>
          {/each}
        </dl>
        <!-- Drill-in: with several paired devices, "what else did this credential do"
             is the question this log exists to answer. -->
        <div class="drill">
          <Button variant="secondary" onclick={() => drillIn('actor', event.actor)}>
            All actions by this actor
          </Button>
          {#if event.subject}
            <Button variant="secondary" onclick={() => drillIn('subject', event.subject!)}>
              All actions on this subject
            </Button>
          {/if}
        </div>
      </div>
    {/if}
  </div>
{/snippet}

<ScreenShell
  prompt="audit"
  title="Admin actions on this server"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="the audit log is always read from a specific server.">
    {#snippet children()}
    <p class="lede">
      Every privileged admin action recorded on this server, newest first — takedowns,
      credential sweeps, code mints and revokes, device pairings and revocations — each
      attributed to the credential that signed it.
    </p>

    <section class="panel" aria-labelledby="audit-filter-label">
      <span id="audit-filter-label" class="label">Filter by action</span>
      <div class="filters" role="group" aria-label="Filter by action">
        <button
          type="button"
          class="filter"
          aria-pressed={actionFilter === null}
          onclick={() => applyActionFilter(null)}
        >
          all
        </button>
        {#each AUDIT_ACTIONS as action (action)}
          <button
            type="button"
            class="filter"
            aria-pressed={actionFilter === action}
            onclick={() => applyActionFilter(action)}
          >
            {action}
          </button>
        {/each}
      </div>
      {#if drilledIn}
        <p class="drill-line" role="status">
          <span class="drill-term">
            {actorFilter ? `actor = ${actorFilter}` : `subject = ${subjectFilter}`}
          </span>
          <Button variant="secondary" onclick={clearDrillIn}>Clear</Button>
        </p>
      {/if}
    </section>

    {#if log.kind === 'loading'}
      <p class="resolving">reading audit log…</p>
    {:else if log.kind === 'error'}
      <ErrorState view={log.errorView!} server={identity} onretry={() => log.load()} />
    {:else if log.items.length === 0}
      <section class="panel" aria-label="No audit events">
        <StatusChip status="info" label="none" />
        <p class="note">
          {#if actionFilter !== null || drilledIn}
            No recorded actions match this filter.
          {:else}
            No admin actions recorded yet. Privileged actions land here as they happen.
          {/if}
        </p>
      </section>
    {:else}
      <section class="panel" aria-labelledby="audit-list-label">
        <span id="audit-list-label" class="label">Recorded actions · {log.items.length}</span>
        <div class="event-list">
          {#each log.items as event (event.id)}
            {@render eventRow(event)}
          {/each}
        </div>
      </section>

      {#if log.cursor}
        <Button variant="secondary" loading={log.paging} onclick={() => log.loadMore()}>
          Load older actions
        </Button>
        {#if log.pagingError}
          <ErrorState view={log.pagingError!} server={identity} retrying={log.paging} onretry={() => log.loadMore()} />
        {/if}
      {/if}
    {/if}
    {/snippet}
  </PinnedPairingGate>

  {#snippet actions()}
    {#if pairing && log.kind === 'ready'}
      <Button variant="secondary" onclick={() => log.load()}>
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
  /* One horizontally-scrollable line: 14 action words stacked would push the log
     itself below the fold on a phone, and the log is what this screen is for. */
  .filters {
    display: flex;
    flex-wrap: nowrap;
    gap: var(--space-xs);
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    /* Keep focus rings and the pressed border visible inside the scroll clip. */
    padding: var(--space-2xs);
    margin: calc(-1 * var(--space-2xs));
  }
  .filter {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
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
    border-color: var(--color-primary);
  }
  .drill-line {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    margin: 0;
  }
  .drill-term {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .event-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .event-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .event-row {
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
  .event-row:hover,
  .event-row:active {
    background: var(--color-surface);
  }
  .event-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  /* The action word is the row's identity: mono, tracked out like a code. */
  .event-action {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    font-weight: var(--weight-medium);
    letter-spacing: 0.06em;
    color: var(--color-ink);
  }
  .event-summary {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .event-panel {
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
  .drill {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-sm);
  }
</style>
