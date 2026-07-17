<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { getRelayStatus, requestCrawl, type RelayStatus } from '$lib/ipc';
  import { relayStatusView } from '$lib/relay-status';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import type { ServerIdentity } from '$lib/server-identity';
  import StatusChip from './StatusChip.svelte';
  import Button from './Button.svelte';
  import ErrorState from './ErrorState.svelte';

  // The Home relay-status block: is the upstream relay actually crawling/indexing the active
  // server right now? Polls `GET /v1/admin/relay-status` every 15s and renders the literal facts
  // as a chip (color + glyph + text, never color alone) + a headline + a fact sheet — the block
  // applies the ok/warn/error thresholds (relay-status.ts), the endpoint reports raw truth. The
  // "Request crawl" action re-invites the relay; it signs, so it runs the biometric gate first.
  //
  // The parent keys this component by pairing id, so switching the active server remounts it and
  // restarts the poll for the new relay — no stale-pairing race to guard against here.

  let { pairingId, server }: { pairingId: string; server: ServerIdentity | null } = $props();

  const POLL_MS = 15_000;

  type View =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; status: RelayStatus; readAt: number };

  let view = $state<View>({ kind: 'loading' });
  // Drops a stale in-flight response when a newer poll (or the crawl-triggered refresh) resolves
  // first — the Status screen's generation-counter pattern.
  let generation = 0;
  let timer: ReturnType<typeof setInterval> | undefined;

  let crawling = $state(false);
  let crawlHint = $state<string | undefined>(undefined);

  onMount(() => {
    void load();
    timer = setInterval(() => void load(), POLL_MS);
  });
  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  async function load() {
    const mine = ++generation;
    // Keep the last-good readout on screen across a refresh — only show the loader on first load,
    // so the 15s poll never flashes the panel.
    if (view.kind !== 'ready') view = { kind: 'loading' };
    try {
      const status = await getRelayStatus(pairingId);
      if (mine !== generation) return;
      view = { kind: 'ready', status, readAt: Math.floor(Date.now() / 1000) };
    } catch (e) {
      if (mine !== generation) return;
      view = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  async function crawl() {
    // Claim the busy flag before the biometric await so rapid taps can't open multiple gates.
    if (crawling) return;
    crawling = true;
    crawlHint = undefined;
    try {
      const presence = await requireUserPresence('Request a relay crawl');
      if (!presenceAllows(presence)) {
        crawlHint = 'Confirm with Face ID to request a crawl.';
        return;
      }
      const result = await requestCrawl(pairingId);
      const plural = result.requested === 1 ? '' : 's';
      crawlHint =
        result.accepted > 0
          ? `Crawl requested — ${result.accepted} of ${result.requested} relay${plural} accepted.`
          : 'Crawl requested, but no relay accepted it yet.';
      // The relay needs a moment to advance its cursor; refresh shortly after so the readout reflects
      // the crawl rather than leaving the operator to wait for the next poll.
      void load();
    } catch (e) {
      crawlHint = classifyRelayError(e).message;
    } finally {
      crawling = false;
    }
  }

  const rendered = $derived(view.kind === 'ready' ? relayStatusView(view.status, view.readAt) : null);
</script>

<section class="panel" aria-labelledby="relay-status-label">
  <div class="head">
    <span id="relay-status-label" class="label">Relay federation</span>
    {#if rendered}
      <StatusChip status={rendered.chip.status} label={rendered.chip.label} />
    {/if}
  </div>

  {#if view.kind === 'loading'}
    <p class="resolving">checking relay…</p>
  {:else if view.kind === 'error'}
    <ErrorState view={view.view} {server} onretry={load} />
  {:else if rendered}
    <p class="headline">{rendered.headline}</p>
    <dl class="facts">
      {#each rendered.facts as fact}
        <dt>{fact.label}</dt>
        <dd>{fact.value}</dd>
      {/each}
    </dl>

    {#if crawlHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="crawl" />
        <span>{crawlHint}</span>
      </p>
    {/if}

    <!-- Secondary, not primary: Home's One-Lamp gold is already "Generate claim code". -->
    <Button variant="secondary" loading={crawling} onclick={crawl}>Request crawl</Button>
  {/if}
</section>

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
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-sm);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .headline {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink);
  }
  .resolving {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
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
  .hint {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
</style>
