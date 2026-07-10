<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { listPairings, getServerHealth, type Pairing, type PairingsState, type ServerHealth } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { formatBytes } from '$lib/format';
  import { formatDuration, formatBackfillWindow, sweepLine } from '$lib/health';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // The Status screen: ONE relay's health, as it reports it — literal row counts,
  // firehose state, and sweep last-runs, no derived verdicts. Pinned to a single
  // pairing at entry like Devices/Account detail (`?server=<pairingId>`, else the
  // active pairing), so a concurrent active-pointer switch on Home can never redirect
  // which relay this screen reads. Reads only — nothing here signs beyond the
  // envelope, so there is no biometric gate.

  type HealthView =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; health: ServerHealth; readAt: number };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let pairing = $state<Pairing | null>(null);
  let healthView = $state<HealthView>({ kind: 'loading' });
  // Drops a stale response when Refresh is tapped mid-flight (the accounts screen's
  // generation-counter pattern).
  let generation = 0;

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
    if (pairing) void loadHealth();
  });

  const identity = $derived(pairing ? serverIdentity(pairing) : null);

  async function loadHealth() {
    if (!pairing) return;
    const mine = ++generation;
    healthView = { kind: 'loading' };
    try {
      const health = await getServerHealth(pairing.id);
      if (mine !== generation) return;
      healthView = { kind: 'ready', health, readAt: Math.floor(Date.now() / 1000) };
    } catch (e) {
      if (mine !== generation) return;
      healthView = { kind: 'error', view: classifyRelayError(e) };
    }
  }
</script>

<ScreenShell prompt="status" title="Server status" onback={() => history.back()} server={identity}>
  {#if pairingsView === 'loading'}
    <p class="resolving">checking servers…</p>
  {:else if pairingsView === 'error'}
    <section class="panel" aria-label="Server check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">Couldn't read this device's servers. Go back and retry.</p>
    </section>
  {:else if !pairing}
    <!-- Unpaired, or no active pick and no ?server pin — there is no relay to read. -->
    <section class="panel" aria-label="No server selected">
      <StatusChip status="pending" label="no server" />
      <p class="note">
        No server is selected. Pick or pair one first — status always reads from a
        specific server.
      </p>
    </section>
  {:else}
    <p class="lede">
      This server's health as it reports it — row counts, firehose state, and
      background-sweep last-runs. Facts only; nothing here is a verdict.
    </p>

    {#if healthView.kind === 'loading'}
      <p class="resolving">reading status…</p>
    {:else if healthView.kind === 'error'}
      <ErrorState view={healthView.view} server={identity} onretry={loadHealth} />
    {:else}
      {@const health = healthView.health}
      <section class="panel" aria-labelledby="server-label">
        <span id="server-label" class="label">Server</span>
        <dl class="facts">
          <dt>version</dt>
          <dd>{health.version}</dd>
          <dt>uptime</dt>
          <dd>{formatDuration(health.uptimeSeconds)}</dd>
        </dl>
      </section>

      <section class="panel" aria-labelledby="accounts-label">
        <span id="accounts-label" class="label">Accounts</span>
        <dl class="facts">
          <dt>total</dt>
          <dd>{health.accounts.total}</dd>
          <dt>active</dt>
          <dd>{health.accounts.active}</dd>
          <dt>deactivated</dt>
          <dd>{health.accounts.deactivated}</dd>
          <dt>suspended</dt>
          <dd>{health.accounts.suspended}</dd>
          <dt>taken down</dt>
          <dd>{health.accounts.takendown}</dd>
        </dl>
      </section>

      <section class="panel" aria-labelledby="storage-label">
        <span id="storage-label" class="label">Storage</span>
        <dl class="facts">
          <dt>blobs</dt>
          <dd>{health.storage.blobCount} · {formatBytes(health.storage.blobBytes)}</dd>
          <dt>repo blocks</dt>
          <dd>{health.storage.blockCount}</dd>
        </dl>
      </section>

      <section class="panel" aria-labelledby="firehose-label">
        <span id="firehose-label" class="label">Firehose</span>
        <dl class="facts">
          <dt>current seq</dt>
          <dd>{health.firehose.currentSeq}</dd>
          <dt>subscribers</dt>
          <dd>{health.firehose.subscribers}</dd>
          <dt>retained events</dt>
          <dd>{health.firehose.retainedEvents}</dd>
          <dt>backfill window</dt>
          <dd>{formatBackfillWindow(health.firehose.backfillWindowSeconds)}</dd>
        </dl>
      </section>

      <!-- A sweep that stops completing records nothing, so its line simply ages —
           this panel is where that staleness becomes visible. -->
      <section class="panel" aria-labelledby="sweeps-label">
        <span id="sweeps-label" class="label">Background sweeps</span>
        <dl class="facts">
          <dt>blob GC</dt>
          <dd>{sweepLine(health.sweeps.blobGc, healthView.readAt)}</dd>
          <dt>firehose GC</dt>
          <dd>{sweepLine(health.sweeps.firehoseGc, healthView.readAt)}</dd>
          <dt>account reaper</dt>
          <dd>{sweepLine(health.sweeps.accountReaper, healthView.readAt)}</dd>
          <dt>claim sweep</dt>
          <dd>{sweepLine(health.sweeps.agentClaimSweep, healthView.readAt)}</dd>
        </dl>
      </section>

      <Button variant="secondary" onclick={loadHealth}>Refresh</Button>
    {/if}
  {/if}
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
</style>
