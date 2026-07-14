<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import {
    getAccountUsage,
    getAccountStorage,
    type Pairing,
    type PairingsState,
    type AccountUsage,
    type AccountStorage,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { formatBytes, formatPct } from '$lib/format';
  import { loadPinnedPairing, pinnedHref } from '$lib/pinned-pairing';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The account-detail screen: the read-only inspection home for ONE account on ONE
  // relay — identity facts plus the usage/storage readout. Reached from the accounts
  // list (`?server=…&did=…`) and pinned to a single pairing at entry (see
  // $lib/pinned-pairing) like Devices/Moderation. Nothing here signs: destructive work
  // (takedown/restore, credential revocation) lives one hop deeper on the moderation
  // screen, reached from here with the same pin + DID.

  // Usage/storage readouts for the account. Both metrics land together or the panel
  // reports one error.
  type MetricsView =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; usage: AccountUsage; storage: AccountStorage };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let pairing = $state<Pairing | null>(null);
  let did = $state<string | null>(null);
  let metricsView = $state<MetricsView>({ kind: 'loading' });

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    did = page.url.searchParams.get('did');
    if (pairing && did) void loadMetrics(did);
  });

  const identity = $derived(pairing ? serverIdentity(pairing) : null);

  /** Fetch usage + storage for the account. Reads only — no biometric gate. */
  async function loadMetrics(target: string) {
    if (!pairing) return;
    metricsView = { kind: 'loading' };
    try {
      const [usage, storage] = await Promise.all([
        getAccountUsage(pairing.id, target),
        getAccountStorage(pairing.id, target),
      ]);
      metricsView = { kind: 'ready', usage, storage };
    } catch (e) {
      metricsView = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  function openModeration() {
    if (!pairing || !did) return;
    void goto(pinnedHref('/moderation', pairing.id, { did }));
  }
</script>

<ScreenShell
  prompt="account"
  title="Account detail"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="account detail always reads from a specific server.">
    {#snippet children()}
    {#if !did}
    <!-- This screen is only reached from the accounts list, which always pins a DID. -->
    <section class="panel" aria-label="No account selected">
      <StatusChip status="pending" label="no account" />
      <p class="note">No account is selected. Open an account from the Accounts list.</p>
    </section>
  {:else}
    <p class="lede">
      This account as the server reports it: usage and storage below, moderation —
      takedown/restore and credential revocation — one tap deeper.
    </p>

    <section class="panel" aria-labelledby="identity-label">
      <span id="identity-label" class="label">Identity</span>
      <dl class="facts">
        <dt>did</dt>
        <dd>{did}</dd>
      </dl>
    </section>

    <!-- The per-account usage/storage readouts, moved here from the moderation screen.
         Reads only — the panel never signs anything, so it carries no arm/gate
         machinery. -->
    <section class="panel" aria-labelledby="metrics-label">
      <span id="metrics-label" class="label">Usage &amp; storage</span>
      {#if metricsView.kind === 'loading'}
        <p class="resolving">reading metrics…</p>
      {:else if metricsView.kind === 'error'}
        <ErrorState
          view={metricsView.view}
          server={identity}
          onretry={() => did && loadMetrics(did)}
        />
      {:else}
        <dl class="facts">
          <dt>records</dt>
          <dd>{metricsView.usage.recordsCount}</dd>
          <dt>commits</dt>
          <dd>≥{metricsView.usage.commitsCount} (GC prunes history)</dd>
          <dt>blobs</dt>
          <dd>{metricsView.usage.blobsCount}</dd>
          <dt>stored</dt>
          <dd>{formatBytes(metricsView.usage.storageBytes)}</dd>
          <dt>last active</dt>
          <dd>{metricsView.usage.lastActive}</dd>
          <dt>blob quota</dt>
          <dd>
            {formatBytes(metricsView.storage.totalBytes)} of {formatBytes(
              metricsView.storage.quotaBytes,
            )} ({formatPct(metricsView.storage.quotaUsedPct)})
          </dd>
          <dt>largest blob</dt>
          <dd>
            {#if metricsView.storage.largestBlob}
              {metricsView.storage.largestBlob.cid} · {formatBytes(
                metricsView.storage.largestBlob.size,
              )}
            {:else}
              none
            {/if}
          </dd>
        </dl>
      {/if}
    </section>

    <section class="panel" aria-labelledby="moderation-label">
      <span id="moderation-label" class="label">Moderation</span>
      <p class="note">
        Take this account down, restore it, or revoke its credentials. The moderation
        screen re-confirms the account against the server before anything is signed.
      </p>
      <Button variant="secondary" onclick={openModeration}>Take down or restore</Button>
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
