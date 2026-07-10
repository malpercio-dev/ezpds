<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    listPairings,
    getSubjectStatus,
    updateSubjectStatus,
    getAccountUsage,
    getAccountStorage,
    type Pairing,
    type PairingsState,
    type SubjectStatus,
    type AccountUsage,
    type AccountStorage,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { formatBytes, formatPct } from '$lib/format';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // The moderation screen: look up an account by DID on ONE relay, then apply or clear
  // an account-level takedown. Pinned to a single pairing at entry (`?server=<pairingId>`
  // else the active pairing) like Devices, so a concurrent active-pointer switch on Home
  // can never redirect what this screen reads or signs. Takedown is the one operator
  // action with deliberate friction: the first tap ARMS an explicit confirmation that
  // restates the relay-confirmed target, and confirming runs the biometric gate before
  // anything is signed. The write always targets the DID from the last successful
  // lookup — never the raw input field — so an edit between lookup and tap can't
  // retarget a signed takedown.

  type StatusView =
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; status: SubjectStatus };

  // Usage/storage readouts for the looked-up account. Loaded after (never blocking)
  // the status lookup; both metrics land together or the panel reports one error.
  type MetricsView =
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; usage: AccountUsage; storage: AccountStorage };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let did = $state('');
  let statusView = $state<StatusView>({ kind: 'idle' });
  let metricsView = $state<MetricsView>({ kind: 'idle' });
  let armed = $state(false);
  let writing = $state(false);
  let writeError = $state<ErrorView | undefined>(undefined);
  let gateHint = $state<string | undefined>(undefined);

  // Pinned once at entry: the pairing this screen reads from and signs for.
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

    // Arriving from the accounts list (`?did=…`): pre-fill the lookup field and run
    // the lookup immediately — the DID came from this same relay's account list, so
    // making the operator retype (or re-tap) it would be pure friction. The lookup
    // still runs the normal path: the relay's answer, not the query param, is what
    // any later takedown targets.
    const requestedDid = page.url.searchParams.get('did');
    if (pairing && requestedDid) {
      did = requestedDid;
      if (didLooksValid) void lookup();
    }
  });

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
  const trimmedDid = $derived(did.trim());
  // Structural pre-check only — the relay's DID validation is authoritative (a bad DID
  // comes back as a 400). This just keeps the lookup button honest for obvious junk.
  const didLooksValid = $derived(/^did:[a-z]+:\S+$/.test(trimmedDid));
  // The status panel reports the relay's answer for ONE did. Once the input drifts from
  // it, the panel — especially its takedown/restore action — is stale: require a fresh
  // lookup rather than let a signed write sit under an edited field.
  const stale = $derived(
    statusView.kind === 'ready' && trimmedDid !== statusView.status.subject.did,
  );

  // Staleness invalidates every signed-action affordance at once: the armed confirm,
  // a failed write's retry panel, and any gate hint. Anything less leaves a live
  // "retry" button pointing at the previous lookup after the input has moved on.
  $effect(() => {
    if (stale) {
      armed = false;
      writeError = undefined;
      gateHint = undefined;
    }
  });

  async function lookup() {
    if (!pairing || !didLooksValid) return;
    if (statusView.kind === 'loading') return;
    armed = false;
    writeError = undefined;
    gateHint = undefined;
    statusView = { kind: 'loading' };
    metricsView = { kind: 'idle' };
    try {
      statusView = { kind: 'ready', status: await getSubjectStatus(pairing.id, trimmedDid) };
    } catch (e) {
      statusView = { kind: 'error', view: classifyRelayError(e) };
      return;
    }
    // Metrics load after — never blocking — the status panel, for the relay-confirmed
    // DID from the lookup, not the raw input.
    void loadMetrics(statusView.status.subject.did);
  }

  /** Fetch usage + storage for the looked-up account. Reads only — no biometric gate. */
  async function loadMetrics(target: string) {
    if (!pairing) return;
    metricsView = { kind: 'loading' };
    try {
      const [usage, storage] = await Promise.all([
        getAccountUsage(pairing.id, target),
        getAccountStorage(pairing.id, target),
      ]);
      // A slow response for an earlier lookup must not land under a newer one: only
      // commit metrics that still describe the DID the status panel reports.
      if (statusView.kind === 'ready' && statusView.status.subject.did === target) {
        metricsView = { kind: 'ready', usage, storage };
      }
    } catch (e) {
      if (statusView.kind === 'ready' && statusView.status.subject.did === target) {
        metricsView = { kind: 'error', view: classifyRelayError(e) };
      }
    }
  }

  /** Tap 1 of the two-tap confirm: swap the action for an explicit Confirm/Cancel pair. */
  function arm() {
    writeError = undefined;
    gateHint = undefined;
    armed = true;
  }

  function disarm() {
    armed = false;
    writeError = undefined;
    gateHint = undefined;
  }

  /** Tap 2: gate on user presence, then sign the takedown (`applied: true`) or restore. */
  async function confirmWrite(applied: boolean) {
    // `stale` is re-checked here (not just in the render path) so no caller — including
    // the error panel's retry — can sign against a lookup the input has drifted from.
    if (!pairing || statusView.kind !== 'ready' || stale) return;
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent writes.
    if (writing) return;
    writing = true;
    gateHint = undefined;
    writeError = undefined;
    // The relay-confirmed target from the lookup — never the raw input field.
    const target = statusView.status.subject.did;
    try {
      const presence = await requireUserPresence(
        applied ? 'Take down an account on this server' : 'Restore an account on this server',
      );
      if (!presenceAllows(presence)) {
        gateHint = applied
          ? 'Confirm with Face ID to take down this account.'
          : 'Confirm with Face ID to restore this account.';
        return;
      }
      // The response reports the resulting takedown state as the relay derives it —
      // re-render that truth, no optimistic edit.
      statusView = {
        kind: 'ready',
        status: await updateSubjectStatus(pairing.id, target, applied),
      };
      armed = false;
    } catch (e) {
      writeError = classifyRelayError(e);
    } finally {
      writing = false;
    }
  }
</script>

<ScreenShell
  prompt="moderation"
  title="Take down or restore an account"
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
    <!-- Unpaired, or no active pick and no ?server pin — there is no relay to act on. -->
    <section class="panel" aria-label="No server selected">
      <StatusChip status="pending" label="no server" />
      <p class="note">
        No server is selected. Pick or pair one first — moderation always acts on a
        specific server.
      </p>
    </section>
  {:else}
    <p class="lede">
      Look up an account on this server by its DID, then take it down or restore it. A
      taken-down account stops being served: logins, writes, and sync are all refused
      until it is restored.
    </p>

    <section class="panel" aria-labelledby="lookup-label">
      <span id="lookup-label" class="label">Account lookup</span>
      <TextField
        label="Account DID"
        bind:value={did}
        placeholder="did:plc:…"
        mono
        error={trimmedDid !== '' && !didLooksValid
          ? 'Enter a full DID, like did:plc:abc123…'
          : undefined}
      />
      <Button
        variant="secondary"
        loading={statusView.kind === 'loading'}
        disabled={!didLooksValid}
        onclick={lookup}
      >
        {statusView.kind === 'idle' ? 'Look up account' : 'Look up again'}
      </Button>
    </section>

    {#if statusView.kind === 'error'}
      <ErrorState view={statusView.view} server={identity} onretry={lookup} />
    {:else if statusView.kind === 'ready'}
      {@const takenDown = statusView.status.takedown.applied}
      <section class="panel" aria-labelledby="status-label">
        <span id="status-label" class="label">Account status</span>
        <StatusChip
          status={takenDown ? 'revoked' : 'active'}
          label={takenDown ? 'taken down' : 'serving'}
        />
        <dl class="facts">
          <dt>did</dt>
          <dd>{statusView.status.subject.did}</dd>
          <dt>takedown</dt>
          <dd>{takenDown ? 'applied' : 'not applied'}</dd>
        </dl>

        {#if stale}
          <p class="note">The DID field changed since this lookup. Look up again before acting.</p>
        {:else if !armed}
          {#if takenDown}
            <Button variant="primary" loading={writing} onclick={arm}>
              Restore this account
            </Button>
          {:else}
            <Button variant="destructive" loading={writing} onclick={arm}>
              Take down this account
            </Button>
          {/if}
        {:else}
          <div
            class="confirm"
            role="group"
            aria-label={takenDown ? 'Confirm restore' : 'Confirm takedown'}
          >
            <p class="confirm-text">
              {#if takenDown}
                Restore <span class="confirm-did">{statusView.status.subject.did}</span>
                on {identity?.host}? The server resumes serving it — unless the account
                is also suspended or deactivated.
              {:else}
                Take down <span class="confirm-did">{statusView.status.subject.did}</span>
                on {identity?.host}? Logins, writes, and sync are refused until it is
                restored.
              {/if}
            </p>
            <Button
              variant={takenDown ? 'primary' : 'destructive'}
              loading={writing}
              onclick={() => confirmWrite(!takenDown)}
            >
              {takenDown ? 'Confirm restore' : 'Confirm takedown'}
            </Button>
            <Button variant="secondary" disabled={writing} onclick={disarm}>Cancel</Button>
          </div>
        {/if}

        {#if writeError}
          <ErrorState
            view={writeError}
            server={identity}
            retrying={writing}
            onretry={() => confirmWrite(!takenDown)}
          />
        {/if}
        {#if gateHint}
          <p class="hint" role="status">
            <StatusChip status="info" label="confirm" />
            <span>{gateHint}</span>
          </p>
        {/if}
      </section>

      <!-- Per-account usage/storage readouts for the looked-up DID. Reads only — the
           panel never signs anything, so it carries no arm/gate machinery. -->
      <section class="panel" aria-labelledby="metrics-label">
        <span id="metrics-label" class="label">Usage &amp; storage</span>
        {#if metricsView.kind === 'loading' || metricsView.kind === 'idle'}
          <p class="resolving">reading metrics…</p>
        {:else if metricsView.kind === 'error'}
          <ErrorState
            view={metricsView.view}
            server={identity}
            onretry={() =>
              statusView.kind === 'ready' && loadMetrics(statusView.status.subject.did)}
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
  .hint {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
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
  /* The armed confirmation: a visibly raised, critical-edged block — the screen state
     itself signals "you are one tap from a signed takedown", not color alone (the
     restated target + button copy carry the meaning too). */
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
  .confirm-did {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    overflow-wrap: anywhere;
  }
</style>
