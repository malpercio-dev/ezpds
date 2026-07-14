<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    getSubjectStatus,
    updateSubjectStatus,
    revokeAccountCredentials,
    type Pairing,
    type PairingsState,
    type SubjectStatus,
    type RevokedCredentials,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createArmedAction } from '$lib/armed-action.svelte';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The moderation screen: look up an account by DID on ONE relay, then apply or clear
  // an account-level takedown. Pinned to a single pairing at entry (see
  // $lib/pinned-pairing) like Devices. Takedown is the one operator action with
  // deliberate friction: the first tap ARMS an explicit confirmation that restates the
  // relay-confirmed target, and confirming runs the biometric gate before anything is
  // signed. The write always targets the DID from the last successful lookup — never the
  // raw input field — so an edit between lookup and tap can't retarget a signed takedown.

  type StatusView =
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; status: SubjectStatus };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let did = $state('');
  let statusView = $state<StatusView>({ kind: 'idle' });

  // The two destructive flows are independent armed state machines — arming a takedown
  // must never leave a credential revocation half-armed, and vice versa (each
  // precondition treats the other's `writing` as a lock, so two biometric prompts can
  // never stack for the same account). The sweep additionally renders the relay's
  // literal per-family counts — route state, so a slower sweep can only land its result
  // under the lookup it targeted.
  const takedown = createArmedAction();
  const creds = createArmedAction();
  let credsReport = $state<RevokedCredentials | null>(null);

  // Pinned once at entry: the pairing this screen reads from and signs for.
  let pairing = $state<Pairing | null>(null);

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;

    // Arriving from the account-detail screen (`?did=…`): pre-fill the lookup field
    // and run the lookup immediately — the DID came from this same relay's account
    // list, so making the operator retype (or re-tap) it would be pure friction. The
    // lookup still runs the normal path: the relay's answer, not the query param, is
    // what any later takedown targets.
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

  // Staleness invalidates every signed-action affordance at once: both armed confirms
  // (with their gate hints and failed-write retry panels) and the credential-sweep
  // report. Anything less leaves a live "retry" pointing at the previous lookup after
  // the input has moved on.
  $effect(() => {
    if (stale) {
      takedown.disarm();
      creds.disarm();
      credsReport = null;
    }
  });

  async function lookup() {
    if (!pairing || !didLooksValid) return;
    if (statusView.kind === 'loading') return;
    takedown.disarm();
    creds.disarm();
    credsReport = null;
    statusView = { kind: 'loading' };
    try {
      statusView = { kind: 'ready', status: await getSubjectStatus(pairing.id, trimmedDid) };
    } catch (e) {
      statusView = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  /** Tap 2: gate on user presence, then sign the takedown (`applied: true`) or restore. */
  async function confirmWrite(applied: boolean) {
    if (!pairing || statusView.kind !== 'ready') return;
    // The relay-confirmed target from the lookup — never the raw input field.
    const target = statusView.status.subject.did;
    const pinned = pairing;
    await takedown.confirm({
      reason: applied
        ? 'Take down an account on this server'
        : 'Restore an account on this server',
      deniedHint: applied
        ? 'Confirm with Face ID to take down this account.'
        : 'Confirm with Face ID to restore this account.',
      // Re-checks staleness here (not just in render) so no caller — including the error
      // panel's retry — can sign against a lookup the input has drifted from; the sweep's
      // `writing` is a lock so the two destructive prompts never stack.
      precondition: () => statusView.kind === 'ready' && !stale && !creds.writing,
      run: async () => {
        // The response reports the resulting takedown state as the relay derives it —
        // re-render that truth, no optimistic edit.
        statusView = {
          kind: 'ready',
          status: await updateSubjectStatus(pinned.id, target, applied),
        };
      },
    });
  }

  /** Tap 2 of the credential sweep: gate on user presence, then sign the revocation. */
  async function confirmRevokeCredentials() {
    if (!pairing || statusView.kind !== 'ready') return;
    const target = statusView.status.subject.did;
    const pinned = pairing;
    // A slower sweep must not land its result under a newer lookup: only commit while
    // the panel still shows the DID this sweep targeted (guards both the report and the
    // disarm/error outcome via `commit`).
    const stillTargeted = () =>
      statusView.kind === 'ready' && statusView.status.subject.did === target;
    await creds.confirm({
      reason: 'Revoke all credentials of an account on this server',
      deniedHint: "Confirm with Face ID to revoke this account's credentials.",
      precondition: () => statusView.kind === 'ready' && !stale && !takedown.writing,
      run: async () => {
        // The relay reports literal per-family counts — render that truth verbatim.
        const report = await revokeAccountCredentials(pinned.id, target);
        if (stillTargeted()) credsReport = report;
      },
      commit: stillTargeted,
    });
  }
</script>

<ScreenShell
  prompt="moderation"
  title="Take down or restore an account"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="moderation always acts on a specific server.">
    {#snippet children()}
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
        {:else if !takedown.armed}
          {#if takenDown}
            <Button variant="primary" loading={takedown.writing} disabled={creds.writing} onclick={takedown.arm}>
              Restore this account
            </Button>
          {:else}
            <Button variant="destructive" loading={takedown.writing} disabled={creds.writing} onclick={takedown.arm}>
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
              loading={takedown.writing}
              disabled={creds.writing}
              onclick={() => confirmWrite(!takenDown)}
            >
              {takenDown ? 'Confirm restore' : 'Confirm takedown'}
            </Button>
            <Button variant="secondary" disabled={takedown.writing} onclick={takedown.disarm}>Cancel</Button>
          </div>
        {/if}

        {#if takedown.error}
          <ErrorState
            view={takedown.error}
            server={identity}
            retrying={takedown.writing}
            onretry={() => confirmWrite(!takenDown)}
          />
        {/if}
        {#if takedown.gateHint}
          <p class="hint" role="status">
            <StatusChip status="info" label="confirm" />
            <span>{takedown.gateHint}</span>
          </p>
        {/if}
      </section>

      <!-- The credential sweep for the looked-up DID: the incident-response follow-up
           to a takedown. Signs, so it carries the same arm → confirm → gate friction. -->
      <section class="panel" aria-labelledby="creds-label">
        <span id="creds-label" class="label">Credential revocation</span>
        <p class="note">
          Lock out everyone holding this account's credentials: sessions, app passwords,
          OAuth grants, and transfer-device tokens all die. The account's password is
          untouched, and already-minted access tokens lapse on their own within minutes.
        </p>

        {#if credsReport}
          <StatusChip status="revoked" label="swept" />
          <dl class="facts">
            <dt>sessions</dt>
            <dd>{credsReport.sessionsRevoked}</dd>
            <dt>app passwords</dt>
            <dd>{credsReport.appPasswordsRevoked}</dd>
            <dt>oauth tokens</dt>
            <dd>{credsReport.oauthTokensRevoked}</dd>
            <dt>oauth codes</dt>
            <dd>{credsReport.oauthCodesRevoked}</dd>
            <dt>transfer devices</dt>
            <dd>{credsReport.transferDeviceTokensRevoked}</dd>
          </dl>
        {/if}

        {#if stale}
          <p class="note">The DID field changed since this lookup. Look up again before acting.</p>
        {:else if !creds.armed}
          <Button
            variant="destructive"
            loading={creds.writing}
            disabled={takedown.writing}
            onclick={creds.arm}
          >
            {credsReport ? 'Revoke credentials again' : 'Revoke all credentials'}
          </Button>
        {:else}
          <div class="confirm" role="group" aria-label="Confirm credential revocation">
            <p class="confirm-text">
              Revoke every credential of
              <span class="confirm-did">{statusView.status.subject.did}</span>
              on {identity?.host}? Every holder — including the account owner — is
              signed out and must log in again with the account password.
            </p>
            <Button
              variant="destructive"
              loading={creds.writing}
              disabled={takedown.writing}
              onclick={confirmRevokeCredentials}
            >
              Confirm revocation
            </Button>
            <Button variant="secondary" disabled={creds.writing} onclick={creds.disarm}>
              Cancel
            </Button>
          </div>
        {/if}

        {#if creds.error}
          <ErrorState
            view={creds.error}
            server={identity}
            retrying={creds.writing}
            onretry={confirmRevokeCredentials}
          />
        {/if}
        {#if creds.gateHint}
          <p class="hint" role="status">
            <StatusChip status="info" label="confirm" />
            <span>{creds.gateHint}</span>
          </p>
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
