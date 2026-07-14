<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import {
    getAccountUsage,
    getAccountStorage,
    setAccountEmail,
    issueResetToken,
    type Pairing,
    type PairingsState,
    type AccountUsage,
    type AccountStorage,
    type RepairedEmail,
    type IssuedResetToken,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { formatBytes, formatPct } from '$lib/format';
  import { loadPinnedPairing, pinnedHref } from '$lib/pinned-pairing';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { createArmedAction } from '$lib/armed-action.svelte';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';

  // The account-detail screen: inspection and repair for ONE account on ONE relay —
  // identity facts, usage/storage, email correction, and reset-token issuance. Reached from the accounts
  // list (`?server=…&did=…`) and pinned to a single pairing at entry (see
  // $lib/pinned-pairing) like Devices/Moderation. Nothing here signs: destructive work
  // (takedown/restore, credential revocation) lives one hop deeper on the moderation
  // screen, reached from here with the same pin + DID. Repair writes use the shared
  // arm → biometric gate → signed request flow and stay bound to this pinned target.

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
  let email = $state('');
  let repairedEmail = $state<RepairedEmail | null>(null);
  let resetToken = $state<IssuedResetToken | null>(null);
  const emailRepair = createArmedAction();
  const tokenIssue = createArmedAction();

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    did = page.url.searchParams.get('did');
    if (pairing && did) void loadMetrics(did);
  });

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
  const normalizedEmail = $derived(email.trim().toLowerCase());
  const emailLooksValid = $derived(/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalizedEmail));

  // The address the operator reviewed when they armed the confirm. If the field drifts
  // from it, auto-disarm — a second tap must never sign a value the operator didn't review
  // (the same stale-target guard the Moderation screen applies to a drifted DID lookup).
  let armedEmail = $state<string | null>(null);
  function armEmailRepair() {
    armedEmail = normalizedEmail;
    emailRepair.arm();
  }
  $effect(() => {
    if (emailRepair.armed && !emailRepair.writing && normalizedEmail !== armedEmail) {
      emailRepair.disarm();
    }
  });

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

  async function confirmEmailRepair() {
    if (!pairing || !did || !emailLooksValid) return;
    const target = did;
    const pinned = pairing;
    await emailRepair.confirm({
      reason: 'Correct an account email on this server',
      deniedHint: 'Confirm with Face ID to correct this account email.',
      precondition: () => did === target && !tokenIssue.writing,
      run: async () => {
        repairedEmail = await setAccountEmail(pinned.id, target, normalizedEmail);
      },
    });
  }

  async function confirmTokenIssue() {
    if (!pairing || !did) return;
    const target = did;
    const pinned = pairing;
    await tokenIssue.confirm({
      reason: 'Issue a password reset token for an account',
      deniedHint: 'Confirm with Face ID to issue this reset token.',
      precondition: () => did === target && !emailRepair.writing,
      run: async () => {
        resetToken = await issueResetToken(pinned.id, target);
      },
    });
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

    <section class="panel" aria-labelledby="email-repair-label">
      <span id="email-repair-label" class="label">Email repair</span>
      <p class="note">Replace the stored address and mark it unconfirmed. The server records the operator and both addresses in its audit trail.</p>
      <TextField
        label="Correct email"
        type="email"
        bind:value={email}
        placeholder="account@example.com"
        error={email !== '' && !emailLooksValid ? 'Enter a complete email address.' : undefined}
      />
      {#if !emailRepair.armed}
        <Button variant="secondary" disabled={!emailLooksValid || tokenIssue.writing} onclick={armEmailRepair}>Review email change</Button>
      {:else}
        <div class="confirm" role="group" aria-label="Confirm email repair">
          <p class="note">Set <span class="literal">{did}</span> to <span class="literal">{normalizedEmail}</span> and reset confirmation?</p>
          <Button variant="primary" loading={emailRepair.writing} onclick={confirmEmailRepair}>Confirm email repair</Button>
          <Button variant="secondary" disabled={emailRepair.writing} onclick={emailRepair.disarm}>Cancel</Button>
        </div>
      {/if}
      {#if repairedEmail}
        <p class="result" role="status">● updated · {repairedEmail.email} · unconfirmed</p>
      {/if}
      {#if emailRepair.error}<ErrorState view={emailRepair.error} server={identity} onretry={confirmEmailRepair} />{/if}
      {#if emailRepair.gateHint}<p class="note" role="status">○ {emailRepair.gateHint}</p>{/if}
    </section>

    <section class="panel" aria-labelledby="reset-token-label">
      <span id="reset-token-label" class="label">Credential issuance</span>
      <p class="note">Mint a single-use password-reset token valid for one hour. Deliver it out of band; the operator never chooses or sees the new password. Only an account that already uses a password can be issued one — a passwordless (key-sovereign) account is recovered through its escrowed key share, not a reset.</p>
      {#if !tokenIssue.armed}
        <Button variant="secondary" disabled={emailRepair.writing} onclick={tokenIssue.arm}>Issue reset token</Button>
      {:else}
        <div class="confirm" role="group" aria-label="Confirm reset token issuance">
          <p class="note">Issue a reset token for <span class="literal">{did}</span>? The issuance is audit-logged, but the plaintext token is not.</p>
          <Button variant="primary" loading={tokenIssue.writing} onclick={confirmTokenIssue}>Confirm token issuance</Button>
          <Button variant="secondary" disabled={tokenIssue.writing} onclick={tokenIssue.disarm}>Cancel</Button>
        </div>
      {/if}
      {#if resetToken}
        <CodeOutput value={resetToken.token} label="Password reset token" />
        <p class="result" role="status">● issued · expires in 1 hour · single use</p>
      {/if}
      {#if tokenIssue.error}<ErrorState view={tokenIssue.error} server={identity} onretry={confirmTokenIssue} />{/if}
      {#if tokenIssue.gateHint}<p class="note" role="status">○ {tokenIssue.gateHint}</p>{/if}
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
  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding: var(--space-sm);
    background: var(--color-surface-raised);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-md);
  }
  .literal {
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
  .result {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-safe);
    overflow-wrap: anywhere;
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
