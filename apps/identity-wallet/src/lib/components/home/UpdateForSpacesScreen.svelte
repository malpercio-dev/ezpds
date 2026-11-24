<script lang="ts">
  import { DEVICE_KEY_UNUSABLE_MESSAGE } from '$lib/claim-errors';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import { truncateDid } from '$lib/did-doc-utils';
  import { shareDidDocument } from '$lib/share';
  import { isUnlockCancelled, withUnlockedSession } from '$lib/unlock';
  import {
    prepareKemKeyPublish,
    completeKemKeyPublish,
    isCodedError,
    type KemKeyError,
    type KemKeyPlan,
  } from '$lib/ipc';

  // "Update identity for Spaces": publish the Spaces key the hosting server holds for this
  // identity, so space records it writes can be checked. Nothing happens until the user asks:
  // the screen opens on an explanation, `prepare` runs on a tap, and the change itself waits on
  // a second tap behind biometrics ($lib/ipc/kem.ts places the prompt).
  let {
    did,
    onback,
    ondone,
  }: {
    did: string;
    onback: () => void;
    /** Called after the update lands and the cached document is refreshed. */
    ondone: () => void;
  } = $props();

  /** The user-facing explainer on the docs site. */
  const EXPLAINER_URL = 'https://docs.obsign.org/user/spaces/';

  type Phase =
    | { kind: 'intro'; error?: string }
    | { kind: 'preparing' }
    | { kind: 'ready'; plan: Exclude<KemKeyPlan, { kind: 'published' }>; error?: string }
    | { kind: 'working'; plan: Exclude<KemKeyPlan, { kind: 'published' }> }
    | { kind: 'success' };

  let phase = $state<Phase>({ kind: 'intro' });

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as KemKeyError;
    switch (err.code) {
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet doesn’t hold a key that can change this identity, so it can’t make the update.';
      case 'GUARD_REJECTED':
        return 'A safety check stopped the update before anything was signed. Nothing changed.';
      case 'KEM_KEY_FAILED':
        return phase.kind === 'working' && phase.plan.kind === 'didWebDocument'
          ? 'Your server can’t see the new key in your did.json yet. Upload the exact file, give your host a minute, then try again.'
          : 'Your server didn’t accept the update. Nothing changed. Please try again.';
      case 'INVALID_DID_DOCUMENT':
        return 'Couldn’t read the did.json your domain serves right now. Check that it’s reachable, then try again.';
      case 'NO_PENDING_KEM_KEY':
        return 'The prepared update expired. Start again.';
      case 'UNSUPPORTED_IDENTITY':
        return 'This kind of identity can’t be updated for Spaces here.';
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Wait a moment and try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The identity directory had a problem. Please try again shortly.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach your server. Check your connection.';
      case 'DEVICE_KEY_UNUSABLE':
        return DEVICE_KEY_UNUSABLE_MESSAGE;
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  /** A dismissed password prompt is a decision, not a fault: no error shown. */
  const cancelled = isUnlockCancelled;

  async function prepare() {
    phase = { kind: 'preparing' };
    try {
      const plan = await withUnlockedSession(did, () => prepareKemKeyPublish(did));
      phase = plan.kind === 'published' ? { kind: 'success' } : { kind: 'ready', plan };
    } catch (e) {
      console.error('[UpdateForSpacesScreen] prepare failed:', e);
      phase = cancelled(e) ? { kind: 'intro' } : { kind: 'intro', error: messageFor(e) };
    }
  }

  async function complete() {
    if (phase.kind !== 'ready') return;
    const plan = phase.plan;
    phase = { kind: 'working', plan };
    try {
      await withUnlockedSession(did, () => completeKemKeyPublish(did));
      phase = { kind: 'success' };
    } catch (e) {
      console.error('[UpdateForSpacesScreen] complete failed:', e);
      phase = { kind: 'ready', plan, error: cancelled(e) ? undefined : messageFor(e) };
    }
  }
</script>

{#if phase.kind === 'success'}
  <div class="screen success">
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
    </SealEmblem>
    <h1 class="s-title">Identity updated for Spaces</h1>
    <p class="s-body">
      Your identity now lists your server’s Spaces key, so apps can check that records in your
      spaces came from your server. Other servers may take a few minutes to notice.
    </p>
    <Button onclick={ondone}>Done</Button>
  </div>
{:else}
  <div class="screen">
    <ScreenHeader title="Update identity for Spaces" onback={onback} backLabel="Back to identity" />

    <div class="identity u-stack-2xs">
      <span class="id-label u-label-muted">Identity</span>
      <span class="id-did u-id-mono">{truncateDid(did)}</span>
    </div>

    {#if phase.kind === 'intro'}
      <p class="intro u-body-soft">
        In a space, apps check that each record really came from your server. To do that they
        need your server’s Spaces key, listed in your identity. This update adds it. Your device
        key, handle, and server stay as they are, and you’ll see the exact change before you
        approve it.
      </p>
      <div class="explainer u-stack-2xs">
        <span class="u-block-label">How Spaces proves a record came from you</span>
        <span class="explainer-url u-id-mono">{EXPLAINER_URL}</span>
        <Button variant="secondary" onclick={() => shareDidDocument(EXPLAINER_URL)}>Share the explainer link</Button>
      </div>
      {#if phase.error}
        <div class="error-box" role="alert"><p class="u-error-text">⚠ {phase.error}</p></div>
      {/if}
      <div class="actions">
        <Button onclick={prepare}>Review the update</Button>
        <Button variant="secondary" onclick={onback}>Not now</Button>
      </div>
    {:else if phase.kind === 'preparing'}
      <div class="center">
        <Spinner size={28} label="Preparing the update" />
        <p class="hint">Asking your server for its Spaces key…</p>
      </div>
    {:else}
      {@const plan = phase.plan}
      <div class="block u-stack-sm">
        <p class="u-block-label">This update will</p>
        <DiffRow variant="restore" title="List your server’s Spaces key" value={plan.diff.kemKey} />
        {#if plan.diff.replacedKemKey}
          <DiffRow variant="remove" title="Retire the previous Spaces key" value={plan.diff.replacedKemKey} />
        {/if}
        {#if plan.diff.removedSpaceKey}
          <DiffRow variant="remove" title="Remove an unused Spaces entry" value={plan.diff.removedSpaceKey} />
        {/if}
        {#if plan.diff.removedSpaceHost}
          <DiffRow variant="remove" title="Remove an unused Spaces service" value={plan.diff.removedSpaceHost} />
        {/if}
      </div>

      {#if plan.kind === 'plcOperation'}
        <div class="sealed">
          <span aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg></span>
          Sealed by your device key
        </div>
      {:else}
        <p class="u-body-soft">
          Your domain serves your identity, so this change is a new did.json. Export it, replace
          the file at <span class="u-id-mono">{plan.documentUrl}</span>, then confirm.
        </p>
        <code>{plan.documentText}</code>
        <Button variant="secondary" onclick={() => shareDidDocument(plan.documentText)}>Export updated did.json</Button>
        <p class="hint">
          How this works: <span class="u-id-mono">{EXPLAINER_URL}</span>
        </p>
      {/if}

      {#if phase.kind === 'ready' && phase.error}
        <div class="error-box" role="alert"><p class="u-error-text">⚠ {phase.error}</p></div>
      {/if}

      <div class="actions">
        {#if phase.kind === 'working'}
          <Spinner size={28} label={plan.kind === 'plcOperation' ? 'Publishing the update' : 'Checking your did.json'} />
        {:else}
          <Button onclick={complete}>
            {plan.kind === 'plcOperation' ? 'Update identity' : 'I’ve uploaded this file'}
          </Button>
          <Button variant="secondary" onclick={onback}>Cancel</Button>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    height: 100%;
    overflow-y: auto;
  }
  .screen.success {
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-lg);
  }
  .s-title {
    font-family: var(--font-display);
    font-weight: var(--weight-regular);
    font-size: var(--text-display);
    color: var(--color-ink);
    margin: 0;
  }
  .s-body {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
    max-width: 34ch;
  }
  .intro { margin: 0; }
  .explainer {
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .explainer-url { overflow-wrap: anywhere; }
  .center {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    padding: var(--space-xl) 0;
  }
  .hint {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    overflow-wrap: anywhere;
  }
  .sealed {
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-primary-deep);
  }
  code {
    display: block;
    max-height: 11rem;
    width: 100%;
    overflow: auto;
    padding: var(--space-sm);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunk);
    color: var(--color-ink);
    font-family: var(--font-mono);
    font-size: var(--text-data);
    white-space: pre;
  }
  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: var(--space-md);
  }
  .error-box p { margin: 0; }
  .actions {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding-bottom: var(--space-lg);
  }
</style>
