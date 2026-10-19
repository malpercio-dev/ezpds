<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import { truncateDid } from '$lib/did-doc-utils';
  import {
    buildSelfHeldKit,
    submitSelfHeldKit,
    isCodedError,
    type SelfHeldKitPreview,
    type SelfHeldKitResult,
    type SelfHeldKitError,
  } from '$lib/ipc';

  let {
    did,
    onback,
    ondone,
  }: {
    did: string;
    onback: () => void;
    /** Called once the kit lands — carries Shares 2 and 3 for the backup step. */
    ondone: (result: SelfHeldKitResult) => void;
  } = $props();

  type Phase =
    | { kind: 'loading' }
    | { kind: 'ready'; preview: SelfHeldKitPreview; error?: string }
    | { kind: 'load_error'; error: string }
    | { kind: 'working' };

  let phase = $state<Phase>({ kind: 'loading' });

  /** Host origin only — the review names the server, not a URL to be read character by character. */
  function hostOf(url: string): string {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  }

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as SelfHeldKitError;
    switch (err.code) {
      case 'NOT_DID_PLC':
        return 'This identity type doesn’t use a recovery key.';
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet isn’t the root key holder for this identity.';
      case 'HOST_OFFERS_ESCROW':
        return 'This identity’s server can hold a recovery share for you — use the upgrade offered on your identity screen instead.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'GUARD_REJECTED':
        return 'The change was blocked by a safety check and was not signed.';
      case 'SHARE_GENERATION_FAILED':
        return 'Your recovery shares couldn’t be prepared. Please try again.';
      case 'SHARE_STORAGE_FAILED':
        return 'Your recovery key was added, but saving the local share failed. Please try again.';
      case 'PLC_SUBMISSION_FAILED':
        return 'The directory rejected the change. Please try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The identity directory had a problem. Please try again shortly.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the directory. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  async function build() {
    phase = { kind: 'loading' };
    try {
      phase = { kind: 'ready', preview: await buildSelfHeldKit(did) };
    } catch (e) {
      console.error('[SelfHeldKitReviewScreen] failed to build the kit:', e);
      phase = { kind: 'load_error', error: messageFor(e) };
    }
  }

  // No session pre-flight, unlike every sibling identity screen: every step that touches the
  // identity is plc.directory, and the one request that reaches the hosting PDS is the public
  // `describeServer` capability probe behind `buildSelfHeldKit`. Neither carries a credential,
  // so there is no session that could be locked and nothing to unlock; offering an unlock here
  // would imply an authenticated server role this flow does not have.
  async function submit() {
    if (phase.kind !== 'ready') return;
    const { preview } = phase;
    phase = { kind: 'working' };
    try {
      ondone(await submitSelfHeldKit(did));
    } catch (e) {
      console.error('[SelfHeldKitReviewScreen] the kit failed:', e);
      phase = { kind: 'ready', preview, error: messageFor(e) };
    }
  }

  onMount(build);
</script>

<div class="screen">
  <ScreenHeader title="Add a recovery key" {onback} backLabel="Back to identity" />

  <p class="intro u-body-soft">
    This identity has no recovery key yet. Adding one gives you a way back in if you lose this
    device. Your device key stays firmly in control, and nothing is removed.
  </p>

  <div class="identity u-stack-2xs">
    <span class="id-label u-label-muted">Identity</span>
    <span class="id-did u-id-mono">{truncateDid(did)}</span>
  </div>

  {#if phase.kind === 'loading'}
    <div class="center">
      <Spinner size={28} label="Preparing your recovery kit" />
      <p class="hint">Generating your recovery shares…</p>
    </div>
  {:else if phase.kind === 'load_error'}
    <p class="status u-notice-text" role="alert">{phase.error}</p>
    <Button onclick={build}>Try again</Button>
  {:else if phase.kind === 'working'}
    <div class="center">
      <Spinner size={28} label="Adding your recovery key" />
      <p class="hint">Publishing the change and saving your share…</p>
    </div>
  {:else if phase.kind === 'ready'}
    <div class="block u-stack-sm">
      <p class="block-label u-block-label">This will</p>
      {#each phase.preview.diff.addedKeys as key (key)}
        <DiffRow variant="restore" title="Add your new recovery key" value={key} />
      {/each}
      <p class="reassure">Nothing is removed. Your device key stays your root key.</p>
    </div>

    <!-- The honest headline of this flow: the shares are the user's, and the server neither
         receives nor can release one. Said before the ceremony, not after, so the person who
         has to keep two shares safe knows that before agreeing to it. -->
    <div class="block u-stack-sm">
      <p class="block-label u-block-label">Where your shares go</p>
      <ul class="shares">
        <li><strong>Share 1</strong> — your Keychain, set to sync to your other Apple devices</li>
        <li><strong>Shares 2 and 3</strong> — yours to save, in the next step</li>
      </ul>
      <p class="reassure">
        {hostOf(phase.preview.pdsUrl)} doesn’t hold recovery shares, so no share and no part of
        your recovery key is ever sent to it. Any two of the three shares restore this identity.
      </p>
    </div>

    <div class="sealed">
      <span class="sealed-ic" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg></span>
      Sealed by your device key
    </div>

    {#if phase.error}
      <div class="error-box" role="alert">
        <p class="error-text u-error-text">{phase.error}</p>
      </div>
    {/if}

    <div class="actions">
      <Button onclick={submit}>Add recovery key</Button>
      <Button variant="secondary" onclick={onback}>Not now</Button>
    </div>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    height: 100%;
    overflow-y: auto;
  }

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
    text-align: center;
  }

  .reassure {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: var(--leading-body);
  }
  .shares {
    margin: 0;
    padding-left: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    line-height: var(--leading-body);
  }

  .sealed {
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-primary-deep);
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: var(--space-md) var(--space-md);
  }

  .actions {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding-bottom: var(--space-lg);
  }
</style>
