<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import { truncateDid } from '$lib/did-doc-utils';
  import {
    buildRekey,
    submitRekey,
    ensureIdentitySession,
    sovereignLogin,
    isCodedError,
    type RekeyPreview,
    type RekeyResult,
    type RekeyError,
  } from '$lib/ipc';

  let {
    did,
    onback,
    ondone,
  }: {
    did: string;
    onback: () => void;
    /** Called once the re-key lands — carries the new Share 3 for the backup step. */
    ondone: (result: RekeyResult) => void;
  } = $props();

  type Phase =
    | { kind: 'loading' }
    | { kind: 'ready'; preview: RekeyPreview; error?: string }
    | { kind: 'load_error'; error: string }
    | { kind: 'working' };

  let phase = $state<Phase>({ kind: 'loading' });

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as RekeyError;
    switch (err.code) {
      case 'NOT_DID_PLC':
        return 'This identity type doesn’t use a recovery key.';
      case 'ALREADY_REKEYED':
        return 'This identity already has a recovery key — nothing to upgrade.';
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet isn’t the root key holder for this identity.';
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'GUARD_REJECTED':
        return 'The upgrade was blocked by a safety check and was not signed.';
      case 'ESCROW_FAILED':
        return 'Couldn’t save your recovery share to the server. Please try again.';
      case 'SHARE_STORAGE_FAILED':
        return 'Your identity was upgraded, but saving the local backup failed. Please try again.';
      case 'PLC_SUBMISSION_FAILED':
        return 'The directory rejected the change. Please try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The identity directory had a problem. Please try again shortly.';
      case 'SERVER_ERROR':
        return 'The server couldn’t complete this step. Please try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  /** Run `fn` with the session pre-flight: unlock passwordlessly once if locked. */
  async function withUnlockedSession<T>(fn: () => Promise<T>): Promise<T> {
    try {
      await ensureIdentitySession(did);
    } catch (e) {
      if (isCodedError(e) && e.code === 'NEEDS_UNLOCK') {
        await sovereignLogin(did);
      } else {
        throw e;
      }
    }
    try {
      return await fn();
    } catch (e) {
      if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
        await sovereignLogin(did);
        return await fn();
      }
      throw e;
    }
  }

  async function build() {
    phase = { kind: 'loading' };
    try {
      const preview = await buildRekey(did);
      phase = { kind: 'ready', preview };
    } catch (e) {
      console.error('[RekeyReviewScreen] failed to build re-key:', e);
      phase = { kind: 'load_error', error: messageFor(e) };
    }
  }

  async function submit() {
    if (phase.kind !== 'ready') return;
    const preview = phase.preview;
    phase = { kind: 'working' };
    try {
      const result = await withUnlockedSession(() => submitRekey(did));
      ondone(result);
    } catch (e) {
      console.error('[RekeyReviewScreen] re-key failed:', e);
      phase = { kind: 'ready', preview, error: messageFor(e) };
    }
  }

  onMount(build);
</script>

<div class="screen">
  <ScreenHeader title="Add a recovery key" onback={onback} backLabel="Back to identity" />

  <p class="intro">
    This identity predates recovery keys. Adding one gives you a way back in if you lose this
    device — through your saved shares — without changing anything you rely on today. Your device
    key stays firmly in control, and nothing is removed.
  </p>

  <div class="identity">
    <span class="id-label">Identity</span>
    <span class="id-did">{truncateDid(did)}</span>
  </div>

  {#if phase.kind === 'loading'}
    <div class="center">
      <Spinner size={28} label="Preparing the upgrade" />
      <p class="hint">Generating your new recovery shares…</p>
    </div>
  {:else if phase.kind === 'load_error'}
    <p class="status" role="alert">{phase.error}</p>
    <Button onclick={build}>Try again</Button>
  {:else if phase.kind === 'working'}
    <div class="center">
      <Spinner size={28} label="Adding your recovery key" />
      <p class="hint">Publishing the change and saving your shares…</p>
    </div>
  {:else if phase.kind === 'ready'}
    <div class="block">
      <p class="block-label">This upgrade will</p>
      {#each phase.preview.diff.addedKeys as key}
        <DiffRow variant="restore" title="Add your new recovery key" value={key} />
      {/each}
      <p class="reassure">Nothing is removed. Your device key stays your root key.</p>
    </div>

    <div class="sealed">
      <span class="sealed-ic" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg></span>
      Sealed by your device key
    </div>

    {#if phase.error}
      <div class="error-box" role="alert">
        <p class="error-text">{phase.error}</p>
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

  .intro {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .identity {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .id-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .id-did {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    word-break: break-all;
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
  .status {
    font-size: var(--text-body);
    color: var(--color-critical);
    margin: 0;
  }

  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .block-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .reassure {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .sealed {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-primary-deep);
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: 12px var(--space-md);
  }
  .error-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }

  .actions {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding-bottom: var(--space-lg);
  }
</style>
