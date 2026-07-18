<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import { truncateDid } from '$lib/did-doc-utils';
  import {
    buildRepoKeyRotation,
    submitRepoKeyRotation,
    ensureIdentitySession,
    sovereignLogin,
    isCodedError,
    type SignedRotationOp,
    type RotationError,
  } from '$lib/ipc';

  let {
    did,
    onback,
    ondone,
  }: {
    did: string;
    onback: () => void;
    /** Called after the rotation lands and the cache is refreshed. */
    ondone: () => void;
  } = $props();

  type Phase =
    | { kind: 'loading' }
    | { kind: 'ready'; op: SignedRotationOp; error?: string }
    | { kind: 'load_error'; error: string }
    | { kind: 'working' }
    | { kind: 'success' };

  let phase = $state<Phase>({ kind: 'loading' });

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as RotationError;
    switch (err.code) {
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet isn’t authorized to rotate this identity’s signing key.';
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'GUARD_REJECTED':
        return 'The rotation was blocked by a safety check and was not signed.';
      case 'ROTATION_FAILED':
        return 'The server rejected the rotation. Please try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The identity directory had a problem. Please try again shortly.';
      case 'SERVER_ERROR':
        return 'The server couldn’t complete this step. Please try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      case 'NO_PENDING_ROTATION':
        return 'The prepared rotation expired. Go back and try again.';
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
      // A live token can lapse between the pre-flight and the command. Unlock once and retry.
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
      const op = await withUnlockedSession(() => buildRepoKeyRotation(did));
      phase = { kind: 'ready', op };
    } catch (e) {
      console.error('[RotateRepoKeyScreen] failed to build rotation:', e);
      phase = { kind: 'load_error', error: messageFor(e) };
    }
  }

  async function submit() {
    if (phase.kind !== 'ready') return;
    const op = phase.op;
    phase = { kind: 'working' };
    try {
      await withUnlockedSession(() => submitRepoKeyRotation(did));
      phase = { kind: 'success' };
    } catch (e) {
      console.error('[RotateRepoKeyScreen] rotation failed:', e);
      phase = { kind: 'ready', op, error: messageFor(e) };
    }
  }

  onMount(build);
</script>

{#if phase.kind === 'success'}
  <div class="screen success">
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
    </SealEmblem>
    <h1 class="s-title">Signing key rotated</h1>
    <p class="s-body">
      Your hosting server now signs your data with a fresh key, and your identity record points at
      it. The old key no longer has any authority. It may take a few minutes to propagate across the
      network.
    </p>
    <Button onclick={ondone}>Done</Button>
  </div>
{:else}
  <div class="screen">
    <ScreenHeader title="Rotate signing key" onback={onback} backLabel="Back to identity" />

    <p class="intro">
      Your hosting server holds a key that signs this identity’s data. Rotating replaces it with a
      freshly generated one — use this if you suspect the server’s key was exposed, or as periodic
      hygiene. Your device key is untouched and stays in control.
    </p>

    <div class="identity">
      <span class="id-label">Identity</span>
      <span class="id-did">{truncateDid(did)}</span>
    </div>

    {#if phase.kind === 'loading'}
      <div class="center">
        <Spinner size={28} label="Preparing the rotation" />
        <p class="hint">Requesting a fresh key and sealing the change…</p>
      </div>
    {:else if phase.kind === 'load_error'}
      <p class="status" role="alert">{phase.error}</p>
      <Button onclick={build}>Try again</Button>
    {:else if phase.kind === 'working'}
      <div class="center">
        <Spinner size={28} label="Rotating the signing key" />
        <p class="hint">Publishing the new key and switching over…</p>
      </div>
    {:else if phase.kind === 'ready'}
      <div class="block">
        <p class="block-label">This rotation will</p>
        {#each phase.op.diff.addedKeys as key}
          <DiffRow variant="restore" title="Install the fresh signing key" value={key} />
        {/each}
        {#each phase.op.diff.removedKeys as key}
          <DiffRow variant="remove" title="Retire the old signing key" value={key} />
        {/each}
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
        <Button onclick={submit}>Rotate signing key</Button>
        <Button variant="secondary" onclick={onback}>Cancel</Button>
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
    font-size: 1.75rem;
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
