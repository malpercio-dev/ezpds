<script lang="ts">
  import { onMount } from 'svelte';
  import {
    buildRecoveryOverride,
    submitRecoveryOverride,
    isCodedError,
    type SignedRecoveryOp,
    type RecoveryError,
  } from '$lib/ipc';
  import { getDeadline, getUrgency } from '$lib/deadline';
  import { truncateDid } from '$lib/did-doc-utils';
  import UrgencyBadge from '$lib/components/ui/UrgencyBadge.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import { useCountdown } from '$lib/components/ui/use-countdown.svelte';
  import { useHoldGesture } from '$lib/components/ui/use-hold-gesture.svelte';

  let {
    did,
    operationCid,
    createdAt,
    onback,
    onsuccess,
  }: {
    did: string;
    operationCid: string;
    createdAt: string;
    onback: () => void;
    onsuccess: () => void;
  } = $props();

  let loading = $state(false);
  let submitting = $state(false);
  let error = $state<string | null>(null);
  let signedOp = $state<SignedRecoveryOp | null>(null);

  const countdown = useCountdown(15_000);

  // Derived so the countdown stays reactive as `now` ticks.
  let deadline = $derived(getDeadline(createdAt));
  let urgency = $derived(getUrgency(deadline, countdown.now));
  let isExpired = $derived(urgency === 'expired');

  // Hold-to-override: a deliberate, irreversible confirmation gesture.
  const HOLD_MS = 1500;
  const hold = useHoldGesture({
    durationMs: HOLD_MS,
    oncomplete: confirmOverride,
    canStart: () => !(submitting || isExpired || !signedOp),
  });
  let holdFill = $derived(hold.state.progress); // 0..1

  function holdStart() {
    hold.start();
  }
  function holdEnd() {
    hold.end();
  }
  const holdKeydown = hold.keydown;
  const holdKeyup = hold.keyup;
  function confirmOverride() {
    hold.state.progress = 1;
    handleSubmit();
  }

  onMount(async () => {
    loading = true;
    error = null;

    try {
      const op = await buildRecoveryOverride(did, operationCid);
      signedOp = op;
    } catch (raw: unknown) {
      console.error('Failed to build recovery override:', raw);

      if (isCodedError(raw)) {
        const err = raw as RecoveryError;
        switch (err.code) {
          case 'RECOVERY_WINDOW_EXPIRED':
            error = 'Recovery window has expired. No longer possible to recover this identity.';
            break;
          case 'SIGNING_FAILED':
            error = `Signing failed: ${err.message || 'unknown error'}`;
            break;
          case 'IDENTITY_NOT_FOUND':
            error = `Identity not found: ${err.message || 'unknown error'}`;
            break;
          case 'UNAUTHORIZED_CHANGE_NOT_FOUND':
            error = 'Unauthorized change not found in audit log.';
            break;
          case 'PLC_DIRECTORY_ERROR':
            error = `PLC directory error: ${err.message || 'unknown error'}`;
            break;
          case 'NETWORK_ERROR':
            error = `Network error: ${err.message || 'unknown error'}`;
            break;
          default:
            error = (err as { message?: string }).message || 'An unexpected error occurred.';
            break;
        }
      } else {
        error = 'Failed to build recovery operation. Please try again.';
      }
    } finally {
      loading = false;
    }
  });

  async function handleSubmit() {
    submitting = true;
    error = null;

    try {
      await submitRecoveryOverride(did);
      submitting = false;
      onsuccess();
    } catch (raw: unknown) {
      console.error('Recovery submission failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as RecoveryError;
        switch (err.code) {
          case 'RECOVERY_WINDOW_EXPIRED':
            error = 'Recovery window has expired. No longer possible to submit this recovery.';
            break;
          case 'SIGNING_FAILED':
            error = `Signing failed: ${err.message || 'unknown error'}`;
            break;
          case 'PLC_DIRECTORY_ERROR':
            error = `PLC directory rejected the operation: ${err.message || 'unknown error'}`;
            break;
          case 'NETWORK_ERROR':
            error = `Network error: ${err.message || 'unknown error'}`;
            break;
          case 'IDENTITY_NOT_FOUND':
            error = `Identity not found: ${err.message || 'unknown error'}`;
            break;
          case 'UNAUTHORIZED_CHANGE_NOT_FOUND':
            error = 'Unauthorized change not found in audit log.';
            break;
          default:
            error = (err as { message?: string }).message || 'An unexpected error occurred.';
            break;
        }
      } else {
        error = 'Submission failed. Please try again.';
      }
      submitting = false;
      hold.state.progress = 0; // reset so the user can retry the hold
    }
  }
</script>

<div class="screen">
  <div class="appbar">
    <button class="back" onclick={onback} disabled={loading || submitting} aria-label="Back">
      <ChevronLeftIcon />
      Back
    </button>
    <h2 class="appbar-title">Review override</h2>
    <UrgencyBadge {urgency} {deadline} now={countdown.now} />
  </div>

  <div class="content">
    <div class="hero">
      <h1 class="hero-title">Reclaim your identity</h1>
      <p class="hero-sub">
        Review what this does, then confirm with your device key. This reverses the change you didn’t
        authorize.
      </p>
    </div>

    <div class="identity">
      <span class="id-label">Identity</span>
      <span class="id-did">{truncateDid(did)}</span>
      <span class="id-deadline">Window closes {deadline.toLocaleString()}</span>
    </div>

    {#if loading}
      <div class="loading">
        <Spinner size={32} label="Building recovery operation" />
        <p class="loading-text">Building recovery operation…</p>
      </div>
    {:else if signedOp}
      <div class="block">
        <p class="block-label">This override will</p>
        {#if signedOp.diff.removedKeys.length === 0 && signedOp.diff.addedKeys.length === 0 && signedOp.diff.changedServices.length === 0}
          <p class="no-changes">No key or service changes to apply.</p>
        {:else}
          {#each signedOp.diff.removedKeys as key}
            <DiffRow variant="remove" title="Remove the unauthorized key" value={key} />
          {/each}
          {#each signedOp.diff.addedKeys as key}
            <DiffRow variant="restore" title="Restore your key" value={key} />
          {/each}
          {#each signedOp.diff.changedServices as service}
            {#if service.changeType === 'added'}
              <DiffRow variant="restore" title="Restore service {service.id}" value={service.newEndpoint ?? undefined} />
            {:else if service.changeType === 'removed'}
              <DiffRow variant="remove" title="Remove service {service.id}" value="was {service.oldEndpoint}" />
            {:else if service.changeType === 'modified'}
              <DiffRow variant="modify" title="Change service {service.id}" value="{service.oldEndpoint} → {service.newEndpoint}" />
            {/if}
          {/each}
        {/if}
      </div>

      <div class="sealed">
        <span class="sealed-ic" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg></span>
        Sealed by your device key
      </div>
    {/if}

    {#if error}
      <div class="error-box" role="alert">
        <p class="error-text">{error}</p>
      </div>
    {/if}
  </div>

  <div class="actions">
    {#if !loading && signedOp}
      <button
        class="hold"
        disabled={submitting || isExpired}
        onpointerdown={holdStart}
        onpointerup={holdEnd}
        onpointerleave={holdEnd}
        onpointercancel={holdEnd}
        onkeydown={holdKeydown}
        onkeyup={holdKeyup}
        aria-label="Press and hold to override"
      >
        <span class="hold-fill" style="transform: scaleX({holdFill})"></span>
        <span class="hold-label">
          {#if submitting}Submitting…{:else if isExpired}Recovery window expired{:else}Hold to override{/if}
        </span>
      </button>
      {#if !isExpired && !submitting}
        <p class="hint">Press and hold — this can’t be undone</p>
      {/if}
    {/if}
    <Button variant="secondary" onclick={onback} disabled={loading || submitting}>Cancel</Button>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .appbar {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-md) var(--space-md) var(--space-sm);
  }
  .back {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs);
    min-height: 44px;
  }
  .back:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .appbar-title {
    flex: 1;
    text-align: center;
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }

  .content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-sm) var(--space-md) var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .hero-title {
    font-family: var(--font-display);
    font-weight: var(--weight-regular);
    font-size: 1.75rem;
    line-height: 1.15;
    color: var(--color-ink);
    margin: 0 0 var(--space-sm);
  }
  .hero-sub {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .identity {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
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
  .id-deadline {
    font-size: var(--text-label);
    color: var(--color-muted);
  }

  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    padding: var(--space-xl) 0;
  }
  .loading-text {
    font-size: var(--text-body);
    color: var(--color-muted);
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
  .no-changes {
    font-size: var(--text-body);
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
    flex-shrink: 0;
    border-top: 1px solid var(--color-line);
    background: var(--color-surface);
    padding: var(--space-md) var(--space-md) var(--space-xl);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .hold {
    position: relative;
    width: 100%;
    height: 54px;
    border-radius: var(--radius-md);
    border: none;
    cursor: pointer;
    overflow: hidden;
    background: var(--color-critical-solid);
    touch-action: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .hold:disabled {
    background: var(--color-surface-sunk);
    cursor: not-allowed;
  }
  .hold-fill {
    position: absolute;
    inset: 0;
    background: var(--color-critical-solid-deep);
    transform: scaleX(0);
    transform-origin: left;
    transition: transform 0.1s linear;
  }
  .hold-label {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--color-on-color);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
  }
  .hold:disabled .hold-label {
    color: var(--color-muted);
  }
  .hint {
    text-align: center;
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
</style>
