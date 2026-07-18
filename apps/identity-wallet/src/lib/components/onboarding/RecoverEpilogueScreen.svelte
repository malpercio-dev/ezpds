<script lang="ts">
  import { onMount } from 'svelte';
  import {
    runRecoveryEpilogue,
    getPendingRecoveryEpilogue,
    isCodedError,
    type EpilogueResult,
    type ShareRecoveryError,
  } from '$lib/ipc';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    resume = false,
    oncomplete,
  }: {
    /** True when re-entering after an app restart found a pending epilogue. */
    resume?: boolean;
    oncomplete: (result: EpilogueResult) => void;
  } = $props();

  type StepId = 'rotate' | 'escrow' | 'local';
  type StepState = 'pending' | 'active' | 'done' | 'skipped' | 'failed';

  const STEPS: { id: StepId; label: string }[] = [
    { id: 'rotate', label: 'Retire the old backup shares' },
    { id: 'escrow', label: 'Escrow a new share with your server' },
    { id: 'local', label: 'Store the new iCloud share' },
  ];

  let stepStates = $state<Record<StepId, StepState>>({
    rotate: 'pending',
    escrow: 'pending',
    local: 'pending',
  });
  let failure = $state<string | null>(null);
  /** The escrow step failed — offer continuing without server escrow. */
  let escrowFailed = $state(false);
  let running = $state(false);

  function statusGlyph(state: StepState): string {
    switch (state) {
      case 'pending':
        return '○';
      case 'active':
        return '◐';
      case 'done':
        return '✓';
      case 'skipped':
        return '–';
      case 'failed':
        return '✕';
    }
  }

  function statusWord(state: StepState): string {
    switch (state) {
      case 'pending':
        return 'Waiting';
      case 'active':
        return 'In progress';
      case 'done':
        return 'Done';
      case 'skipped':
        return 'Skipped';
      case 'failed':
        return 'Failed';
    }
  }

  function describeError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch ((raw as ShareRecoveryError).code) {
        case 'SESSION_FAILED':
          return "Couldn't sign in to your server to deposit the new escrow share.";
        case 'ESCROW_DEPOSIT_FAILED':
          return "Your server refused the new escrow share.";
        case 'PLC_DIRECTORY_ERROR':
          return 'The PLC directory rejected the share-rotation operation. Try again in a moment.';
        case 'SIGNING_FAILED':
          return 'Signing failed on this device. Try again.';
        case 'KEYCHAIN_ERROR':
          return "Couldn't store the new share on this device. Check storage and try again.";
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        case 'EPILOGUE_CORRUPT':
          return 'The saved rotation record could not be read. Contact support before retrying.';
        default:
          return `An unexpected error occurred (${(raw as ShareRecoveryError).code}). Please try again.`;
      }
    }
    return 'An unexpected error occurred. Please try again.';
  }

  /** Re-derive the checklist from the durable record's progress flags. */
  async function refreshFromRecord() {
    try {
      const pending = await getPendingRecoveryEpilogue();
      if (!pending) return;
      stepStates.rotate = pending.opSubmitted ? 'done' : stepStates.rotate;
      if (pending.escrowDeposited) stepStates.escrow = 'done';
      else if (pending.escrowSkipped) stepStates.escrow = 'skipped';
      if (pending.share1Written) stepStates.local = 'done';
    } catch (e) {
      console.warn('getPendingRecoveryEpilogue failed:', e);
    }
  }

  async function run(skipEscrow: boolean) {
    running = true;
    failure = null;
    escrowFailed = false;
    for (const step of STEPS) {
      if (stepStates[step.id] === 'failed') stepStates[step.id] = 'pending';
    }
    if (stepStates.rotate !== 'done') stepStates.rotate = 'active';
    else if (stepStates.escrow !== 'done' && stepStates.escrow !== 'skipped')
      stepStates.escrow = 'active';
    else stepStates.local = 'active';
    try {
      const result = await runRecoveryEpilogue(skipEscrow);
      stepStates.rotate = 'done';
      stepStates.escrow = result.escrowDeposited ? 'done' : 'skipped';
      stepStates.local = 'done';
      oncomplete(result);
    } catch (raw: unknown) {
      console.error('Rotation epilogue failed:', raw);
      await refreshFromRecord();
      const code = isCodedError(raw) ? (raw as ShareRecoveryError).code : null;
      escrowFailed = code === 'SESSION_FAILED' || code === 'ESCROW_DEPOSIT_FAILED';
      if (escrowFailed) {
        stepStates.escrow = 'failed';
      } else if (stepStates.rotate !== 'done') {
        stepStates.rotate = 'failed';
      } else {
        stepStates.local = 'failed';
      }
      failure = describeError(raw);
      running = false;
    }
  }

  onMount(() => {
    if (resume) {
      refreshFromRecord().then(() => run(false));
    } else {
      run(false);
    }
  });
</script>

<div class="screen">
  <div class="header">
    {#if running}
      <Spinner size={40} label="Rotating shares" />
    {/if}
    <h1 class="title">{resume ? 'Finishing your recovery' : 'Securing your new backup'}</h1>
    <p class="subtitle">
      The lost device's backup shares are being retired and replaced with a fresh set only this
      device knows. This step is required — the old shares can never be trusted again.
    </p>
  </div>

  <ul class="checklist">
    {#each STEPS as step (step.id)}
      <li class="leg leg--{stepStates[step.id]}">
        <span class="leg-glyph" aria-hidden="true">{statusGlyph(stepStates[step.id])}</span>
        <span class="leg-body">
          <span class="leg-label">{step.label}</span>
          <span class="leg-status">{statusWord(stepStates[step.id])}</span>
        </span>
      </li>
    {/each}
  </ul>

  {#if failure}
    <div class="error-box" role="alert">
      <p class="error-text">{failure}</p>
      {#if escrowFailed}
        <p class="error-detail">
          You can retry, or continue without server escrow — then only your iCloud share and your
          saved share protect this identity, and you can re-enable escrow later from settings.
        </p>
      {/if}
    </div>
    <Button onclick={() => run(false)}>Retry</Button>
    {#if escrowFailed}
      <Button variant="secondary" onclick={() => run(true)}>Continue without escrow</Button>
    {/if}
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-xl) var(--space-lg);
    gap: var(--space-lg);
    overflow-y: auto;
  }
  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--space-sm);
  }
  .title {
    font-family: var(--font-sans);
    font-size: var(--text-headline);
    line-height: var(--leading-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }
  .subtitle {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    max-width: 34ch;
  }

  .checklist {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .leg {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .leg-glyph {
    font-size: var(--text-title);
    line-height: var(--leading-headline);
    width: 22px;
    flex-shrink: 0;
    text-align: center;
    color: var(--color-muted);
  }
  .leg--done .leg-glyph {
    color: var(--color-safe);
  }
  .leg--active .leg-glyph {
    color: var(--color-primary-deep);
  }
  .leg--failed .leg-glyph {
    color: var(--color-critical);
  }
  .leg-body {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  .leg-label {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .leg-status {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .leg--done .leg-status {
    color: var(--color-safe);
  }
  .leg--failed .leg-status {
    color: var(--color-critical);
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
  }
  .error-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }
  .error-detail {
    font-size: var(--text-label);
    color: var(--color-critical-soft);
    margin: var(--space-xs) 0 0;
    line-height: 1.4;
  }
</style>
