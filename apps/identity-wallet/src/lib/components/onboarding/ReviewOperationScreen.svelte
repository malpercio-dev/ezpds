<script lang="ts">
  import { submitClaim, type VerifiedClaimOp, type ClaimResult, type ClaimError } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    did,
    verifiedClaim,
    onnext,
    oncancel,
  }: {
    did: string;
    verifiedClaim: VerifiedClaimOp;
    onnext: (result: ClaimResult) => void;
    oncancel: () => void;
  } = $props();

  let submitting = $state(false);
  let error = $state<string | null>(null);
  let warningsAcknowledged = $state(false);

  let hasChanges = $derived(
    verifiedClaim.diff.addedKeys.length > 0 ||
      verifiedClaim.diff.removedKeys.length > 0 ||
      verifiedClaim.diff.changedServices.length > 0
  );

  async function handleSubmit() {
    submitting = true;
    error = null;

    try {
      const result = await submitClaim(did);
      onnext(result);
    } catch (raw: unknown) {
      console.error('Claim submission failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'PLC_DIRECTORY_ERROR':
            error = `PLC directory rejected the operation: ${err.message || 'unknown error'}`;
            break;
          case 'RATE_LIMITED':
            error = formatRateLimitMessage(err.retryAfter);
            break;
          case 'SERVER_ERROR':
            error = formatServerErrorMessage(err.message);
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          case 'UNAUTHORIZED':
            error = 'Authorization expired. Please restart the import flow.';
            break;
          default:
            error = `Submission failed (${err.code}). Please try again.`;
        }
      } else {
        error = 'Submission failed. Please try again.';
      }
      submitting = false;
    }
  }
</script>

<div class="screen">
  <div class="content">
    <div class="hero">
      <h1 class="hero-title">Claim your identity</h1>
      <p class="hero-sub">Review what this changes, then confirm. This makes your device key the controlling key.</p>
    </div>

    <div class="block">
      <p class="block-label">This will</p>
      {#if !hasChanges}
        <p class="no-changes">No key or service changes to apply.</p>
      {:else}
        {#each verifiedClaim.diff.addedKeys as key}
          <DiffRow variant="restore" title="Add your device key" value={key} />
        {/each}
        {#each verifiedClaim.diff.removedKeys as key}
          <DiffRow variant="remove" title="Remove key" value={key} />
        {/each}
        {#each verifiedClaim.diff.changedServices as service}
          {#if service.changeType === 'added'}
            <DiffRow variant="restore" title="Add service {service.id}" value={service.newEndpoint ?? undefined} />
          {:else if service.changeType === 'removed'}
            <DiffRow variant="remove" title="Remove service {service.id}" value="was {service.oldEndpoint}" />
          {:else if service.changeType === 'modified'}
            <DiffRow variant="modify" title="Change service {service.id}" value="{service.oldEndpoint} → {service.newEndpoint}" />
          {/if}
        {/each}
      {/if}
    </div>

    {#if verifiedClaim.warnings.length > 0}
      <div class="warnings">
        <div class="warnings-head">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
          Warnings
        </div>
        {#each verifiedClaim.warnings as warning}
          <p class="warning-text">{warning}</p>
        {/each}
        <label class="ack">
          <input type="checkbox" bind:checked={warningsAcknowledged} disabled={submitting} />
          <span>I understand these warnings and want to proceed</span>
        </label>
      </div>
    {/if}

    {#if error}
      <div class="error-box" role="alert">
        <p class="error-text">{error}</p>
      </div>
    {/if}
  </div>

  <div class="actions">
    <Button
      disabled={submitting || (verifiedClaim.warnings.length > 0 && !warningsAcknowledged)}
      onclick={handleSubmit}
    >
      {submitting ? 'Submitting…' : 'Confirm & submit'}
    </Button>
    <Button variant="secondary" onclick={oncancel} disabled={submitting}>Cancel</Button>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-lg) var(--space-md) var(--space-md);
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

  .warnings {
    background: var(--color-warning-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .warnings-head {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-warning);
  }
  .warning-text {
    font-size: var(--text-label);
    color: var(--color-warning);
    margin: 0;
    line-height: 1.45;
  }
  .ack {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: var(--text-label);
    color: var(--color-ink);
    cursor: pointer;
  }
  .ack input {
    width: 18px;
    height: 18px;
    accent-color: var(--color-primary);
    flex-shrink: 0;
    cursor: pointer;
  }
  .ack span {
    user-select: none;
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
</style>
