<script lang="ts">
  import { submitClaim, type VerifiedClaimOp, type ClaimResult, type ClaimError } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';

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
  <div class="header">
    <h2 class="title">Review Operation</h2>
  </div>

  <!-- Keys section -->
  <div class="section">
    <p class="section-label">Keys</p>
    {#if verifiedClaim.diff.addedKeys.length > 0 || verifiedClaim.diff.removedKeys.length > 0}
      {#if verifiedClaim.diff.addedKeys.length > 0}
        <div class="subsection-label">Keys being added</div>
        {#each verifiedClaim.diff.addedKeys as key}
          <div class="diff-entry added">
            <span class="diff-prefix">+</span>
            <code class="diff-value">{key.slice(0, 20)}…</code>
          </div>
        {/each}
      {/if}

      {#if verifiedClaim.diff.removedKeys.length > 0}
        <div class="subsection-label">Keys being removed</div>
        {#each verifiedClaim.diff.removedKeys as key}
          <div class="diff-entry removed">
            <span class="diff-prefix">−</span>
            <code class="diff-value">{key.slice(0, 20)}…</code>
          </div>
        {/each}
      {/if}
    {:else}
      <p class="no-changes">No key changes</p>
    {/if}
  </div>

  <!-- Services section -->
  <div class="section">
    <p class="section-label">Services</p>
    {#if verifiedClaim.diff.changedServices.length > 0}
      {#each verifiedClaim.diff.changedServices as service}
        {#if service.changeType === 'added'}
          <div class="diff-entry added">
            <span class="diff-prefix">+</span>
            <span class="service-text">Adding service: {service.id} → {service.newEndpoint}</span>
          </div>
        {:else if service.changeType === 'removed'}
          <div class="diff-entry removed">
            <span class="diff-prefix">−</span>
            <span class="service-text">Removing service: {service.id} (was: {service.oldEndpoint})</span>
          </div>
        {:else if service.changeType === 'modified'}
          <div class="diff-entry modified">
            <span class="diff-prefix">~</span>
            <span class="service-text">Modifying service: {service.id}: {service.oldEndpoint} → {service.newEndpoint}</span>
          </div>
        {/if}
      {/each}
    {:else}
      <p class="no-changes">No service changes</p>
    {/if}
  </div>

  <!-- Warnings section -->
  {#if verifiedClaim.warnings.length > 0}
    <div class="warnings-section">
      <p class="section-label">Warnings</p>
      {#each verifiedClaim.warnings as warning}
        <div class="warning-box">
          <p class="warning-text">{warning}</p>
        </div>
      {/each}
      <label class="checkbox-label">
        <input
          type="checkbox"
          bind:checked={warningsAcknowledged}
          disabled={submitting}
        />
        <span>I understand these warnings and want to proceed</span>
      </label>
    </div>
  {/if}

  <!-- Error display -->
  {#if error}
    <div class="error-box">
      <p class="error-text">{error}</p>
    </div>
  {/if}

  <!-- Action buttons -->
  <div class="button-group">
    <button
      class="cta cta--primary"
      onclick={handleSubmit}
      disabled={submitting || (verifiedClaim.warnings.length > 0 && !warningsAcknowledged)}
    >
      {submitting ? 'Submitting…' : 'Confirm & Submit'}
    </button>
    <button
      class="cta cta--secondary"
      onclick={oncancel}
      disabled={submitting}
    >
      Cancel
    </button>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 1.5rem;
    gap: 1.25rem;
    overflow-y: auto;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .title {
    font-size: 1.2rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .section {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .section-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .subsection-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0.5rem 0 0.25rem 0;
  }

  .no-changes {
    font-size: 0.85rem;
    color: #6b7280;
    margin: 0.5rem 0 0;
    font-style: italic;
  }

  .diff-entry {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.5rem;
    border-radius: 8px;
    margin: 0.25rem 0;
    font-size: 0.85rem;
  }

  .diff-entry.added {
    background: rgba(34, 197, 94, 0.1);
    border-left: 3px solid #22c55e;
    color: #166534;
  }

  .diff-entry.removed {
    background: rgba(239, 68, 68, 0.1);
    border-left: 3px solid #ef4444;
    color: #7f1d1d;
  }

  .diff-entry.modified {
    background: rgba(245, 158, 11, 0.1);
    border-left: 3px solid #f59e0b;
    color: #92400e;
  }

  .diff-prefix {
    font-weight: 600;
    flex-shrink: 0;
    width: 1rem;
  }

  .diff-value {
    font-family: monospace;
    font-size: 0.75rem;
    word-break: break-all;
    margin: 0;
  }

  .service-text {
    word-break: break-word;
  }

  .warnings-section {
    background: #fffbeb;
    border: 1px solid #f59e0b;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .warning-box {
    background: #fff;
    border-left: 3px solid #f59e0b;
    border-radius: 4px;
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .warning-text {
    font-size: 0.85rem;
    color: #92400e;
    margin: 0;
    line-height: 1.4;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    color: #374151;
    cursor: pointer;
    margin-top: 0.5rem;
  }

  .checkbox-label input {
    cursor: pointer;
    accent-color: #f59e0b;
  }

  .checkbox-label span {
    user-select: none;
  }

  .error-box {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }

  .error-text {
    font-size: 0.85rem;
    color: #7f1d1d;
    margin: 0;
    line-height: 1.4;
  }

  .button-group {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-top: auto;
  }

  .cta {
    padding: 1rem;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
    width: 100%;
  }

  .cta--primary {
    background: #007aff;
    color: #fff;
  }

  .cta--primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .cta--secondary {
    background: #e5e7eb;
    color: #374151;
  }

  .cta--secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
