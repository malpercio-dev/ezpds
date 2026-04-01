<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import {
    buildRecoveryOverride,
    submitRecoveryOverride,
    type SignedRecoveryOp,
    type RecoveryError,
  } from '$lib/ipc';
  import { getDeadline, formatCountdown, getUrgency } from '$lib/utils/deadline';
  import { isCodedError, truncateDid } from '$lib/did-doc-utils';

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
  let now = $state(Date.now());
  let timer: ReturnType<typeof setInterval> | null = null;

  const deadline = getDeadline(createdAt);

  onMount(async () => {
    // Start the countdown timer
    timer = setInterval(() => {
      now = Date.now();
    }, 60_000);

    // Build the recovery operation
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
        }
      } else {
        error = 'Failed to build recovery operation. Please try again.';
      }
    } finally {
      loading = false;
    }
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  async function handleSubmit() {
    submitting = true;
    error = null;

    try {
      await submitRecoveryOverride(did);
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
    <button class="back-btn" onclick={onback} aria-label="Back" disabled={loading || submitting}
      >‹ Back</button
    >
    <h2 class="title">Recovery Override</h2>
  </div>

  <!-- Identity section -->
  <div class="section">
    <p class="section-label">Identity</p>
    <p class="mono-value">{truncateDid(did)}</p>
  </div>

  <!-- Deadline section -->
  <div class="section">
    <p class="section-label">Recovery Deadline</p>
    <span class="deadline-status deadline-status--{getUrgency(deadline, now)}">
      <span class="badge-dot"></span>
      {formatCountdown(deadline, now)}
    </span>
    <p class="deadline-text">{deadline.toLocaleString()}</p>
  </div>

  {#if loading}
    <div class="loading-section">
      <p>Building recovery operation...</p>
    </div>
  {:else if signedOp}
    <!-- Keys section -->
    <div class="section">
      <p class="section-label">Keys</p>
      {#if signedOp.diff.addedKeys.length > 0 || signedOp.diff.removedKeys.length > 0}
        {#if signedOp.diff.addedKeys.length > 0}
          <div class="subsection-label">Keys being restored</div>
          {#each signedOp.diff.addedKeys as key}
            <div class="diff-entry added">
              <span class="diff-prefix">+</span>
              <code class="diff-value">{key.slice(0, 20)}…</code>
            </div>
          {/each}
        {/if}

        {#if signedOp.diff.removedKeys.length > 0}
          <div class="subsection-label">Keys being removed</div>
          {#each signedOp.diff.removedKeys as key}
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
      {#if signedOp.diff.changedServices.length > 0}
        {#each signedOp.diff.changedServices as service}
          {#if service.changeType === 'added'}
            <div class="diff-entry added">
              <span class="diff-prefix">+</span>
              <span class="service-text">Restoring service: {service.id} → {service.newEndpoint}</span>
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
  {/if}

  <!-- Error display -->
  {#if error}
    <div class="error-box">
      <p class="error-text">{error}</p>
    </div>
  {/if}

  <!-- Action buttons -->
  <div class="button-group">
    {#if !loading && signedOp}
      <button
        class="cta cta--primary"
        onclick={handleSubmit}
        disabled={submitting || getUrgency(deadline, now) === 'expired'}
      >
        {submitting ? 'Submitting…' : 'Confirm & Submit'}
      </button>
    {/if}
    <button class="cta cta--secondary" onclick={onback} disabled={loading || submitting}>
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

  .back-btn {
    background: none;
    border: none;
    font-size: 1rem;
    color: #007aff;
    cursor: pointer;
    padding: 0;
    font-weight: 500;
    white-space: nowrap;
  }

  .back-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
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

  .mono-value {
    font-family: monospace;
    font-size: 0.8rem;
    color: #374151;
    margin: 0;
    word-break: break-all;
  }

  .deadline-status {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
    width: fit-content;
  }

  .badge-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .deadline-status--safe {
    background: #dcfce7;
    color: #166534;
  }

  .deadline-status--safe .badge-dot {
    background: #16a34a;
  }

  .deadline-status--warning {
    background: #fef3c7;
    color: #92400e;
  }

  .deadline-status--warning .badge-dot {
    background: #f59e0b;
  }

  .deadline-status--critical,
  .deadline-status--expired {
    background: #fef2f2;
    color: #991b1b;
  }

  .deadline-status--critical .badge-dot,
  .deadline-status--expired .badge-dot {
    background: #ef4444;
  }

  .deadline-text {
    font-size: 0.85rem;
    color: #6b7280;
    margin: 0.5rem 0 0 0;
  }

  .loading-section {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1.5rem;
    color: #6b7280;
    font-size: 0.9rem;
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
