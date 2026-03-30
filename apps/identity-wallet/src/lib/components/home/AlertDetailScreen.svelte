<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getUrgency, getDeadline, formatCountdown } from '$lib/utils/deadline';
  import type { UnauthorizedChange } from '$lib/ipc';
  import { truncateDid } from '$lib/did-doc-utils';

  let {
    did,
    changes,
    onback,
  }: {
    did: string;
    changes: UnauthorizedChange[];
    onback: () => void;
  } = $props();

  let now = $state(Date.now());
  let timer: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    timer = setInterval(() => {
      now = Date.now();
    }, 60_000);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });
</script>

<div class="screen">
  <div class="header">
    <button class="back-btn" onclick={onback} aria-label="Back">‹ Back</button>
    <h2 class="title">Security Alerts</h2>
  </div>

  <!-- Identity section -->
  <div class="section">
    <p class="section-label">Identity</p>
    <p class="mono-value">{truncateDid(did)}</p>
  </div>

  <!-- Alert cards -->
  <div class="alerts-container">
    {#each changes as change (change.cid)}
      {@const deadline = getDeadline(change.createdAt)}
      {@const urgency = getUrgency(deadline, now)}

      <div class="alert-card">
        <div class="alert-header">
          <span class="alert-urgency alert-urgency--{urgency}">
            <span class="badge-dot"></span>
            {formatCountdown(deadline, now)}
          </span>
        </div>

        <div class="alert-field">
          <span class="alert-label">Signing Key</span>
          <span class="alert-value monospace">{change.signingKey ?? 'Unknown key'}</span>
        </div>

        <div class="alert-field">
          <span class="alert-label">Detected</span>
          <span class="alert-value">{new Date(change.createdAt).toLocaleString()}</span>
        </div>

        <div class="alert-field">
          <span class="alert-label">Recovery Deadline</span>
          <span class="alert-value">{deadline.toLocaleString()}</span>
        </div>

        <button class="action-button" disabled>
          Review & Override
        </button>
      </div>
    {/each}
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

  .title {
    font-size: 1.2rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .section {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .section-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #374151;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .mono-value {
    font-family: monospace;
    font-size: 0.8rem;
    color: #374151;
    margin: 0;
    word-break: break-all;
  }

  .alerts-container {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .alert-card {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .alert-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .alert-urgency {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .badge-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .alert-urgency--safe {
    background: #dcfce7;
    color: #166534;
  }

  .alert-urgency--safe .badge-dot {
    background: #16a34a;
  }

  .alert-urgency--warning {
    background: #fef3c7;
    color: #92400e;
  }

  .alert-urgency--warning .badge-dot {
    background: #f59e0b;
  }

  .alert-urgency--critical,
  .alert-urgency--expired {
    background: #fef2f2;
    color: #991b1b;
  }

  .alert-urgency--critical .badge-dot,
  .alert-urgency--expired .badge-dot {
    background: #ef4444;
  }

  .alert-field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .alert-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #374151;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .alert-value {
    font-size: 1rem;
    color: #374151;
    margin: 0;
    line-height: 1.4;
  }

  .monospace {
    font-family: monospace;
    font-size: 0.8rem;
    word-break: break-all;
  }

  .action-button {
    width: 100%;
    padding: 0.9rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: not-allowed;
    opacity: 0.5;
    margin-top: 0.5rem;
  }

  .action-button:active:not(:disabled) {
    background: #0051d5;
  }
</style>
