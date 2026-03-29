<script lang="ts">
  import { onMount } from 'svelte';
  import {
    requestClaimVerification,
    signAndVerifyClaim,
    type VerifiedClaimOp,
    type ClaimError,
  } from '$lib/ipc';

  let {
    did,
    onnext,
    onback,
  }: {
    did: string;
    onnext: (result: VerifiedClaimOp) => void;
    onback: () => void;
  } = $props();

  let token = $state('');
  let sending = $state(true); // true while sending verification email
  let sendError = $state<string | null>(null);
  let verifying = $state(false); // true while verifying token
  let verifyError = $state<string | null>(null);

  // ── Send verification email on mount ─────────────────────────────────────
  async function sendVerificationEmail() {
    sending = true;
    sendError = null;

    try {
      await requestClaimVerification(did);
      sending = false;
    } catch {
      sending = false;
      sendError = 'Failed to send verification email. Please try again.';
    }
  }

  // ── Verify token and sign claim ──────────────────────────────────────────
  async function verifyToken() {
    verifying = true;
    verifyError = null;

    try {
      const result = await signAndVerifyClaim(did, token.trim());
      onnext(result);
    } catch (raw: unknown) {
      verifying = false;

      // Guard against non-ClaimError shapes
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as ClaimError).code === 'string'
      ) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'INVALID_TOKEN':
            verifyError = 'Invalid or expired verification code. Check your email and try again.';
            break;
          case 'VERIFICATION_FAILED':
            verifyError = `Verification failed: ${err.message ?? 'Please try again.'}`;
            break;
          case 'NETWORK_ERROR':
            verifyError = 'Network error. Check your connection and try again.';
            break;
          default:
            verifyError = 'An error occurred. Please try again.';
        }
      } else {
        verifyError = 'An error occurred. Please try again.';
      }
    }
  }

  // ── Initialization ───────────────────────────────────────────────────────
  // Send verification email on component mount
  onMount(() => {
    sendVerificationEmail();
  });
</script>

<div class="screen">
  {#if sending}
    <div class="spinner" aria-label="Loading"></div>
    <p class="status">Sending verification email…</p>
  {:else if sendError}
    <div class="content">
      <h2>Email Verification</h2>
      <p class="hint">We couldn't send the verification email.</p>
      <p class="error-text">{sendError}</p>
      <div class="button-group">
        <button class="primary" onclick={sendVerificationEmail}>
          Retry
        </button>
        <button class="secondary" onclick={onback}>
          Back
        </button>
      </div>
    </div>
  {:else}
    <div class="content">
      <h2>Email Verification</h2>
      <p class="hint">A verification code has been sent to your email. Enter the code below.</p>

      <input
        type="text"
        class:error={!!verifyError}
        placeholder="Enter verification code"
        autocomplete="off"
        bind:value={token}
        disabled={verifying}
      />

      {#if verifyError}
        <p class="error-text">{verifyError}</p>
      {/if}

      <div class="button-group">
        <button
          class="primary"
          disabled={!token.trim() || verifying}
          onclick={verifyToken}
        >
          {verifying ? 'Verifying…' : 'Verify'}
        </button>
        <button class="secondary" onclick={onback} disabled={verifying}>
          Back
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 24px;
    padding: 32px;
  }

  .content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1.5rem;
    max-width: 320px;
    width: 100%;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
    text-align: center;
  }

  .hint {
    font-size: 0.95rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
    line-height: 1.5;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
  }

  input {
    width: 100%;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
  }

  input.error {
    border-color: #ef4444;
  }

  input:disabled {
    background: #f3f4f6;
    color: #9ca3af;
  }

  .button-group {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    width: 100%;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .status {
    text-align: center;
    color: #6b7280;
    font-size: 1rem;
    margin: 0;
  }

  button {
    width: 100%;
    padding: 1rem;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .primary {
    background: #007aff;
    color: #fff;
  }

  .primary:active:not(:disabled) {
    background: #0051d5;
  }

  .secondary {
    background: #f3f4f6;
    color: #374151;
  }

  .secondary:active:not(:disabled) {
    background: #e5e7eb;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
    color: #fff;
  }
</style>
