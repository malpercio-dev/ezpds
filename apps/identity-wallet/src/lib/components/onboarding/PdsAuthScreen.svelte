<script lang="ts">
  import { startPdsAuth, type ClaimError } from '$lib/ipc';

  let {
    pdsUrl,
    onnext,
    onback,
  }: {
    pdsUrl: string;
    onnext: () => void;
    onback: () => void;
  } = $props();

  let authenticating = $state(false);
  let error = $state<string | null>(null);

  async function authenticate() {
    authenticating = true;
    error = null;

    try {
      await startPdsAuth(pdsUrl);
      onnext();
    } catch (raw: unknown) {
      authenticating = false;

      // Guard against non-ClaimError shapes
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as ClaimError).code === 'string'
      ) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'UNAUTHORIZED':
            error = 'Authentication was denied. Please try again.';
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = 'Authentication failed. Please try again.';
        }
      } else {
        error = 'Authentication failed. Please try again.';
      }
    }
  }
</script>

<div class="screen">
  {#if authenticating}
    <div class="spinner" aria-label="Loading"></div>
    <p class="status">Opening browser for PDS authentication…</p>
  {:else if error}
    <div class="content">
      <h2>Connect to Your PDS</h2>
      <p class="hint">Connect to your PDS at <code>{pdsUrl}</code> to verify your identity.</p>
      <p class="error-text">{error}</p>
      <div class="button-group">
        <button class="primary" onclick={authenticate}>
          Try Again
        </button>
        <button class="secondary" onclick={onback}>
          Back
        </button>
      </div>
    </div>
  {:else}
    <div class="content">
      <h2>Connect to Your PDS</h2>
      <p class="hint">Connect to your PDS at <code>{pdsUrl}</code> to verify your identity.</p>
      <div class="button-group">
        <button class="primary" onclick={authenticate}>
          Authenticate with PDS
        </button>
        <button class="secondary" onclick={onback}>
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

  code {
    background: #f3f4f6;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.85rem;
    word-break: break-all;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
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
    transition: background-color 0.2s;
  }

  .primary {
    background: #007aff;
    color: #fff;
  }

  .primary:active {
    background: #0051d5;
  }

  .secondary {
    background: #f3f4f6;
    color: #374151;
  }

  .secondary:active {
    background: #e5e7eb;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
    color: #fff;
  }
</style>
