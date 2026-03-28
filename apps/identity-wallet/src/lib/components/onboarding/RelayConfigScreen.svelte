<script lang="ts">
  import { saveRelayUrl, type RelayConfigError } from '$lib/ipc';

  const DEFAULT_RELAY_URL = 'https://relay.ezpds.com';

  let { onnext }: { onnext: () => void } = $props();

  let url = $state(DEFAULT_RELAY_URL);
  let loading = $state(false);
  let error = $state<string | undefined>(undefined);

  let isValidFormat = $derived(
    url.trim().length > 0 &&
      (url.startsWith('http://') || url.startsWith('https://'))
  );

  async function handleConnect() {
    error = undefined;
    loading = true;
    try {
      await saveRelayUrl(url.trim());
      onnext();
    } catch (e) {
      const relayError = e as RelayConfigError;
      if (relayError.code === 'INVALID_URL') {
        error = 'Invalid URL — must start with http:// or https://';
      } else if (relayError.code === 'KEYCHAIN_ERROR') {
        error = 'Could not save the relay URL. Please try again.';
      } else {
        error = 'Could not reach the relay. Check the URL and try again.';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="screen">
  <div class="content">
    <h2>Connect to Relay</h2>
    <p class="hint">
      Your wallet connects to a relay to create your identity. Use the default
      or enter the address of your own relay.
    </p>

    <input
      type="url"
      class:error={!!error}
      disabled={loading}
      bind:value={url}
      placeholder="https://relay.ezpds.com"
      autocomplete="off"
      autocorrect="off"
      autocapitalize="off"
      spellcheck={false}
    />

    {#if error}
      <p class="error-text">{error}</p>
    {/if}
  </div>

  <div class="actions">
    {#if loading}
      <div class="spinner" role="status" aria-label="Connecting…"></div>
    {:else}
      <button disabled={!isValidFormat} onclick={handleConnect}>Connect</button>
    {/if}
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem;
    gap: 1.5rem;
  }

  .content {
    display: flex;
    flex-direction: column;
    align-items: center;
    flex: 1;
    justify-content: center;
    gap: 1rem;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
    text-align: center;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    max-width: 280px;
    line-height: 1.4;
    margin: 0;
  }

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
    outline: none;
    font-family: monospace;
    color: #111827;
  }

  input:focus {
    border-color: #007aff;
  }

  input.error {
    border-color: #ef4444;
  }

  input:disabled {
    opacity: 0.6;
  }

  .error-text {
    font-size: 0.875rem;
    color: #ef4444;
    margin: 0;
    text-align: center;
    max-width: 320px;
  }

  .actions {
    display: flex;
    justify-content: center;
    padding-bottom: env(safe-area-inset-bottom, 0);
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    font-weight: 600;
    background: #007aff;
    color: white;
    border: none;
    border-radius: 12px;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }

  .spinner {
    width: 48px;
    height: 48px;
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
</style>
