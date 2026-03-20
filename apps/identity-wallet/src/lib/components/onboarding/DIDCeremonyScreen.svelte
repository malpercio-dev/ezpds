<script lang="ts">
  import { onMount } from 'svelte';
  import LoadingScreen from './LoadingScreen.svelte';
  import { performDIDCeremony, type DIDCeremonyError } from '$lib/ipc';

  let {
    handle,
    onsuccess,
  }: {
    handle: string;
    onsuccess: (did: string) => void;
  } = $props();

  let loading = $state(true);
  let error = $state<DIDCeremonyError | null>(null);

  async function runCeremony() {
    loading = true;
    error = null;
    try {
      const result = await performDIDCeremony(handle);
      loading = false;
      onsuccess(result.did);
    } catch (raw: unknown) {
      loading = false;
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as DIDCeremonyError).code === 'string'
      ) {
        error = raw as DIDCeremonyError;
      } else {
        error = { code: 'NETWORK_ERROR', message: 'An unexpected error occurred.' };
      }
    }
  }

  function errorMessage(err: DIDCeremonyError): string {
    switch (err.code) {
      case 'NO_RELAY_SIGNING_KEY':
        return "The relay hasn't been configured yet. Please try again later.";
      case 'RELAY_KEY_FETCH_FAILED':
      case 'NETWORK_ERROR':
        return "Couldn't reach the server. Check your connection.";
      case 'SIGNING_FAILED':
        return 'Device signing failed. Please try again.';
      case 'DID_CREATION_FAILED':
        return "Couldn't create your identity. Please try again.";
      case 'KEYCHAIN_ERROR':
        return "Couldn't save to your device. Please try again.";
      case 'KEY_NOT_FOUND':
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  onMount(() => runCeremony());
</script>

{#if loading}
  <LoadingScreen statusText="Setting up your identity…" />
{:else if error}
  <div class="screen">
    <p class="error-text">{errorMessage(error)}</p>
    <button class="retry" onclick={() => runCeremony()}>Retry</button>
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 1.5rem;
    text-align: center;
  }

  .error-text {
    font-size: 1rem;
    color: #ef4444;
    margin: 0;
  }

  .retry {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
