<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import LoadingScreen from './LoadingScreen.svelte';
  import { registerHandle, checkHandleResolution, type RegisterHandleError } from '$lib/ipc';

  let {
    handleLabel,
    did,
    onsuccess,
    ontimeout,
  }: {
    /** The label portion of the handle (e.g. `"alice"`), collected earlier in onboarding. */
    handleLabel: string;
    /** The user's DID, used to verify HTTP resolution resolves to the correct identity. */
    did: string;
    /** Called when the handle registers and HTTP resolution confirms the DID. */
    onsuccess: (handle: string) => void;
    /**
     * Called when registration succeeded but HTTP resolution timed out after 2 minutes.
     * The handle is registered — DNS is just still propagating.
     * The caller should proceed and show a "still resolving" banner on the home screen.
     */
    ontimeout: (handle: string) => void;
  } = $props();

  type Phase =
    | { kind: 'registering' }
    | { kind: 'polling'; handle: string }
    | { kind: 'error'; error: RegisterHandleError };

  let phase = $state<Phase>({ kind: 'registering' });

  const POLL_INTERVAL_MS = 4_000;
  const POLL_TIMEOUT_MS = 120_000;

  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  // Guard against the rare race where a poll tick resolves after the timeout fires.
  let settled = false;

  function stopPolling() {
    if (pollTimer !== undefined) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
    if (timeoutTimer !== undefined) {
      clearTimeout(timeoutTimer);
      timeoutTimer = undefined;
    }
  }

  function startPolling(handle: string) {
    phase = { kind: 'polling', handle };
    settled = false;

    pollTimer = setInterval(() => {
      checkHandleResolution(handle, did)
        .then((resolved) => {
          if (resolved && !settled) {
            settled = true;
            stopPolling();
            onsuccess(handle);
          }
        })
        .catch((err) => {
          console.error('[HandleRegistrationScreen] poll tick failed:', err);
        });
    }, POLL_INTERVAL_MS);

    timeoutTimer = setTimeout(() => {
      if (!settled) {
        settled = true;
        stopPolling();
        ontimeout(handle);
      }
    }, POLL_TIMEOUT_MS);
  }

  async function run() {
    phase = { kind: 'registering' };
    stopPolling();

    try {
      const result = await registerHandle(handleLabel);
      startPolling(result.handle);
    } catch (raw: unknown) {
      console.error('[HandleRegistrationScreen] registerHandle failed:', raw);
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as RegisterHandleError).code === 'string'
      ) {
        phase = { kind: 'error', error: raw as RegisterHandleError };
      } else {
        phase = { kind: 'error', error: { code: 'UNKNOWN', message: 'An unexpected error occurred.' } };
      }
    }
  }

  function errorMessage(err: RegisterHandleError): string {
    switch (err.code) {
      case 'HANDLE_TAKEN':
        return 'That handle is already taken.';
      case 'INVALID_HANDLE':
        return 'The handle format is invalid. Please go back and choose another.';
      case 'DNS_ERROR':
        return 'Handle registered, but DNS setup failed. Please contact support.';
      case 'NO_DOMAINS':
        return 'The relay has no handle domains configured. Please contact support.';
      case 'SESSION_EXPIRED':
        return 'Your session has expired. Please sign in again to continue.';
      case 'KEYCHAIN_ERROR':
        return "Couldn't read your credentials. Please restart the app and try again.";
      case 'NETWORK_ERROR':
      default:
        return "Couldn't reach the server. Check your connection.";
    }
  }

  function canRetry(err: RegisterHandleError): boolean {
    return (
      err.code !== 'INVALID_HANDLE' &&
      err.code !== 'DNS_ERROR' &&
      err.code !== 'NO_DOMAINS' &&
      err.code !== 'SESSION_EXPIRED'
    );
  }

  onMount(() => run());
  onDestroy(() => stopPolling());
</script>

{#if phase.kind === 'registering'}
  <LoadingScreen statusText="Registering your handle…" />
{:else if phase.kind === 'polling'}
  <div class="screen">
    <div class="handle-badge">{phase.handle}</div>
    <h2 class="title">Almost there!</h2>
    <p class="subtitle">Waiting for your handle to become active…</p>
    <div class="spinner" aria-label="Loading"></div>
    <p class="hint">This usually takes a few seconds.</p>
  </div>
{:else if phase.kind === 'error'}
  <div class="screen">
    <p class="error-text">{errorMessage(phase.error)}</p>
    {#if canRetry(phase.error)}
      <button class="retry" onclick={() => run()}>Retry</button>
    {/if}
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
    gap: 1rem;
    text-align: center;
  }

  .handle-badge {
    font-size: 1.1rem;
    font-weight: 600;
    color: #007aff;
    background: #eff6ff;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    font-family: monospace;
  }

  .title {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
    color: #111827;
  }

  .subtitle {
    font-size: 0.95rem;
    color: #6b7280;
    margin: 0;
  }

  .hint {
    font-size: 0.8rem;
    color: #9ca3af;
    margin: 0;
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
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
