<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import LoadingScreen from './LoadingScreen.svelte';
  import { registerHandle, checkHandleResolution, isCodedError, type RegisterHandleError } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    handle,
    did,
    onsuccess,
    ontimeout,
  }: {
    /** The full handle (e.g. `"alice.ezpds.com"`), assembled earlier in onboarding. */
    handle: string;
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
      const result = await registerHandle(handle);
      startPolling(result.handle);
    } catch (raw: unknown) {
      console.error('[HandleRegistrationScreen] registerHandle failed:', raw);
      if (isCodedError(raw)) {
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
        return 'Custos has no handle domains configured. Please contact support.';
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
  {@const activeHandle = phase.handle}
  <OnboardingShell title="Almost there" subtitle="Waiting for your handle to become active…">
    {#snippet icon()}
      <span class="handle-chip">{activeHandle}</span>
    {/snippet}
    <Spinner size={32} label="Waiting for the handle to resolve" />
    <p class="hint">This usually takes a few seconds.</p>
  </OnboardingShell>
{:else if phase.kind === 'error'}
  <OnboardingShell title="Handle registration failed" subtitle={errorMessage(phase.error)}>
    {#if canRetry(phase.error)}
      <Button onclick={run}>Try again</Button>
    {/if}
  </OnboardingShell>
{/if}

<style>
  .handle-chip {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-full);
    padding: var(--space-sm) var(--space-md);
  }
  .hint {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
</style>
