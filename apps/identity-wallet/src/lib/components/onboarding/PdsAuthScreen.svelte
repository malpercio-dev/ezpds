<script lang="ts">
  import { startPdsAuth, type ClaimError } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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
      console.error('PDS authentication failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'UNAUTHORIZED':
            error = 'Sign-in was cancelled or denied. Try again when ready.';
            break;
          case 'OAUTH_REJECTED':
            error = `The PDS's authorization server rejected the request: ${err.message}`;
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = `Authentication failed (${err.code}). Please try again.`;
        }
      } else {
        error = 'Authentication failed. Please try again.';
      }
    }
  }
</script>

{#if authenticating}
  <div class="centered">
    <Spinner size={44} label="Authenticating" />
    <p class="status">Opening secure sign-in to your PDS…</p>
  </div>
{:else}
  <OnboardingShell title="Connect to your PDS" subtitle="Authenticate with your PDS to verify you control this identity.">
    <span class="pds-chip">{pdsUrl}</span>
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button onclick={authenticate}>{error ? 'Try again' : 'Authenticate with PDS'}</Button>
    <Button variant="secondary" onclick={onback}>Back</Button>
  </OnboardingShell>
{/if}

<style>
  .centered {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: var(--space-lg);
    padding: var(--space-xl);
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }
  .pds-chip {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    word-break: break-all;
    max-width: 100%;
  }
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
</style>
