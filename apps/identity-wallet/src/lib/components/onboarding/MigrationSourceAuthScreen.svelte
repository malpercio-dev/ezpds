<script lang="ts">
  import { startSourceAuth, type MigrationError } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    did,
    onnext,
    onback,
  }: {
    did: string;
    onnext: () => void;
    onback: () => void;
  } = $props();

  let authenticating = $state(false);
  let error = $state<string | null>(null);

  async function authenticate() {
    authenticating = true;
    error = null;

    try {
      await startSourceAuth(did);
      onnext();
    } catch (raw: unknown) {
      authenticating = false;
      console.error('Migration source authentication failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as MigrationError;
        switch (err.code) {
          case 'SOURCE_AUTH_FAILED':
            error = 'Sign-in was cancelled. Try again when ready.';
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          case 'MIGRATION_NOT_READY':
            error = 'Migration is not ready yet. Please restart the migration flow.';
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
    <p class="status">Opening browser for your current PDS…</p>
  </div>
{:else}
  <OnboardingShell title="Sign in to your current PDS" subtitle="Authenticate with your current PDS to authorize the migration.">
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button onclick={authenticate}>{error ? 'Try again' : 'Sign in'}</Button>
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
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
</style>
