<script lang="ts">
  import {
    verifyRecoveryShares,
    recoverIdentity,
    isCodedError,
    type RecoveredIdentity,
    type RecoveryAnchor,
    type ShareRecoveryError,
  } from '$lib/ipc';
  import { truncateDid } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    onanchored,
    onback,
  }: {
    onanchored: (anchor: RecoveryAnchor) => void;
    onback: () => void;
  } = $props();

  let verifying = $state(true);
  let verified = $state<RecoveredIdentity | null>(null);
  let anchoring = $state(false);
  let error = $state<string | null>(null);

  function describeError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch ((raw as ShareRecoveryError).code) {
        case 'SHARES_DO_NOT_MATCH_IDENTITY':
          return "These shares don't match this identity. They may belong to a different account, or to a backup that was replaced by a newer one.";
        case 'SHARES_INCOMPLETE':
          return 'Two shares are needed before verification. Go back and collect another.';
        case 'PLC_DIRECTORY_ERROR':
          return 'The PLC directory rejected the operation. Try again in a moment.';
        case 'SIGNING_FAILED':
          return 'Signing failed on this device. Try again.';
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        default:
          return `An unexpected error occurred (${(raw as ShareRecoveryError).code}). Please try again.`;
      }
    }
    return 'An unexpected error occurred. Please try again.';
  }

  async function verify() {
    verifying = true;
    error = null;
    verified = null;
    try {
      verified = await verifyRecoveryShares();
    } catch (raw: unknown) {
      console.error('Share verification failed:', raw);
      error = describeError(raw);
    } finally {
      verifying = false;
    }
  }

  async function anchor() {
    anchoring = true;
    error = null;
    try {
      const result = await recoverIdentity();
      onanchored(result);
    } catch (raw: unknown) {
      console.error('Recovery anchor failed:', raw);
      error = describeError(raw);
      anchoring = false;
    }
  }

  verify();

  let displayDid = $derived(truncateDid(verified?.did ?? ''));
</script>

{#if verifying}
  <OnboardingShell
    title="Checking your shares"
    subtitle="Reconstructing the recovery key and comparing it against the public record of your identity."
  >
    <Spinner label="Verifying shares" />
  </OnboardingShell>
{:else if verified}
  <OnboardingShell
    tone="signet"
    title="Shares verified"
    subtitle="These shares reconstruct a key this identity recognizes. Recovering will make this device its new home."
  >
    {#snippet icon()}
      <SealEmblem>
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="m9 11.5 2 2 4-4" />
        </svg>
      </SealEmblem>
    {/snippet}
    <div class="preview">
      {#if verified.handle}
        <div class="row"><span class="k">Handle</span><span class="v">@{verified.handle}</span></div>
      {/if}
      <div class="row"><span class="k">DID</span><span class="v mono">{displayDid}</span></div>
      <div class="row">
        <span class="k">What happens next</span>
        <span class="v small">
          A new device key is created here and signed into your identity, replacing the lost
          device's key. Your old backup shares are then retired and replaced with a fresh set.
        </span>
      </div>
    </div>
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button disabled={anchoring} onclick={anchor}>
      {anchoring ? 'Recovering…' : 'Recover this identity'}
    </Button>
    <Button variant="secondary" onclick={onback}>Back</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell title="Verification failed" subtitle="Nothing was signed or changed.">
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button onclick={verify}>Try again</Button>
    <Button variant="secondary" onclick={onback}>Back to shares</Button>
  </OnboardingShell>
{/if}

<style>
  .preview {
    width: 100%;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    text-align: left;
  }
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
  }
  .k {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .v {
    font-size: var(--text-body);
    color: var(--color-ink);
    word-break: break-word;
  }
  .v.mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
  }
  .v.small {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
  }
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }
</style>
