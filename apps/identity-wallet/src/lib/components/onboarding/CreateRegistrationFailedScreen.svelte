<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { registerCreatedIdentity } from '$lib/ipc';

  let {
    did,
    handle,
    onregistered,
    oncontinue,
  }: {
    /** The new identity's DID, already committed and persisted by the ceremony. */
    did: string;
    /** The full registered handle. */
    handle: string;
    /** Called once the identity is recorded in the wallet's list. */
    onregistered: () => void;
    /**
     * Leave without recording it now. The identity is intact either way, and the app
     * re-attempts this on every launch — trapping the user in onboarding over a device-side
     * bookkeeping step would be the worse failure.
     */
    oncontinue: () => void;
  } = $props();

  let retrying = $state(false);
  let retryFailed = $state(false);

  async function retry() {
    retrying = true;
    retryFailed = false;
    try {
      await registerCreatedIdentity(did, handle);
      onregistered();
    } catch (e) {
      console.error('Retry of register_created_identity failed:', e);
      retryFailed = true;
    } finally {
      retrying = false;
    }
  }
</script>

<OnboardingShell
  title="Identity created — not yet saved"
  subtitle="Your identity exists and is safe. This device couldn't add it to your wallet list."
>
  {#snippet icon()}
    <!-- An unfinished-step mark, deliberately not a warning triangle: nothing is at risk and
         no key or share was lost. One local bookkeeping write did not land. -->
    <svg
      width="32"
      height="32"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 7v5l3 2" />
    </svg>
  {/snippet}

  <p class="handle">{handle}</p>

  <p class="body">
    Your identity, its master key, and your recovery share are all stored. The only step that
    failed is the one that lists it on your home screen, so it may not appear yet.
  </p>
  <p class="body">
    Obsign retries this every time you open the app. Trying again now usually fixes it
    straight away.
  </p>

  <div class="actions">
    <Button onclick={retry} disabled={retrying}>
      {#if retrying}
        <Spinner size={18} label="Saving to your wallet" />
      {:else}
        Try again
      {/if}
    </Button>
    <Button variant="secondary" onclick={oncontinue} disabled={retrying}>Continue</Button>
  </div>

  <!-- Announced, and carried by text plus its position under the action — never by colour
       alone, and never as an alarm: the retry failing changes nothing about the identity. -->
  <p class="retry-status" role="status" aria-live="polite">
    {#if retryFailed}
      That didn't work either. Your identity is still safe — continue, and Obsign will try
      again next time you open it.
    {/if}
  </p>
</OnboardingShell>

<style>
  .handle {
    margin: 0;
    align-self: stretch;
    padding: var(--space-xs) var(--space-sm);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-ink);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    word-break: break-all;
    text-align: left;
  }
  .body {
    margin: 0;
    align-self: stretch;
    color: var(--color-ink);
    font-size: var(--text-body);
    line-height: var(--leading-body);
    text-align: left;
  }
  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    width: 100%;
    padding-top: var(--space-xs);
  }
  .retry-status {
    margin: 0;
    align-self: stretch;
    color: var(--color-ink);
    font-size: var(--text-label);
    line-height: var(--leading-body);
    text-align: left;
  }
  .retry-status:empty {
    display: none;
  }
</style>
