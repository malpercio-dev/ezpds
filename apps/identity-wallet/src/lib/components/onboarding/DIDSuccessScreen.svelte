<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    did,
    oncontinue,
  }: {
    did: string;
    oncontinue: () => void;
  } = $props();

  // Truncate the DID suffix for display on a narrow mobile screen.
  // "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcde…uvwx"
  let displayDid = $derived(
    did.startsWith('did:plc:') && did.length > 20
      ? `did:plc:${did.slice(8, 13)}…${did.slice(-4)}`
      : did
  );

  let copied = $state(false);

  async function copyDid() {
    try {
      await navigator.clipboard.writeText(did);
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch (e) {
      console.error('clipboard write failed:', e);
    }
  }
</script>

<OnboardingShell tone="signet" title="Identity created" subtitle="Your decentralized identifier — yours alone.">
  {#snippet icon()}
    <SealEmblem size={80}>
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 11.5 2 2 4-4" />
      </svg>
    </SealEmblem>
  {/snippet}

  <button class="did" onclick={copyDid} title="Tap to copy full DID">
    <span class="did-value">{displayDid}</span>
    <span class="copy-hint">{copied ? 'Copied!' : 'Tap to copy'}</span>
  </button>

  <Button onclick={oncontinue}>Continue</Button>
</OnboardingShell>

<style>
  .did {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-xs);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard);
  }
  .did:active {
    background: var(--color-surface-sunk);
  }
  .did-value {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    word-break: break-all;
  }
  .copy-hint {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
</style>
