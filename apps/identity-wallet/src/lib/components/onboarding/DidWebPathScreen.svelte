<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import type { DidWebOrigin } from '$lib/did-web';
  let { onselect, onback }: { onselect: (origin: DidWebOrigin) => void; onback: () => void } = $props();
</script>

<OnboardingShell title="Set up your domain identity" subtitle="Choose what exists today. You will serve the DID document from your own domain." {onback}>
  <div class="grid">
    <button onclick={() => onselect('new')}><strong>New identity</strong><span>Compose a new did.json, then export and publish it on your own web host.</span></button>
    <button onclick={() => onselect('existing')}><strong>Existing identity</strong><span>Review, export, and publish the key and service changes.</span></button>
  </div>
  <p class="truth"><strong>Key protection:</strong> your device key signs every change and detects unapproved ones, but it cannot prevent your web host from serving them. Your domain remains the root of trust — and your exit.</p>
  <p class="truth"><strong>Custos-hosted domains are unavailable for now.</strong> If Custos served your did.json, anyone holding a stolen session could rewrite the very key that authorises passwordless sign-in. We would rather offer nothing than offer that.</p>
</OnboardingShell>

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-sm); width: 100%; text-align: left; }
  button { display: grid; align-content: start; gap: var(--space-xs); min-height: 9rem; padding: var(--space-md); border: 1px solid var(--color-line); border-radius: var(--radius-lg); background: var(--color-surface); color: var(--color-ink); font: inherit; cursor: pointer; }
  button:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
  button span, .truth { font-size: var(--text-label); line-height: var(--leading-body); }
  .truth { margin: 0; padding: var(--space-sm); border-radius: var(--radius-md); background: var(--color-info-surface); color: var(--color-ink); text-align: left; }
</style>
