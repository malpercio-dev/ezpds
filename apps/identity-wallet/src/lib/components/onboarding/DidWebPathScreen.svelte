<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import type { DidWebHosting, DidWebOrigin } from '$lib/did-web';
  let { onselect, onback }: { onselect: (origin: DidWebOrigin, hosting: DidWebHosting) => void; onback: () => void } = $props();
</script>

<OnboardingShell title="Set up your domain identity" subtitle="Choose what exists today and who will serve the DID document." {onback}>
  <div class="grid">
    <button onclick={() => onselect('new', 'custos')}><strong>New · Custos-hosted</strong><span>Compose a new document, then point your domain to Custos.</span></button>
    <button onclick={() => onselect('new', 'self')}><strong>New · Self-hosted</strong><span>Export did.json and publish it on your own web host.</span></button>
    <button onclick={() => onselect('existing', 'custos')}><strong>Existing · Custos-hosted</strong><span>Migrate the account, then transfer document hosting.</span></button>
    <button onclick={() => onselect('existing', 'self')}><strong>Existing · Self-hosted</strong><span>Review, export, and publish the key and service changes.</span></button>
  </div>
  <p class="truth"><strong>Key protection:</strong> Custos-hosted changes require your device key. With self-hosting, the key detects unapproved changes but cannot prevent your web host from serving them.</p>
</OnboardingShell>

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-sm); width: 100%; text-align: left; }
  button { display: grid; align-content: start; gap: var(--space-xs); min-height: 9rem; padding: var(--space-md); border: 1px solid var(--color-line); border-radius: var(--radius-lg); background: var(--color-surface); color: var(--color-ink); font: inherit; cursor: pointer; }
  button:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
  button span, .truth { font-size: var(--text-label); line-height: var(--leading-body); }
  .truth { margin: 0; padding: var(--space-sm); border-radius: var(--radius-md); background: var(--color-info-surface); color: var(--color-ink); text-align: left; }
</style>
