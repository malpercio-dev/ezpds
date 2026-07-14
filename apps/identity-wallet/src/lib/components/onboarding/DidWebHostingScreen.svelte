<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import type { DidWebHosting } from '$lib/did-web';
  let { onselect, onback }: { onselect: (hosting: DidWebHosting) => void; onback: () => void } = $props();
</script>

<OnboardingShell title="Who will serve did.json?" subtitle="Choose hosting for this domain migration." {onback}>
  <div class="options">
    <button onclick={() => onselect('custos')}><strong>Custos-hosted</strong><span>Custos serves updates with device-key approval and monitoring.</span></button>
    <button onclick={() => onselect('self')}><strong>Self-hosted</strong><span>You publish the file; Custos monitors for changes it did not approve.</span></button>
  </div>
</OnboardingShell>

<style>
  .options { display: grid; gap: var(--space-sm); width: 100%; text-align: left; }
  button { display: grid; gap: var(--space-xs); padding: var(--space-md); border: 1px solid var(--color-line); border-radius: var(--radius-lg); background: var(--color-surface); color: var(--color-ink); font: inherit; cursor: pointer; }
  span { font-size: var(--text-label); line-height: var(--leading-body); }
</style>
