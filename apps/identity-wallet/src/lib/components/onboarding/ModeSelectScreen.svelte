<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    oncreate,
    onimport,
    onrecover,
    onback = undefined,
  }: {
    oncreate: () => void;
    onimport: () => void;
    onrecover: () => void;
    onback?: () => void;
  } = $props();
</script>

<OnboardingShell tone="signet" title="Obsign" subtitle="Your self-sovereign identity, sealed in your pocket." {onback}>
  {#snippet icon()}
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 11.5 2 2 4-4" />
      </svg>
    </SealEmblem>
  {/snippet}
  <div class="actions">
    <!--
      "Import" is a correction, not a rewording: this button starts the claim flow, which
      takes custody of an identity that stays on its current server. Moving an identity to
      another PDS is a different feature entirely, and it lives on the identity detail
      screen. The old label sent people looking for import somewhere it was never offered.
    -->
    <Button onclick={oncreate}>Create an identity</Button>
    <Button variant="secondary" onclick={onimport}>Import an identity</Button>
    <Button variant="secondary" onclick={onrecover}>Recover from backup shares</Button>
  </div>
</OnboardingShell>

<style>
  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    width: 100%;
  }
</style>
