<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  let { onplc, onweb, onback }: { onplc: () => void; onweb: () => void; onback: () => void } = $props();
</script>

<OnboardingShell title="Choose how your identity is anchored" subtitle="This determines who can recover it and how changes are verified." {onback}>
  <div class="choices">
    <button class="choice" onclick={onplc}>
      <strong>Cryptographic identity</strong>
      <span>did:plc · Escrowed-key recovery with a 72-hour override window.</span>
    </button>
    <button class="choice" onclick={onweb}>
      <strong>Your domain</strong>
      <span>did:web · Your domain is your identity; recovery is domain control plus escrowed keys.</span>
    </button>
  </div>
  <Button variant="secondary" onclick={onback}>Cancel</Button>
</OnboardingShell>

<style>
  .choices { display: grid; gap: var(--space-sm); width: 100%; text-align: left; }
  .choice { display: grid; gap: var(--space-xs); width: 100%; padding: var(--space-md); border: 1px solid var(--color-line); border-radius: var(--radius-lg); background: var(--color-surface); color: var(--color-ink); font: inherit; cursor: pointer; }
  .choice:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
  .choice strong { font-size: var(--text-title); }
  .choice span { line-height: var(--leading-body); }
</style>
