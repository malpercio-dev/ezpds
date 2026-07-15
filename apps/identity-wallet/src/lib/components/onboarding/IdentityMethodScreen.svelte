<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  let { onplc, onweb, onback }: { onplc: () => void; onweb: () => void; onback: () => void } = $props();
</script>

<OnboardingShell
  title="Create your identity"
  subtitle="Custos anchors your identity with a key held on this device. If anyone else tries to change it, you get a 72-hour window to reverse it."
  {onback}
>
  <Button onclick={onplc}>Create identity</Button>

  <div class="advanced">
    <button type="button" class="advanced-link" onclick={onweb}>
      Advanced: anchor to a domain you control (did:web)
    </button>
    <p class="advanced-note">
      For people who already run a domain and want it to be their identity. Recovery
      then depends on controlling that domain as well as your device key.
    </p>
  </div>
</OnboardingShell>

<style>
  /* The default path is did:plc on Custos — the single primary (sealing-wax gold)
     action. did:web is deliberately demoted to a quiet aubergine "reveal the
     machinery" link below a hairline, one tap away for advanced users only. */
  .advanced {
    width: 100%;
    padding-top: var(--space-md);
    border-top: 1px solid var(--color-line);
    text-align: left;
  }
  .advanced-link {
    display: inline-block;
    min-height: 44px;
    padding: var(--space-xs) 0;
    background: none;
    border: none;
    color: var(--color-accent);
    font: inherit;
    font-weight: var(--weight-medium);
    text-decoration: underline;
    text-underline-offset: 2px;
    cursor: pointer;
  }
  .advanced-link:focus-visible {
    outline: 2px solid var(--color-accent);
    outline-offset: 2px;
    border-radius: var(--radius-sm);
  }
  .advanced-note {
    margin: var(--space-xs) 0 0;
    color: var(--color-muted);
    font-size: var(--text-label);
    line-height: var(--leading-body);
  }
</style>
