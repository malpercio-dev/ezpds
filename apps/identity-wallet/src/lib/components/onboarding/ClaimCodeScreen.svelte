<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    value = $bindable(''),
    onnext,
    onback = undefined,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    onback?: () => void;
    error?: string;
  } = $props();

  let isValid = $derived(value.length === 6);

  function handleInput(e: Event) {
    const raw = (e.currentTarget as HTMLInputElement).value;
    value = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6);
  }
</script>

<OnboardingShell {onback} title="Enter your claim code" subtitle="You'll receive a 6-character code from your administrator.">
  <input
    class="code-input"
    class:error={!!error}
    maxlength="6"
    placeholder="ABC123"
    autocomplete="off"
    autocorrect="off"
    autocapitalize="characters"
    spellcheck={false}
    aria-label="Claim code"
    aria-invalid={!!error}
    {value}
    oninput={handleInput}
  />
  {#if error}
    <p class="code-error" role="alert">{error}</p>
  {/if}
  <Button disabled={!isValid} onclick={onnext}>Next</Button>
</OnboardingShell>

<style>
  .code-input {
    width: 100%;
    padding: var(--space-md);
    font-family: var(--font-mono);
    font-size: 1.5rem;
    letter-spacing: 0.5rem;
    text-align: center;
    text-transform: uppercase;
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    transition: border-color var(--duration-base) var(--ease-standard);
  }
  .code-input::placeholder {
    color: var(--color-muted);
  }
  .code-input:focus-visible {
    border-color: var(--color-accent);
  }
  .code-input.error {
    border-color: var(--color-critical);
  }
  .code-error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    text-align: center;
  }
</style>
