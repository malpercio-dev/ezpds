<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
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

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let isValid = $derived(emailRegex.test(value));
</script>

<OnboardingShell {onback} title="Enter your email" subtitle="We'll associate this email with your new account.">
  <TextField
    bind:value
    type="email"
    placeholder="you@example.com"
    autocomplete="email"
    inputmode="email"
    aria-label="Email"
    {error}
  />
  <Button disabled={!isValid} onclick={onnext}>Next</Button>
</OnboardingShell>
