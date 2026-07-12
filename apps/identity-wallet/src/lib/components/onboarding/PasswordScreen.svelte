<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    value = $bindable(''),
    error,
    onnext,
    onback = undefined,
  }: {
    value: string;
    error?: string;
    onnext: () => void;
    onback?: () => void;
  } = $props();

  let confirm = $state('');

  let mismatchError = $derived(
    confirm.length > 0 && value !== confirm ? "Passwords don't match." : undefined
  );

  let isValid = $derived(value.length >= 8 && value === confirm);
</script>

<OnboardingShell {onback} title="Create a password" subtitle="You'll use this to sign in to your account.">
  <TextField
    bind:value
    type="password"
    placeholder="Password"
    autocomplete="new-password"
    aria-label="Password"
  />
  <TextField
    bind:value={confirm}
    type="password"
    placeholder="Confirm password"
    autocomplete="new-password"
    aria-label="Confirm password"
    error={mismatchError ?? error}
  />
  <Button disabled={!isValid} onclick={onnext}>Continue</Button>
</OnboardingShell>
