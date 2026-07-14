<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import { didWebFromDomain } from '$lib/did-web';
  let { value = $bindable(''), onnext, onback }: { value?: string; onnext: () => void; onback: () => void } = $props();
  let error = $state('');
  function next() {
    try { didWebFromDomain(value); error = ''; onnext(); }
    catch (e) { error = e instanceof Error ? e.message : 'Enter a valid domain.'; }
  }
</script>
<OnboardingShell title="Which domain is your identity?" subtitle="You must control this domain and be able to publish its did.json." {onback}>
  <TextField aria-label="Identity domain" placeholder="identity.example.com" bind:value {error} mono />
  <Button onclick={next}>Continue</Button>
</OnboardingShell>
