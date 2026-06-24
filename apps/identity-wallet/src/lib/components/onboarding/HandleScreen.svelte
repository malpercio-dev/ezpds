<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  // ATProto handle segment: RFC 1035 DNS label — alphanumeric start/end, hyphens in middle only.
  // Dots and underscores are excluded: dots would create multi-label handles (alice.bob instead of
  // alice.ezpds.com); underscores are not valid in DNS labels per RFC 1035.
  const handleRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
  let isValid = $derived(handleRegex.test(value.trim()));
</script>

<OnboardingShell title="Choose your handle" subtitle="This is your unique identifier on the network (e.g. alice.ezpds.com).">
  <TextField
    bind:value
    type="text"
    placeholder="alice"
    autocomplete="off"
    autocapitalize="none"
    autocorrect="off"
    spellcheck={false}
    aria-label="Handle"
    {error}
  />
  <Button disabled={!isValid} onclick={onnext}>Create account</Button>
</OnboardingShell>
