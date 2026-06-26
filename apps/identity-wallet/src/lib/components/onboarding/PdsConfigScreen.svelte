<script lang="ts">
  import { savePdsUrl, type PdsConfigError } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  const DEFAULT_PDS_URL = 'https://relay.ezpds.com';

  let { onnext }: { onnext: () => void } = $props();

  let url = $state(DEFAULT_PDS_URL);
  let loading = $state(false);
  let error = $state<string | undefined>(undefined);

  let isValidFormat = $derived(
    url.trim().length > 0 &&
      (url.startsWith('http://') || url.startsWith('https://'))
  );

  async function handleConnect() {
    error = undefined;
    loading = true;
    try {
      await savePdsUrl(url.trim());
      onnext();
    } catch (e) {
      const err = e as PdsConfigError;
      if (err.code === 'INVALID_URL') {
        error = 'Invalid URL — must start with http:// or https://';
      } else if (err.code === 'KEYCHAIN_ERROR') {
        error = 'Could not save the server URL. Please try again.';
      } else {
        error = 'Could not reach the server. Check the URL and try again.';
      }
    } finally {
      loading = false;
    }
  }
</script>

<OnboardingShell
  title="Connect to Custos"
  subtitle="Your wallet connects to a server to create your identity. Use the default, or enter the address of your own."
>
  <TextField
    bind:value={url}
    type="url"
    mono
    disabled={loading}
    placeholder="https://relay.ezpds.com"
    autocomplete="off"
    autocorrect="off"
    autocapitalize="off"
    spellcheck={false}
    aria-label="Server URL"
    {error}
  />
  {#if loading}
    <Spinner label="Connecting…" />
  {:else}
    <Button disabled={!isValidFormat} onclick={handleConnect}>Connect</Button>
  {/if}
</OnboardingShell>
