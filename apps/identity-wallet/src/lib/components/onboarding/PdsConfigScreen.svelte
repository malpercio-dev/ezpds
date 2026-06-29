<script lang="ts">
  import { onMount } from 'svelte';
  import { savePdsUrl, getPdsUrl, type PdsConfigError } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  const DEFAULT_PDS_URL = 'https://obsign.org';

  let { onnext }: { onnext: () => void } = $props();

  let url = $state(DEFAULT_PDS_URL);
  let loading = $state(false);
  let error = $state<string | undefined>(undefined);

  // Seed the field from the currently-saved PDS URL (if any) so the user sees the host that is
  // actually active, instead of always seeing the built-in default. The active URL is restored
  // from the Keychain at launch and is otherwise invisible — which made a stale/wrong host
  // (e.g. a previous staging URL) impossible to notice.
  onMount(async () => {
    try {
      const saved = await getPdsUrl();
      if (saved) url = saved;
    } catch (e) {
      console.warn('[PdsConfigScreen] failed to load saved PDS URL:', e);
    }
  });

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
    placeholder="https://obsign.org"
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
