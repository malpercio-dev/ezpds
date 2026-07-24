<script lang="ts">
  import { onMount } from 'svelte';
  import {
    savePdsUrl,
    getPdsUrl,
    getPdsCapabilities,
    hasPdsCapability,
    type PdsConfigError,
  } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  const DEFAULT_PDS_URL = 'https://obsign.org';

  let {
    onnext,
    oncreateunavailable,
    onback = undefined,
  }: {
    onnext: () => void;
    /**
     * The configured server does not run the create ceremony. Called with the saved URL
     * instead of `onnext`, so the flow can explain that here rather than letting the user
     * fill in a claim code, an email, and a handle before a `/v1/*` call fails opaquely.
     */
    oncreateunavailable: (pdsUrl: string) => void;
    onback?: () => void;
  } = $props();

  let url = $state(DEFAULT_PDS_URL);
  let loading = $state(false);
  let error = $state<string | undefined>(undefined);

  // Seed the field from the currently-saved PDS URL (if any) so the user sees the host that is
  // actually active, instead of always seeing the built-in default. The active URL is restored
  // from the Keychain at launch and is otherwise invisible — which made a stale/wrong host
  // (e.g. a previous staging URL) impossible to notice.
  onMount(() => {
    const initialUrl = url;
    void (async () => {
      try {
        const saved = await getPdsUrl();
        // Only hydrate if the user hasn't started editing while the IPC call was in flight,
        // otherwise a late resolve would clobber their input.
        if (saved && url === initialUrl) url = saved;
      } catch (e) {
        console.warn('[PdsConfigScreen] failed to load saved PDS URL:', e);
      }
    })();
  });

  let isValidFormat = $derived(
    url.trim().length > 0 &&
      (url.startsWith('http://') || url.startsWith('https://'))
  );

  async function handleConnect() {
    error = undefined;
    loading = true;
    const trimmed = url.trim();
    try {
      await savePdsUrl(trimmed);

      // Ask the server what it can do before the user invests any typing in it.
      // `save_pds_url` has already re-probed this host, so this reads a warm cache.
      const capabilities = await getPdsCapabilities(trimmed);

      // A host we could not ask is NOT a host that cannot create identities. Telling the
      // user their server can't do this because the network blinked is a false accusation
      // they have no way to tell apart from a true one, so it surfaces as a retryable
      // error instead of the steer.
      if (!capabilities.reached) {
        error = "Could not check what this server supports. Check the URL and try again.";
        return;
      }

      if (!hasPdsCapability(capabilities, 'createCeremony')) {
        oncreateunavailable(trimmed);
        return;
      }
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
  {onback}
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
