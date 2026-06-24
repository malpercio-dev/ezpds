<script lang="ts">
  import { onMount } from 'svelte';
  import { startOAuthFlow, type OAuthError } from '$lib/ipc';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    onresolved,
    onfailed,
  }: {
    onresolved: () => void;
    onfailed: (err: OAuthError) => void;
  } = $props();

  async function authenticate() {
    try {
      await startOAuthFlow();
      onresolved();
    } catch (raw) {
      onfailed(raw as OAuthError);
    }
  }

  onMount(() => {
    authenticate();
  });
</script>

<div class="screen">
  <Spinner size={44} label="Authenticating" />
  <p class="status">Opening browser for authentication…</p>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: var(--space-lg);
    padding: var(--space-xl);
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }
</style>
