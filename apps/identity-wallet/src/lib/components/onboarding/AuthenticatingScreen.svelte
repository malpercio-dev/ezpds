<script lang="ts">
  import { onMount } from 'svelte';
  import { startOAuthFlow, type OAuthError } from '$lib/ipc';

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
  <div class="spinner" aria-label="Loading"></div>
  <p class="status">Opening browser for authentication…</p>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 24px;
    padding: 32px;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .status {
    text-align: center;
    color: #6b7280;
    font-size: 1rem;
  }
</style>
