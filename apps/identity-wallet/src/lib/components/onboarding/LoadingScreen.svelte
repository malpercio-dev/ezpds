<script lang="ts">
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    statusText = 'Creating your account…',
  }: {
    statusText?: string;
  } = $props();
</script>

<div class="screen">
  <Spinner size={48} label={statusText} />
  <p class="status u-status-text">{statusText}</p>
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
</style>
