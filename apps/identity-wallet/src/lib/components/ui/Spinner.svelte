<script lang="ts">
  let { size = 40, label = 'Loading' }: { size?: number; label?: string } = $props();
</script>

<span class="spinner" style="width: {size}px; height: {size}px" role="status" aria-label={label}></span>

<style>
  .spinner {
    display: inline-block;
    border: 3px solid var(--color-surface-sunk); /* px-ok: spinner ring thickness, deliberately thicker than a hairline */
    border-top-color: var(--color-primary);
    border-radius: var(--radius-full);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
