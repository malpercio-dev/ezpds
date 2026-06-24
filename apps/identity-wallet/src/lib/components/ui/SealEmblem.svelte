<script lang="ts">
  import type { Snippet } from 'svelte';

  // The app's gold wax seal — an embossed mark used at brand and ceremonial moments.
  let { size = 72, children }: { size?: number; children: Snippet } = $props();
</script>

<span class="seal" style="width: {size}px; height: {size}px" aria-hidden="true">
  {@render children()}
</span>

<style>
  .seal {
    border-radius: var(--radius-full);
    background: var(--color-primary);
    color: var(--color-on-color);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    box-shadow:
      inset 0 0 0 2px oklch(0.99 0.05 80 / 0.35),
      inset 0 -3px 8px oklch(0.2 0.05 60 / 0.22);
  }
</style>
