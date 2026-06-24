<script lang="ts">
  // Global design layer: fonts, tokens, then base element styles (order matters).
  import '$lib/styles/fonts.css';
  import '$lib/styles/tokens.css';
  import '$lib/styles/base.css';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

{@render children()}
