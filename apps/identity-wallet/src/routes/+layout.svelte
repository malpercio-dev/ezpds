<script lang="ts">
  // Global design layer: fonts, tokens, base element styles, then the shared
  // utility classes screens compose with their own local styles (order matters).
  import '$lib/styles/fonts.css';
  import '$lib/styles/tokens.css';
  import '$lib/styles/base.css';
  import '$lib/styles/utilities.css';
  import { initAppearance } from '$lib/appearance';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();

  // Reconcile the pre-paint localStorage mirror (applied by app.html's inline
  // script) against the Keychain-backed appearance preference.
  initAppearance();
</script>

{@render children()}
