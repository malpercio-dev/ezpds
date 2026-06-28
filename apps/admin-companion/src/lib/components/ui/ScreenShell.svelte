<script lang="ts">
  import type { Snippet } from 'svelte';

  // The screen scaffold: the `ezpds ▸ <prompt>` line (the console "prompt", mono,
  // the one place the display face appears) over a working-voice headline, then the
  // screen body, then an optional pinned actions row. Keeps every operator screen
  // structurally identical — the consistency the product register prizes.
  let {
    prompt,
    title,
    onback,
    children,
    actions,
  }: {
    /** The prompt segment after `ezpds ▸` (e.g. "claim code", "pair device"). */
    prompt: string;
    title: string;
    /** Render a back affordance and call this on activate. */
    onback?: () => void;
    children: Snippet;
    /** Optional pinned action row (e.g. the primary Button) at the screen foot. */
    actions?: Snippet;
  } = $props();
</script>

<div class="screen">
  <header class="head">
    {#if onback}
      <button class="back" type="button" onclick={onback}>
        <span aria-hidden="true">←</span> Back
      </button>
    {/if}
    <p class="prompt"><span class="brand">ezpds</span><span class="caret" aria-hidden="true">▸</span>{prompt}</p>
    <h1 class="title">{title}</h1>
  </header>

  <main class="body">
    {@render children()}
  </main>

  {#if actions}
    <footer class="actions">
      {@render actions()}
    </footer>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    min-height: 100dvh;
    padding: var(--space-xl) var(--space-lg) var(--space-lg);
    gap: var(--space-lg);
  }
  .head {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .back {
    align-self: flex-start;
    margin-bottom: var(--space-xs);
    padding: var(--space-xs) 0;
    background: transparent;
    border: none;
    color: var(--color-primary);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    cursor: pointer;
  }
  /* The prompt is the display moment: mono, brand gold, used once per screen. */
  .prompt {
    margin: 0;
    font-family: var(--font-display);
    font-size: var(--text-data);
    letter-spacing: 0.02em;
  }
  .brand {
    color: var(--color-primary);
  }
  .caret {
    margin: 0 var(--space-sm);
    color: var(--color-muted);
  }
  .prompt {
    color: var(--color-ink-soft);
  }
  .title {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-headline);
    line-height: var(--leading-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    flex: 1;
  }
  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding-top: var(--space-sm);
  }
</style>
