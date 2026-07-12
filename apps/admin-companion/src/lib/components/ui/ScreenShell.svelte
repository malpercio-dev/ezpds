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
    server,
    onservertap,
    children,
    actions,
  }: {
    /** The prompt segment after `ezpds ▸` (e.g. "claim code", "pair device"). */
    prompt: string;
    title: string;
    /** Render a back affordance and call this on activate. */
    onback?: () => void;
    /** The active server identity (nickname + host). When omitted, the server block is
     * not rendered. */
    server?: { nickname: string; host: string } | null;
    /** When provided, the server-context block renders as a button (Home uses this to
     * open the inline switcher). Without it, the block is static text (Settings). */
    onservertap?: () => void;
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
    {#if server}
      {#if onservertap}
        <button type="button" class="server server-tappable" onclick={onservertap}>
          <span class="server-nickname">{server.nickname}</span>
          <span class="server-host">{server.host}</span>
          <span class="server-affordance" aria-hidden="true">▾</span>
          <span class="visually-hidden">Switch server</span>
        </button>
      {:else}
        <div class="server">
          <span class="server-nickname">{server.nickname}</span>
          <span class="server-host">{server.host}</span>
        </div>
      {/if}
    {/if}
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
    display: inline-flex;
    align-items: center;
    align-self: flex-start;
    min-height: var(--control-min-height);
    margin-bottom: var(--space-xs);
    padding: var(--space-xs);
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
    color: var(--color-ink-soft);
  }
  .brand {
    color: var(--color-primary);
  }
  .caret {
    margin: 0 var(--space-sm);
    color: var(--color-muted);
  }
  .title {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-headline);
    line-height: var(--leading-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .server {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin-top: var(--space-xs);
  }
  .server-tappable {
    align-self: flex-start;
    padding: var(--space-xs) 0;
    background: transparent;
    border: none;
    font-family: inherit;
    text-align: inherit;
    cursor: pointer;
  }
  .server-nickname {
    display: block;
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .server-host {
    display: block;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .server-affordance {
    display: inline;
    margin-left: var(--space-xs);
    color: var(--color-muted);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
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
