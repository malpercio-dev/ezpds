<script lang="ts">
  import type { Snippet } from 'svelte';

  // The shared onboarding layout: an optional back affordance, a centered column
  // with an optional icon, title (work sans or signet serif), subtitle, and content.
  let {
    title = undefined,
    subtitle = undefined,
    tone = 'work',
    onback = undefined,
    icon = undefined,
    children,
  }: {
    title?: string;
    subtitle?: string;
    tone?: 'work' | 'signet';
    onback?: () => void;
    icon?: Snippet;
    children: Snippet;
  } = $props();
</script>

<div class="screen">
  {#if onback}
    <button class="back" onclick={onback} aria-label="Back">
      <svg width="11" height="18" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 1 2 9l7 8" /></svg>
      Back
    </button>
  {/if}
  <div class="content">
    {#if icon}<div class="icon">{@render icon()}</div>{/if}
    {#if title}<h1 class="title" class:signet={tone === 'signet'}>{title}</h1>{/if}
    {#if subtitle}<p class="subtitle">{subtitle}</p>{/if}
    {@render children()}
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-xl) var(--space-lg);
  }

  .back {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs) 0;
  }

  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-md);
    text-align: center;
    width: 100%;
    max-width: 360px;
    margin: 0 auto;
  }

  .icon {
    margin-bottom: var(--space-xs);
  }

  .title {
    margin: 0;
    color: var(--color-ink);
    font-family: var(--font-sans);
    font-size: 1.5rem;
    font-weight: var(--weight-bold);
    line-height: 1.2;
  }
  .title.signet {
    font-family: var(--font-display);
    font-size: 2rem;
    font-weight: var(--weight-regular);
    line-height: 1.1;
  }

  .subtitle {
    margin: 0;
    color: var(--color-muted);
    font-size: var(--text-body);
    line-height: var(--leading-body);
    max-width: 32ch;
  }
</style>
