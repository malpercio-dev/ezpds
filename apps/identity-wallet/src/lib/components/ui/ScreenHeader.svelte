<script lang="ts">
  import type { Snippet } from 'svelte';
  import ChevronLeftIcon from './ChevronLeftIcon.svelte';

  // The shared home-surface chrome: an optional circular back affordance, the screen
  // title, and an optional right-aligned actions cluster. Replaces the per-screen
  // `.topbar`/`.back`/`.title` copies (MyAgentsScreen, AgentDetailScreen, SettingsScreen,
  // AgentClaimApprovalScreen) and the root IdentityListHome header.
  let {
    title,
    onback,
    backLabel = 'Back',
    backText,
    truncate = false,
    size = 'screen',
    actions,
  }: {
    title: string;
    /** Render a circular back affordance and call this on activate. Omit for a root header. */
    onback?: () => void;
    /** Accessible label for the back button (e.g. "Back to agent list"). */
    backLabel?: string;
    /**
     * Render the exit as a labelled pill rather than the icon-only circle. `backLabel` is
     * an *accessible* name — a sighted user sees only a chevron, which is the right weight
     * for "go back up" and the wrong weight for a decision the screen is asking them to
     * make. Set this when leaving is a choice rather than a navigation (the alarm
     * takeover's "Not now"), so the way out is legible to everyone, not just to a screen
     * reader.
     */
    backText?: string;
    /** Ellipsize the title when it can't fit (used when the title is user data). */
    truncate?: boolean;
    /** `screen` is the standard sub-screen title; `home` is the larger root-list title. */
    size?: 'screen' | 'home';
    /** Optional right-aligned action cluster (e.g. refresh + settings on the root list). */
    actions?: Snippet;
  } = $props();
</script>

<div class="topbar">
  {#if onback}
    <button
      class="back"
      class:back--text={backText}
      onclick={onback}
      aria-label={backText ?? backLabel}
    >
      <ChevronLeftIcon />
      {#if backText}<span class="back-text">{backText}</span>{/if}
    </button>
  {/if}
  <h1 class="title" class:title--home={size === 'home'} class:truncate>{title}</h1>
  {#if actions}
    <span class="actions">{@render actions()}</span>
  {/if}
</div>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .back {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--size-tap-target);
    height: var(--size-tap-target);
    border-radius: var(--radius-full);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    color: var(--color-ink);
    cursor: pointer;
    flex-shrink: 0;
  }
  /* The labelled variant: still a ≥44px target, but sized to its text rather than to a
     circle, so the word carries the weight the icon alone cannot. */
  .back--text {
    width: auto;
    gap: var(--space-2xs);
    padding: 0 var(--space-sm);
    border-radius: var(--radius-full);
  }
  .back-text {
    font-family: var(--font-sans);
    font-size: 0.9375rem;
    font-weight: var(--weight-medium);
    white-space: nowrap;
  }
  .title {
    font-family: var(--font-sans);
    font-size: 1.375rem;
    font-weight: var(--weight-bold);
    letter-spacing: -0.01em;
    color: var(--color-ink);
    margin: 0;
    min-width: 0;
  }
  .title--home {
    font-size: 1.875rem;
    letter-spacing: -0.02em;
  }
  .truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .actions {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
    flex-shrink: 0;
  }
</style>
