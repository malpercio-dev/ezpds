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
    truncate = false,
    size = 'screen',
    actions,
  }: {
    title: string;
    /** Render a circular back affordance and call this on activate. Omit for a root header. */
    onback?: () => void;
    /** Accessible label for the back button (e.g. "Back to agent list"). */
    backLabel?: string;
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
    <button class="back" onclick={onback} aria-label={backLabel}>
      <ChevronLeftIcon />
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
    width: 44px;
    height: 44px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    color: var(--color-ink);
    cursor: pointer;
    flex-shrink: 0;
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
