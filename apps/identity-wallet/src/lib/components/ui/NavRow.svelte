<script lang="ts">
  import type { Snippet } from 'svelte';

  // One row in a list of destinations: icon, what it is, what it does, chevron.
  //
  // The instrument-panel IA is built from lists of these — the Use zone, the two doors,
  // the everyday tier, the advanced tier — so the tiers differ by *depth and framing*,
  // never by row styling. A row that looked different at each level would put the warning
  // in the decoration; here the warning is the door you had to open to reach it.
  let {
    title,
    subtitle,
    onclick,
    tone = 'default',
    icon,
  }: {
    title: string;
    subtitle?: string;
    onclick: () => void;
    /**
     * `door` marks a row that opens a further list rather than performing anything;
     * `critical` marks a destructive destination, paired with the trailing ellipsis in
     * its title so the meaning never rests on colour.
     */
    tone?: 'default' | 'door' | 'critical';
    icon?: Snippet;
  } = $props();
</script>

<button class="row row--{tone}" {onclick}>
  {#if icon}
    <span class="ic" aria-hidden="true">{@render icon()}</span>
  {/if}
  <span class="body">
    <span class="title">{title}</span>
    {#if subtitle}<span class="subtitle">{subtitle}</span>{/if}
  </span>
  <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8" /></svg>
</button>

<style>
  .row {
    display: flex;
    align-items: center;
    gap: 13px;
    width: 100%;
    min-height: var(--size-tap-target);
    padding: var(--space-md);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard),
      border-color var(--duration-base) var(--ease-standard);
  }
  .row:active {
    background: var(--color-surface);
    border-color: var(--color-line-strong);
  }
  .ic {
    width: 38px;
    height: 38px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }
  .title {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .subtitle {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.4;
  }
  .chev {
    color: var(--color-ink-faint);
    flex-shrink: 0;
  }

  /* A door reveals machinery rather than doing anything itself — the aubergine accent the
     brief reserves for disclosure, matching the settings gear and detail expanders. */
  .row--door .ic {
    background: var(--color-seal-tint);
    color: var(--color-accent);
  }

  /* Destructive destination. The colour reinforces; the title's trailing ellipsis and the
     subtitle carry the meaning on their own. */
  .row--critical {
    border-color: var(--color-critical);
  }
  .row--critical .ic {
    background: var(--color-critical-surface);
    color: var(--color-critical);
  }
  .row--critical .title {
    color: var(--color-critical);
  }
</style>
