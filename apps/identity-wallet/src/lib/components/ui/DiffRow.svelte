<script lang="ts">
  // A single change in an operation diff. Full tonal ground + leading icon —
  // deliberately not a colored side-stripe (a hard design ban).
  let {
    variant,
    title,
    value = undefined,
  }: {
    variant: 'remove' | 'restore' | 'modify';
    title: string;
    value?: string;
  } = $props();
</script>

<div class="diff diff--{variant}">
  <span class="diff-ic" aria-hidden="true">
    {#if variant === 'remove'}
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M5 12h14" /></svg>
    {:else if variant === 'restore'}
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
    {:else}
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7h13l-3-3M21 17H8l3 3" /></svg>
    {/if}
  </span>
  <span class="diff-body">
    <span class="diff-t">{title}</span>
    {#if value}<span class="diff-v">{value}</span>{/if}
  </span>
</div>

<style>
  .diff {
    display: flex;
    gap: var(--space-sm);
    align-items: flex-start;
    border-radius: var(--radius-md);
    padding: var(--space-sm) 12px;
  }
  .diff-ic {
    width: 28px;
    height: 28px;
    border-radius: var(--radius-full);
    background: var(--color-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .diff-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .diff-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    line-height: 1.3;
  }
  .diff-v {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    word-break: break-all;
    line-height: 1.4;
  }
  .diff--remove {
    background: var(--color-critical-surface);
  }
  .diff--remove .diff-ic,
  .diff--remove .diff-t {
    color: var(--color-critical);
  }
  .diff--remove .diff-v {
    color: var(--color-critical-soft);
  }
  .diff--restore {
    background: var(--color-seal-pale);
  }
  .diff--restore .diff-ic,
  .diff--restore .diff-t {
    color: var(--color-gold-ink);
  }
  .diff--restore .diff-v {
    color: var(--color-gold-soft);
  }
  .diff--modify {
    background: var(--color-warning-surface);
  }
  .diff--modify .diff-ic,
  .diff--modify .diff-t {
    color: var(--color-warning);
  }
  .diff--modify .diff-v {
    color: var(--color-warning-soft);
  }
</style>
