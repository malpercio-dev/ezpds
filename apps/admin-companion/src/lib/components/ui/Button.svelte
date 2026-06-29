<script lang="ts">
  import type { Snippet } from 'svelte';

  // The One-Lamp action. `primary` is Sealing-Wax Gold and should appear at most
  // once per screen (the operator's single most-likely action); `secondary` is the
  // quiet default; `destructive` is reserved for the irreversible revoke/unpair and
  // is deliberately scarce.
  let {
    variant = 'secondary',
    type = 'button',
    disabled = false,
    loading = false,
    onclick,
    children,
  }: {
    variant?: 'primary' | 'secondary' | 'destructive';
    type?: 'button' | 'submit';
    disabled?: boolean;
    loading?: boolean;
    onclick?: (e: MouseEvent) => void;
    children: Snippet;
  } = $props();
</script>

<button
  class="btn btn--{variant}"
  {type}
  disabled={disabled || loading}
  aria-busy={loading}
  {onclick}
>
  {#if loading}
    <svg class="spinner" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-dasharray="44" stroke-dashoffset="33" />
    </svg>
  {/if}
  <span class="label">{@render children()}</span>
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--control-min-height);
    padding: var(--space-sm) var(--space-md);
    border: var(--border-hairline) solid transparent;
    border-radius: var(--control-radius);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    line-height: 1;
    cursor: pointer;
    transition:
      background var(--duration-base) var(--ease-standard),
      border-color var(--duration-base) var(--ease-standard);
  }

  /* Primary — Sealing-Wax Gold fill with deep-slate ink (7.7:1, AAA). The One Lamp. */
  .btn--primary {
    background: var(--color-primary);
    color: var(--color-on-primary);
  }
  .btn--primary:hover:not(:disabled) {
    background: var(--color-primary-hover);
  }
  .btn--primary:active:not(:disabled) {
    background: var(--color-primary-deep);
  }

  /* Secondary — Panel Slate with a Steel Line hairline. The quiet default. */
  .btn--secondary {
    background: var(--color-surface);
    color: var(--color-ink);
    border-color: var(--color-border-strong);
  }
  .btn--secondary:hover:not(:disabled) {
    background: var(--color-surface-raised);
  }
  .btn--secondary:active:not(:disabled) {
    background: var(--color-surface-raised);
    border-color: var(--color-line);
  }

  /* Destructive — Alarm Solid with light text (7.5:1, AAA). Irreversible actions only. */
  .btn--destructive {
    background: var(--color-critical-solid);
    color: var(--color-on-color);
  }
  .btn--destructive:hover:not(:disabled) {
    filter: brightness(1.08);
  }
  .btn--destructive:active:not(:disabled) {
    filter: brightness(0.94);
  }

  .btn:disabled {
    background: var(--color-surface);
    color: var(--color-muted);
    border-color: var(--color-line);
    cursor: not-allowed;
  }

  .spinner {
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  /* Reduced motion: hold the spinner still rather than removing the loading affordance. */
  @media (prefers-reduced-motion: reduce) {
    .spinner {
      animation: none;
    }
  }
</style>
