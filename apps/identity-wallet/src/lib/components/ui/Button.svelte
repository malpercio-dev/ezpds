<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    variant = 'primary',
    type = 'button',
    disabled = false,
    onclick,
    children,
  }: {
    variant?: 'primary' | 'secondary';
    type?: 'button' | 'submit';
    disabled?: boolean;
    onclick?: (e: MouseEvent) => void;
    children: Snippet;
  } = $props();
</script>

<button class="btn {variant}" {type} {disabled} {onclick}>
  {@render children()}
</button>

<style>
  .btn {
    width: 100%;
    padding: var(--space-md);
    border: none;
    border-radius: var(--radius-md);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard);
  }

  .primary {
    background: var(--color-primary);
    color: var(--color-on-color);
  }
  @media (hover: hover) {
    .primary:hover:not(:disabled) {
      background: var(--color-primary-deep);
    }
    .secondary:hover:not(:disabled) {
      background: var(--color-surface-sunk);
    }
  }
  .primary:active:not(:disabled) {
    background: var(--color-primary-deep);
  }

  .secondary {
    background: var(--color-surface);
    color: var(--color-ink);
    border: 1px solid var(--color-line);
  }
  .secondary:active:not(:disabled) {
    background: var(--color-surface-sunk);
  }

  .btn:disabled {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
    cursor: not-allowed;
  }
</style>
