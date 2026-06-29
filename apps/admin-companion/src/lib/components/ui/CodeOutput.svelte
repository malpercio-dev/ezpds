<script lang="ts">
  // The signature component: a claim code, did:key, or device ID rendered as
  // copyable terminal-style output. Literal-Truth rule (DESIGN.md §3) — mono, and
  // wraps `break-all` so a code is NEVER truncated silently. The leading prompt
  // glyph and the copy affordance make it read as command output, not a label.
  let {
    value,
    label,
    prompt = true,
    copyable = true,
  }: {
    value: string;
    /** Optional caption above the code (e.g. "Account claim code"). */
    label?: string;
    /** Show the leading ▸ prompt glyph. */
    prompt?: boolean;
    copyable?: boolean;
  } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1600);
    } catch {
      // Clipboard denied (rare on iOS WKWebView) — the value stays selectable by hand.
      copied = false;
    }
  }
</script>

<div class="wrap">
  {#if label}
    <span class="caption">{label}</span>
  {/if}
  <div class="surface">
    <code class="value">
      {#if prompt}<span class="prompt" aria-hidden="true">▸</span>{/if}{value}
    </code>
    {#if copyable}
      <button type="button" class="copy" class:is-copied={copied} onclick={copy} aria-label={copied ? 'Copied' : 'Copy to clipboard'}>
        {#if copied}
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>
          <span class="copy-text">copied</span>
        {:else}
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
          <span class="copy-text">copy</span>
        {/if}
      </button>
    {/if}
  </div>
  <span class="sr-status" role="status" aria-live="polite">{copied ? 'Copied to clipboard' : ''}</span>
</div>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .caption {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .surface {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-surface-raised);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--control-radius);
    padding: var(--space-sm) var(--space-md);
  }
  .value {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    line-height: var(--leading-data);
    color: var(--color-ink);
    /* Literal-Truth: never truncate a code silently. */
    overflow-wrap: anywhere;
    word-break: break-all;
    user-select: all;
  }
  .prompt {
    color: var(--color-primary);
    margin-right: var(--space-sm);
  }
  .copy {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    min-height: var(--control-height-compact);
    padding: var(--space-xs) var(--space-sm);
    background: transparent;
    border: var(--border-hairline) solid var(--color-border-strong);
    border-radius: var(--radius-sm);
    color: var(--color-ink-soft);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    cursor: pointer;
    transition: color var(--duration-fast) var(--ease-standard),
      border-color var(--duration-fast) var(--ease-standard);
  }
  .copy:hover {
    color: var(--color-ink);
    border-color: var(--color-muted);
  }
  /* Confirmation reinforces text ("copied") + check glyph with the safe tone — not color alone. */
  .copy.is-copied {
    color: var(--color-safe);
    border-color: var(--color-safe-surface);
  }
  .copy :global(svg) {
    flex: none;
  }
  .sr-status {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
</style>
