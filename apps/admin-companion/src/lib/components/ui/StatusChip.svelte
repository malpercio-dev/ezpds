<script lang="ts">
  // Status is never color alone (DESIGN.md §2): every chip is a tonal pair (signal
  // tone on a deep same-hue surface) PLUS a terminal glyph PLUS a text label. The
  // glyph is the register's native voice — `● active` / `⊘ revoked` — but it is
  // decorative for assistive tech; the label text carries the meaning to VoiceOver.
  export type Status =
    | 'active'
    | 'ready'
    | 'revoked'
    | 'error'
    | 'pending'
    | 'flagged'
    | 'info';

  let {
    status,
    label,
  }: {
    status: Status;
    /** Override the default label text; the glyph and tone follow `status`. */
    label?: string;
  } = $props();

  const MAP: Record<Status, { tone: string; glyph: string; text: string }> = {
    active: { tone: 'safe', glyph: '●', text: 'active' }, // ●
    ready: { tone: 'safe', glyph: '●', text: 'ready' }, // ●
    revoked: { tone: 'critical', glyph: '⊘', text: 'revoked' }, // ⊘
    error: { tone: 'critical', glyph: '!', text: 'error' },
    pending: { tone: 'warning', glyph: '◌', text: 'pending' }, // ◌
    flagged: { tone: 'warning', glyph: '⚑', text: 'flagged' }, // ⚑ labeler flag
    info: { tone: 'info', glyph: '○', text: 'info' }, // ○
  };

  const meta = $derived(MAP[status]);
  const text = $derived(label ?? meta.text);
</script>

<span class="chip chip--{meta.tone}">
  <span class="glyph" aria-hidden="true">{meta.glyph}</span>
  <span class="text">{text}</span>
</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    padding: var(--space-xs) var(--space-sm);
    border-radius: var(--chip-radius);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    line-height: 1;
    white-space: nowrap;
    width: fit-content;
  }
  .glyph {
    font-size: 0.9em;
  }

  .chip--safe {
    color: var(--color-safe);
    background: var(--color-safe-surface);
  }
  .chip--warning {
    color: var(--color-warning);
    background: var(--color-warning-surface);
  }
  .chip--critical {
    color: var(--color-critical);
    background: var(--color-critical-surface);
  }
  .chip--info {
    color: var(--color-info);
    background: var(--color-info-surface);
  }
</style>
