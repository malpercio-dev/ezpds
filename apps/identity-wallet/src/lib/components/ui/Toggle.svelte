<script lang="ts">
  // A settings on/off switch. The whole row is the control (a generous ≥44px tap target),
  // exposed as a WAI-ARIA `switch`. State is conveyed by knob POSITION and track fill/hollow
  // shape — never colour alone — plus `aria-checked` for VoiceOver, per the AAA status rule.
  let {
    checked,
    onchange,
    label,
    description,
    disabled = false,
  }: {
    checked: boolean;
    onchange: (next: boolean) => void;
    label: string;
    description?: string;
    disabled?: boolean;
  } = $props();
</script>

<button
  type="button"
  role="switch"
  aria-checked={checked}
  {disabled}
  class="row"
  class:row--on={checked}
  onclick={() => onchange(!checked)}
>
  <span class="text">
    <span class="label">{label}</span>
    {#if description}<span class="desc">{description}</span>{/if}
  </span>
  <span class="switch" aria-hidden="true">
    <span class="knob"></span>
  </span>
</button>

<style>
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-md);
    width: 100%;
    min-height: var(--size-tap-target);
    padding: var(--space-2xs) 0;
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
    font-family: var(--font-sans);
  }
  .row:disabled {
    cursor: default;
    /* Dimmed AND inert — the disabled attribute already removes it from the tab order and
       drops aria-checked's actionability, so the state isn't carried by opacity alone. */
    opacity: 0.5;
  }

  .text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .label {
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .desc {
    font-size: var(--text-label);
    line-height: var(--leading-label);
    color: var(--color-muted);
  }

  /* ── The switch ─────────────────────────────────────────────────────────────
     Off: hollow — a bordered sunk track with the knob at the left.
     On:  filled — the sealing-wax gold track with the knob at the right.
     The fill/hollow contrast and the knob travel are both non-colour signals. */
  .switch {
    position: relative;
    flex-shrink: 0;
    width: 46px;
    height: 28px;
    border-radius: var(--radius-full);
    background: var(--color-surface-sunk);
    border: 1.5px solid var(--color-line-strong);
    transition:
      background var(--duration-base) var(--ease-standard),
      border-color var(--duration-base) var(--ease-standard);
  }
  .row--on .switch {
    background: var(--color-primary);
    border-color: var(--color-primary);
  }

  .knob {
    position: absolute;
    top: 50%;
    left: 3px;
    width: 20px;
    height: 20px;
    border-radius: var(--radius-full);
    /* Always a light knob (like a physical switch), so it stays high-contrast on both the
       hollow off-track and the gold on-track, in light and dark alike. */
    background: var(--color-on-color);
    border: 1px solid var(--color-line);
    transform: translate(0, -50%);
    transition: transform var(--duration-base) var(--ease-standard);
  }
  .row--on .knob {
    /* 46 track − 20 knob − 3 left − 1.5 border ≈ 18px travel to seat at the right. */
    transform: translate(18px, -50%);
    border-color: transparent;
  }

  .row:active:not(:disabled) .knob {
    /* A brief widen on press — tactile feedback, state still by position. */
    width: 23px;
  }

  @media (prefers-reduced-motion: reduce) {
    .switch,
    .knob {
      transition: none;
    }
  }
</style>
