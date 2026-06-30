<script lang="ts">
  // A labelled switch for a boolean setting (e.g. the biometric gate). State is conveyed
  // by thumb POSITION and an explicit `on`/`off` mono label — never color alone
  // (DESIGN.md §2). The gold "on" track is the active-state use of the brass accent, not a
  // status color. Renders as a native role="switch" so VoiceOver announces it correctly.
  let {
    checked = $bindable(false),
    label,
    description,
    disabled = false,
    onchange,
  }: {
    checked?: boolean;
    label: string;
    /** Optional secondary line under the label explaining the setting. */
    description?: string;
    disabled?: boolean;
    onchange?: (checked: boolean) => void;
  } = $props();

  const id = crypto.randomUUID();
  const descId = $derived(description ? `${id}-desc` : undefined);

  function toggle() {
    if (disabled) return;
    checked = !checked;
    onchange?.(checked);
  }
</script>

<div class="row">
  <div class="text">
    <span class="label" {id}>{label}</span>
    {#if description}<span class="desc" id={descId}>{description}</span>{/if}
  </div>
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-labelledby={id}
    aria-describedby={descId}
    {disabled}
    class="switch"
    class:is-on={checked}
    onclick={toggle}
  >
    <span class="state" aria-hidden="true">{checked ? 'on' : 'off'}</span>
    <span class="track"><span class="thumb"></span></span>
  </button>
</div>

<style>
  .row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-md);
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    min-width: 0;
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .desc {
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .switch {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
    /* keep the whole control inside the 44px touch floor */
    min-height: var(--control-min-height);
    padding: 0;
    background: transparent;
    border: none;
    cursor: pointer;
  }
  .switch:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }
  /* The on/off word carries state to sighted users alongside the thumb position. */
  .state {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
    min-width: 2ch;
    text-align: right;
  }
  .switch.is-on .state {
    color: var(--color-primary);
  }
  .track {
    position: relative;
    display: inline-block;
    width: calc(var(--space-xl) + var(--space-sm)); /* 40px */
    height: var(--space-lg); /* 24px */
    background: var(--color-surface-raised);
    border: var(--border-hairline) solid var(--color-border-strong);
    border-radius: var(--radius-full);
    transition:
      background var(--duration-base) var(--ease-standard),
      border-color var(--duration-base) var(--ease-standard);
  }
  .switch.is-on .track {
    background: var(--color-primary);
    border-color: var(--color-primary);
  }
  .thumb {
    position: absolute;
    top: 50%;
    left: var(--space-xs); /* 4px inset */
    width: var(--space-md); /* 16px */
    height: var(--space-md);
    margin-top: calc(var(--space-md) / -2);
    background: var(--color-ink);
    border-radius: var(--radius-full);
    transition: transform var(--duration-base) var(--ease-standard);
  }
  /* travel = track(40) − thumb(16) − 2×inset(4) = 16px = --space-md */
  .switch.is-on .thumb {
    transform: translateX(var(--space-md));
    background: var(--color-on-primary);
  }
  .switch:focus-visible {
    outline: var(--ring-width) solid var(--color-primary);
    outline-offset: var(--ring-offset);
    border-radius: var(--radius-sm);
  }
  @media (prefers-reduced-motion: reduce) {
    .track,
    .thumb {
      transition: none;
    }
  }
</style>
