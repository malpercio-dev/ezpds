<script lang="ts">
  // A labelled input well: Raised Slate ground, Steel Line border, gold focus ring.
  // `mono` sets the field in JetBrains Mono for fields that take a literal value
  // (a relay URL, a pairing code). Errors are border + icon + message, never color
  // alone (DESIGN.md §5 Inputs).
  let {
    label,
    value = $bindable(''),
    placeholder,
    type = 'text',
    mono = false,
    error,
    id = crypto.randomUUID(),
    inputmode,
    autocomplete = 'off',
  }: {
    label: string;
    value?: string;
    placeholder?: string;
    type?: 'text' | 'url' | 'email' | 'password';
    /** Set the field in monospace for literal values (URLs, codes, keys). */
    mono?: boolean;
    error?: string;
    id?: string;
    inputmode?: 'text' | 'url' | 'email' | 'numeric';
    autocomplete?: 'on' | 'off';
  } = $props();

  const errorId = $derived(error ? `${id}-error` : undefined);
</script>

<div class="field">
  <label class="label" for={id}>{label}</label>
  <input
    {id}
    class="input"
    class:input--mono={mono}
    class:input--error={error}
    {type}
    {placeholder}
    {inputmode}
    {autocomplete}
    bind:value
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={errorId}
  />
  {#if error}
    <p class="error" id={errorId}>
      <span class="error-glyph" aria-hidden="true">!</span>
      {error}
    </p>
  {/if}
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink-soft);
  }
  .input {
    width: 100%;
    min-height: var(--control-min-height);
    padding: var(--space-sm) var(--space-md);
    background: var(--color-surface-raised);
    color: var(--color-ink);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--control-radius);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    transition: border-color var(--duration-fast) var(--ease-standard);
  }
  .input::placeholder {
    color: var(--color-muted);
  }
  .input--mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
  }
  .input:focus-visible {
    outline: var(--ring-width) solid var(--color-primary);
    outline-offset: var(--ring-offset);
    border-color: var(--color-primary);
  }
  .input--error {
    border-color: var(--color-critical);
  }
  .error {
    display: flex;
    align-items: flex-start;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    color: var(--color-critical);
  }
  .error-glyph {
    font-family: var(--font-mono);
    font-weight: var(--weight-medium);
  }
</style>
