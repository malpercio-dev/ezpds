<script lang="ts">
  let {
    value = $bindable(''),
    type = 'text',
    error = undefined,
    mono = false,
    disabled = false,
    oninput = undefined,
    ...rest
  }: {
    value?: string;
    type?: string;
    error?: string;
    mono?: boolean;
    disabled?: boolean;
    oninput?: (e: Event & { currentTarget: HTMLInputElement }) => void;
    [key: string]: unknown;
  } = $props();
</script>

<div class="field">
  <input
    {...rest}
    {type}
    {disabled}
    class:error={!!error}
    class:mono
    aria-invalid={!!error}
    value={value}
    oninput={(e) => {
      value = e.currentTarget.value;
      oninput?.(e);
    }}
  />
  {#if error}
    <p class="error-text" role="alert">{error}</p>
  {/if}
</div>

<style>
  .field {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  input {
    width: 100%;
    padding: var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    transition: border-color var(--duration-base) var(--ease-standard);
  }
  input.mono {
    font-family: var(--font-mono);
  }
  input::placeholder {
    color: var(--color-muted);
  }
  input:focus-visible {
    border-color: var(--color-accent);
  }
  input.error {
    border-color: var(--color-critical);
  }
  input:disabled {
    opacity: 0.55;
  }

  .error-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    text-align: center;
  }
</style>
