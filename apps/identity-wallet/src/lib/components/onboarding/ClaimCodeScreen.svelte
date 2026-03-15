<script lang="ts">
  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  let isValid = $derived(value.length === 6);

  function handleInput(e: Event) {
    const raw = (e.currentTarget as HTMLInputElement).value;
    value = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6);
  }
</script>

<div class="screen">
  <h2>Enter Your Claim Code</h2>
  <p class="hint">You'll receive a 6-character code from your administrator.</p>

  <input
    type="text"
    class="code-input"
    class:error={!!error}
    maxlength="6"
    placeholder="ABC123"
    autocomplete="off"
    autocorrect="off"
    autocapitalize="characters"
    spellcheck={false}
    {value}
    oninput={handleInput}
  />

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <button disabled={!isValid} onclick={onnext}>Next</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem;
    gap: 1rem;
    height: 100%;
    justify-content: center;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
  }

  .code-input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1.5rem;
    font-family: monospace;
    letter-spacing: 0.5rem;
    text-align: center;
    border: 2px solid #d1d5db;
    border-radius: 12px;
    text-transform: uppercase;
  }

  .code-input.error {
    border-color: #ef4444;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }
</style>
