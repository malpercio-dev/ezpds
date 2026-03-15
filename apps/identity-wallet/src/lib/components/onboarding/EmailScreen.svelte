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

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let isValid = $derived(emailRegex.test(value));
</script>

<div class="screen">
  <h2>Enter Your Email</h2>
  <p class="hint">We'll associate this email with your new account.</p>

  <input
    type="email"
    class:error={!!error}
    placeholder="you@example.com"
    autocomplete="email"
    inputmode="email"
    bind:value
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

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
  }

  input.error {
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
