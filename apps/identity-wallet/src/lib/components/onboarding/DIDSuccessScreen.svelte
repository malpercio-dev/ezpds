<script lang="ts">
  let {
    did,
    oncontinue,
  }: {
    did: string;
    oncontinue: () => void;
  } = $props();

  // Truncate the DID suffix for display on a narrow mobile screen.
  // "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcde…uvwx"
  let displayDid = $derived(
    did.startsWith('did:plc:') && did.length > 20
      ? `did:plc:${did.slice(8, 13)}…${did.slice(-4)}`
      : did
  );

  let copied = $state(false);

  async function copyDid() {
    try {
      await navigator.clipboard.writeText(did);
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch (e) {
      console.error('clipboard write failed:', e);
    }
  }
</script>

<div class="screen">
  <div class="success-icon" aria-hidden="true">✓</div>
  <h2>Identity Created!</h2>
  <p class="label">Your decentralized identifier</p>
  <button class="did" onclick={copyDid} title="Tap to copy full DID">
    {displayDid}
    <span class="copy-hint">{copied ? 'Copied!' : 'Tap to copy'}</span>
  </button>
  <button class="cta" onclick={oncontinue}>Continue</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 1.25rem;
    text-align: center;
  }

  .success-icon {
    width: 64px;
    height: 64px;
    background: #007aff;
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: 700;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .label {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0;
  }

  .did {
    font-family: monospace;
    font-size: 0.9rem;
    background: #f3f4f6;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    word-break: break-all;
    border: none;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.25rem;
    width: 100%;
    max-width: 320px;
  }

  .copy-hint {
    font-family: system-ui, sans-serif;
    font-size: 0.75rem;
    color: #6b7280;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
