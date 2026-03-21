<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';

  let {
    share3,
    oncomplete,
  }: {
    share3: string;
    oncomplete: () => void;
  } = $props();

  let confirmed = $state(false);
  let copied = $state(false);
  let copyFailed = $state(false);
  let qrSvg = $state('');
  let qrFailed = $state(false);

  // Format share as groups of 4 for readability (52 chars → 13 groups of 4).
  // Mirrors hardware wallet recovery key display conventions.
  let formattedShare = $derived(share3.match(/.{1,4}/g)?.join(' ') ?? share3);

  onMount(async () => {
    try {
      qrSvg = await QRCode.toString(share3, {
        type: 'svg',
        width: 200,
        margin: 2,
      });
    } catch {
      // QR generation failed — share text and copy button remain the primary backup methods.
      qrFailed = true;
    }
  });

  async function copyShare() {
    try {
      await navigator.clipboard.writeText(share3);
      copied = true;
      copyFailed = false;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch {
      // Clipboard denied or bridge error — show failure so the user knows to use another method.
      copyFailed = true;
      setTimeout(() => {
        copyFailed = false;
      }, 3000);
    }
  }
</script>

<div class="screen">
  <div class="header">
    <h2>Back Up Your Recovery Key</h2>
    <p class="subtitle">
      Your recovery key has been split into 3 parts for safety. If you ever lose access to your
      account, any 2 parts can restore it.
    </p>
  </div>

  <div class="share-row">
    <div class="share-status">
      <span class="check-icon" aria-hidden="true">✓</span>
      <div>
        <p class="share-label">Part 1 of 3</p>
        <p class="share-desc">Saved to iCloud Keychain automatically</p>
      </div>
    </div>
  </div>

  <div class="share-block">
    <p class="share-label">Part 3 of 3 — Save this yourself</p>
    <code class="share-code">{formattedShare}</code>
    <button class="copy-btn" onclick={copyShare}>
      {copied ? 'Copied!' : 'Copy'}
    </button>
    {#if copyFailed}
      <p class="inline-error" role="alert">Copy failed. Please write it down or use the QR code.</p>
    {/if}

    {#if qrSvg}
      <div class="qr-container" aria-label="QR code for recovery key part 3">
        {@html qrSvg}
      </div>
    {:else if qrFailed}
      <p class="inline-error">QR code unavailable — use Copy or write down the key above.</p>
    {/if}

    <div class="backup-tips">
      <p class="tip-label">Backup options</p>
      <ul>
        <li>Save to a password manager (1Password, Bitwarden, etc.)</li>
        <li>Print and store in a safe place</li>
        <li>Write it down and keep it separate from your device</li>
      </ul>
    </div>
  </div>

  <label class="confirm-label">
    <input type="checkbox" bind:checked={confirmed} />
    I've saved Part 3 somewhere safe
  </label>

  {#if !confirmed}
    <p class="warning" role="alert">You must save your recovery key before continuing.</p>
  {/if}

  <button class="cta" onclick={oncomplete} disabled={!confirmed}>
    I've Saved My Backup
  </button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 1.5rem;
    gap: 1.25rem;
    overflow-y: auto;
  }

  .header h2 {
    font-size: 1.4rem;
    font-weight: 700;
    margin: 0 0 0.5rem;
  }

  .subtitle {
    font-size: 0.9rem;
    color: #6b7280;
    margin: 0;
    line-height: 1.5;
  }

  .share-row {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 12px;
    padding: 1rem;
  }

  .share-status {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .check-icon {
    width: 36px;
    height: 36px;
    background: #22c55e;
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    font-weight: 700;
    flex-shrink: 0;
  }

  .share-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0 0 0.2rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .share-desc {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0;
  }

  .share-block {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .share-code {
    font-family: monospace;
    font-size: 0.85rem;
    background: #fff;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 0.75rem;
    word-break: break-all;
    letter-spacing: 0.08em;
    line-height: 1.8;
  }

  .copy-btn {
    align-self: flex-start;
    padding: 0.4rem 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
  }

  .qr-container {
    display: flex;
    justify-content: center;
    padding: 0.5rem 0;
  }

  .qr-container :global(svg) {
    max-width: 180px;
    height: auto;
  }

  .inline-error {
    font-size: 0.8rem;
    color: #ef4444;
    margin: 0;
  }

  .backup-tips {
    border-top: 1px solid #e5e7eb;
    padding-top: 0.75rem;
  }

  .tip-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0 0 0.4rem;
  }

  ul {
    margin: 0;
    padding-left: 1.25rem;
    font-size: 0.85rem;
    color: #6b7280;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .confirm-label {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
  }

  .confirm-label input[type='checkbox'] {
    width: 20px;
    height: 20px;
    accent-color: #007aff;
    flex-shrink: 0;
  }

  .warning {
    font-size: 0.85rem;
    color: #ef4444;
    margin: 0;
    text-align: center;
  }

  .cta {
    width: 100%;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .cta:disabled {
    background: #93c5fd;
    cursor: not-allowed;
  }
</style>
