<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    share3,
    share3Words = '',
    oncomplete,
  }: {
    /** Machine form of Share 3 (base32 envelope) — the QR payload. */
    share3: string;
    /**
     * Share 3 as the BIP-39-style word phrase (same bytes) — the primary
     * human-custody rendering. Empty on legacy did:web ceremonies, where the
     * screen falls back to the machine form.
     */
    share3Words?: string;
    oncomplete: () => void;
  } = $props();

  let confirmed = $state(false);
  let copied = $state(false);
  let copyFailed = $state(false);
  let qrSvg = $state('');
  let qrFailed = $state(false);

  // The word phrase is what a human writes down; copy mirrors what is displayed.
  let words = $derived(share3Words.trim() === '' ? [] : share3Words.trim().split(/\s+/));
  let copyText = $derived(words.length > 0 ? words.join(' ') : share3);

  // Legacy fallback: format the machine share as groups of 4 for readability
  // (mirrors hardware wallet recovery key display conventions).
  let formattedShare = $derived(share3.match(/.{1,4}/g)?.join(' ') ?? share3);

  onMount(async () => {
    try {
      // The QR always carries the compact machine form — both forms encode the
      // identical share envelope, and base32 keeps the QR in alphanumeric mode.
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
      await navigator.clipboard.writeText(copyText);
      copied = true;
      copyFailed = false;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch (e) {
      // Clipboard denied or bridge error — show failure so the user knows to use another method.
      console.error('clipboard write failed:', e);
      copyFailed = true;
      setTimeout(() => {
        copyFailed = false;
      }, 3000);
    }
  }
</script>

<div class="screen">
  <div class="header">
    <h1 class="title">Back up your recovery key</h1>
    <p class="subtitle">
      Your recovery key has been split into 3 shares for safety. If you ever lose access to your
      account, any 2 shares can restore it.
    </p>
  </div>

  <div class="part part--saved">
    <span class="check" aria-hidden="true">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
    </span>
    <div>
      <p class="part-label">Share 1 of 3</p>
      <p class="part-desc">Saved to iCloud Keychain automatically</p>
    </div>
  </div>

  <div class="part part--saved">
    <span class="check" aria-hidden="true">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
    </span>
    <div>
      <p class="part-label">Share 2 of 3</p>
      <p class="part-desc">Held in your server's escrow</p>
    </div>
  </div>

  <div class="part-block">
    <p class="part-label">Share 3 of 3 — save this yourself</p>
    {#if words.length > 0}
      <ol class="word-grid" aria-label="Recovery share word phrase">
        {#each words as word, i (i)}
          <li class="word"><span class="word-index">{i + 1}</span>{word}</li>
        {/each}
      </ol>
    {:else}
      <code class="share-code">{formattedShare}</code>
    {/if}
    <button class="copy-btn" onclick={copyShare}>
      {copied ? 'Copied!' : 'Copy'}
    </button>
    {#if copyFailed}
      <p class="inline-error" role="alert">Copy failed. Please write it down or use the QR code.</p>
    {/if}

    {#if qrSvg}
      <!-- eslint-disable-next-line svelte/no-at-html-tags -->
      <div class="qr" aria-label="QR code for recovery key share 3">
        {@html qrSvg}
      </div>
    {:else if qrFailed}
      <p class="inline-error">QR code unavailable — use Copy or write down the key above.</p>
    {/if}

    <div class="tips">
      <p class="tips-label">Backup options</p>
      <ul>
        <li>Save to a password manager (1Password, Bitwarden, etc.)</li>
        <li>Print and store in a safe place</li>
        <li>Write it down and keep it separate from your device</li>
      </ul>
    </div>
  </div>

  <label class="confirm">
    <input type="checkbox" bind:checked={confirmed} />
    I've saved Share 3 somewhere safe
  </label>

  {#if !confirmed}
    <p class="warning" role="alert">You must save your recovery key before continuing.</p>
  {/if}

  <Button onclick={oncomplete} disabled={!confirmed}>I've saved my backup</Button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md);
    gap: var(--space-md);
    overflow-y: auto;
  }

  .title {
    font-family: var(--font-sans);
    font-size: 1.4rem;
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0 0 var(--space-sm);
  }
  .subtitle {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    line-height: var(--leading-body);
  }

  .part {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .part--saved {
    background: var(--color-safe-surface);
  }
  .check {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    background: var(--color-safe);
    color: var(--color-on-color);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .part-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink-soft);
    margin: 0 0 var(--space-3xs);
  }
  .part-desc {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }

  .part-block {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .word-grid {
    list-style: none;
    margin: 0;
    padding: var(--space-sm);
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2xs) var(--space-sm);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
  }
  .word {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink);
    display: flex;
    align-items: baseline;
    gap: var(--space-2xs);
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .word-index {
    font-size: var(--text-label);
    color: var(--color-muted);
    min-width: 1.4em;
    text-align: right;
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .share-code {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm);
    word-break: break-all;
    letter-spacing: 0.08em;
    line-height: 1.8;
    color: var(--color-ink);
  }
  .copy-btn {
    align-self: flex-start;
    padding: var(--space-xs) var(--space-md);
    background: var(--color-bg);
    color: var(--color-ink);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    cursor: pointer;
  }
  .qr {
    display: flex;
    justify-content: center;
    padding: var(--space-sm) 0;
  }
  .qr :global(svg) {
    max-width: 180px;
    height: auto;
  }
  .inline-error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
  .tips {
    border-top: 1px solid var(--color-line);
    padding-top: var(--space-sm);
  }
  .tips-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink-soft);
    margin: 0 0 var(--space-xs);
  }
  ul {
    margin: 0;
    padding-left: 1.25rem;
    font-size: var(--text-label);
    color: var(--color-muted);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .confirm {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    cursor: pointer;
  }
  .confirm input[type='checkbox'] {
    width: 20px;
    height: 20px;
    accent-color: var(--color-primary);
    flex-shrink: 0;
    cursor: pointer;
  }
  .warning {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    text-align: center;
  }
</style>
