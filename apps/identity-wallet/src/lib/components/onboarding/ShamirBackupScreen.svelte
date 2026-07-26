<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    share3,
    share3Words = '',
    share2 = '',
    share2Words = '',
    confirmError = null,
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
    /**
     * Machine form of Share 2, passed ONLY by the escrow-less self-held kit, where the user
     * holds Share 2 as well because no server escrows it. Empty on every escrowed ceremony —
     * the create flow, the did:web ceremony, and the re-key — where Share 2 is a machine
     * deposit the user never sees, and the screen keeps its "held in your server's escrow"
     * framing. Passing it is what turns this screen from "save one share" into "save two".
     */
    share2?: string;
    /** Share 2 as the BIP-39-style word phrase (same bytes). */
    share2Words?: string;
    /**
     * Failure from the parent's confirmation step (biometric gate or staging
     * teardown). The user stays here and can retry via the same button.
     */
    confirmError?: string | null;
    oncomplete: () => void;
  } = $props();

  /** One share the user must physically keep, in the order the screen presents them. */
  type SelfHeldShare = { index: number; code: string; words: string[] };

  let confirmed = $state(false);
  let copiedIndex = $state<number | null>(null);
  let copyFailedIndex = $state<number | null>(null);
  let qrSvgs = $state<Record<number, string>>({});
  let qrFailed = $state(false);

  const toWords = (phrase: string) => (phrase.trim() === '' ? [] : phrase.trim().split(/\s+/));

  // Share 2 leads when the user holds it, because it is the one an escrowed ceremony would
  // have kept from them — presenting it second would read as an afterthought.
  let selfHeld = $derived<SelfHeldShare[]>([
    ...(share2 === '' ? [] : [{ index: 2, code: share2, words: toWords(share2Words) }]),
    { index: 3, code: share3, words: toWords(share3Words) },
  ]);
  let escrowsShare2 = $derived(share2 === '');

  // Legacy fallback: format a machine share as groups of 4 for readability
  // (mirrors hardware wallet recovery key display conventions).
  const formatCode = (code: string) => code.match(/.{1,4}/g)?.join(' ') ?? code;

  // Encoded per share, not per screen: a failure on one share must not discard another's
  // already-rendered QR. With two self-held shares the all-or-nothing form would have let a
  // single encoder hiccup blank both, and this screen is the user's one chance to capture them.
  onMount(async () => {
    const rendered: Record<number, string> = {};
    for (const share of selfHeld) {
      try {
        // The QR always carries the compact machine form — both forms encode the
        // identical share envelope, and base32 keeps the QR in alphanumeric mode.
        rendered[share.index] = await QRCode.toString(share.code, {
          type: 'svg',
          width: 200,
          margin: 2,
        });
      } catch {
        // Only this share loses its QR; its text and copy button remain intact.
        qrFailed = true;
      }
    }
    qrSvgs = rendered;
  });

  async function copyShare(share: SelfHeldShare) {
    try {
      await navigator.clipboard.writeText(
        share.words.length > 0 ? share.words.join(' ') : share.code
      );
      copiedIndex = share.index;
      copyFailedIndex = null;
      setTimeout(() => {
        copiedIndex = null;
      }, 2000);
    } catch (e) {
      // Clipboard denied or bridge error — show failure so the user knows to use another method.
      console.error('clipboard write failed:', e);
      copyFailedIndex = share.index;
      setTimeout(() => {
        copyFailedIndex = null;
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
      <!-- Honest by construction: the app can prove it wrote the share into the Keychain
           marked for iCloud sync, but iOS gives it no way to observe whether the share
           actually reached the Apple account — so the copy claims only the write.
           The design plan hoped to at least surface whether iCloud Keychain is enabled for
           the account; iOS publishes no API for that toggle either (iCloud Drive / KVS
           availability is a different switch and would mislead), so this takes the plan's
           documented fallback: state the condition, don't assert it holds. -->
      <p class="part-desc">
        Saved to your Keychain — set to sync to your other Apple devices when iCloud Keychain
        is on
      </p>
    </div>
  </div>

  {#if escrowsShare2}
    <div class="part part--saved">
      <span class="check" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
      </span>
      <div>
        <p class="part-label">Share 2 of 3</p>
        <p class="part-desc">Held in your server's escrow</p>
      </div>
    </div>
  {:else}
    <p class="self-held-note">
      Your server doesn't hold recovery shares, so Shares 2 and 3 are both yours to keep. Any
      two of the three shares restore this identity — store these two apart from each other.
    </p>
  {/if}

  {#each selfHeld as share (share.index)}
    <div class="part-block">
      <p class="part-label">Share {share.index} of 3 — save this yourself</p>
      {#if share.words.length > 0}
        <ol class="word-grid" aria-label="Recovery share {share.index} word phrase">
          {#each share.words as word, i (i)}
            <li class="word"><span class="word-index">{i + 1}</span>{word}</li>
          {/each}
        </ol>
      {:else}
        <code class="share-code">{formatCode(share.code)}</code>
      {/if}
      <button class="copy-btn" onclick={() => copyShare(share)}>
        {copiedIndex === share.index ? 'Copied!' : 'Copy'}
      </button>
      {#if copyFailedIndex === share.index}
        <p class="inline-error" role="alert">
          Copy failed. Please write it down or use the QR code.
        </p>
      {/if}

      {#if qrSvgs[share.index]}
        <!-- eslint-disable-next-line svelte/no-at-html-tags -->
        <div class="qr" aria-label="QR code for recovery key share {share.index}">
          {@html qrSvgs[share.index]}
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
  {/each}

  <label class="confirm">
    <input type="checkbox" bind:checked={confirmed} />
    {escrowsShare2
      ? "I've saved Share 3 somewhere safe"
      : "I've saved Shares 2 and 3 somewhere safe"}
  </label>

  {#if !confirmed}
    <p class="warning" role="alert">You must save your recovery key before continuing.</p>
  {/if}

  {#if confirmError}
    <p class="warning" role="alert">{confirmError}</p>
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

  .self-held-note {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    line-height: var(--leading-body);
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
