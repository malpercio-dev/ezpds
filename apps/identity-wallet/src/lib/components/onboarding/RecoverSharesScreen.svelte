<script lang="ts">
  import { addRecoveryShare, isCodedError, type CollectedShare, type ShareRecoveryError } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    collected = $bindable([] as CollectedShare[]),
    onescrow,
    onverify,
    onback,
  }: {
    collected: CollectedShare[];
    /** Start the escrow-assisted path (Share 2 via emailed code). */
    onescrow: () => void;
    /** Two shares collected — continue to verification. */
    onverify: () => void;
    onback: () => void;
  } = $props();

  let manualShare = $state('');
  let adding = $state(false);
  let error = $state<string | null>(null);

  const SHARE_HOMES: Record<number, string> = {
    1: 'iCloud Keychain share',
    2: 'Server escrow share',
    3: 'Your saved backup share',
  };

  async function addManual() {
    if (!manualShare.trim()) return;
    adding = true;
    error = null;
    try {
      const share = await addRecoveryShare(manualShare);
      collected = [...collected.filter((s) => s.index !== share.index), share];
      manualShare = '';
    } catch (raw: unknown) {
      console.error('Adding share failed:', raw);
      if (isCodedError(raw)) {
        switch ((raw as ShareRecoveryError).code) {
          case 'SHARE_CHECKSUM':
            error =
              "This share is damaged or mistyped — its check digits don't match. Re-check each word or character and try again.";
            break;
          case 'SHARE_SET_MISMATCH':
            error =
              'This share is from a different backup generation than the one already collected. Shares only work together when they were created together — find the matching copy.';
            break;
          case 'DUPLICATE_SHARE':
            error = 'This share is already collected. Enter a different one.';
            break;
          case 'SHARE_VERSION':
            error = 'This share was created by a newer version of the app. Update the app and try again.';
            break;
          case 'SHARE_FORMAT':
            error = "This doesn't look like a backup share. Paste the word phrase or the code from your QR backup.";
            break;
          default:
            error = `An unexpected error occurred (${raw.code}). Please try again.`;
        }
      } else {
        error = 'An unexpected error occurred. Please try again.';
      }
    } finally {
      adding = false;
    }
  }

  let haveTwo = $derived(collected.length >= 2);
</script>

<OnboardingShell
  title="Collect two shares"
  subtitle="Your identity was split into three shares. Any two of them recover it — no single share reveals anything."
  {onback}
>
  <div class="shares" role="status">
    <p class="count">{Math.min(collected.length, 2)} of 2 shares collected</p>
    {#each collected as share (share.index)}
      <div class="share-row">
        <span class="glyph" aria-hidden="true">✓</span>
        <span class="body">
          <span class="label">Share {share.index} — {SHARE_HOMES[share.index] ?? 'Backup share'}</span>
          <span class="meta">Set {share.setId.toString(16).padStart(8, '0')}</span>
        </span>
      </div>
    {/each}
  </div>

  {#if !haveTwo}
    <div class="option">
      <p class="option-title">Ask your server for its share</p>
      <p class="option-copy">
        Your server holds Share 2 in escrow. Releasing it needs a code sent to your account email,
        and may include a waiting period you can cancel from any signed-in device.
      </p>
      <Button variant="secondary" onclick={onescrow}>Request escrow share</Button>
    </div>

    <div class="option">
      <p class="option-title">Enter a share yourself</p>
      <p class="option-copy">Type the word phrase from your saved backup, or paste a share code.</p>
      <textarea
        bind:value={manualShare}
        rows="3"
        placeholder="anchor baker canyon … (or the share code)"
        autocapitalize="none"
        spellcheck={false}
        aria-label="Backup share"
        class:has-error={error !== null}
      ></textarea>
      {#if error}
        <p class="error" role="alert">{error}</p>
      {/if}
      <Button variant="secondary" disabled={adding || !manualShare.trim()} onclick={addManual}>
        {adding ? 'Checking…' : 'Add share'}
      </Button>
    </div>
  {/if}

  {#if haveTwo}
    <Button onclick={onverify}>Verify shares</Button>
  {/if}
</OnboardingShell>

<style>
  .shares {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .count {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
    text-align: left;
  }
  .share-row {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
    text-align: left;
  }
  .glyph {
    color: var(--color-safe);
    font-size: var(--text-title);
    line-height: 1.2;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  .label {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .meta {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
  }

  .option {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    text-align: left;
  }
  .option-title {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .option-copy {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.4;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm);
    resize: vertical;
  }
  textarea:focus {
    outline: 2px solid var(--color-primary-deep);
    outline-offset: 1px;
  }
  textarea.has-error {
    border-color: var(--color-critical);
  }
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }
</style>
