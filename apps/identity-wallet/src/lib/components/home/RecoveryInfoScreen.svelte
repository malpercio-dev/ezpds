<script lang="ts">
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';

  let {
    share1InKeychain,
    onback,
  }: {
    share1InKeychain: boolean;
    onback: () => void;
  } = $props();
</script>

<div class="screen">
  <button class="back" onclick={onback} aria-label="Back">
    <ChevronLeftIcon />
    Back
  </button>
  <h1 class="title">Recovery info</h1>

  <p class="desc">Your identity can be recovered with any 2 of 3 recovery shares.</p>

  <div class="share share--{share1InKeychain ? 'ok' : 'err'}">
    <span class="share-ic" aria-hidden="true">
      {#if share1InKeychain}
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
      {:else}
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6 6 18" /></svg>
      {/if}
    </span>
    <div class="share-info">
      <p class="share-label">Share 1 of 3</p>
      <p class="share-desc">
        {share1InKeychain
          ? 'Saved to iCloud Keychain — backed up automatically'
          : 'Not found in Keychain — this device may have lost it'}
      </p>
    </div>
  </div>

  <div class="share share--ok">
    <span class="share-ic" aria-hidden="true">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
    </span>
    <div class="share-info">
      <p class="share-label">Share 2 of 3</p>
      <p class="share-desc">Held by the relay — stored during account setup</p>
    </div>
  </div>

  <div class="share share--neutral">
    <span class="share-ic" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="2" width="8" height="4" rx="1" /><path d="M9 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-3" /></svg>
    </span>
    <div class="share-info">
      <p class="share-label">Share 3 of 3</p>
      <p class="share-desc">Your manual backup — shown during setup. Keep it safe.</p>
    </div>
  </div>

  <div class="note">
    <p>Any 2 shares together can restore your identity. Keep Share 3 somewhere safe and offline.</p>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }
  .back {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs) 0;
  }
  .title {
    font-size: var(--text-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }
  .desc {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    line-height: var(--leading-body);
  }

  .share {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    padding: var(--space-md);
    border-radius: var(--radius-lg);
  }
  .share--ok {
    background: var(--color-safe-surface);
  }
  .share--err {
    background: var(--color-critical-surface);
  }
  .share--neutral {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
  }

  .share-ic {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    color: var(--color-on-color);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .share--ok .share-ic {
    background: var(--color-safe);
  }
  .share--err .share-ic {
    background: var(--color-critical);
  }
  .share--neutral .share-ic {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
  }

  .share-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .share-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink-soft);
    margin: 0;
  }
  .share-desc {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.4;
  }

  .note {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    margin-top: auto;
  }
  .note p {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: var(--leading-body);
  }
</style>
