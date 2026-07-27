<script lang="ts">
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';

  // The exit door. Moving to another server and rebuilding from your own backup are the
  // same job seen from two sides — "this identity is mine to take elsewhere" — so they
  // share one entry, placed where it can be found rather than filed under maintenance.
  // A credible exit is the sovereignty claim made structural; burying it would quietly
  // withdraw the claim.
  let {
    onback,
    onmigrate,
    onrebuild,
  }: {
    onback: () => void;
    /** Wallet-authorized outbound migration. Withheld unless this device holds the top
     *  rotation key — nothing here can sign the identity leg without it. */
    onmigrate?: () => void;
    /** Sovereign disaster recovery: rebuild the account on a new host from the iCloud
     *  backups. did:plc + top rotation key only. */
    onrebuild?: () => void;
  } = $props();
</script>

<div class="screen">
  <ScreenHeader title="Move or rebuild" onback={onback} backLabel="Back to identity" />

  <p class="lede">
    This identity is yours to take with you. Both routes keep the same identifier and the
    same followers — what changes is which server holds your data.
  </p>

  {#if onmigrate}
    <NavRow
      title="Move to another server"
      subtitle="Copy your posts and media to a new host, then repoint your identity to it"
      onclick={onmigrate}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 17V7a2 2 0 0 1 2-2h7" /><path d="m10 8 3-3-3-3" /><path d="M20 7v10a2 2 0 0 1-2 2h-7" /><path d="m14 16-3 3 3 3" /></svg>
      {/snippet}
    </NavRow>
  {/if}

  {#if onrebuild}
    <NavRow
      title="Rebuild from backup"
      subtitle="For when your current server is gone: recreate the account elsewhere from your own iCloud copy"
      onclick={onrebuild}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /><path d="M3 21v-5h5" /></svg>
      {/snippet}
    </NavRow>
  {/if}

  {#if !onmigrate && !onrebuild}
    <!-- Never an empty list: an absent route is a fact about this identity's key custody,
         and saying so is the difference between a missing feature and an explained one. -->
    <div class="note" role="note">
      <p class="note-t">Neither route is available for this identity</p>
      <p class="note-s">
        Both work by signing a change to the identity itself, which needs this device to
        hold its top rotation key. Restore that first and they reappear here.
      </p>
    </div>
  {:else if !onrebuild}
    <p class="foot">
      Rebuilding from backup needs a did:plc identity whose top rotation key is on this
      device. A did:web moves by editing its <code>did.json</code> at your domain instead.
    </p>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-sm);
    overflow-y: auto;
  }
  .lede {
    font-size: var(--text-body);
    color: var(--color-ink-soft);
    line-height: 1.5;
    margin: var(--space-2xs) 0 var(--space-xs);
  }
  .foot {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: var(--space-2xs) 0 0;
  }
  .foot code {
    font-family: var(--font-mono);
    font-size: 0.92em;
    background: var(--color-surface-sunk);
    padding: 1px 4px;
    border-radius: var(--radius-sm);
  }
  .note {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .note-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .note-s {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    line-height: 1.5;
    margin: 0;
  }
</style>
