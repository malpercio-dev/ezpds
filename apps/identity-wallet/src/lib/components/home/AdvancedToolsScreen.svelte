<script lang="ts">
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';

  // The vestibule, then the surgery.
  //
  // Depth is the warning; this screen is the consent. It says plainly what this tier of
  // tools does before showing any of it, so nobody arrives at a protocol-level operation
  // without having read what tier they are in. It is additive framing only — every
  // operation below keeps its own biometric gate, its own review of the exact change to be
  // signed, and its own hold-to-confirm where it has one. Nothing here replaces those.
  let {
    onback,
    onrotatekey,
    onrecoverykit,
    onrepairendpoint,
    onremove,
  }: {
    onback: () => void;
    /** Replace the server-held commit-signing key. did:plc + top rotation key on device. */
    onrotatekey?: () => void;
    /** Add an escrow-less recovery key (the self-held Shamir kit). Offered only where the
     *  host advertises no escrow, so the better escrow-backed ceremony is never shadowed. */
    onrecoverykit?: () => void;
    /** Repoint the DID document at a host that changed hostname underneath the account. */
    onrepairendpoint?: () => void;
    /** Permanent removal: delete on the server, retire the DID, wipe this device. */
    onremove: () => void;
  } = $props();
</script>

<div class="screen">
  <ScreenHeader title="Advanced" onback={onback} backLabel="Back to manage identity" />

  <div class="vestibule">
    <span class="vestibule-ic" aria-hidden="true">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
    </span>
    <div class="vestibule-body">
      <p class="vestibule-t">These tools change how your identity works underneath</p>
      <p class="vestibule-s">
        They act on the protocol itself — the keys that prove the identity is yours, the
        server it points at, whether it exists at all. You rarely need them, and each one
        explains exactly what it will sign, and asks you to confirm, before anything happens.
      </p>
    </div>
  </div>

  <section class="zone">
    {#if onrecoverykit}
      <NavRow
        title="Add a recovery key"
        subtitle="A second way back in if this device is lost, with every share held by you"
        onclick={onrecoverykit}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4" /><path d="m10.8 12.2 8.2-8.2" /><path d="m17 6 2 2" /><path d="m14.5 8.5 2 2" /></svg>
        {/snippet}
      </NavRow>
    {/if}

    {#if onrotatekey}
      <NavRow
        title="Rotate repo signing key"
        subtitle="Replace the key your server uses to sign your posts"
        onclick={onrotatekey}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /><path d="M3 21v-5h5" /></svg>
        {/snippet}
      </NavRow>
    {/if}

    {#if onrepairendpoint}
      <NavRow
        title="Repair hosting endpoint"
        subtitle="For when your server changed address and clients can no longer find you"
        onclick={onrepairendpoint}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7" /><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" /></svg>
        {/snippet}
      </NavRow>
    {/if}

    <NavRow
      tone="critical"
      title="Remove identity…"
      subtitle="Delete the account on your server and retire the identity. This cannot be undone."
      onclick={onremove}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18" /><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" /><path d="M10 11v6" /><path d="M14 11v6" /></svg>
      {/snippet}
    </NavRow>
  </section>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-lg);
    overflow-y: auto;
  }

  /* Framing, not an alarm: the seal tint the brief reserves for revealing the machinery,
     never the warning or critical palette. Nothing has gone wrong — the user simply walked
     into the room where the machinery lives. */
  .vestibule {
    display: flex;
    gap: var(--space-sm);
    background: var(--color-seal-tint);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .vestibule-ic {
    width: 38px;
    height: 38px;
    border-radius: var(--radius-full);
    background: var(--color-bg);
    color: var(--color-accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .vestibule-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    min-width: 0;
  }
  .vestibule-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .vestibule-s {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    line-height: 1.5;
    margin: 0;
  }

  .zone {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
</style>
