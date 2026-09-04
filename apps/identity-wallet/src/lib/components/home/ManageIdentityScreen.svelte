<script lang="ts">
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';

  // The maintenance door. What a person actually changes about an identity — its handle,
  // its backups, and the document that states both — is visible on entry; the protocol-level
  // tools sit one more deliberate step down, behind a vestibule that says what they are.
  //
  // The everyday tier carries no group label: it is what this screen is for, and labelling
  // it would imply a sibling group at the same level that does not exist.
  let {
    onback,
    onchangehandle,
    onbackups,
    ondiddocument,
    onadvanced,
  }: {
    onback: () => void;
    /** Sovereign change-handle. did:plc whose top rotation key is on this device only. */
    onchangehandle?: () => void;
    /** The media + posts backup surface, presented as one thing because it is one job. */
    onbackups: () => void;
    /** The DID document, as an inspection and verification surface. */
    ondiddocument: () => void;
    /** The vestibule in front of the protocol-level tools. */
    onadvanced: () => void;
  } = $props();
</script>

<div class="screen u-screen-lg">
  <ScreenHeader title="Manage identity" onback={onback} backLabel="Back to identity" />

  <section class="zone">
    {#if onchangehandle}
      <NavRow
        title="Change handle"
        subtitle="The @name people use to find you"
        onclick={onchangehandle}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4" /><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8" /></svg>
        {/snippet}
      </NavRow>
    {/if}

    <NavRow
      title="Backups"
      subtitle="Your own copy of your posts and media, in iCloud"
      onclick={onbackups}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19a4.5 4.5 0 0 0 .3-9 6.5 6.5 0 0 0-12.4 1.7A3.9 3.9 0 0 0 6 19z" /><path d="M12 12v5" /><path d="m9.5 14.5 2.5-2.5 2.5 2.5" /></svg>
      {/snippet}
    </NavRow>

    <NavRow
      title="DID document"
      subtitle="The public record of your identity's keys and server"
      onclick={ondiddocument}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7z" /><path d="M14 2v5h5" /><path d="M9 13h6" /><path d="M9 17h4" /></svg>
      {/snippet}
    </NavRow>
  </section>

  <section class="zone">
    <NavRow
      tone="door"
      title="Advanced"
      subtitle="Protocol-level tools you rarely need"
      onclick={onadvanced}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m14.5 5.5 4 4" /><path d="M8 21H3v-5L16.5 2.5a2.1 2.1 0 0 1 3 3z" /><path d="M3 16h5v5" /></svg>
      {/snippet}
    </NavRow>
  </section>
</div>

<style>
  .zone {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
</style>
