<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';

  // One situation question, replacing the old door taxonomy.
  //
  // The doors this supersedes ("Create an identity" / "Import an identity" / "Recover from
  // backup shares") named the *machinery* — and their names were near-synonymous to anyone
  // who had not already learned the machinery, which is precisely the person standing here
  // on first launch. Someone whose server has just vanished can tell you their situation
  // long before they can tell you whether that calls for an import, a recovery, or a
  // rebuild. So the screen asks the question they can answer and does the routing itself.
  //
  // Every downstream ceremony is unchanged; this screen only chooses which one to enter.
  let {
    onfresh,
    onexisting,
    onlostwallet,
    onservergone,
    onback = undefined,
  }: {
    /** Make a brand-new identity — the create ceremony (method choice one level in). */
    onfresh: () => void;
    /** Take custody of an account that already exists elsewhere — the claim flow. */
    onexisting: () => void;
    /** Rebuild wallet custody from recovery shares — the share-recovery ceremony. */
    onlostwallet: () => void;
    /** Not a flow: honest routing for a dead host (see ServerGoneScreen). */
    onservergone: () => void;
    /** Absent on first launch, where there is no home to go back to. */
    onback?: () => void;
  } = $props();
</script>

<OnboardingShell
  tone="signet"
  title="Add an identity"
  subtitle="What's your situation?"
  {onback}
>
  {#snippet icon()}
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 11.5 2 2 4-4" />
      </svg>
    </SealEmblem>
  {/snippet}

  <div class="options">
    <NavRow
      title="Starting fresh"
      subtitle="Make a brand-new identity on a server you choose"
      onclick={onfresh}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14" /><path d="M5 12h14" /></svg>
      {/snippet}
    </NavRow>

    <NavRow
      title="I have an account somewhere"
      subtitle="Hold the keys to a Bluesky or ATProto account you already use"
      onclick={onexisting}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a4 4 0 0 0-4-4h-3.5" /><path d="m16 5-3 3 3 3" /><path d="M7 8v12" /><circle cx="7" cy="5" r="2" /></svg>
      {/snippet}
    </NavRow>

    <NavRow
      title="I lost access to my wallet"
      subtitle="Rebuild custody of an identity from your recovery shares"
      onclick={onlostwallet}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /><path d="M3 21v-5h5" /></svg>
      {/snippet}
    </NavRow>

    <NavRow
      title="My server is gone"
      subtitle="Your host disappeared and you need the identity somewhere else"
      onclick={onservergone}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2" /><path d="M3 17a2 2 0 0 1 2-2h6" /><path d="M7 7.5h.01" /><path d="m15 15 6 6" /><path d="m21 15-6 6" /></svg>
      {/snippet}
    </NavRow>
  </div>
</OnboardingShell>

<style>
  .options {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    width: 100%;
    /* The shell centres its column; these rows read as a list, so they own their
       alignment rather than inheriting the centred text. */
    text-align: left;
  }
</style>
