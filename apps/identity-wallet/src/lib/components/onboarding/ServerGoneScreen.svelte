<script lang="ts">
  import { onMount } from 'svelte';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { loadIdentityCards, type IdentityCard } from '$lib/identity-cards';

  // "My server is gone" is the one situation that is NOT a journey of its own.
  //
  // Rebuilding an account elsewhere means signing a change to the identity itself, which
  // needs this wallet to hold the identity's top rotation key. So there is no rebuild flow
  // that starts here — there is only the question of whether the wallet already has custody:
  //
  //   * it does  → the work lives on that identity's "Move or rebuild" door, and this screen
  //                walks the user to it rather than growing a duplicate entrance;
  //   * it does not → share recovery has to come first, and this screen says so plainly and
  //                chains straight into it.
  //
  // Either way the user leaves with a next step. A dead end here would be the cruellest
  // possible place for one: they arrived because something already went wrong.
  let {
    onidentity,
    onlostwallet,
    onback,
  }: {
    /** Open this identity's "Move or rebuild" door. */
    onidentity: (card: IdentityCard) => void;
    /** Chain into share recovery — the prerequisite when the wallet is gone too. */
    onlostwallet: () => void;
    onback: () => void;
  } = $props();

  let cards = $state<IdentityCard[] | null>(null);

  onMount(async () => {
    try {
      cards = await loadIdentityCards();
    } catch (e) {
      // A failed read is reported as "no identities in this wallet", which routes to share
      // recovery — the same place an empty wallet goes, and the recoverable answer either
      // way. Claiming custody we could not confirm would be the harmful direction to err.
      console.warn('loadIdentityCards failed on ServerGoneScreen:', e);
      cards = [];
    }
  });

  function label(card: IdentityCard): string {
    // `@handle` matches how the home list names the same identity; a DID is shown bare
    // because it is not a handle and prefixing it would say it was.
    return card.handle ? `@${card.handle}` : card.did;
  }
</script>

<OnboardingShell
  title="Your server is gone"
  subtitle="Your identity is not your server. Which of these is true?"
  {onback}
>
  {#if cards === null}
    <div class="loading"><Spinner /></div>
  {:else if cards.length > 0}
    <div class="options">
      <p class="lede">
        This wallet already holds {cards.length === 1 ? 'an identity' : 'identities'}. That
        custody is what makes rebuilding possible — open the one you need and take the
        "Move or rebuild" door.
      </p>

      {#each cards as card (card.did)}
        <NavRow
          title={label(card)}
          subtitle="Move or rebuild this identity"
          onclick={() => onidentity(card)}
        >
          {#snippet icon()}
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /><path d="M3 21v-5h5" /></svg>
          {/snippet}
        </NavRow>
      {/each}

      <p class="foot">
        If the identity you mean is not listed, this wallet does not hold its keys yet —
        recover them first.
      </p>
      <NavRow
        title="That identity isn't here"
        subtitle="Rebuild wallet custody from your recovery shares, then rebuild the account"
        tone="door"
        onclick={onlostwallet}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>
        {/snippet}
      </NavRow>
    </div>
  {:else}
    <div class="options">
      <p class="lede">
        Rebuilding an account elsewhere is signed by the identity's own key — so the wallet
        has to hold that key before it can rebuild anything. This wallet holds none yet, so
        recovery comes first; the rebuild is waiting on the other side of it.
      </p>

      <NavRow
        title="Recover my wallet first"
        subtitle="Restore custody from your recovery shares, then rebuild the account elsewhere"
        onclick={onlostwallet}
      >
        {#snippet icon()}
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>
        {/snippet}
      </NavRow>

      <p class="foot">
        Recovery needs two of your three backup shares. It talks only to the public identity
        directory, so it does not need your old server to be alive.
      </p>
    </div>
  {/if}
</OnboardingShell>

<style>
  .options {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    width: 100%;
    text-align: left;
  }
  .lede {
    font-size: var(--text-body);
    color: var(--color-ink-soft);
    line-height: 1.5;
    margin: 0;
  }
  .foot {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: var(--space-2xs) 0 0;
  }
  .loading {
    display: flex;
    justify-content: center;
    padding: var(--space-lg) 0;
  }
</style>
