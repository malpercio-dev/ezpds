<script lang="ts">
  import {
    startShareRecovery,
    verifyRecoveryShares,
    isCodedError,
    type CollectedShare,
    type ShareRecoveryError,
  } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import RecoverSharesScreen from '$lib/components/onboarding/RecoverSharesScreen.svelte';
  import RecoverEscrowScreen from '$lib/components/onboarding/RecoverEscrowScreen.svelte';

  // Backfill the delegation seed for an identity created before agent accounts existed.
  //
  // The seed is derived from the account's recovery seed, so provisioning is the *first half*
  // of the recovery ceremony and nothing more: collect two shares, verify them against the
  // public record, stop. `verifyRecoveryShares` persists the seed as a side effect of the
  // verification that proves these shares really are this identity's — which is why this
  // screen deliberately never reaches `recoverIdentity`. No key is rotated, no PLC operation is
  // submitted, and the identity is untouched apart from one new Keychain entry.
  let {
    did,
    handle,
    onback,
    ondone,
  }: {
    did: string;
    handle: string | null;
    onback: () => void;
    /** Provisioning succeeded — the caller re-checks `agentAccountsProvisioned`. */
    ondone: () => void;
  } = $props();

  type Phase = 'intro' | 'shares' | 'escrow' | 'verifying' | 'done';
  let phase = $state<Phase>('intro');
  let collected = $state<CollectedShare[]>([]);
  let starting = $state(false);
  let error = $state<string | null>(null);

  function describeError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch ((raw as ShareRecoveryError).code) {
        case 'SHARES_DO_NOT_MATCH_IDENTITY':
          return "These shares don't match this identity. They may belong to a different account, or to a backup that was replaced by a newer one.";
        case 'SHARES_INCOMPLETE':
          return 'Two shares are needed. Go back and add another.';
        case 'UNSUPPORTED_IDENTITY':
          return 'Only did:plc identities have recovery shares, so this identity cannot be set up this way.';
        case 'NETWORK_ERROR':
          return 'Couldn’t reach the server. Check your connection and try again.';
        default:
          return `Something went wrong (${(raw as ShareRecoveryError).code}). Please try again.`;
      }
    }
    return 'Something went wrong. Please try again.';
  }

  async function begin() {
    starting = true;
    error = null;
    try {
      const target = await startShareRecovery(did);
      collected = target.collected;
      phase = 'shares';
    } catch (raw: unknown) {
      console.error('[EnableAgentAccounts] starting share collection failed:', raw);
      error = describeError(raw);
    } finally {
      starting = false;
    }
  }

  async function verify() {
    phase = 'verifying';
    error = null;
    try {
      await verifyRecoveryShares();
      phase = 'done';
    } catch (raw: unknown) {
      console.error('[EnableAgentAccounts] share verification failed:', raw);
      error = describeError(raw);
      phase = 'shares';
    }
  }
</script>

{#if phase === 'shares'}
  <RecoverSharesScreen
    bind:collected
    onescrow={() => (phase = 'escrow')}
    onverify={verify}
    onback={onback}
  />
  {#if error}
    <p class="inline-error" role="alert">{error}</p>
  {/if}
{:else if phase === 'escrow'}
  <RecoverEscrowScreen
    onreleased={(share) => {
      collected = [...collected.filter((s) => s.index !== share.index), share];
      phase = 'shares';
    }}
    onback={() => (phase = 'shares')}
  />
{:else if phase === 'verifying'}
  <OnboardingShell title="Checking your shares" subtitle="Verifying them against the public record.">
    <div class="center"><Spinner /></div>
  </OnboardingShell>
{:else if phase === 'done'}
  <OnboardingShell
    title="Agent accounts enabled"
    subtitle={handle ? `${handle} can now give an agent an account of its own.` : undefined}
  >
    {#snippet icon()}
      <SealEmblem>
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="m9 11.5 2 2 4-4" />
        </svg>
      </SealEmblem>
    {/snippet}
    <p class="body">
      Nothing about your identity changed. This device now holds one extra secret, derived from
      your recovery shares, that signs the keys of any account you create for an agent.
    </p>
    <p class="body">
      Because it comes from your shares, the same two shares restore it on any device — and it
      never leaves this one.
    </p>
    <Button onclick={ondone}>Done</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell
    title="Enable agent accounts"
    subtitle="Give an agent its own account instead of the keys to yours."
    onback={onback}
  >
    {#snippet icon()}
      <SealEmblem>
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="4" y="10" width="16" height="10" rx="2" />
          <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        </svg>
      </SealEmblem>
    {/snippet}
    <p class="body">
      An agent with its own account posts under its own name, and you own the keys to it. Setting
      that up needs one secret this identity predates — derived from your recovery shares, so it
      is the shares themselves that unlock it.
    </p>
    <p class="body">
      You will enter two of your three recovery shares, exactly as you would to recover this
      identity on a new device. <strong>Nothing is rotated or published</strong> — the shares are
      checked against the public record and then only this device changes.
    </p>
    {#if error}
      <p class="inline-error" role="alert">{error}</p>
    {/if}
    <Button onclick={begin} disabled={starting}>
      {starting ? 'Starting…' : 'Enter recovery shares'}
    </Button>
  </OnboardingShell>
{/if}

<style>
  .body {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.55;
    margin: 0 0 var(--space-md);
    text-align: left;
  }

  .center {
    display: flex;
    justify-content: center;
    padding: var(--space-lg) 0;
  }

  .inline-error {
    font-size: var(--text-body);
    color: var(--color-critical);
    line-height: 1.5;
    margin: 0 0 var(--space-md);
    text-align: left;
  }
</style>
