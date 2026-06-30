<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { pairingState, generateClaimCode, type Pairing } from '$lib/ipc';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import { shareText } from '$lib/share';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // Phase 8 Home: the demo-lifesaver flow, focused. A paired operator generates an account
  // claim code over a signed request, gated by biometric user-presence, and shares it via
  // the iOS Share Pane or copies it. An unpaired app never calls the endpoint — it routes
  // to Pair. Device detail and unpair live in Settings.

  // 'error' is distinct from null (unpaired): a failed pairing read leaves the real state
  // unknown, so we must not expose the Generate action against an unknown pairing.
  let pairing = $state<Pairing | null | 'loading' | 'error'>('loading');

  let claiming = $state(false);
  let claimCode = $state<string | undefined>(undefined);
  let claimErrorView = $state<ErrorView | undefined>(undefined);
  // A cancelled biometric prompt is not a failure — a quiet info hint, not an alarm.
  let gateHint = $state<string | undefined>(undefined);
  let shareHint = $state<string | undefined>(undefined);

  onMount(reloadPairing);

  async function reloadPairing() {
    pairing = 'loading';
    try {
      pairing = await pairingState();
    } catch {
      pairing = 'error';
    }
  }

  async function mintClaimCode() {
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent mints.
    if (claiming) return;
    claiming = true;
    gateHint = undefined;
    shareHint = undefined;
    try {
      // Confirm user presence before signing. A denial blocks; a disabled gate or an
      // off-device build proceeds (see requireUserPresence).
      const presence = await requireUserPresence('Generate a claim code');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to generate a claim code.';
        return;
      }
      claimErrorView = undefined;
      // Drop the prior code so a failed mint never leaves a stale code beside the error.
      claimCode = undefined;
      claimCode = await generateClaimCode();
    } catch (e) {
      claimErrorView = classifyRelayError(e);
    } finally {
      claiming = false;
    }
  }

  async function shareCode() {
    if (!claimCode) return;
    shareHint = undefined;
    const opened = await shareText(claimCode);
    if (!opened) {
      shareHint = "Sharing isn't available here — copy the code instead.";
    }
  }

  const isPaired = $derived(
    pairing !== null && pairing !== 'loading' && pairing !== 'error',
  );
</script>

<ScreenShell prompt="claim code" title="Generate a claim code">
  {#if pairing === 'loading'}
    <p class="resolving">checking pairing…</p>
  {:else if pairing === 'error'}
    <section class="panel" aria-label="Pairing check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">
        Couldn't read this device's pairing state. This is not the same as being unpaired —
        retry before pairing again.
      </p>
      <Button variant="secondary" onclick={reloadPairing}>Retry</Button>
    </section>
  {:else if pairing === null}
    <!-- Unpaired — route to Pair, never call the endpoint. -->
    <section class="panel" aria-label="Not paired">
      <StatusChip status="pending" label="not paired" />
      <p class="note">
        This device isn't paired with a relay yet. Pair it to mint account claim codes from
        your phone.
      </p>
    </section>
  {:else}
    <p class="lede">
      Mint a single-use account claim code, signed by this device. Share it with the person
      onboarding, or copy it.
    </p>

    {#if claimCode}
      <CodeOutput value={claimCode} label="Account claim code" onshare={shareCode} />
      {#if shareHint}
        <p class="hint" role="status">
          <StatusChip status="info" label="copy" />
          <span>{shareHint}</span>
        </p>
      {/if}
    {/if}

    {#if claimErrorView}
      <ErrorState
        view={claimErrorView}
        relayUrl={pairing.relayUrl}
        retrying={claiming}
        onretry={mintClaimCode}
        onpair={() => goto('/pair')}
      />
    {/if}

    {#if gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{gateHint}</span>
      </p>
    {/if}
  {/if}

  {#snippet actions()}
    {#if isPaired}
      <Button variant="primary" loading={claiming} onclick={mintClaimCode}>
        {claimCode ? 'Generate another code' : 'Generate claim code'}
      </Button>
      <Button variant="secondary" onclick={() => goto('/settings')}>Settings</Button>
    {:else if pairing === null}
      <Button variant="primary" onclick={() => goto('/pair')}>Pair this device</Button>
    {/if}
    <!-- 'loading'/'error': no primary action until the real pairing state is known. -->
  {/snippet}
</ScreenShell>

<style>
  .panel {
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .lede {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .note {
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .resolving {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .hint {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
</style>
