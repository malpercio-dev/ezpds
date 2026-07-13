<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { listPairings, setActivePairing, generateClaimCode, unpair, type PairingsState } from '$lib/ipc';
  import { serverIdentity, type ServerIdentity } from '$lib/server-identity';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import { shareText } from '$lib/share';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // Home: multi-server home, tappable identity block opening an inline switcher,
  // explicit pick required when active is cleared (two+ remaining). The demo-lifesaver flow
  // is unchanged: generate a claim code via a signed request gated by biometric, share via
  // iOS Share Pane or copy. An unpaired app routes to Pair; a no-active-pick app forces
  // a server selection before any action.

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let switcherOpen = $state(false);

  let claiming = $state(false);
  let claimCode = $state<string | undefined>(undefined);
  // The server the shown code was actually minted for — pinned when the mint starts, so
  // switching servers while a mint is in flight can never relabel A's code as B's.
  let claimCodeServer = $state<ServerIdentity | null>(null);
  let claimErrorView = $state<ErrorView | undefined>(undefined);
  // The server a failure is attributed to — the *attempted* pairing for a switch error
  // (the active selection is unchanged there, so `identity` would name the wrong relay).
  let claimErrorServer = $state<ServerIdentity | null>(null);
  // A cancelled biometric prompt is not a failure — a quiet info hint, not an alarm.
  let gateHint = $state<string | undefined>(undefined);
  let shareHint = $state<string | undefined>(undefined);

  onMount(reloadPairings);

  async function reloadPairings() {
    pairingsView = 'loading';
    try {
      pairingsView = await listPairings();
    } catch {
      pairingsView = 'error';
    }
  }

  async function mintClaimCode() {
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent mints.
    if (claiming) return;
    claiming = true;
    gateHint = undefined;
    shareHint = undefined;
    // Pinned to the server the mint acts on, so a switch during the in-flight request
    // can never relabel the code (or a failure) with another server's identity.
    let target: ServerIdentity | null = null;
    try {
      // Confirm user presence before signing. A denial blocks; a disabled gate or an
      // off-device build proceeds (see requireUserPresence).
      const presence = await requireUserPresence('Generate a claim code');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to generate a claim code.';
        return;
      }
      claimErrorView = undefined;
      claimErrorServer = null;
      // Drop the prior code so a failed mint never leaves a stale code beside the error.
      claimCode = undefined;
      claimCodeServer = null;
      // Captured in the same tick the Rust side resolves the active pairing.
      target = identity;
      claimCode = await generateClaimCode();
      claimCodeServer = target;
    } catch (e) {
      claimErrorView = classifyRelayError(e);
      claimErrorServer = target ?? identity;
      await reloadPairings();
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

  async function switchServer(id: string) {
    // Capture the tapped pairing before anything can change the list, so a failure
    // (e.g. a stale row → NO_SUCH_PAIRING) is attributed to the server the operator
    // actually tried to select, not the unchanged active one.
    const attempted = pairings.find((p) => p.id === id);
    try {
      await setActivePairing(id);
      await reloadPairings();
      switcherOpen = false;
      // Clear stale code so a code minted for the old server never shows beside the new identity.
      claimCode = undefined;
      claimCodeServer = null;
      claimErrorView = undefined;
      claimErrorServer = null;
    } catch (e) {
      claimErrorView = classifyRelayError(e);
      claimErrorServer = attempted ? serverIdentity(attempted) : identity;
      await reloadPairings();
    }
  }

  async function forgetActive() {
    if (!activePairing) return;
    try {
      await unpair(activePairing.id);
      await reloadPairings();
      // Clear state scoped to the forgotten server — a code it minted or an error it
      // produced must never render beside an auto-promoted successor's identity.
      claimCode = undefined;
      claimCodeServer = null;
      claimErrorView = undefined;
      claimErrorServer = null;
    } catch (e) {
      claimErrorView = classifyRelayError(e);
      claimErrorServer = identity;
      await reloadPairings();
    }
  }

  const loadedState = $derived.by(() => {
    if (pairingsView !== null && pairingsView !== 'loading' && pairingsView !== 'error') {
      return pairingsView;
    }
    return null;
  });
  const pairings = $derived(loadedState?.pairings ?? []);
  const activePairing = $derived(
    loadedState ? loadedState.pairings.find((p) => p.id === loadedState.active) ?? null : null,
  );
  const needsPick = $derived(
    loadedState !== null && loadedState.pairings.length > 0 && loadedState.active === null,
  );
  const identity = $derived(activePairing ? serverIdentity(activePairing) : null);

  /**
   * Navigate to a per-server screen pinned to the pairing this Home render shows.
   * Passing `?server=` captures the active id at tap time, so the destination screen
   * reads exactly the relay whose identity block the operator was looking at — never a
   * concurrently-switched successor.
   */
  function openPinned(path: string) {
    if (!activePairing) return;
    void goto(`${path}?server=${encodeURIComponent(activePairing.id)}`);
  }
</script>

<ScreenShell
  prompt="claim code"
  title="Generate a claim code"
  server={identity}
  onservertap={() => (switcherOpen = !switcherOpen)}
>
  {#if pairingsView === 'loading'}
    <p class="resolving">checking servers…</p>
  {:else if pairingsView === 'error'}
    <section class="panel" aria-label="Server check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">
        Couldn't read this device's servers. Retry before pairing again.
      </p>
      <Button variant="secondary" onclick={reloadPairings}>Retry</Button>
    </section>
  {:else if pairings.length === 0}
    <!-- Unpaired — route to Pair, never call the endpoint. -->
    <section class="panel" aria-label="Not paired">
      <StatusChip status="pending" label="not paired" />
      <p class="note">
        This device isn't paired with a relay yet. Pair it to mint account claim codes from
        your phone.
      </p>
    </section>
  {:else}
    {#if needsPick}
      <!-- Active was removed with two+ remaining — force an explicit pick. -->
      <section class="panel" aria-label="Pick a server">
        <StatusChip status="pending" label="pick a server" />
        <p class="note">Two or more servers remain — choose which one this console acts on.</p>
      </section>
    {/if}

    <!-- Inline switcher: shown when needsPick (forced open) or switcherOpen (tappable). -->
    {#if switcherOpen || needsPick}
      <section class="switcher" aria-label="Choose a server">
        {#each pairings as pairing}
          <button
            class="switcher-row"
            class:active={pairing.id === loadedState?.active}
            type="button"
            onclick={() => switchServer(pairing.id)}
          >
            <div class="switcher-left">
              <span class="switcher-label">{serverIdentity(pairing).nickname}</span>
              {#if pairing.id === loadedState?.active}
                <span class="switcher-active">active</span>
              {/if}
            </div>
            <span class="switcher-host">{serverIdentity(pairing).host}</span>
            {#if pairing.id === loadedState?.active}
              <span class="switcher-glyph" aria-hidden="true">▸</span>
            {/if}
          </button>
        {/each}
        <button class="switcher-row" type="button" onclick={() => goto('/pair')}>
          <span class="switcher-label">Pair another server…</span>
        </button>
      </section>
    {/if}

    <!-- Rendered outside the pick gate: a failed switch (the only action available
         while a pick is required) must still surface its error, attributed to the
         tapped server. -->
    {#if claimErrorView}
      <ErrorState
        view={claimErrorView}
        server={claimErrorServer ?? identity}
        retrying={claiming}
        onretry={mintClaimCode}
        onforget={forgetActive}
        onswitch={() => (switcherOpen = true)}
      />
    {/if}

    <!-- Main claim-code flow — hidden while a pick is required (the forced-open
         switcher is the only affordance in that state). -->
    {#if !needsPick}
    <p class="lede">
      Mint a single-use account claim code, signed by this device. Share it with the person
      onboarding, or copy it.
    </p>

    {#if claimCode && claimCodeServer}
      <div class="code-block">
        <div class="code-server">
          <span class="code-server-nickname">{claimCodeServer.nickname}</span>
          <span class="code-server-host">{claimCodeServer.host}</span>
        </div>
        <CodeOutput value={claimCode} label="Account claim code" onshare={shareCode} />
      </div>
      {#if shareHint}
        <p class="hint" role="status">
          <StatusChip status="info" label="copy" />
          <span>{shareHint}</span>
        </p>
      {/if}
    {/if}

    {#if gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{gateHint}</span>
      </p>
    {/if}
    {/if}
  {/if}

  {#snippet actions()}
    {#if pairings.length > 0 && !needsPick && identity}
      <Button variant="primary" loading={claiming} onclick={mintClaimCode}>
        {claimCode ? 'Generate another code' : 'Generate claim code'}
      </Button>
      <Button variant="secondary" onclick={() => openPinned('/accounts')}>Accounts</Button>
      <Button variant="secondary" onclick={() => openPinned('/codes')}>Codes</Button>
      <Button variant="secondary" onclick={() => openPinned('/transfers')}>Transfers</Button>
      <Button variant="secondary" onclick={() => openPinned('/devices')}>Devices</Button>
      <Button variant="secondary" onclick={() => openPinned('/moderation')}>Moderation</Button>
      <Button variant="secondary" onclick={() => openPinned('/status')}>Status</Button>
      <Button variant="secondary" onclick={() => goto('/settings')}>Settings</Button>
    {:else if pairings.length === 0}
      <Button variant="primary" onclick={() => goto('/pair')}>Pair this device</Button>
    {/if}
    <!-- 'loading'/'error'/'needsPick': no primary action until state is resolved. -->
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
  .switcher {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm);
  }
  .switcher-row {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-xs);
    padding: var(--space-sm);
    background: transparent;
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    color: var(--color-ink);
    cursor: pointer;
    text-align: left;
  }
  .switcher-row:hover,
  .switcher-row:active {
    background: var(--color-surface-raised);
  }
  .switcher-row.active {
    background: var(--color-surface-raised);
  }
  .switcher-left {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
  }
  .switcher-label {
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .switcher-active {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
    margin-left: auto;
  }
  .switcher-host {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .switcher-glyph {
    font-size: var(--text-body);
    color: var(--color-primary);
    margin-left: auto;
  }
  .code-block {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .code-server {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .code-server-nickname {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .code-server-host {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
</style>
