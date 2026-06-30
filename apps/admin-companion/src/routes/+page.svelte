<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    getOrCreateDeviceKey,
    pairingState,
    generateClaimCode,
    unpair,
    type DevicePublicKey,
    type DeviceKeyError,
    type Pairing,
    type RelayClientError,
  } from '$lib/ipc';
  import { describeRelayError } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  // Phase 7: the home screen branches on whether this device has paired. Unpaired →
  // the operator pairs it; paired → they can mint a claim code (the demo action) over
  // a signed request. The polished claim-code / Settings screens land in Phase 8; this
  // is the minimal wiring that proves pairing + signing end-to-end.
  type KeyState =
    | { kind: 'loading' }
    | { kind: 'ready'; key: DevicePublicKey }
    | { kind: 'error'; code: string };

  let keyState = $state<KeyState>({ kind: 'loading' });
  // 'error' is distinct from null (unpaired): a failed pairing read leaves the real
  // state unknown, so we must not expose the pair CTA until it succeeds.
  let pairing = $state<Pairing | null | 'loading' | 'error'>('loading');

  let claiming = $state(false);
  let claimCode = $state<string | undefined>(undefined);
  let claimError = $state<string | undefined>(undefined);

  let unpairing = $state(false);
  let unpairError = $state<string | undefined>(undefined);

  onMount(async () => {
    const [key, pair] = await Promise.allSettled([getOrCreateDeviceKey(), pairingState()]);
    keyState =
      key.status === 'fulfilled'
        ? { kind: 'ready', key: key.value }
        : { kind: 'error', code: (key.reason as DeviceKeyError)?.code ?? 'UNKNOWN' };
    // A failed pairing read is an *unknown* state, not "unpaired" — surfacing it as
    // unpaired would wrongly invite re-pairing a device that is in fact paired.
    pairing = pair.status === 'fulfilled' ? pair.value : 'error';
  });

  async function reloadPairing() {
    pairing = 'loading';
    try {
      pairing = await pairingState();
    } catch {
      pairing = 'error';
    }
  }

  async function mintClaimCode() {
    claiming = true;
    claimError = undefined;
    try {
      claimCode = await generateClaimCode();
    } catch (e) {
      claimError = describeRelayError(e as RelayClientError);
    } finally {
      claiming = false;
    }
  }

  async function doUnpair() {
    unpairing = true;
    unpairError = undefined;
    try {
      await unpair();
      pairing = null;
      claimCode = undefined;
      claimError = undefined;
    } catch (e) {
      unpairError = describeRelayError(e as RelayClientError);
    } finally {
      unpairing = false;
    }
  }
</script>

<ScreenShell prompt="admin console" title="Operator">
  <!-- Pairing status: the operator's primary context. -->
  <section class="panel" aria-labelledby="pairing-label">
    <div class="panel-head">
      <span id="pairing-label" class="label">Relay pairing</span>
      {#if pairing === 'loading'}
        <StatusChip status="info" label="checking" />
      {:else if pairing === 'error'}
        <StatusChip status="error" label="check failed" />
      {:else if pairing}
        <StatusChip status="active" label="paired" />
      {:else}
        <StatusChip status="pending" label="not paired" />
      {/if}
    </div>

    {#if pairing === 'loading'}
      <p class="resolving">checking pairing…</p>
    {:else if pairing === 'error'}
      <p class="note" role="alert">
        Couldn't read this device's pairing state. This is not the same as being unpaired —
        retry before pairing again.
      </p>
      <div class="row">
        <Button variant="secondary" onclick={reloadPairing}>Retry</Button>
      </div>
    {:else if pairing}
      <CodeOutput value={pairing.relayUrl} label="Paired relay" prompt={false} copyable={false} />
      <CodeOutput value={pairing.deviceId} label="Device id" prompt={false} />
      {#if unpairError}
        <p class="note" role="alert">{unpairError}</p>
      {/if}
      <div class="row">
        <Button variant="destructive" loading={unpairing} onclick={doUnpair}>
          Unpair this device
        </Button>
      </div>
    {:else}
      <p class="note">
        This device is not yet paired with a relay. Pair it to mint account claim codes
        from your phone.
      </p>
    {/if}
  </section>

  <!-- The demo action (paired only): a signed claim-code request. -->
  {#if pairing && pairing !== 'loading' && pairing !== 'error'}
    <section class="panel" aria-labelledby="claim-label">
      <div class="panel-head">
        <span id="claim-label" class="label">Account claim code</span>
        {#if claimError}
          <StatusChip status="error" label="failed" />
        {/if}
      </div>
      {#if claimCode}
        <CodeOutput value={claimCode} label="Latest claim code" />
      {/if}
      {#if claimError}
        <p class="note" role="alert">{claimError}</p>
      {/if}
      <p class="note">
        Generating a code sends a signed request the relay verifies against this device's
        admin key — no shared secret leaves the phone.
      </p>
    </section>
  {/if}

  <!-- Device admin key (Phase 6 panel, retained). -->
  <section class="panel" aria-labelledby="device-key-label">
    <div class="panel-head">
      <span id="device-key-label" class="label">This device's admin key</span>
      {#if keyState.kind === 'ready'}
        <StatusChip status="ready" label="ready" />
      {:else if keyState.kind === 'loading'}
        <StatusChip status="info" label="generating" />
      {:else}
        <StatusChip status="error" label="error" />
      {/if}
    </div>

    {#if keyState.kind === 'ready'}
      <CodeOutput value={keyState.key.keyId} prompt={false} />
    {:else if keyState.kind === 'loading'}
      <p class="resolving">resolving did:key…</p>
    {:else}
      <CodeOutput value={keyState.code} prompt={false} copyable={false} />
      <p class="note">Could not access the device key. Check the device and retry.</p>
    {/if}
  </section>

  {#snippet actions()}
    {#if pairing && pairing !== 'loading' && pairing !== 'error'}
      <Button variant="primary" loading={claiming} onclick={mintClaimCode}>
        Generate claim code
      </Button>
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
  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-sm);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
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
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
</style>
