<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    getOrCreateDeviceKey,
    pairingState,
    revokeSelf,
    unpair,
    biometricEnabled,
    setBiometricEnabled,
    type DevicePublicKey,
    type DeviceKeyError,
    type Pairing,
  } from '$lib/ipc';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Toggle from '$lib/components/ui/Toggle.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // Phase 8 Settings: the device's identity + relay link, the biometric-gate toggle, and
  // unpair. Unpair is a *server-side self-revoke* — the admin credential is killed on the
  // relay so a later-lost phone can't act as admin — with a local-only "forget anyway"
  // fallback for when the relay can't be reached.

  type KeyState =
    | { kind: 'loading' }
    | { kind: 'ready'; key: DevicePublicKey }
    | { kind: 'error'; code: string };

  let keyState = $state<KeyState>({ kind: 'loading' });
  let pairing = $state<Pairing | null | 'loading' | 'error'>('loading');

  let biometricOn = $state(true);
  let biometricBusy = $state(false);

  let unpairing = $state(false);
  let forgetting = $state(false);
  let unpairErrorView = $state<ErrorView | undefined>(undefined);
  let gateHint = $state<string | undefined>(undefined);

  onMount(async () => {
    const [key, pair, bio] = await Promise.allSettled([
      getOrCreateDeviceKey(),
      pairingState(),
      biometricEnabled(),
    ]);
    keyState =
      key.status === 'fulfilled'
        ? { kind: 'ready', key: key.value }
        : { kind: 'error', code: (key.reason as DeviceKeyError)?.code ?? 'UNKNOWN' };
    pairing = pair.status === 'fulfilled' ? pair.value : 'error';
    if (bio.status === 'fulfilled') biometricOn = bio.value;
  });

  async function onBiometricChange(next: boolean) {
    biometricBusy = true;
    try {
      await setBiometricEnabled(next);
    } catch {
      // Revert the visual state if the preference couldn't be persisted.
      biometricOn = !next;
    } finally {
      biometricBusy = false;
    }
  }

  async function doRevoke() {
    gateHint = undefined;
    unpairErrorView = undefined;
    // Revoking is a signing action — gate it on user presence.
    const presence = await requireUserPresence('Unpair this device');
    if (!presenceAllows(presence)) {
      gateHint = 'Confirm with Face ID to unpair this device.';
      return;
    }
    unpairing = true;
    try {
      await revokeSelf();
      await goto('/');
    } catch (e) {
      unpairErrorView = classifyRelayError(e);
    } finally {
      unpairing = false;
    }
  }

  async function forgetLocally() {
    forgetting = true;
    try {
      await unpair();
      await goto('/');
    } finally {
      forgetting = false;
    }
  }

  // The pairing as a concrete object when paired, else undefined — narrows cleanly in the
  // markup (`{#if paired}` exposes `paired.relayUrl` etc. without repeated guards).
  const paired = $derived(
    pairing !== null && pairing !== 'loading' && pairing !== 'error' ? pairing : undefined,
  );
</script>

<ScreenShell prompt="settings" title="Settings" onback={() => goto('/')}>
  <!-- Device identity -->
  <section class="panel" aria-labelledby="device-label">
    <div class="panel-head">
      <span id="device-label" class="label">This device</span>
      {#if paired}
        <StatusChip status="active" label="paired" />
      {:else if pairing === 'loading'}
        <StatusChip status="info" label="checking" />
      {:else if pairing === 'error'}
        <StatusChip status="error" label="check failed" />
      {:else}
        <StatusChip status="pending" label="not paired" />
      {/if}
    </div>

    {#if paired}
      <p class="device-name">{paired.label || 'Unlabelled device'}</p>
      <CodeOutput value={paired.deviceId} label="Device id" prompt={false} />
    {/if}

    {#if keyState.kind === 'ready'}
      <CodeOutput value={keyState.key.keyId} label="Admin key" prompt={false} copyable={false} />
    {:else if keyState.kind === 'loading'}
      <p class="resolving">resolving did:key…</p>
    {:else}
      <p class="note">Couldn't read this device's admin key.</p>
    {/if}
  </section>

  <!-- Relay link -->
  {#if paired}
    <section class="panel" aria-labelledby="relay-label">
      <span id="relay-label" class="label">Paired relay</span>
      <CodeOutput value={paired.relayUrl} prompt={false} copyable={false} />
    </section>
  {/if}

  <!-- Security: the biometric gate -->
  <section class="panel" aria-label="Security">
    <Toggle
      bind:checked={biometricOn}
      disabled={biometricBusy}
      label="Require Face ID to sign"
      description="Confirm with Face ID, Touch ID, or your passcode before generating a claim code or unpairing."
      onchange={onBiometricChange}
    />
  </section>

  <!-- Danger: unpair = server-side self-revoke -->
  {#if paired}
    <section class="panel danger" aria-labelledby="unpair-label">
      <span id="unpair-label" class="label">Unpair</span>
      <p class="note">
        Revokes this device on the relay, then forgets the pairing here. The relay will
        reject this device's admin requests until you pair again.
      </p>

      {#if unpairErrorView}
        <ErrorState
          view={unpairErrorView}
          relayUrl={paired.relayUrl}
          retrying={unpairing}
          onretry={doRevoke}
          onpair={forgetLocally}
        />
        <Button variant="secondary" loading={forgetting} onclick={forgetLocally}>
          Forget on this device anyway
        </Button>
      {/if}

      {#if gateHint}
        <p class="hint" role="status">
          <StatusChip status="info" label="confirm" />
          <span>{gateHint}</span>
        </p>
      {/if}
    </section>
  {/if}

  {#snippet actions()}
    {#if paired}
      <Button variant="destructive" loading={unpairing} onclick={doRevoke}>
        Unpair this device
      </Button>
    {:else if pairing === null}
      <Button variant="primary" onclick={() => goto('/pair')}>Pair this device</Button>
    {/if}
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
  .danger {
    border-color: var(--color-critical-surface);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .device-name {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
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
