<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import {
    listAdminDevices,
    revokeAdminDevice,
    type AdminDevice,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { loadPinnedPairing } from '$lib/pinned-pairing';
  import { createGuardedActions } from '$lib/guarded-action.svelte';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import DeviceRow from '$lib/components/ui/DeviceRow.svelte';
  import PinnedPairingGate from '$lib/components/ui/PinnedPairingGate.svelte';

  // The loss-response screen: every device registered on ONE relay, with a remote
  // revoke for a lost one. Pinned to a single pairing at entry (see $lib/pinned-pairing),
  // id-addressed like revoke_self. The row whose relay-assigned id equals the pairing's
  // deviceId is the device in your hand; its revoke lives in Settings (with the local
  // cleanup), never here.

  type DevicesState =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; devices: AdminDevice[] };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let devicesView = $state<DevicesState>({ kind: 'loading' });
  let expandedId = $state<string | null>(null);
  // Owns the per-row busy/error state and the gate hint for the biometric-gated revoke.
  const guarded = createGuardedActions();

  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  onMount(async () => {
    const resolved = await loadPinnedPairing(page.url.searchParams);
    pairingsView = resolved.view;
    pairing = resolved.pairing;
    if (pairing) await loadDevices(pairing.id);
  });

  async function loadDevices(pairingId: string) {
    devicesView = { kind: 'loading' };
    try {
      devicesView = { kind: 'ready', devices: await listAdminDevices(pairingId) };
    } catch (e) {
      devicesView = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  async function doRevoke(device: AdminDevice) {
    if (!pairing) return;
    const target = pairing;
    await guarded.run({
      id: device.id,
      reason: 'Revoke a device on this server',
      deniedHint: 'Confirm with Face ID to revoke this device.',
      action: async () => {
        await revokeAdminDevice(target.id, device.id);
        // Reload so the row reports the relay's post-revoke truth (status flips to
        // revoked with its timestamp) rather than an optimistic local edit.
        await loadDevices(target.id);
      },
    });
  }

  function toggleExpanded(deviceId: string) {
    expandedId = expandedId === deviceId ? null : deviceId;
  }

  /** The relay's `lastSeenAt`/`createdAt` verbatim — literal truth, no relative-time gloss. */
  function seenLine(device: AdminDevice): string {
    return device.lastSeenAt ? `seen ${device.lastSeenAt}` : `registered ${device.createdAt}`;
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
</script>

<ScreenShell
  prompt="devices"
  title="Devices on this server"
  onback={() => history.back()}
  server={identity}
>
  <PinnedPairingGate view={pairingsView} {pairing} resource="the device list is always read from a specific server.">
    {#snippet children(pairing)}
    {#if devicesView.kind === 'loading'}
    <p class="resolving">reading device registry…</p>
  {:else if devicesView.kind === 'error'}
    <ErrorState view={devicesView.view} server={identity} onretry={() => loadDevices(pairing.id)} />
  {:else}
    <p class="lede">
      Every admin device registered on this server, active and revoked. Revoke a lost
      device to cut off its access — signed by the device in your hand.
    </p>

    <section class="panel" aria-labelledby="devices-label">
      <span id="devices-label" class="label">Registered devices</span>
      {#if devicesView.devices.length === 0}
        <p class="note">No devices are registered on this server yet.</p>
      {/if}
      <div class="device-list">
        {#each devicesView.devices as device (device.id)}
          {@const isCurrent = device.id === pairing.deviceId}
          <div class="device-item">
            <button
              class="device-row"
              type="button"
              aria-expanded={expandedId === device.id}
              aria-controls={`device-panel-${device.id}`}
              onclick={() => toggleExpanded(device.id)}
            >
              <DeviceRow
                label={device.label}
                deviceId={device.publicKey}
                lastSeen={seenLine(device)}
                status={device.status}
                current={isCurrent}
              />
            </button>

            {#if expandedId === device.id}
              <div class="device-panel" id={`device-panel-${device.id}`}>
                <dl class="facts">
                  <dt>registration id</dt>
                  <dd>{device.id}</dd>
                  <dt>public key</dt>
                  <dd>{device.publicKey}</dd>
                  <dt>platform</dt>
                  <dd>{device.platform}</dd>
                  <dt>registered</dt>
                  <dd>{device.createdAt}</dd>
                  <dt>last seen</dt>
                  <dd>{device.lastSeenAt ?? 'never authenticated'}</dd>
                  {#if device.revokedAt}
                    <dt>revoked</dt>
                    <dd>{device.revokedAt}</dd>
                  {/if}
                </dl>

                {#if isCurrent}
                  <p class="note">
                    This is the device in your hand. To revoke it, use Settings →
                    Revoke on this server — that also forgets the pairing here.
                  </p>
                  <Button variant="secondary" onclick={() => goto('/settings')}>
                    Open Settings
                  </Button>
                {:else if device.status === 'active'}
                  <Button
                    variant="destructive"
                    loading={guarded.isBusy(device.id)}
                    onclick={() => doRevoke(device)}
                  >
                    Revoke this device
                  </Button>
                  {#if guarded.errorFor(device.id)}
                    <ErrorState
                      view={guarded.errorFor(device.id)!}
                      server={identity}
                      retrying={guarded.isBusy(device.id)}
                      onretry={() => doRevoke(device)}
                    />
                  {/if}
                {/if}
                <!-- A revoked device needs no action: the chip + revoked timestamp
                     already report the terminal state. -->
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </section>

    {#if guarded.gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{guarded.gateHint}</span>
      </p>
    {/if}
  {/if}
    {/snippet}
  </PinnedPairingGate>

  {#snippet actions()}
    {#if pairing && devicesView.kind === 'ready'}
      <Button variant="secondary" onclick={() => pairing && loadDevices(pairing.id)}>
        Refresh
      </Button>
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
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
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
  .device-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .device-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .device-row {
    display: block;
    width: 100%;
    padding: var(--space-sm);
    background: transparent;
    border: none;
    font: inherit;
    color: inherit;
    cursor: pointer;
    text-align: left;
  }
  .device-row:hover,
  .device-row:active {
    background: var(--color-surface);
  }
  .device-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    padding-top: var(--space-sm);
    border-top: var(--border-hairline) solid var(--color-line);
  }
  /* The fact sheet: aligned label/value pairs, the legibility of a good `ls -l`. */
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2xs) var(--space-md);
    margin: 0;
  }
  /* Inside a raised well: ink-soft, per the tokens.css contrast rule for muted. */
  .facts dt {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink-soft);
  }
  .facts dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
</style>
