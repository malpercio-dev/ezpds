<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { SvelteMap } from 'svelte/reactivity';
  import {
    listPairings,
    listAdminDevices,
    revokeAdminDevice,
    type AdminDevice,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import DeviceRow from '$lib/components/ui/DeviceRow.svelte';

  // The loss-response screen: every device registered on ONE relay, with a remote
  // revoke for a lost one. Pinned to a single pairing at entry (`?server=<pairingId>`
  // from Settings, else the active pairing) — id-addressed like revoke_self, so a
  // concurrent active-pointer switch on Home can never redirect what this screen
  // shows or signs. The row whose relay-assigned id equals the pairing's deviceId is
  // the device in your hand; its revoke lives in Settings (with the local cleanup),
  // never here.

  type DevicesState =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; devices: AdminDevice[] };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let devicesView = $state<DevicesState>({ kind: 'loading' });
  let expandedId = $state<string | null>(null);
  let revokingStates = $state<SvelteMap<string, boolean>>(new SvelteMap());
  let revokeErrors = $state<SvelteMap<string, ErrorView | undefined>>(new SvelteMap());
  let gateHint = $state<string | undefined>(undefined);

  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  onMount(async () => {
    try {
      pairingsView = await listPairings();
    } catch {
      pairingsView = 'error';
      return;
    }
    const requested = page.url.searchParams.get('server');
    const targetId = requested ?? pairingsView.active;
    pairing = pairingsView.pairings.find((p) => p.id === targetId) ?? null;
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
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent revokes.
    if (revokingStates.get(device.id)) return;
    revokingStates.set(device.id, true);
    gateHint = undefined;
    revokeErrors.set(device.id, undefined);

    try {
      // Revoking is a signing action — gate it on user presence.
      const presence = await requireUserPresence('Revoke a device on this server');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to revoke this device.';
        return;
      }
      await revokeAdminDevice(pairing.id, device.id);
      // Reload so the row reports the relay's post-revoke truth (status flips to
      // revoked with its timestamp) rather than an optimistic local edit.
      await loadDevices(pairing.id);
    } catch (e) {
      revokeErrors.set(device.id, classifyRelayError(e));
    } finally {
      revokingStates.set(device.id, false);
    }
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
  {#if pairingsView === 'loading'}
    <p class="resolving">checking servers…</p>
  {:else if pairingsView === 'error'}
    <section class="panel" aria-label="Server check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">Couldn't read this device's servers. Go back and retry.</p>
    </section>
  {:else if !pairing}
    <!-- Unpaired, or no active pick and no ?server pin — there is no relay to ask. -->
    <section class="panel" aria-label="No server selected">
      <StatusChip status="pending" label="no server" />
      <p class="note">
        No server is selected. Pick or pair one first — the device list is always read
        from a specific server.
      </p>
    </section>
  {:else if devicesView.kind === 'loading'}
    <p class="resolving">reading device registry…</p>
  {:else if devicesView.kind === 'error'}
    <ErrorState
      view={devicesView.view}
      server={identity}
      onretry={() => pairing && loadDevices(pairing.id)}
    />
  {:else}
    <p class="lede">
      Every admin device registered on this server, active and revoked. Revoke a lost
      device to cut off its access — signed by the device in your hand.
    </p>

    <section class="panel" aria-labelledby="devices-label">
      <span id="devices-label" class="label">Registered devices</span>
      <div class="device-list">
        {#each devicesView.devices as device (device.id)}
          {@const isCurrent = device.id === pairing.deviceId}
          <div class="device-item">
            <button class="device-row" type="button" onclick={() => toggleExpanded(device.id)}>
              <DeviceRow
                label={device.label}
                deviceId={device.publicKey}
                lastSeen={seenLine(device)}
                status={device.status}
                current={isCurrent}
              />
            </button>

            {#if expandedId === device.id}
              <div class="device-panel">
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
                    loading={revokingStates.get(device.id) ?? false}
                    onclick={() => doRevoke(device)}
                  >
                    Revoke this device
                  </Button>
                  {#if revokeErrors.get(device.id)}
                    <ErrorState
                      view={revokeErrors.get(device.id)!}
                      server={identity}
                      retrying={revokingStates.get(device.id) ?? false}
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

    {#if gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{gateHint}</span>
      </p>
    {/if}
  {/if}

  {#snippet actions()}
    {#if pairing && devicesView.kind === 'ready'}
      <Button variant="secondary" onclick={() => pairing && loadDevices(pairing.id)}>
        Refresh list
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
  .device-row:hover {
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
  .facts dt {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .facts dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
</style>
