<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { SvelteMap } from 'svelte/reactivity';
  import {
    getOrCreateDeviceKey,
    listPairings,
    renamePairing,
    revokeSelf,
    unpair,
    biometricEnabled,
    setBiometricEnabled,
    type DevicePublicKey,
    type DeviceKeyError,
    type PairingsState,
    type RelayClientError,
  } from '$lib/ipc';
  import { serverIdentity } from '$lib/server-identity';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Toggle from '$lib/components/ui/Toggle.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import DeviceRow from '$lib/components/ui/DeviceRow.svelte';

  // Phase 8→3 Settings: global device identity (admin key), per-server list with rename/revoke/forget,
  // and the biometric-gate toggle. Unpair is now per-server — a *server-side self-revoke* for each
  // pairing with a local-only "forget anyway" fallback when the relay can't be reached.

  type KeyState =
    | { kind: 'loading' }
    | { kind: 'ready'; key: DevicePublicKey }
    | { kind: 'error'; code: string };

  let keyState = $state<KeyState>({ kind: 'loading' });
  let pairingsState = $state<PairingsState | 'loading' | 'error'>('loading');

  let biometricOn = $state(true);
  let biometricBusy = $state(false);

  let expandedId = $state<string | null>(null);
  let renameStates = $state<SvelteMap<string, { value: string; error?: string }>>(
    new SvelteMap(),
  );
  let errorStates = $state<SvelteMap<string, ErrorView | undefined>>(new SvelteMap());
  let actionStates = $state<SvelteMap<string, { busy: boolean }>>(new SvelteMap());
  let gateHint = $state<string | undefined>(undefined);

  onMount(async () => {
    const [key, pair, bio] = await Promise.allSettled([
      getOrCreateDeviceKey(),
      listPairings(),
      biometricEnabled(),
    ]);
    keyState =
      key.status === 'fulfilled'
        ? { kind: 'ready', key: key.value }
        : { kind: 'error', code: (key.reason as DeviceKeyError)?.code ?? 'UNKNOWN' };
    pairingsState = pair.status === 'fulfilled' ? pair.value : 'error';
    if (bio.status === 'fulfilled') biometricOn = bio.value;
  });

  async function reloadPairings() {
    pairingsState = 'loading';
    try {
      pairingsState = await listPairings();
    } catch {
      pairingsState = 'error';
    }
  }

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

  async function saveNickname(id: string) {
    const state = renameStates.get(id);
    if (!state) return;

    const newNick = state.value.trim();
    if (newNick.length === 0) {
      renameStates.set(id, {
        ...state,
        error: "Give this server a name — it's how you'll tell environments apart.",
      });
      return;
    }

    actionStates.set(id, { busy: true });

    try {
      renameStates.set(id, { ...state, error: undefined });
      await renamePairing(id, newNick);
      await reloadPairings();
    } catch (e) {
      renameStates.set(id, { ...state, error: 'Could not save the name. Try again.' });
    } finally {
      actionStates.set(id, { busy: false });
    }
  }

  async function doRevoke(id: string) {
    const actionState = actionStates.get(id) || { busy: false };
    if (actionState.busy) return;

    actionStates.set(id, { busy: true });
    gateHint = undefined;
    errorStates.set(id, undefined);

    try {
      // Revoking is a signing action — gate it on user presence.
      const presence = await requireUserPresence('Revoke this server pairing');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to revoke this server pairing.';
        return;
      }
      await revokeSelf(id);
      await reloadPairings();
    } catch (e) {
      errorStates.set(id, classifyRelayError(e));
      await reloadPairings();
    } finally {
      actionStates.set(id, { busy: false });
    }
  }

  async function forgetLocally(id: string) {
    const actionState = actionStates.get(id) || { busy: false };
    if (actionState.busy) return;

    actionStates.set(id, { busy: true });
    gateHint = undefined;

    try {
      await unpair(id);
      await reloadPairings();
    } catch {
      gateHint = "Couldn't forget this server locally. Try again.";
    } finally {
      actionStates.set(id, { busy: false });
    }
  }

  function toggleExpandedRow(pairingId: string) {
    if (expandedId === pairingId) {
      expandedId = null;
      return;
    }
    expandedId = pairingId;
    // Seed the rename state when the row opens (not during render).
    if (!renameStates.has(pairingId)) {
      const pairing = pairings.find((p) => p.id === pairingId);
      if (pairing) {
        renameStates.set(pairingId, { value: serverIdentity(pairing).nickname });
      }
    }
  }

  const pairings = $derived(
    pairingsState !== null && pairingsState !== 'loading' && pairingsState !== 'error'
      ? pairingsState.pairings
      : [],
  );
  const activeId = $derived(
    pairingsState !== null && pairingsState !== 'loading' && pairingsState !== 'error'
      ? pairingsState.active
      : null,
  );
  const activePairing = $derived(
    pairings.find((p) => p.id === activeId) ?? null,
  );
  const activeIdentity = $derived(activePairing ? serverIdentity(activePairing) : null);
</script>

<ScreenShell
  prompt="settings"
  title="Settings"
  onback={() => goto('/')}
  server={activeIdentity}
>
  <!-- Device identity -->
  <section class="panel" aria-labelledby="device-label">
    <span id="device-label" class="label">Device admin key</span>
    {#if keyState.kind === 'ready'}
      <CodeOutput value={keyState.key.keyId} label="Admin key" prompt={false} copyable={false} />
    {:else if keyState.kind === 'loading'}
      <p class="resolving">resolving did:key…</p>
    {:else}
      <p class="note">Couldn't read this device's admin key.</p>
    {/if}
  </section>

  <!-- Servers list -->
  {#if pairingsState === 'loading'}
    <p class="resolving">loading servers…</p>
  {:else if pairingsState === 'error'}
    <section class="panel" aria-label="Server list error">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">Couldn't load the server list. Try again.</p>
      <Button variant="secondary" onclick={reloadPairings}>Retry</Button>
    </section>
  {:else if pairings.length === 0}
    <section class="panel" aria-label="Not paired">
      <StatusChip status="pending" label="not paired" />
      <p class="note">This device isn't paired with any servers yet.</p>
    </section>
  {:else}
    <section class="panel" aria-labelledby="servers-label">
      <span id="servers-label" class="label">Servers</span>
      <div class="server-list">
        {#each pairings as pairing}
          <div class="server-item">
            <button
              class="server-row"
              type="button"
              onclick={() => toggleExpandedRow(pairing.id)}
            >
              <DeviceRow
                label={serverIdentity(pairing).nickname}
                deviceId={pairing.deviceId}
                lastSeen={serverIdentity(pairing).host}
                status={pairing.id === activeId ? 'active' : 'ready'}
                current={pairing.id === activeId}
                currentLabel="active"
              />
            </button>

            {#if expandedId === pairing.id}
              <div class="server-panel">
                <!-- Rename -->
                <div class="rename-block">
                  {#if renameStates.get(pairing.id) !== undefined}
                    {@const renameState = renameStates.get(pairing.id)!}
                    <TextField
                      label="Nickname"
                      bind:value={renameState.value}
                      placeholder="staging"
                      mono
                      error={renameState.error}
                    />
                  {/if}
                  <Button
                    variant="secondary"
                    loading={actionStates.get(pairing.id)?.busy ?? false}
                    onclick={() => saveNickname(pairing.id)}
                  >
                    Save name
                  </Button>
                </div>

                <!-- Device label -->
                <div class="label-block">
                  <p class="meta-label">Device label on this server</p>
                  <p class="device-label-value">{pairing.deviceLabel}</p>
                </div>

                <!-- Revoke -->
                <div class="revoke-block">
                  <Button
                    variant="destructive"
                    loading={actionStates.get(pairing.id)?.busy ?? false}
                    onclick={async () => {
                      await doRevoke(pairing.id);
                    }}
                  >
                    Revoke on this server
                  </Button>

                  {#if errorStates.get(pairing.id)}
                    <ErrorState
                      view={errorStates.get(pairing.id)!}
                      server={serverIdentity(pairing)}
                      onforgetlocally={() => forgetLocally(pairing.id)}
                    />
                  {/if}

                  <!-- Forget locally fallback -->
                  <Button variant="secondary" onclick={() => forgetLocally(pairing.id)}>
                    Forget locally
                  </Button>
                </div>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}

  <!-- Security: the biometric gate -->
  <section class="panel" aria-label="Security">
    <Toggle
      bind:checked={biometricOn}
      disabled={biometricBusy}
      label="Require Face ID to sign"
      description="Confirm with Face ID, Touch ID, or your passcode before generating a claim code or revoking on a server."
      onchange={onBiometricChange}
    />
  </section>

  {#if gateHint}
    <p class="hint" role="status">
      <StatusChip status="info" label="confirm" />
      <span>{gateHint}</span>
    </p>
  {/if}

  {#snippet actions()}
    {#if pairings.length === 0}
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
  .hint {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .server-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .server-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .server-row {
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
  .server-row:hover {
    background: var(--color-surface);
  }
  .server-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    padding-top: var(--space-sm);
    border-top: var(--border-hairline) solid var(--color-line);
  }
  .rename-block {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .label-block {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .meta-label {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
  }
  .device-label-value {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .revoke-block {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
</style>
