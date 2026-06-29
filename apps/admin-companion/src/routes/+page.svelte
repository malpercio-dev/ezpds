<script lang="ts">
  import { onMount } from 'svelte';
  import { getOrCreateDeviceKey, type DevicePublicKey, type DeviceKeyError } from '$lib/ipc';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';

  // Phase 6 is a scaffold: the only wired capability is the device's admin key.
  // This screen proves it round-trips through IPC and now sits on the extracted
  // Brass Console primitives (ScreenShell + StatusChip + CodeOutput). The Pair /
  // Home / Settings screens land in Phases 7–8.
  type State =
    | { kind: 'loading' }
    | { kind: 'ready'; key: DevicePublicKey }
    | { kind: 'error'; code: string };

  let state = $state<State>({ kind: 'loading' });

  onMount(async () => {
    try {
      const key = await getOrCreateDeviceKey();
      state = { kind: 'ready', key };
    } catch (e) {
      const err = e as DeviceKeyError;
      state = { kind: 'error', code: err?.code ?? 'UNKNOWN' };
    }
  });
</script>

<ScreenShell prompt="admin console" title="Operator">
  <section class="panel" aria-labelledby="device-key-label">
    <div class="panel-head">
      <span id="device-key-label" class="label">This device's admin key</span>
      {#if state.kind === 'ready'}
        <StatusChip status="ready" />
      {:else if state.kind === 'loading'}
        <StatusChip status="info" label="generating" />
      {:else}
        <StatusChip status="error" />
      {/if}
    </div>

    {#if state.kind === 'ready'}
      <CodeOutput value={state.key.keyId} prompt={false} />
      <p class="note">
        The private key stays in this device's secure key store — the Secure Enclave on
        iPhone hardware. The relay holds only the public key above; by design it will
        verify a per-request signature rather than store any replayable secret.
      </p>
    {:else if state.kind === 'loading'}
      <p class="resolving">resolving did:key…</p>
    {:else}
      <CodeOutput value={state.code} prompt={false} copyable={false} />
      <p class="note">Could not access the device key. Check the device and retry.</p>
    {/if}
  </section>

  <p class="footnote">Pairing &amp; claim codes — Phase 7+.</p>
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
  .footnote {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
</style>
