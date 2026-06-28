<script lang="ts">
  import { onMount } from 'svelte';
  import { getOrCreateDeviceKey, type DevicePublicKey, type DeviceKeyError } from '$lib/ipc';

  // Phase 6 is a scaffold: the only wired capability is the device's admin key.
  // This screen proves it round-trips through the IPC bridge and shows the forked
  // terminal-native tokens in their intended register. The Pair / Home / Settings
  // screens land in Phases 7–8.
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

<main>
  <header>
    <p class="prompt">ezpds<span class="caret">▸</span> admin console</p>
    <h1>Operator</h1>
  </header>

  <section class="panel" aria-labelledby="device-key-label">
    <div class="panel-head">
      <span id="device-key-label" class="label">This device's admin key</span>
      {#if state.kind === 'ready'}
        <span class="chip chip--safe"><span aria-hidden="true">●</span> ready</span>
      {:else if state.kind === 'loading'}
        <span class="chip chip--info"><span aria-hidden="true">○</span> generating</span>
      {:else}
        <span class="chip chip--critical"><span aria-hidden="true">!</span> error</span>
      {/if}
    </div>

    {#if state.kind === 'ready'}
      <code class="data">{state.key.keyId}</code>
      <p class="note">
        Held in the Secure Enclave on device. The relay stores only this public key
        and verifies a signature on every request — no replayable secret lives here.
      </p>
    {:else if state.kind === 'loading'}
      <code class="data data--dim">resolving did:key…</code>
    {:else}
      <code class="data data--alarm">{state.code}</code>
      <p class="note">Could not access the device key. Check the device and retry.</p>
    {/if}
  </section>

  <p class="footnote">Pairing &amp; claim codes — Phase 7+.</p>
</main>

<style>
  main {
    min-height: 100dvh;
    padding: var(--space-xl) var(--space-lg);
    display: flex;
    flex-direction: column;
    gap: var(--space-lg);
  }

  header {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .prompt {
    margin: 0;
    font-family: var(--font-display);
    font-size: var(--text-data);
    color: var(--color-primary);
    letter-spacing: 0.02em;
  }
  .caret {
    margin: 0 var(--space-xs);
    color: var(--color-muted);
  }

  h1 {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-headline);
    line-height: var(--leading-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }

  .panel {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
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

  /* Status chip: color + glyph + text, never color alone (DESIGN.md §2). */
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    padding: var(--space-xs) var(--space-sm);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: var(--text-label);
  }
  .chip--safe {
    color: var(--color-safe);
    background: var(--color-safe-surface);
  }
  .chip--info {
    color: var(--color-info);
    background: var(--color-info-surface);
  }
  .chip--critical {
    color: var(--color-critical);
    background: var(--color-critical-surface);
  }

  /* Literal-Truth rule: every did:key is mono and wraps break-all, never truncates. */
  .data {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    line-height: var(--leading-data);
    color: var(--color-ink);
    background: var(--color-surface-raised);
    border-radius: var(--radius-sm);
    padding: var(--space-sm);
    overflow-wrap: anywhere;
    word-break: break-all;
  }
  .data--dim {
    color: var(--color-ink-soft);
  }
  .data--alarm {
    color: var(--color-critical);
  }

  .note {
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }

  .footnote {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
</style>
