<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { Pairing, PairingsState } from '$lib/ipc';
  import StatusChip from './StatusChip.svelte';

  // The three pre-flight states every per-server operator screen shows before its own
  // content: checking the pairing document, a failed read, and "no server selected".
  // Only when a pairing is resolved does it render the screen body — handing that
  // resolved, non-null pairing to `children` so the screen never re-checks for null.
  //
  // The pairing is pinned ONCE at screen entry (see `$lib/pinned-pairing.ts`): a
  // concurrent active-pointer switch on Home can't redirect what a pinned screen reads
  // or signs. This gate is where that resolved-or-not state becomes the visible chrome.
  let {
    view,
    pairing,
    resource,
    children,
  }: {
    /** The pairing document, or a load sentinel. */
    view: PairingsState | 'loading' | 'error';
    /** The pinned pairing resolved from `view` + `?server=`, or `null`. */
    pairing: Pairing | null;
    /** The tail clause of the no-server note, after "Pick or pair one first — ". Varies
     * per screen ("the device list is always read from a specific server.", etc.). */
    resource: string;
    /** The screen body, rendered only once a pairing is resolved. */
    children: Snippet<[Pairing]>;
  } = $props();
</script>

{#if view === 'loading'}
  <p class="resolving">checking servers…</p>
{:else if view === 'error'}
  <section class="panel" aria-label="Server check failed">
    <StatusChip status="error" label="check failed" />
    <p class="note" role="alert">Couldn't read this device's servers. Go back and retry.</p>
  </section>
{:else if !pairing}
  <!-- Unpaired, or no active pick and no ?server pin — there is no relay to act on. -->
  <section class="panel" aria-label="No server selected">
    <StatusChip status="pending" label="no server" />
    <p class="note">No server is selected. Pick or pair one first — {resource}</p>
  </section>
{:else}
  {@render children(pairing)}
{/if}

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
</style>
