<script lang="ts">
  import type { ErrorView } from '$lib/errors';
  import StatusChip from './StatusChip.svelte';
  import Button from './Button.svelte';
  import CodeOutput from './CodeOutput.svelte';

  // Renders a classified failure (errors.ts → ErrorView) as a recovery state: a status
  // chip (color + glyph + text, never color alone) over the message, the relay URL when
  // the failure is a reachability one, and the single recovery affordance the
  // classification calls for — Pair (revoked / not-paired) or Retry (clock-skew /
  // unreachable). Used by Home and Settings so every failure reads the same way.
  let {
    view,
    relayUrl,
    retrying = false,
    onpair,
    onretry,
  }: {
    view: ErrorView;
    /** Shown for an unreachable relay so the operator can verify the address. */
    relayUrl?: string;
    retrying?: boolean;
    onpair?: () => void;
    onretry?: () => void;
  } = $props();

  // The relay URL is only meaningful for a reachability failure; showing it on a revoked
  // or clock-skew state would just be noise.
  const showRelayUrl = $derived(Boolean(relayUrl) && view.chipLabel === 'unreachable');
</script>

<div class="state" role="alert">
  <StatusChip status={view.status} label={view.chipLabel} />
  <p class="message">{view.message}</p>

  {#if showRelayUrl}
    <CodeOutput value={relayUrl ?? ''} label="Relay" prompt={false} copyable={false} />
  {/if}

  {#if view.recovery === 'pair' && onpair}
    <Button variant="primary" onclick={onpair}>Pair this device</Button>
  {:else if view.recovery === 'retry' && onretry}
    <Button variant="secondary" loading={retrying} onclick={onretry}>Retry</Button>
  {/if}
</div>

<style>
  .state {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .message {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
</style>
