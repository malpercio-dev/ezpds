<script lang="ts">
  import type { ErrorView } from '$lib/errors';
  import StatusChip from './StatusChip.svelte';
  import Button from './Button.svelte';

  // Renders a classified failure (errors.ts → ErrorView) as a recovery state: a status
  // chip (color + glyph + text, never color alone) over the message, server attribution
  // (when provided, shown for every classification to prevent misreading against the wrong
  // relay), and the recovery affordances the classification calls for — Pair (revoked /
  // not-paired), Retry ± local-forget fallback (unreachable), or forget/switch (revoked).
  // Used by Home and Settings so every failure reads the same way.
  let {
    view,
    server = null,
    retrying = false,
    onpair,
    onretry,
    onforget,
    onswitch,
    onforgetlocally,
  }: {
    view: ErrorView;
    /** The server the failed action targeted. Every classified failure is attributed to a
     * named server so "unreachable" can never be misread against the wrong relay. */
    server?: { nickname: string; host: string } | null;
    retrying?: boolean;
    onpair?: () => void;
    onretry?: () => void;
    /** recovery === 'forget-or-switch' (revoked) and the unreachable fallback. */
    onforget?: () => void;
    onswitch?: () => void;
    /** Offered alongside a retry when the relay is unreachable: local-only forget. */
    onforgetlocally?: () => void;
  } = $props();
</script>

<div class="state" role="alert">
  <StatusChip status={view.status} label={view.chipLabel} />
  {#if server}
    <p class="attribution">
      <span class="attribution-nickname">{server.nickname}</span>
      <span class="attribution-host">{server.host}</span>
    </p>
  {/if}
  <p class="message">{view.message}</p>

  {#if view.recovery === 'pair' && onpair}
    <Button variant="primary" onclick={onpair}>Pair this device</Button>
  {:else if view.recovery === 'retry' && onretry}
    <Button variant="secondary" loading={retrying} onclick={onretry}>Retry</Button>
    {#if onforgetlocally}
      <Button variant="destructive" onclick={onforgetlocally}>Forget on this device anyway</Button>
    {/if}
  {:else if view.recovery === 'forget-or-switch'}
    {#if onforget}
      <Button variant="destructive" onclick={onforget}>Forget this server</Button>
    {/if}
    {#if onswitch}
      <Button variant="secondary" onclick={onswitch}>Switch server</Button>
    {/if}
  {/if}
</div>

<style>
  .state {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .attribution {
    margin: 0;
    font-size: var(--text-body);
    color: var(--color-ink-soft);
  }
  .attribution-nickname {
    font-family: var(--font-sans);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .attribution-host {
    display: block;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
  }
  .message {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
</style>
