<script lang="ts">
  import { getUrgency, getDeadline } from '$lib/deadline';
  import type { UnauthorizedChange } from '$lib/ipc';
  import { truncateDid } from '$lib/did-doc-utils';
  import { formatTimestamp } from '$lib/datetime';
  import UrgencyBadge from '$lib/components/ui/UrgencyBadge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import { useCountdown } from '$lib/components/ui/use-countdown.svelte';

  let {
    did,
    changes,
    onback,
    onoverride,
  }: {
    did: string;
    changes: UnauthorizedChange[];
    onback: () => void;
    onoverride: (cid: string, createdAt: string) => void;
  } = $props();

  const countdown = useCountdown(60_000);
</script>

<div class="screen">
  <button class="back" onclick={onback}>
    <ChevronLeftIcon />
    Back
  </button>

  <div class="hero">
    <h1 class="hero-title">Someone changed your identity</h1>
    <p class="hero-sub">
      {changes.length === 1
        ? 'A key you didn’t authorize was added.'
        : `${changes.length} unauthorized changes were detected.`}
      Reverse {changes.length === 1 ? 'it' : 'them'} before the recovery window closes.
    </p>
  </div>

  <div class="identity">
    <span class="id-label">Affected identity</span>
    <span class="id-did">{truncateDid(did)}</span>
  </div>

  <div class="cards">
    {#each changes as change (change.cid)}
      {@const deadline = getDeadline(change.createdAt)}
      {@const urgency = getUrgency(deadline, countdown.now)}
      <div class="card">
        <UrgencyBadge {urgency} {deadline} now={countdown.now} />

        <div class="field">
          <span class="k">Signing key</span>
          <span class="v mono">{change.signingKey ?? 'Unknown key'}</span>
        </div>
        <div class="field">
          <span class="k">Detected</span>
          <span class="v">{formatTimestamp(change.createdAt)}</span>
        </div>
        <div class="field">
          <span class="k">Recovery deadline</span>
          <span class="v">{formatTimestamp(deadline)}</span>
        </div>

        <Button disabled={urgency === 'expired'} onclick={() => onoverride(change.cid, change.createdAt)}>
          {urgency === 'expired' ? 'Recovery window expired' : 'Review & override'}
        </Button>
      </div>
    {/each}
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }

  .back {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs);
    min-height: 44px;
  }

  .hero-title {
    font-family: var(--font-display);
    font-weight: var(--weight-regular);
    font-size: 1.75rem;
    line-height: 1.15;
    color: var(--color-ink);
    margin: 0 0 var(--space-sm);
  }
  .hero-sub {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .identity {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .id-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .id-did {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    word-break: break-all;
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .k {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .v {
    font-size: var(--text-body);
    color: var(--color-ink);
    line-height: 1.4;
  }
  .v.mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    word-break: break-all;
  }
</style>
