<script lang="ts">
  import { onMount } from 'svelte';
  import { getBlobBackupStatus, getRepoBackupStatus } from '$lib/ipc';
  import { isDidWeb } from '$lib/did-doc-utils';
  import { formatTimestamp } from '$lib/datetime';

  // The quiet disclosure under a secure status panel: the standing defences, named, so the
  // protection the wallet performs invisibly has somewhere to be seen. Everything here is a
  // read of state the wallet already holds — the checkup never runs an operation, so opening
  // it is free and costs the user nothing to be curious.
  //
  // Deliberately absent: whether the user confirmed their Share 3 backup. The wallet stores
  // that only as a staging slot it tears down on confirmation, and "no staging slot" is
  // equally true of an identity that never had one — so there is no read that could tell the
  // two apart, and a line that guessed would be worse than no line.
  let {
    did,
    deviceKeyIsRoot,
    deviceKeyUnusable,
  }: {
    did: string;
    deviceKeyIsRoot: boolean | null;
    deviceKeyUnusable: boolean;
  } = $props();

  type Verdict = 'held' | 'attention' | 'unknown';
  type Line = { label: string; value: string; verdict: Verdict };

  let mediaLine = $state<Line | null>(null);
  let postsLine = $state<Line | null>(null);

  let isWeb = $derived(isDidWeb(did));

  let custody = $derived<Line>(
    deviceKeyUnusable
      ? {
          label: 'Key custody',
          value: "This device's key is gone",
          verdict: 'attention',
        }
      : isWeb
        ? {
            // A did:web has no rotation-key hierarchy to hold a position in, so reporting
            // one either way would describe machinery this identity does not have.
            label: 'Key custody',
            value: 'Held by your domain',
            verdict: 'held',
          }
        : deviceKeyIsRoot === true
          ? {
              label: 'Key custody',
              value: 'This device holds the deciding key',
              verdict: 'held',
            }
          : deviceKeyIsRoot === false
            ? {
                label: 'Key custody',
                value: "This device doesn't hold the deciding key",
                verdict: 'attention',
              }
            : { label: 'Key custody', value: 'Not confirmed', verdict: 'unknown' }
  );

  let record = $derived<Line>(
    isWeb
      ? {
          label: 'Public record',
          value: 'No audit log to watch',
          verdict: 'unknown',
        }
      : {
          label: 'Public record',
          value: 'Watched for unauthorized changes',
          verdict: 'held',
        }
  );

  /** Shared shape for the two backup readouts — the only difference is which status they read. */
  function backupLine(
    label: string,
    status: { enabled: boolean; lastBackupAt: string | null }
  ): Line {
    if (!status.enabled) return { label, value: 'Off', verdict: 'attention' };
    if (!status.lastBackupAt) return { label, value: 'On, not run yet', verdict: 'attention' };
    return { label, value: `Last saved ${formatTimestamp(status.lastBackupAt)}`, verdict: 'held' };
  }

  onMount(() => {
    // Each read stands alone: a backup surface that cannot answer leaves its own line
    // unknown rather than blanking the whole checkup. A checkup that disappears on one
    // failed read would be worse than one that admits a gap.
    getBlobBackupStatus(did)
      .then((s) => {
        mediaLine = backupLine('Media backup', s);
      })
      .catch((e) => {
        console.warn('Security checkup: media backup status unavailable', e);
        mediaLine = { label: 'Media backup', value: 'Not confirmed', verdict: 'unknown' };
      });

    getRepoBackupStatus(did)
      .then((s) => {
        postsLine = backupLine('Posts backup', s);
      })
      .catch((e) => {
        console.warn('Security checkup: posts backup status unavailable', e);
        postsLine = { label: 'Posts backup', value: 'Not confirmed', verdict: 'unknown' };
      });
  });

  let lines = $derived(
    [custody, record, mediaLine, postsLine].filter((l): l is Line => l !== null)
  );
</script>

<details class="checkup">
  <summary>
    Security checkup
    <svg class="caret" width="11" height="7" viewBox="0 0 12 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m1 1.5 5 5 5-5" /></svg>
  </summary>
  <dl class="lines">
    {#each lines as line (line.label)}
      <div class="line">
        <span class="mark mark--{line.verdict}" aria-hidden="true">
          {#if line.verdict === 'held'}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7" /></svg>
          {:else if line.verdict === 'attention'}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v5" /><path d="M12 17h.01" /></svg>
          {:else}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14" /></svg>
          {/if}
        </span>
        <span class="text">
          <dt>{line.label}</dt>
          <dd>{line.value}</dd>
        </span>
      </div>
    {/each}
  </dl>
</details>

<style>
  .checkup {
    border-top: 1px solid var(--color-line);
    padding-top: var(--space-sm);
  }
  summary {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: var(--size-tap-target);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-accent);
    cursor: pointer;
    list-style: none;
  }
  summary::-webkit-details-marker {
    display: none;
  }
  .caret {
    transition: transform var(--duration-base) var(--ease-standard);
  }
  .checkup[open] .caret {
    transform: rotate(180deg);
  }
  @media (prefers-reduced-motion: reduce) {
    .caret {
      transition: none;
    }
  }

  .lines {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0 0 var(--space-2xs);
  }
  /* Label above value, both left-aligned. A right-aligned value column looked tidy until a
     phrase wrapped, and a ragged right edge on a two-line value is harder to read than the
     extra line this costs. */
  .line {
    display: grid;
    grid-template-columns: 16px minmax(0, 1fr);
    gap: var(--space-xs);
  }
  .mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding-top: 2px;
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  /* The icon shape and the value text each say the verdict on their own; colour only
     reinforces what both already state. */
  .mark--held {
    color: var(--color-safe);
  }
  .mark--attention {
    color: var(--color-warning);
  }
  .mark--unknown {
    color: var(--color-muted);
  }
  dt {
    font-size: var(--text-caption);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    letter-spacing: 0.01em;
  }
  dd {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    line-height: 1.4;
    margin: 0;
  }
</style>
