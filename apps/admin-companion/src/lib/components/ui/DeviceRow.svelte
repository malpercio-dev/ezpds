<script lang="ts">
  import StatusChip, { type Status } from './StatusChip.svelte';

  // A dense, aligned list row — the legibility of a good `ls -l`. Label + shortened
  // mono did:key + last-seen on the left, a status chip on the right. The full key
  // is one tap away (onclick → device detail), so the row shows a head…tail form
  // with a VISIBLE ellipsis — explicit truncation, never the silent kind the
  // Literal-Truth rule forbids.
  let {
    label,
    deviceId,
    lastSeen,
    status,
    current = false,
    onclick,
  }: {
    label: string;
    deviceId: string;
    lastSeen: string;
    status: Status;
    /** Mark the operator's current device. */
    current?: boolean;
    onclick?: () => void;
  } = $props();

  // did:key:zDnae…aH2g — keep the method prefix and a tail so it stays recognizable.
  function shorten(id: string): string {
    if (id.length <= 24) return id;
    return `${id.slice(0, 14)}…${id.slice(-4)}`;
  }
</script>

{#snippet content()}
  <div class="main">
    <div class="line1">
      <span class="label">{label}</span>
      {#if current}<span class="current">this device</span>{/if}
    </div>
    <span class="id">{shorten(deviceId)}</span>
    <span class="meta">{lastSeen}</span>
  </div>
  <StatusChip {status} />
{/snippet}

{#if onclick}
  <button class="row row--tappable" type="button" {onclick}>
    {@render content()}
  </button>
{:else}
  <div class="row">
    {@render content()}
  </div>
{/if}

<style>
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-md);
    width: 100%;
    min-height: var(--control-min-height);
    padding: var(--space-sm) 0;
    text-align: left;
    background: transparent;
    border: none;
    font: inherit;
    color: inherit;
  }
  .row--tappable {
    cursor: pointer;
  }
  .main {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .line1 {
    display: flex;
    align-items: baseline;
    gap: var(--space-sm);
  }
  .label {
    font-family: var(--font-sans);
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  /* `current` is the One-Lamp moment in a list: gold label, not a side stripe. */
  .current {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-primary);
  }
  .id {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .meta {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
</style>
