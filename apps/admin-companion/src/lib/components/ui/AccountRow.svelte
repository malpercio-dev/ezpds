<script lang="ts">
  import StatusChip, { type Status } from './StatusChip.svelte';

  // One account in the operator list — DeviceRow's dense `ls -l` register, plus the
  // blob-quota readout the list exists to make scannable. Handle (or an explicit
  // "no handle") + shortened mono DID on the left with the quota meter beneath them,
  // a lifecycle chip on the right. The full DID is one tap away (onclick → the
  // per-account screens), so the row shows a head…tail form with a VISIBLE ellipsis —
  // explicit truncation, never the silent kind the Literal-Truth rule forbids.
  let {
    did,
    handle,
    status,
    quota,
    onclick,
  }: {
    did: string;
    /** The account's handle, or null when it has none (rendered as an explicit gap). */
    handle: string | null;
    status: 'active' | 'deactivated' | 'suspended' | 'takendown';
    /** The monospace quota readout for this row (see format.ts `quotaBar`). */
    quota: string;
    onclick?: () => void;
  } = $props();

  // Lifecycle → chip tone/glyph/label. Precedence and vocabulary come from the relay;
  // this only picks the register: deactivated is a dormant (warning) state the user
  // chose, suspended and takendown are operator-imposed (critical) states.
  const CHIP: Record<typeof status, { chip: Status; label: string }> = {
    active: { chip: 'active', label: 'active' },
    deactivated: { chip: 'pending', label: 'deactivated' },
    suspended: { chip: 'error', label: 'suspended' },
    takendown: { chip: 'revoked', label: 'taken down' },
  };
  const chip = $derived(CHIP[status]);

  // did:plc:abc12…z9q — keep the method prefix and a tail so it stays recognizable.
  function shorten(id: string): string {
    if (id.length <= 24) return id;
    return `${id.slice(0, 14)}…${id.slice(-4)}`;
  }
</script>

{#snippet content()}
  <div class="main">
    <div class="line1">
      {#if handle}
        <span class="label">{handle}</span>
      {:else}
        <span class="label label--none">no handle</span>
      {/if}
    </div>
    <span class="id">{shorten(did)}</span>
    <span class="quota">{quota}</span>
  </div>
  <StatusChip status={chip.chip} label={chip.label} />
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
    gap: var(--space-2xs);
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
  /* An absent handle is a stated fact, not an empty cell. */
  .label--none {
    color: var(--color-muted);
    font-style: italic;
  }
  .id {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  /* The capacity column: identical monospace width per row, so a scrolling list scans
     like aligned terminal output. */
  .quota {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    white-space: pre;
  }
</style>
