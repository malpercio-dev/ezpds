<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { SvelteMap } from 'svelte/reactivity';
  import {
    listPairings,
    listClaimCodes,
    revokeClaimCode,
    type ClaimCodeEntry,
    type Pairing,
    type PairingsState,
  } from '$lib/ipc';
  import { partitionCodes, chipFor, timelineLine } from '$lib/claim-codes';
  import { serverIdentity } from '$lib/server-identity';
  import { classifyRelayError, type ErrorView } from '$lib/errors';
  import { requireUserPresence, presenceAllows } from '$lib/biometric';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';

  // The claim-code inventory: every code minted on ONE relay with its derived
  // lifecycle status, split into outstanding live credentials (revocable) and the
  // historical record. Pinned to a single pairing at entry (`?server=<pairingId>`,
  // else the active pairing) — id-addressed like Devices, so a concurrent active
  // switch on Home can never redirect what this screen shows or signs.

  type InventoryState =
    | { kind: 'loading' }
    | { kind: 'error'; view: ErrorView }
    | { kind: 'ready'; codes: ClaimCodeEntry[]; cursor?: string; paging: boolean };

  let pairingsView = $state<PairingsState | 'loading' | 'error'>('loading');
  let inventory = $state<InventoryState>({ kind: 'loading' });
  // A failed *page* fetch never clobbers the rows already shown — it renders
  // inline next to the paging button instead (mirrors the Accounts screen).
  let pagingError = $state<ErrorView | undefined>(undefined);
  let expandedCode = $state<string | null>(null);
  let revokingStates = $state<SvelteMap<string, boolean>>(new SvelteMap());
  let revokeErrors = $state<SvelteMap<string, ErrorView | undefined>>(new SvelteMap());
  let gateHint = $state<string | undefined>(undefined);

  // Pinned once at entry: the pairing this screen shows and signs for.
  let pairing = $state<Pairing | null>(null);

  onMount(async () => {
    try {
      pairingsView = await listPairings();
    } catch {
      pairingsView = 'error';
      return;
    }
    const requested = page.url.searchParams.get('server');
    const targetId = requested ?? pairingsView.active;
    pairing = pairingsView.pairings.find((p) => p.id === targetId) ?? null;
    if (pairing) await loadInventory(pairing.id);
  });

  async function loadInventory(pairingId: string) {
    inventory = { kind: 'loading' };
    pagingError = undefined;
    try {
      const first = await listClaimCodes(pairingId);
      inventory = { kind: 'ready', codes: first.codes, cursor: first.cursor, paging: false };
    } catch (e) {
      inventory = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  /** Fetch the next page and append — the accumulated list stays newest-first. */
  async function loadMore() {
    if (!pairing || inventory.kind !== 'ready' || !inventory.cursor || inventory.paging) return;
    inventory = { ...inventory, paging: true };
    pagingError = undefined;
    try {
      const next = await listClaimCodes(pairing.id, inventory.cursor);
      inventory = {
        kind: 'ready',
        codes: [...inventory.codes, ...next.codes],
        cursor: next.cursor,
        paging: false,
      };
    } catch (e) {
      // A failed page keeps what is already shown; the error renders by the button.
      pagingError = classifyRelayError(e);
      inventory = { ...inventory, paging: false };
    }
  }

  async function doRevoke(entry: ClaimCodeEntry) {
    if (!pairing) return;
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent revokes.
    if (revokingStates.get(entry.code)) return;
    revokingStates.set(entry.code, true);
    gateHint = undefined;
    revokeErrors.set(entry.code, undefined);

    try {
      // Revoking kills a live credential — gate it on user presence.
      const presence = await requireUserPresence('Revoke a claim code on this server');
      if (!presenceAllows(presence)) {
        gateHint = 'Confirm with Face ID to revoke this code.';
        return;
      }
      await revokeClaimCode(pairing.id, entry.code);
      // Reload so the row reports the relay's post-revoke truth (status flips to
      // revoked with its timestamp) rather than an optimistic local edit.
      await loadInventory(pairing.id);
    } catch (e) {
      revokeErrors.set(entry.code, classifyRelayError(e));
    } finally {
      revokingStates.set(entry.code, false);
    }
  }

  function toggleExpanded(code: string) {
    expandedCode = expandedCode === code ? null : code;
  }

  const identity = $derived(pairing ? serverIdentity(pairing) : null);
  const grouped = $derived(
    inventory.kind === 'ready' ? partitionCodes(inventory.codes) : null,
  );
</script>

{#snippet codeRow(entry: ClaimCodeEntry, revocable: boolean)}
  {@const chip = chipFor(entry.status)}
  <div class="code-item">
    <button
      class="code-row"
      type="button"
      aria-expanded={expandedCode === entry.code}
      aria-controls={`code-panel-${entry.code}`}
      onclick={() => toggleExpanded(entry.code)}
    >
      <span class="code-value">{entry.code}</span>
      <span class="code-timeline">{timelineLine(entry)}</span>
      <StatusChip status={chip.chip} label={chip.label} />
    </button>

    {#if expandedCode === entry.code}
      <div class="code-panel" id={`code-panel-${entry.code}`}>
        <dl class="facts">
          <dt>minted</dt>
          <dd>{entry.createdAt}</dd>
          <dt>expires</dt>
          <dd>{entry.expiresAt}</dd>
          {#if entry.redeemedAt}
            <dt>redeemed</dt>
            <dd>{entry.redeemedAt}</dd>
          {/if}
          {#if entry.revokedAt}
            <dt>revoked</dt>
            <dd>{entry.revokedAt}</dd>
          {/if}
        </dl>

        {#if revocable}
          <Button
            variant="destructive"
            loading={revokingStates.get(entry.code) ?? false}
            onclick={() => doRevoke(entry)}
          >
            Revoke this code
          </Button>
          {#if revokeErrors.get(entry.code)}
            <ErrorState
              view={revokeErrors.get(entry.code)!}
              server={identity}
              retrying={revokingStates.get(entry.code) ?? false}
              onretry={() => doRevoke(entry)}
            />
          {/if}
        {/if}
        <!-- A terminal code needs no action: the chip + timestamp already report it. -->
      </div>
    {/if}
  </div>
{/snippet}

<ScreenShell
  prompt="codes"
  title="Claim codes on this server"
  onback={() => history.back()}
  server={identity}
>
  {#if pairingsView === 'loading'}
    <p class="resolving">checking servers…</p>
  {:else if pairingsView === 'error'}
    <section class="panel" aria-label="Server check failed">
      <StatusChip status="error" label="check failed" />
      <p class="note" role="alert">Couldn't read this device's servers. Go back and retry.</p>
    </section>
  {:else if !pairing}
    <!-- Unpaired, or no active pick and no ?server pin — there is no relay to ask. -->
    <section class="panel" aria-label="No server selected">
      <StatusChip status="pending" label="no server" />
      <p class="note">
        No server is selected. Pick or pair one first — the code inventory is always read
        from a specific server.
      </p>
    </section>
  {:else if inventory.kind === 'loading'}
    <p class="resolving">reading code inventory…</p>
  {:else if inventory.kind === 'error'}
    <ErrorState
      view={inventory.view}
      server={identity}
      onretry={() => pairing && loadInventory(pairing.id)}
    />
  {:else if grouped}
    <p class="lede">
      Every claim code minted on this server. An outstanding code is a live signup
      credential — revoke one to kill it before anyone redeems it.
    </p>

    <section class="panel" aria-labelledby="outstanding-label">
      <span id="outstanding-label" class="label">
        Outstanding · {grouped.outstanding.length}
      </span>
      {#if grouped.outstanding.length === 0}
        <p class="note">No live codes. Codes minted on Home appear here until redeemed.</p>
      {:else}
        <div class="code-list">
          {#each grouped.outstanding as entry (entry.code)}
            {@render codeRow(entry, true)}
          {/each}
        </div>
      {/if}
    </section>

    {#if grouped.history.length > 0}
      <section class="panel" aria-labelledby="history-label">
        <span id="history-label" class="label">History · {grouped.history.length}</span>
        <div class="code-list">
          {#each grouped.history as entry (entry.code)}
            {@render codeRow(entry, false)}
          {/each}
        </div>
      </section>
    {/if}

    {#if inventory.cursor}
      <Button variant="secondary" loading={inventory.paging} onclick={loadMore}>
        Load more
      </Button>
      {#if pagingError}
        <ErrorState view={pagingError} server={identity} retrying={inventory.paging} onretry={loadMore} />
      {/if}
    {/if}

    {#if gateHint}
      <p class="hint" role="status">
        <StatusChip status="info" label="confirm" />
        <span>{gateHint}</span>
      </p>
    {/if}
  {/if}

  {#snippet actions()}
    {#if pairing && inventory.kind === 'ready'}
      <Button variant="secondary" onclick={() => pairing && loadInventory(pairing.id)}>
        Refresh
      </Button>
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
  .lede {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
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
  .code-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .code-item {
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    background: var(--color-surface-raised);
  }
  .code-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--control-min-height);
    padding: var(--space-sm);
    background: transparent;
    border: none;
    font: inherit;
    color: inherit;
    cursor: pointer;
    text-align: left;
  }
  .code-row:hover,
  .code-row:active {
    background: var(--color-surface);
  }
  /* The code itself is the row's identity: mono, tracked out like CodeOutput. */
  .code-value {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    font-weight: var(--weight-medium);
    letter-spacing: 0.12em;
    color: var(--color-ink);
  }
  .code-timeline {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
  .code-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding: var(--space-md);
    padding-top: var(--space-sm);
    border-top: var(--border-hairline) solid var(--color-line);
  }
  /* The fact sheet: aligned label/value pairs, the legibility of a good `ls -l`. */
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2xs) var(--space-md);
    margin: 0;
  }
  /* Inside a raised well: ink-soft, per the tokens.css contrast rule for muted. */
  .facts dt {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink-soft);
  }
  .facts dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-wrap: anywhere;
  }
</style>
