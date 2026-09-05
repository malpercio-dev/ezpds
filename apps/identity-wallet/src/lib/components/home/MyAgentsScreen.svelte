<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listAgents,
    listChildren,
    reconcileChildren,
    agentAccountsProvisioned,
    sovereignLogin,
    isCodedError,
    type AgentSummary,
    type ChildSummary,
    type ChildKeyCheck,
    type AgentsError,
  } from '$lib/ipc';
  import {
    AGENT_STATUS,
    AGENT_TYPE_LABELS,
    CHILD_STATUS,
    agentName,
    childState,
  } from '$lib/agent-display';
  import { formatTimestamp } from '$lib/datetime';
  import Button from '$lib/components/ui/Button.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';
  import AgentDetailScreen from './AgentDetailScreen.svelte';
  import ChildAgentDetailScreen from './ChildAgentDetailScreen.svelte';

  // The per-identity agent list (the `my_agents` step, from the identity screen's Use
  // zone). Renders AgentDetailScreen as a sub-view on selection; a SESSION_LOCKED load
  // offers a sovereign unlock instead of an error.
  let {
    did,
    onback,
    onapprove,
    onprovision,
  }: {
    did: string;
    onback: () => void;
    /** Navigate to the claim-approval screen (enter a code from an agent). */
    onapprove: () => void;
    /** Navigate to "Enable agent accounts" — this identity holds no delegation seed. */
    onprovision: () => void;
  } = $props();

  let agents = $state<AgentSummary[]>([]);
  // Sovereign children come from a different route than delegated agents and always will: a
  // child's registration is bound to the *child's* DID, so it never appears on `GET /v1/agents`,
  // which lists what is bound to this account. Two lists, one screen.
  let children = $state<ChildSummary[]>([]);
  let loading = $state(true);
  // The list couldn't load because the identity's session needs a passwordless unlock.
  let locked = $state(false);
  let loadError = $state<string | null>(null);

  // Whether this identity can give an agent an account of its own. Local Keychain read, so it
  // resolves even when the agent list itself is locked or offline — the provisioning entry has
  // to be reachable from exactly those states, since it needs no session at all.
  let provisioned = $state(true);

  // The recovery epilogue's verdict on this identity's children, when it ran. A restored wallet
  // holds the delegation seed again but no counter, so this is where it finds out which agent
  // accounts it can still recover — and says so, rather than leaving the answer implicit.
  let recovered = $state<ChildKeyCheck[]>([]);
  let unrecoverable = $derived(recovered.filter((c) => c.status === 'unmatched'));
  let uncheckable = $derived(recovered.filter((c) => c.status === 'unchecked'));
  let relinked = $derived(recovered.filter((c) => c.status === 'matched'));

  // The selected agent or child, if any. Each detail sub-view's lifetime is this selection, so
  // its audit/lifecycle state is scoped to one subject by construction.
  let selected = $state<AgentSummary | null>(null);
  let selectedChild = $state<ChildSummary | null>(null);

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Could not load your agents. Please try again.';
    const err = raw as AgentsError;
    switch (err.code) {
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'NOT_AUTHENTICATED':
        return 'Your session for this identity has expired. Unlock it and try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Could not load your agents. Please try again.';
    }
  }

  async function loadAgents() {
    loading = true;
    locked = false;
    loadError = null;
    try {
      // Both lists or neither: a half-loaded screen would understate what this account has
      // granted, which is the one thing this surface exists to report accurately.
      [agents, children] = await Promise.all([listAgents(did), listChildren(did)]);
    } catch (e) {
      if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
        locked = true;
      } else {
        console.error('Failed to load agents:', e);
        loadError = messageFor(e);
      }
    } finally {
      loading = false;
    }
  }

  // Re-derive the children against the public directory. Only ever reports something on a device
  // that is behind the server's list — the recovery case — since the command short-circuits
  // otherwise. Never blocks or fails the list: the accounts are real and manageable either way,
  // and a check that could not run says so instead of pretending it did.
  async function reconcile() {
    recovered = [];
    if (children.length === 0) return;
    try {
      const result = await reconcileChildren(did);
      if (result.rebuilt) recovered = result.children;
    } catch (e) {
      console.warn('[MyAgentsScreen] child reconciliation did not run:', e);
    }
  }

  async function unlockAndReload() {
    try {
      await sovereignLogin(did);
    } catch (e) {
      console.error('[MyAgentsScreen] sovereign login failed:', e);
      return;
    }
    await loadAgents();
    await reconcile();
  }

  function markRevoked(registrationId: string) {
    agents = agents.map((a) =>
      a.registrationId === registrationId ? { ...a, status: 'revoked' } : a
    );
  }

  function markChildChanged(updated: ChildSummary) {
    children = children.map((c) => (c.did === updated.did ? updated : c));
    selectedChild = updated;
  }

  onMount(async () => {
    provisioned = await agentAccountsProvisioned(did).catch((e) => {
      console.warn('[MyAgentsScreen] provisioning probe failed:', e);
      return true; // Don't advertise setup we can't confirm is missing.
    });
    await loadAgents();
    await reconcile();
  });
</script>

{#if selected}
  <AgentDetailScreen
    {did}
    agent={selected}
    onback={() => (selected = null)}
    onrevoked={markRevoked}
  />
{:else if selectedChild}
  <ChildAgentDetailScreen
    {did}
    child={selectedChild}
    onback={() => (selectedChild = null)}
    onchanged={markChildChanged}
  />
{:else}
  <div class="screen u-screen">
    <ScreenHeader title="My agents" {onback} />

    {#if loading}
      <div class="loading">
        {#each [0, 1] as i (i)}
          <SkeletonCard />
        {/each}
      </div>
    {:else if locked}
      <div class="notice u-notice" role="alert">
        <p class="notice-text u-notice-text">This identity is locked. Unlock it to see and manage your agents.</p>
        <Button onclick={unlockAndReload}>Unlock identity</Button>
      </div>
    {:else if loadError}
      <div class="notice u-notice" role="alert">
        <p class="notice-text u-notice-text">{loadError}</p>
        <Button variant="secondary" onclick={loadAgents}>Try again</Button>
      </div>
    {:else if agents.length === 0 && children.length === 0}
      <div class="empty">
        <span class="empty-seal" aria-hidden="true">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><path d="M9 14h.01M15 14h.01"/></svg>
        </span>
        <p class="empty-title">No agents connected</p>
        <p class="empty-sub">
          When an app or agent asks to act on your behalf, it will show you a code. Approving it
          here is what grants access — and you will see everything it does.
        </p>
        <Button onclick={onapprove}>Approve an agent</Button>
      </div>
    {:else}
      <!-- The recovery epilogue's verdict, shown above the accounts it is about. Three separate
           sentences on purpose: "we cannot recover this" and "we could not check this" are not
           the same claim, and neither is carried by colour alone. -->
      {#if unrecoverable.length > 0}
        <div class="recovery recovery--warning" role="alert">
          <p class="recovery-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>
            {unrecoverable.length === 1 ? 'One account' : `${unrecoverable.length} accounts`} can’t be
            recovered from this device
          </p>
          <p class="recovery-detail">
            {unrecoverable.map((c) => c.handle).join(', ')} — the public directory lists a recovery
            key this wallet can’t reproduce. {unrecoverable.length === 1
              ? 'The account still works and you can still revoke or delete it, but its recovery key lives somewhere else.'
              : 'The accounts still work and you can still revoke or delete them, but their recovery keys live somewhere else.'}
          </p>
        </div>
      {/if}
      {#if uncheckable.length > 0}
        <div class="recovery recovery--muted">
          <p class="recovery-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><path d="M12 16h.01"/></svg>
            Couldn’t check {uncheckable.length === 1 ? 'one account' : `${uncheckable.length} accounts`}
          </p>
          <p class="recovery-detail">
            {uncheckable.map((c) => c.handle).join(', ')} — the public directory couldn’t be
            reached, so this isn’t a verdict either way. Try again when you’re back online.
          </p>
          <Button variant="secondary" onclick={reconcile}>Check again</Button>
        </div>
      {:else if relinked.length > 0 && unrecoverable.length === 0}
        <div class="recovery recovery--safe">
          <p class="recovery-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5L20 7"/></svg>
            {relinked.length === 1 ? 'One account is' : `${relinked.length} accounts are`} back on this
            device
          </p>
          <p class="recovery-detail">
            {relinked.map((c) => c.handle).join(', ')} — your recovery seed still holds the recovery
            {relinked.length === 1 ? 'key for it' : 'keys for them'}, so this device can recover
            {relinked.length === 1 ? 'it' : 'them'} again.
          </p>
        </div>
      {/if}

      {#if children.length > 0}
        <p class="section-label">Agents with their own account</p>
        <p class="lede u-body-copy">
          These agents act as themselves, not as you. You signed each account into existence, so
          you can revoke or delete it — but nothing it posts is attributed to you.
        </p>
        <div class="cards">
          {#each children as child (child.did)}
            {@const state_ = childState(child)}
            <button class="card" onclick={() => (selectedChild = child)}>
              <span class="info">
                <span class="name truncate">{child.handle}</span>
                <span class="kind">Its own account</span>
                <span class="badges">
                  <span class="badge badge--child-{state_}">
                    {#if state_ === 'live'}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21s7-3.5 7-8.7V4.9L12 2 5 4.9v7.4C5 17.5 12 21 12 21z"/></svg>
                    {:else if state_ === 'deleting'}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/></svg>
                    {:else if state_ === 'revoked'}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
                    {:else}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                    {/if}
                    {CHILD_STATUS[state_].label}
                  </span>
                  {#if child.deleteAfter}
                    <span class="badge badge--muted">Removed after {formatTimestamp(child.deleteAfter)}</span>
                  {/if}
                </span>
              </span>
              <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {/each}
        </div>
      {/if}

      {#if agents.length > 0}
        {#if children.length > 0}<p class="section-label">Agents acting for you</p>{/if}
        <p class="lede u-body-copy">
          Agents you have approved to act on your behalf. Tap one to see its permissions and its
          full activity record.
        </p>
        <div class="cards">
          {#each agents as agent (agent.registrationId)}
            {@const status = AGENT_STATUS[agent.status]}
            <button class="card" onclick={() => (selected = agent)}>
              <span class="info">
                <span class="name truncate">{agentName(agent)}</span>
                <span class="kind">{AGENT_TYPE_LABELS[agent.registrationType] ?? agent.registrationType}</span>
                <span class="badges">
                  <span class="badge badge--{agent.status}">
                    {#if agent.status === 'claimed'}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>
                    {:else if agent.status === 'revoked'}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
                    {:else}
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                    {/if}
                    {status.label}
                  </span>
                  {#if agent.lastUsedAt}
                    <span class="badge badge--muted">Last used {formatTimestamp(agent.lastUsedAt)}</span>
                  {/if}
                </span>
              </span>
              <svg class="chev" width="9" height="16" viewBox="0 0 11 18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 1 7 8-7 8"/></svg>
            </button>
          {/each}
        </div>
      {/if}

      <button class="add-card" onclick={onapprove}>
        <span class="add-plus" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
        </span>
        <span class="add-body">
          <span class="add-t u-title-strong">Approve an agent</span>
          <span class="add-s">Enter the code an agent showed you</span>
        </span>
      </button>
    {/if}

    {#if !provisioned && !loading}
      <button class="add-card" onclick={onprovision}>
        <span class="add-plus" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
        </span>
        <span class="add-body">
          <span class="add-t u-title-strong">Enable agent accounts</span>
          <span class="add-s">Let an agent have its own account, not the keys to yours</span>
        </span>
      </button>
    {/if}
  </div>
{/if}

<style>
  .truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .section-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: var(--space-xs) 0 calc(-1 * var(--space-2xs));
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
  .card {
    display: flex;
    align-items: center;
    gap: var(--space-md);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: var(--space-md);
    width: 100%;
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-base) var(--ease-standard), border-color var(--duration-base) var(--ease-standard);
  }
  .card:active {
    background: var(--color-surface);
    border-color: var(--color-line-strong);
  }
  .info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .name {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .kind {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-sm);
    margin-top: var(--space-xs);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    padding: var(--space-2xs) var(--space-sm);
    border-radius: var(--radius-full);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    white-space: nowrap;
  }
  .badge--claimed {
    background: var(--color-safe-surface);
    color: var(--color-safe);
  }
  .badge--active {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .badge--revoked {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
  }
  .badge--child-live {
    background: var(--color-safe-surface);
    color: var(--color-safe);
  }
  .badge--child-provisioning {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .badge--child-deleting {
    background: var(--color-critical-surface);
    color: var(--color-critical);
  }
  .badge--child-revoked {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
  }
  .badge--muted {
    background: var(--color-surface-sunk);
    color: var(--color-muted);
    font-weight: var(--weight-regular, 400);
  }
  .chev {
    color: var(--color-ink-faint);
    flex-shrink: 0;
  }

  .add-card {
    display: flex;
    align-items: center;
    gap: var(--space-md);
    background: transparent;
    border: 1.5px dashed var(--color-line); /* px-ok: small badge hairline, deliberately thicker than 1px */
    border-radius: var(--radius-xl);
    padding: var(--space-md);
    width: 100%;
    text-align: left;
    cursor: pointer;
  }
  .add-card:active {
    border-color: var(--color-primary);
    background: var(--color-seal-tint);
  }
  .add-plus {
    width: var(--size-icon-2xl);
    height: var(--size-icon-2xl);
    border-radius: var(--radius-full);
    background: var(--color-surface);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .add-body {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .add-s {
    font-size: var(--text-label);
    color: var(--color-muted);
  }

  /* Empty, error, loading */
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-sm);
    flex: 1;
    padding: var(--space-xl) var(--space-md);
  }
  .empty-seal {
    width: var(--size-avatar-md);
    height: var(--size-avatar-md);
    border-radius: var(--radius-full);
    background: var(--color-seal-pale);
    color: var(--color-primary-deep);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: var(--space-sm);
  }
  .empty-title {
    font-size: var(--text-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .empty-sub {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0 0 var(--space-sm);
    max-width: 34ch;
    line-height: 1.5;
  }

  /* The recovery epilogue's report. Each state is carried by its own icon, word, and surface —
     never by colour alone (DESIGN.md), so the three read apart in monochrome. */
  .recovery {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-xs);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    margin-bottom: var(--space-lg);
    text-align: left;
  }
  .recovery--warning {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .recovery--safe {
    background: var(--color-safe-surface);
    color: var(--color-safe);
  }
  .recovery--muted {
    background: var(--color-surface);
    color: var(--color-text);
  }
  .recovery-title {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    font-size: var(--text-body);
    font-weight: 600;
    margin: 0;
  }
  .recovery-detail {
    font-size: var(--text-label);
    line-height: var(--leading-body);
    margin: 0;
    color: inherit;
    opacity: 0.9;
  }
  .recovery :global(button) {
    margin-top: var(--space-sm);
    align-self: flex-start;
    width: auto;
  }

  .loading {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
</style>
