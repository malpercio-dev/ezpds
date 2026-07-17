<script lang="ts">
  import { onMount } from 'svelte';
  import { listAgents, type AgentSummary } from '$lib/ipc';
  import { AGENT_STATUS, AGENT_TYPE_LABELS, agentName } from '$lib/agent-display';
  import { formatTimestamp } from '$lib/datetime';
  import Button from '$lib/components/ui/Button.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';
  import AgentDetailScreen from './AgentDetailScreen.svelte';

  let {
    onback,
    onapprove,
  }: {
    onback: () => void;
    /** Navigate to the claim-approval screen (enter a code from an agent). */
    onapprove: () => void;
  } = $props();

  let agents = $state<AgentSummary[]>([]);
  let loading = $state(true);
  let loadError = $state<string | null>(null);

  // The selected agent, if any. The detail sub-view lives in AgentDetailScreen; its lifetime is
  // this selection, so its audit/revoke state is scoped to one agent by construction.
  let selected = $state<AgentSummary | null>(null);

  async function loadAgents() {
    loading = true;
    loadError = null;
    try {
      agents = await listAgents();
    } catch (e) {
      console.error('Failed to load agents:', e);
      loadError = 'Could not load your agents. Check your connection and try again.';
    } finally {
      loading = false;
    }
  }

  function markRevoked(registrationId: string) {
    agents = agents.map((a) =>
      a.registrationId === registrationId ? { ...a, status: 'revoked' } : a
    );
  }

  onMount(loadAgents);
</script>

{#if selected}
  <AgentDetailScreen
    agent={selected}
    onback={() => (selected = null)}
    onrevoked={markRevoked}
  />
{:else}
  <div class="screen">
    <ScreenHeader title="My agents" {onback} />

    {#if loading}
      <div class="loading">
        {#each [0, 1] as i (i)}
          <SkeletonCard />
        {/each}
      </div>
    {:else if loadError}
      <div class="notice" role="alert">
        <p class="notice-text">{loadError}</p>
        <Button variant="secondary" onclick={loadAgents}>Try again</Button>
      </div>
    {:else if agents.length === 0}
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
      <p class="lede">
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

      <button class="add-card" onclick={onapprove}>
        <span class="add-plus" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
        </span>
        <span class="add-body">
          <span class="add-t">Approve an agent</span>
          <span class="add-s">Enter the code an agent showed you</span>
        </span>
      </button>
    {/if}
  </div>
{/if}

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }

  .truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .lede {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card {
    display: flex;
    align-items: center;
    gap: 14px;
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
    gap: 6px;
    margin-top: 5px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
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
    gap: 13px;
    background: transparent;
    border: 1.5px dashed var(--color-line);
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
    width: 42px;
    height: 42px;
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
  .add-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
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
    width: 64px;
    height: 64px;
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

  .notice {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    background: var(--color-critical-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    text-align: center;
  }
  .notice-text {
    font-size: var(--text-body);
    color: var(--color-critical);
    margin: 0;
  }

  .loading {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
</style>
