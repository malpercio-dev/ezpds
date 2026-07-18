<script lang="ts">
  import { onMount } from 'svelte';
  import {
    revokeAgent,
    getAgentAudit,
    type AgentSummary,
    type AgentAuditEvent,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { describeScopes } from '$lib/agent-scopes';
  import {
    AGENT_STATUS,
    AGENT_EVENT_LABELS,
    AGENT_TYPE_LABELS,
    agentName,
    agentDetailLine,
  } from '$lib/agent-display';
  import { formatTimestamp } from '$lib/datetime';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';

  let {
    did,
    agent,
    onback,
    onrevoked,
  }: {
    did: string;
    agent: AgentSummary;
    onback: () => void;
    /** Tell the parent list this agent is now revoked, so its card reflects the new status. */
    onrevoked: (registrationId: string) => void;
  } = $props();

  // This component's lifetime is the selection, so no cross-agent stale-guards are needed: an
  // audit/revoke request in flight when the user navigates back simply resolves into an unmounted
  // component. Status is the only field that changes here — a successful revoke sets the local
  // override, and the displayed status derives from it over the incoming prop.
  let revokedLocally = $state(false);
  let status = $derived(revokedLocally ? 'revoked' : agent.status);

  let auditEvents = $state<AgentAuditEvent[]>([]);
  let auditCursor = $state<string | undefined>(undefined);
  let auditLoading = $state(false);
  let auditError = $state<string | null>(null);

  // Revocation flow: explicit confirm step, then biometric.
  let confirmingRevoke = $state(false);
  let revoking = $state(false);
  let revokeError = $state<string | null>(null);

  let currentStatus = $derived(AGENT_STATUS[status]);

  async function loadMoreAudit() {
    const cursor = auditCursor;
    auditLoading = true;
    auditError = null;
    try {
      const page = await getAgentAudit(did, agent.registrationId, cursor);
      auditEvents = [...auditEvents, ...page.events];
      auditCursor = page.cursor;
    } catch (e) {
      console.error('Failed to load audit trail:', e);
      auditError = 'Could not load the activity record.';
    } finally {
      auditLoading = false;
    }
  }

  async function doRevoke() {
    if (revoking) return;
    revokeError = null;
    // Set the in-flight flag before the biometric prompt so a second tap during the Face ID
    // wait cannot fire a duplicate prompt/revocation.
    revoking = true;
    try {
      await authenticateBiometric('Revoke this agent’s access');
    } catch {
      revoking = false;
      return; // gate rejected — nothing changes.
    }
    try {
      await revokeAgent(did, agent.registrationId);
      confirmingRevoke = false;
      revokedLocally = true;
      onrevoked(agent.registrationId);
      // Re-pull the trail so the freshly-recorded revocation entry shows.
      auditEvents = [];
      auditCursor = undefined;
      revoking = false;
      await loadMoreAudit();
    } catch (e) {
      console.error('Revocation failed:', e);
      revokeError = 'Revocation did not go through. Check your connection and try again.';
    } finally {
      revoking = false;
    }
  }

  onMount(loadMoreAudit);
</script>

<div class="screen">
  <ScreenHeader title={agentName(agent)} {onback} backLabel="Back to agent list" truncate />

  <div class="status status--{status}">
    <span class="status-ic" aria-hidden="true">
      {#if status === 'claimed'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      {:else if status === 'revoked'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
      {:else}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
      {/if}
    </span>
    <span class="status-body">
      <span class="status-t">{currentStatus.label}</span>
      <span class="status-s">{currentStatus.hint}</span>
    </span>
  </div>

  <dl class="meta">
    <dt>Kind</dt><dd>{AGENT_TYPE_LABELS[agent.registrationType] ?? agent.registrationType}</dd>
    {#if agent.issuer}<dt>Issuer</dt><dd class="mono">{agent.issuer}</dd>{/if}
    <dt>Registration</dt><dd class="mono">{agent.registrationId}</dd>
    <dt>Added</dt><dd>{formatTimestamp(agent.createdAt)}</dd>
    {#if agent.lastUsedAt}<dt>Last used</dt><dd>{formatTimestamp(agent.lastUsedAt)}</dd>{/if}
  </dl>

  <p class="section-label">Permissions</p>
  <ul class="grants">
    {#each describeScopes(agent.scopes) as scope (scope.token)}
      <li class="grant" class:grant--elevated={scope.elevated}>
        {#if scope.elevated}
          <span class="grant-warn-row">
            <span class="grant-warn-ic" aria-hidden="true">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
            </span>
            <span class="grant-t">{scope.summary} <em class="grant-warn">(elevated access)</em></span>
          </span>
        {:else}
          <span class="grant-t">{scope.summary}</span>
        {/if}
        <code class="grant-token">{scope.token}</code>
      </li>
    {/each}
  </ul>

  <p class="section-label">Activity record</p>
  <p class="section-sub">Everything this agent has done, newest first. Entries cannot be edited or deleted.</p>
  {#if auditError}
    <div class="notice" role="alert">
      <p class="notice-text">{auditError}</p>
      <Button variant="secondary" onclick={loadMoreAudit}>Try again</Button>
    </div>
  {:else if auditEvents.length === 0 && !auditLoading}
    <p class="empty-trail">No recorded activity yet.</p>
  {:else}
    <ol class="trail">
      {#each auditEvents as event (event.id)}
        <li class="entry">
          <span class="entry-dot" aria-hidden="true"></span>
          <span class="entry-body">
            <span class="entry-t">{AGENT_EVENT_LABELS[event.eventType] ?? event.eventType}</span>
            {#if agentDetailLine(event)}<span class="entry-d">{agentDetailLine(event)}</span>{/if}
            <span class="entry-when">{formatTimestamp(event.createdAt)}</span>
          </span>
        </li>
      {/each}
    </ol>
    {#if auditCursor}
      <Button variant="secondary" onclick={loadMoreAudit} disabled={auditLoading}>
        {#if auditLoading}<Spinner size={16} /> Loading…{:else}Show earlier activity{/if}
      </Button>
    {/if}
  {/if}

  {#if status !== 'revoked'}
    <div class="danger">
      {#if confirmingRevoke}
        <p class="danger-confirm">
          Revoking stops this agent from getting new credentials. Any credential it already
          holds expires within minutes. This cannot be undone.
        </p>
        {#if revokeError}<p class="danger-error" role="alert">{revokeError}</p>{/if}
        <Button onclick={doRevoke} disabled={revoking}>
          {#if revoking}<Spinner size={16} /> Revoking…{:else}Revoke with biometrics{/if}
        </Button>
        <Button variant="secondary" onclick={() => { confirmingRevoke = false; revokeError = null; }} disabled={revoking}>
          Keep access
        </Button>
      {:else}
        <Button variant="secondary" onclick={() => (confirmingRevoke = true)}>
          Revoke this agent’s access
        </Button>
      {/if}
    </div>
  {/if}
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

  .status {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .status--claimed {
    background: var(--color-safe-surface);
  }
  .status--claimed .status-ic,
  .status--claimed .status-t {
    color: var(--color-safe);
  }
  .status--claimed .status-s {
    color: var(--color-safe-soft);
  }
  .status--active {
    background: var(--color-warning-surface);
  }
  .status--active .status-ic,
  .status--active .status-t {
    color: var(--color-warning);
  }
  .status--active .status-s {
    color: var(--color-warning);
  }
  .status--revoked {
    background: var(--color-surface-sunk);
  }
  .status--revoked .status-ic,
  .status--revoked .status-t,
  .status--revoked .status-s {
    color: var(--color-muted);
  }
  .status-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
  }
  .status-t {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
  }
  .status-s {
    font-size: var(--text-label);
  }
  .status-ic {
    flex-shrink: 0;
  }

  .meta {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 6px var(--space-md);
    margin: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .meta dt {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .meta dd {
    margin: 0;
    font-size: var(--text-data);
    color: var(--color-ink);
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: var(--font-mono);
  }

  .section-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: var(--space-xs) 0 0;
  }
  .section-sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: calc(-1 * var(--space-xs)) 0 0;
    line-height: 1.45;
  }

  .grants {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin: 0;
    padding: 0;
  }
  .grant {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .grant-t {
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  .grant-token {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    overflow-wrap: anywhere;
  }
  .grant--elevated {
    border-color: var(--color-warning);
    background: var(--color-warning-surface);
  }
  .grant-warn-row {
    display: flex;
    align-items: flex-start;
    gap: 6px;
  }
  .grant-warn-ic {
    color: var(--color-warning);
    flex-shrink: 0;
    margin-top: var(--space-3xs);
  }
  .grant-warn {
    font-style: normal;
    font-weight: var(--weight-semibold);
    color: var(--color-warning);
  }

  .trail {
    list-style: none;
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
  }
  .entry {
    display: flex;
    gap: var(--space-sm);
    padding: var(--space-sm) 0;
    border-bottom: 1px solid var(--color-line);
  }
  .entry:last-child {
    border-bottom: none;
  }
  .entry-dot {
    width: var(--space-sm);
    height: var(--space-sm);
    border-radius: var(--radius-full);
    background: var(--color-line-strong);
    flex-shrink: 0;
    /* Optically centres the dot on the first line of entry text; not a scale step. */
    margin-top: 7px;
  }
  .entry-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
    min-width: 0;
  }
  .entry-t {
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  .entry-d {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .entry-when {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
  }

  .empty-trail {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
  }

  .danger {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin-top: var(--space-md);
    padding-top: var(--space-md);
    border-top: 1px solid var(--color-line);
  }
  .danger-confirm {
    font-size: var(--text-body);
    color: var(--color-critical);
    line-height: 1.5;
    margin: 0;
  }
  .danger-error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
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
</style>
