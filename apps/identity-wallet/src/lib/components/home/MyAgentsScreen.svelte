<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listAgents,
    revokeAgent,
    getAgentAudit,
    authenticateBiometric,
    type AgentSummary,
    type AgentAuditEvent,
  } from '$lib/ipc';
  import { describeScopes } from '$lib/agent-scopes';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';

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

  // Detail sub-view: selected agent + its audit trail.
  let selected = $state<AgentSummary | null>(null);
  let auditEvents = $state<AgentAuditEvent[]>([]);
  let auditCursor = $state<string | undefined>(undefined);
  let auditLoading = $state(false);
  let auditError = $state<string | null>(null);

  // Revocation flow: explicit confirm step, then biometric.
  let confirmingRevoke = $state(false);
  let revoking = $state(false);
  let revokeError = $state<string | null>(null);

  /** Status is always text + icon + position — never color alone. */
  const STATUS: Record<AgentSummary['status'], { label: string; hint: string }> = {
    active: { label: 'Pending approval', hint: 'Registered, waiting for your confirmation' },
    claimed: { label: 'Connected', hint: 'Can act within its granted permissions' },
    revoked: { label: 'Revoked', hint: 'Access turned off — new sign-ins are refused' },
  };

  const EVENT_LABELS: Record<AgentAuditEvent['eventType'], string> = {
    registered: 'Registered with your server',
    claim_initiated: 'Asked for your approval',
    claim_confirmed: 'You approved access',
    claim_expired: 'Approval request expired',
    token_exchanged: 'Signed in',
    repo_write: 'Wrote to your repository',
    blob_upload: 'Uploaded a file',
    revoked: 'Access revoked',
  };

  const TYPE_LABELS: Record<AgentSummary['registrationType'], string> = {
    service_auth: 'Server-requested',
    identity_assertion: 'Identity-provider vouched',
    anonymous: 'Self-registered',
  };

  function agentName(agent: AgentSummary): string {
    return agent.subject ?? agent.registrationId;
  }

  function formatWhen(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  }

  /** Mechanical detail facts → one short human line; unknown shapes stay hidden behind the label. */
  function detailLine(event: AgentAuditEvent): string | null {
    const d = event.detail;
    if (!d) return null;
    if (event.eventType === 'repo_write') {
      const parts: string[] = [];
      const counts: string[] = [];
      if (typeof d.creates === 'number' && d.creates > 0) counts.push(`${d.creates} created`);
      if (typeof d.updates === 'number' && d.updates > 0) counts.push(`${d.updates} edited`);
      if (typeof d.deletes === 'number' && d.deletes > 0) counts.push(`${d.deletes} deleted`);
      if (counts.length) parts.push(counts.join(', '));
      if (Array.isArray(d.collections) && d.collections.length) {
        parts.push(`in ${d.collections.join(', ')}`);
      }
      return parts.length ? parts.join(' ') : null;
    }
    if (event.eventType === 'blob_upload') {
      const mime = typeof d.mime_type === 'string' ? d.mime_type : null;
      const size = typeof d.size === 'number' ? `${Math.max(1, Math.round(d.size / 1024))} KB` : null;
      return [mime, size].filter(Boolean).join(', ') || null;
    }
    if (event.eventType === 'token_exchanged' && typeof d.grant === 'string') {
      return d.grant === 'claim' ? 'collected its first credential' : 'renewed its credential';
    }
    return null;
  }

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

  async function openDetail(agent: AgentSummary) {
    selected = agent;
    confirmingRevoke = false;
    revokeError = null;
    auditEvents = [];
    auditCursor = undefined;
    await loadMoreAudit();
  }

  async function loadMoreAudit() {
    if (!selected) return;
    // Capture the request's context: the user can navigate to another agent (or back to the
    // list) while the fetch is in flight, and a stale page must never land in the new view.
    const registrationId = selected.registrationId;
    const cursor = auditCursor;
    auditLoading = true;
    auditError = null;
    try {
      const page = await getAgentAudit(registrationId, cursor);
      if (selected?.registrationId !== registrationId) return;
      auditEvents = [...auditEvents, ...page.events];
      auditCursor = page.cursor;
    } catch (e) {
      console.error('Failed to load audit trail:', e);
      if (selected?.registrationId === registrationId) {
        auditError = 'Could not load the activity record.';
      }
    } finally {
      if (selected?.registrationId === registrationId) {
        auditLoading = false;
      }
    }
  }

  async function doRevoke() {
    if (!selected || revoking) return;
    const registrationId = selected.registrationId;
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
      await revokeAgent(registrationId);
      // Reflect the revocation in the list unconditionally; touch the detail view only if the
      // user is still looking at this agent (they may have navigated away mid-flight).
      agents = agents.map((a) =>
        a.registrationId === registrationId ? { ...a, status: 'revoked' } : a
      );
      if (selected?.registrationId === registrationId) {
        confirmingRevoke = false;
        selected = { ...selected, status: 'revoked' };
        auditEvents = [];
        auditCursor = undefined;
        revoking = false;
        await loadMoreAudit();
      }
    } catch (e) {
      console.error('Revocation failed:', e);
      if (selected?.registrationId === registrationId) {
        revokeError = 'Revocation did not go through. Check your connection and try again.';
      }
    } finally {
      revoking = false;
    }
  }

  onMount(loadAgents);
</script>

{#if selected}
  {@const status = STATUS[selected.status]}
  <div class="screen">
    <div class="topbar">
      <button class="back" onclick={() => (selected = null)} aria-label="Back to agent list">
        <ChevronLeftIcon />
      </button>
      <h1 class="title truncate">{agentName(selected)}</h1>
    </div>

    <div class="status status--{selected.status}">
      <span class="status-ic" aria-hidden="true">
        {#if selected.status === 'claimed'}
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
        {:else if selected.status === 'revoked'}
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
        {:else}
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        {/if}
      </span>
      <span class="status-body">
        <span class="status-t">{status.label}</span>
        <span class="status-s">{status.hint}</span>
      </span>
    </div>

    <dl class="meta">
      <dt>Kind</dt><dd>{TYPE_LABELS[selected.registrationType] ?? selected.registrationType}</dd>
      {#if selected.issuer}<dt>Issuer</dt><dd class="mono">{selected.issuer}</dd>{/if}
      <dt>Registration</dt><dd class="mono">{selected.registrationId}</dd>
      <dt>Added</dt><dd>{formatWhen(selected.createdAt)}</dd>
      {#if selected.lastUsedAt}<dt>Last used</dt><dd>{formatWhen(selected.lastUsedAt)}</dd>{/if}
    </dl>

    <p class="section-label">Permissions</p>
    <ul class="grants">
      {#each describeScopes(selected.scopes) as scope (scope.token)}
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
              <span class="entry-t">{EVENT_LABELS[event.eventType] ?? event.eventType}</span>
              {#if detailLine(event)}<span class="entry-d">{detailLine(event)}</span>{/if}
              <span class="entry-when">{formatWhen(event.createdAt)}</span>
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

    {#if selected.status !== 'revoked'}
      <div class="danger">
        {#if confirmingRevoke}
          <p class="danger-confirm">
            Revoking stops this agent from getting new credentials. Any credential it already
            holds expires within minutes. This cannot be undone.
          </p>
          {#if revokeError}<p class="danger-error" role="alert">{revokeError}</p>{/if}
          <Button onclick={doRevoke} disabled={revoking}>
            {#if revoking}<Spinner size={16} /> Revoking…{:else}Revoke with Face ID{/if}
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
{:else}
  <div class="screen">
    <div class="topbar">
      <button class="back" onclick={onback} aria-label="Back">
        <ChevronLeftIcon />
      </button>
      <h1 class="title">My agents</h1>
    </div>

    {#if loading}
      <div class="loading" aria-hidden="true">
        {#each [0, 1] as i (i)}
          <div class="skel">
            <div class="skel-lines">
              <span class="skel-line w55"></span>
              <span class="skel-line w80"></span>
            </div>
          </div>
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
          {@const status = STATUS[agent.status]}
          <button class="card" onclick={() => openDetail(agent)}>
            <span class="info">
              <span class="name truncate">{agentName(agent)}</span>
              <span class="kind">{TYPE_LABELS[agent.registrationType] ?? agent.registrationType}</span>
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
                  <span class="badge badge--muted">Last used {formatWhen(agent.lastUsedAt)}</span>
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

  .topbar {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .back {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    color: var(--color-ink);
    cursor: pointer;
    flex-shrink: 0;
  }
  .title {
    font-family: var(--font-sans);
    font-size: 1.375rem;
    font-weight: var(--weight-bold);
    letter-spacing: -0.01em;
    color: var(--color-ink);
    margin: 0;
    min-width: 0;
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
    padding: 15px;
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
    gap: 3px;
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
    font-size: 11.5px;
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
    padding: 16px 15px;
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

  /* Detail sub-view */
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
    gap: 2px;
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
    gap: 3px;
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
    margin-top: 2px;
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
    width: 8px;
    height: 8px;
    border-radius: var(--radius-full);
    background: var(--color-line-strong);
    flex-shrink: 0;
    margin-top: 7px;
  }
  .entry-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
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
    color: var(--color-ink-faint);
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
  .skel {
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: 15px;
  }
  .skel-lines {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .skel-line {
    height: 12px;
    border-radius: var(--radius-sm);
    background: var(--color-surface-sunk);
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skel-line.w55 { width: 55%; }
  .skel-line.w80 { width: 80%; }
  @keyframes shimmer {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
