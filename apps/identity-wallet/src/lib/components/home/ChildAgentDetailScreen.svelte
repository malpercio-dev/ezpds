<script lang="ts">
  import { onMount } from 'svelte';
  import {
    revokeChild,
    deleteChild,
    remintChildAssertion,
    getAgentAudit,
    sovereignLogin,
    isCodedError,
    type ChildSummary,
    type ChildAssertion,
    type AgentAuditEvent,
    type AgentsError,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { describeScopes } from '$lib/agent-scopes';
  import { AGENT_EVENT_LABELS, CHILD_STATUS, agentDetailLine, childState } from '$lib/agent-display';
  import { formatTimestamp } from '$lib/datetime';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';

  // The detail view for one sovereign child — an account of the user's own making, not a
  // credential on theirs. Lifetime is the selection, so no cross-child stale-guards are needed:
  // a request in flight when the user navigates back resolves into an unmounted component.
  let {
    did,
    child,
    onback,
    onchanged,
  }: {
    did: string;
    child: ChildSummary;
    onback: () => void;
    /** Hand the parent list the child's new shape, so its row reflects the lifecycle change. */
    onchanged: (child: ChildSummary) => void;
  } = $props();

  // Local overrides for the two facts an action here can change. Everything else about a child
  // is immutable, so this is the whole mutable surface.
  let statusOverride = $state<ChildSummary['status'] | null>(null);
  let deleteAfterOverride = $state<string | null>(null);
  let current = $derived<ChildSummary>({
    ...child,
    status: statusOverride ?? child.status,
    deleteAfter: deleteAfterOverride ?? child.deleteAfter,
  });
  let state_ = $derived(childState(current));
  let vocabulary = $derived(CHILD_STATUS[state_]);

  // The child's audit trail reads through the /v1/agents parent arm: a child's own tokens never
  // pass the owner guard, so the parent is the only reader its history has.
  let auditEvents = $state<AgentAuditEvent[]>([]);
  let auditCursor = $state<string | undefined>(undefined);
  let auditLoading = $state(false);
  let auditError = $state<string | null>(null);

  // One confirm-then-biometric flow per destructive action; `pending` names which is open so
  // the two can never be armed at once.
  let pending = $state<'revoke' | 'delete' | null>(null);
  let busy = $state(false);
  let actionError = $state<string | null>(null);

  // The renewed credential, shown once. Dismissing drops it; the wallet keeps no copy, exactly
  // like the app-password reveal.
  let renewed = $state<ChildAssertion | null>(null);
  let copied = $state(false);
  let copyFailed = $state(false);

  function messageFor(raw: unknown, fallback: string): string {
    if (!isCodedError(raw)) return fallback;
    const err = raw as AgentsError;
    switch (err.code) {
      case 'ACCESS_DENIED':
        return 'The server refused this. A revoked agent account cannot be renewed.';
      case 'AGENT_NOT_FOUND':
        return 'This agent account is no longer on your server.';
      case 'SESSION_LOCKED':
        return 'This identity is locked. Unlock it and try again.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return fallback;
    }
  }

  async function loadMoreAudit() {
    const cursor = auditCursor;
    auditLoading = true;
    auditError = null;
    try {
      const page = await getAgentAudit(did, child.registrationId, cursor);
      auditEvents = [...auditEvents, ...page.events];
      auditCursor = page.cursor;
    } catch (e) {
      console.error('[ChildAgentDetailScreen] failed to load audit trail:', e);
      auditError = 'Could not load the activity record.';
    } finally {
      auditLoading = false;
    }
  }

  async function reloadAudit() {
    auditEvents = [];
    auditCursor = undefined;
    await loadMoreAudit();
  }

  /**
   * Run one gated lifecycle action. The in-flight flag is set *before* the biometric prompt so a
   * second tap during the Face ID wait cannot fire a duplicate prompt — and so a duplicate
   * deletion can never be scheduled from one intent.
   */
  async function gated(reason: string, run: () => Promise<void>, fallback: string) {
    if (busy) return;
    actionError = null;
    busy = true;
    try {
      await authenticateBiometric(reason);
    } catch {
      busy = false;
      return; // gate rejected — nothing changes.
    }
    try {
      await run();
      pending = null;
    } catch (e) {
      console.error('[ChildAgentDetailScreen] lifecycle action failed:', e);
      actionError = messageFor(e, fallback);
      if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
        await sovereignLogin(did).catch((err) =>
          console.error('[ChildAgentDetailScreen] sovereign login failed:', err)
        );
      }
    } finally {
      busy = false;
    }
  }

  function publish() {
    onchanged({ ...current });
  }

  const doRevoke = () =>
    gated(
      'Revoke this agent account’s credential',
      async () => {
        await revokeChild(did, child.did);
        statusOverride = 'revoked';
        publish();
        await reloadAudit();
      },
      'Revocation did not go through. Check your connection and try again.'
    );

  const doDelete = () =>
    gated(
      'Delete this agent account',
      async () => {
        const scheduled = await deleteChild(did, child.did);
        statusOverride = 'revoked';
        deleteAfterOverride = scheduled.deleteAfter;
        publish();
        await reloadAudit();
      },
      'Deletion did not go through. Check your connection and try again.'
    );

  const doRenew = () =>
    gated(
      'Renew this agent account’s credential',
      async () => {
        renewed = await remintChildAssertion(did, child.did);
        await reloadAudit();
      },
      'Renewal did not go through. Check your connection and try again.'
    );

  async function copyAssertion() {
    if (!renewed) return;
    try {
      await navigator.clipboard.writeText(renewed.identityAssertion);
      copied = true;
      copyFailed = false;
      setTimeout(() => (copied = false), 2000);
    } catch {
      copyFailed = true;
      setTimeout(() => (copyFailed = false), 2000);
    }
  }

  onMount(loadMoreAudit);
</script>

<div class="screen u-screen">
  <ScreenHeader title={child.handle} {onback} backLabel="Back to agent list" truncate />

  <div class="status status--{state_}">
    <span class="status-ic" aria-hidden="true">
      {#if state_ === 'live'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      {:else if state_ === 'deleting'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v5M14 11v5"/></svg>
      {:else if state_ === 'revoked'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
      {:else}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
      {/if}
    </span>
    <span class="status-body u-stack-3xs">
      <span class="status-t">{vocabulary.label}</span>
      <span class="status-s">{vocabulary.hint}</span>
    </span>
  </div>

  <p class="lede u-body-copy">
    This agent has an account of its own — its own handle, DID, and repository — signed into
    existence by your recovery key. Nothing it does touches your account.
  </p>

  <dl class="meta">
    <dt>Handle</dt><dd>{child.handle}</dd>
    <dt>DID</dt><dd class="mono">{child.did}</dd>
    <dt>Registration</dt><dd class="mono">{child.registrationId}</dd>
    <dt>Created</dt><dd>{formatTimestamp(child.createdAt)}</dd>
    {#if current.deleteAfter}
      <dt>Removed after</dt><dd>{formatTimestamp(current.deleteAfter)}</dd>
    {/if}
  </dl>

  {#if current.deleteAfter}
    <p class="purge-note">
      Its data is already offline. After that date the account, repository, and files are
      permanently removed from your server. The DID itself lives in the public directory and is
      not deleted by this.
    </p>
  {/if}

  <p class="section-label">Permissions</p>
  {#if child.scopes.length === 0}
    <p class="empty-trail">No permissions were granted to this account.</p>
  {:else}
    <ul class="grants u-list-reset">
      {#each describeScopes(child.scopes) as scope (scope.token)}
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
  {/if}

  <p class="section-label">Activity record</p>
  <p class="section-sub">
    Everything this account has done, newest first. Entries cannot be edited or deleted.
  </p>
  {#if auditError}
    <div class="notice u-notice" role="alert">
      <p class="notice-text u-notice-text">{auditError}</p>
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

  {#if renewed}
    <div class="reveal" role="status">
      <p class="reveal-title">New credential ready</p>
      <p class="reveal-sub u-fine">
        Give this to the agent so it can sign in again. It works until
        {formatTimestamp(renewed.assertionExpires)} and is shown only once — the wallet keeps no
        copy. Treat it like a password.
      </p>
      <div class="reveal-row">
        <code class="reveal-secret">{renewed.identityAssertion}</code>
        <button class="copy" onclick={copyAssertion}>
          {copied ? 'Copied!' : copyFailed ? 'Failed' : 'Copy'}
        </button>
      </div>
      {#if copyFailed}
        <p class="danger-error" role="alert">
          Copy failed — press and hold the credential to select and copy it manually.
        </p>
      {/if}
      <Button variant="secondary" onclick={() => (renewed = null)}>Done — I saved it</Button>
    </div>
  {/if}

  {#if !current.deleteAfter}
    <div class="danger">
      {#if actionError && pending === null}
        <p class="danger-error" role="alert">{actionError}</p>
      {/if}

      <!-- Hidden while a destructive confirmation is open: offering renewal beside "this cannot
           be undone" muddles which decision the user is being asked to make. -->
      {#if state_ === 'live' && !renewed && pending === null}
        <Button variant="secondary" onclick={doRenew} disabled={busy}>
          {#if busy}<Spinner size={16} /> Renewing…{:else}Renew its credential{/if}
        </Button>
      {/if}

      {#if pending === 'revoke'}
        <p class="danger-confirm">
          Revoking stops this agent from signing in as itself. Its account, its posts, and its
          history all stay — you can still read everything it did. This cannot be undone.
        </p>
        {#if actionError}<p class="danger-error" role="alert">{actionError}</p>{/if}
        <Button onclick={doRevoke} disabled={busy}>
          {#if busy}<Spinner size={16} /> Revoking…{:else}Revoke with biometrics{/if}
        </Button>
        <Button variant="secondary" onclick={() => { pending = null; actionError = null; }} disabled={busy}>
          Keep its credential
        </Button>
      {:else if pending === 'delete'}
        <p class="danger-confirm">
          Deleting takes the account offline immediately and permanently removes it — handle,
          repository, posts, and files — after a grace period your server sets. Its DID stays in
          the public directory. This cannot be undone.
        </p>
        {#if actionError}<p class="danger-error" role="alert">{actionError}</p>{/if}
        <Button onclick={doDelete} disabled={busy}>
          {#if busy}<Spinner size={16} /> Deleting…{:else}Delete with biometrics{/if}
        </Button>
        <Button variant="secondary" onclick={() => { pending = null; actionError = null; }} disabled={busy}>
          Keep this account
        </Button>
      {:else}
        {#if state_ !== 'revoked'}
          <Button variant="secondary" onclick={() => (pending = 'revoke')} disabled={busy}>
            Revoke its credential
          </Button>
        {/if}
        <Button variant="secondary" onclick={() => (pending = 'delete')} disabled={busy}>
          Delete this account
        </Button>
      {/if}
    </div>
  {/if}
</div>

<style>
  .status {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .status--live {
    background: var(--color-safe-surface);
  }
  .status--live .status-ic,
  .status--live .status-t {
    color: var(--color-safe);
  }
  .status--live .status-s {
    color: var(--color-safe-soft);
  }
  .status--provisioning {
    background: var(--color-warning-surface);
  }
  .status--provisioning .status-ic,
  .status--provisioning .status-t,
  .status--provisioning .status-s {
    color: var(--color-warning);
  }
  .status--deleting {
    background: var(--color-critical-surface);
  }
  .status--deleting .status-ic,
  .status--deleting .status-t,
  .status--deleting .status-s {
    color: var(--color-critical);
  }
  .status--revoked {
    background: var(--color-surface-sunk);
  }
  .status--revoked .status-ic,
  .status--revoked .status-t,
  .status--revoked .status-s {
    color: var(--color-muted);
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

  .purge-note {
    font-size: var(--text-label);
    color: var(--color-critical);
    line-height: 1.5;
    margin: 0;
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

  /* One-time credential reveal, mirroring the app-password pattern. */
  .reveal {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-seal-tint);
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .reveal-title {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .reveal-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .reveal-secret {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-bg);
    border-radius: var(--radius-md);
    padding: var(--space-sm);
    overflow-wrap: anywhere;
    /* A JWT is long; cap it so the copy button never leaves the viewport. */
    max-height: 7.5em;
    overflow-y: auto;
  }
  .copy {
    flex-shrink: 0;
    align-self: stretch;
    min-width: 72px;
    min-height: 44px;
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-primary-deep);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    cursor: pointer;
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

</style>
