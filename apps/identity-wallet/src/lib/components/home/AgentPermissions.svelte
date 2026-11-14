<script lang="ts">
  // The Permissions section of both agent detail screens, and the "More permissions" consent
  // screen it opens (ADR-0041; design plan 2026-11-09 §4). Held scopes are listed; suspended
  // ones (in the grant, outside the operator's profile) fold behind a disclosure; when the
  // profile offers scopes the grant lacks, a banner opens a consent screen that approves the
  // whole profile with one biometric tap. The parent owns the network call, so a child can
  // chain its credential hand-over under the same tap; this component owns the gate and the
  // sentence a failed widening reads as (ADR-0031).
  import { describeScopes, scopeStanding, type ScopeDescription } from '$lib/agent-scopes';
  import { authenticateBiometric } from '$lib/biometric';
  import { sovereignLogin, isCodedError, type AgentsError } from '$lib/ipc';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';

  let {
    did,
    scopes,
    effectiveScopes,
    profile,
    noun,
    canWiden,
    onapprove,
  }: {
    /** The authenticating identity, unlocked here if its session turns out to be locked. */
    did: string;
    /** The stored grant. */
    scopes: string[];
    /** The grant clamped to the profile; absent from an older server, which means all held. */
    effectiveScopes: string[] | undefined;
    /** The operator's current scope profile. */
    profile: string[];
    /** Copy only. An agent account's scopes reach its own account, not the user's. */
    noun: 'agent' | 'agent account';
    /** False for anything not live, and for an OAuth grant: never offer widening there. */
    canWiden: boolean;
    /** Called after the biometric gate passes, with exactly the set the consent screen showed. */
    onapprove: (shown: string[]) => Promise<void>;
  } = $props();

  let holder = $derived<'self' | 'child'>(noun === 'agent account' ? 'child' : 'self');
  let standing = $derived(scopeStanding(scopes, effectiveScopes ?? scopes, profile));
  let held = $derived(describeScopes(standing.held, holder));
  let suspended = $derived(describeScopes(standing.suspended, holder));
  let available = $derived(standing.available.length);
  let offer = $derived(canWiden && available > 0);
  // The consent screen's rows: the whole profile, read only while `offer` keeps it non-empty.
  let profileRows = $derived(describeScopes(profile, holder));

  let consenting = $state(false);
  let approving = $state(false);
  let approveError = $state<string | null>(null);
  let widened = $state(false);

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  async function failureFor(e: unknown): Promise<string> {
    if (!isCodedError(e)) return 'That didn’t go through. Try again.';
    switch ((e as AgentsError).code) {
      case 'SESSION_LOCKED':
        // Unlock now, so the next tap goes straight through.
        try {
          await sovereignLogin(did);
          return 'This identity was locked. It’s unlocked now; approve again.';
        } catch (err) {
          console.error('[AgentPermissions] sovereign login failed:', err);
          return 'This identity is locked. Unlock it and try again.';
        }
      case 'ACCESS_DENIED':
        return `The server refused this. This ${noun} is no longer active.`;
      case 'AGENT_NOT_FOUND':
        return `This ${noun} is no longer on your server.`;
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'That didn’t go through. Try again.';
    }
  }

  function openConsent() {
    approveError = null;
    consenting = true;
  }

  async function approve() {
    if (approving) return;
    approveError = null;
    // In flight before the prompt, so a second tap during the Face ID wait cannot double-send.
    approving = true;
    try {
      await authenticateBiometric(`Give this ${noun} more permissions`);
    } catch {
      approving = false;
      return; // gate rejected — nothing is sent.
    }
    try {
      await onapprove(profile);
      consenting = false;
      widened = true;
    } catch (e) {
      console.error('[AgentPermissions] widening failed:', e);
      approveError = await failureFor(e);
    } finally {
      approving = false;
    }
  }
</script>

{#snippet plusIcon()}
  <span class="ic ic--accent" aria-hidden="true">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
  </span>
{/snippet}

{#snippet pauseIcon()}
  <span class="ic" aria-hidden="true">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M10 9v6M14 9v6"/></svg>
  </span>
{/snippet}

{#snippet warnIcon()}
  <span class="ic ic--warn" aria-hidden="true">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
  </span>
{/snippet}

<!-- One scope row. State is carried by icon + word + strike-through, never colour alone. -->
{#snippet row(scope: ScopeDescription, kind: 'held' | 'suspended' | 'new')}
  <li class="grant grant--{kind}" class:grant--elevated={scope.elevated && kind !== 'suspended'}>
    <span class="grant-row">
      {#if kind === 'suspended'}{@render pauseIcon()}
      {:else if kind === 'new'}{@render plusIcon()}
      {:else if scope.elevated}{@render warnIcon()}{/if}
      <span class="grant-t">
        {scope.summary}
        {#if scope.elevated && kind !== 'suspended'}<em class="grant-warn">(elevated access)</em>{/if}
      </span>
      {#if kind === 'suspended'}<span class="tag">Suspended</span>{/if}
      {#if kind === 'new'}<span class="tag tag--accent">New</span>{/if}
    </span>
    {#if scope.elevated && kind === 'new'}
      <span class="grant-row grant-row--sub">
        {@render warnIcon()}<span class="grant-warn">New and elevated: read it before approving.</span>
      </span>
    {/if}
    <code class="grant-token">{scope.token}</code>
  </li>
{/snippet}

{#if consenting}
  <div class="consent-screen u-screen">
    <ScreenHeader
      title="More permissions"
      onback={() => (consenting = false)}
      backLabel="Back to {noun}"
    />
    <p class="consent-h">Give this {noun} everything your server allows?</p>
    <p class="consent-p">
      Your server now allows {available} more {plural(available, 'permission', 'permissions')}.
      This approves the whole set below; you can’t pick some. Only revoking the {noun} undoes it.
    </p>
    <ul class="grants u-list-reset">
      {#each profileRows as scope (scope.token)}
        {@render row(scope, scopes.includes(scope.token) ? 'held' : 'new')}
      {/each}
    </ul>
    {#if suspended.length}
      <p class="consent-foot">
        {suspended.length} suspended {plural(suspended.length, 'permission stays', 'permissions stay')}
        suspended. Approving doesn’t bring {plural(suspended.length, 'it', 'them')} back.
      </p>
    {/if}
    {#if approveError}<p class="error" role="alert">{approveError}</p>{/if}
    <Button onclick={approve} disabled={approving}>
      {#if approving}<Spinner size={16} /> Approving…{:else}Approve with biometrics{/if}
    </Button>
    <Button variant="secondary" onclick={() => (consenting = false)} disabled={approving}>
      Not now
    </Button>
  </div>
{/if}

{#if offer}
  <button class="banner" onclick={openConsent}>
    {@render plusIcon()}
    <span class="banner-body">
      <span class="banner-t">More permissions available</span>
      <span class="banner-s">Your server allows {available} more. Tap to review.</span>
    </span>
    <span class="chev" aria-hidden="true">›</span>
  </button>
{:else if widened}
  <p class="done" role="status">Permissions updated. This {noun} has everything your server allows.</p>
{/if}

<p class="section-label">Permissions</p>
{#if held.length === 0 && suspended.length === 0}
  <p class="empty">No permissions were granted to this {noun}.</p>
{:else}
  <ul class="grants u-list-reset">
    {#each held as scope (scope.token)}{@render row(scope, 'held')}{/each}
  </ul>
{/if}
{#if suspended.length}
  <details class="disclosure">
    <summary>{@render pauseIcon()} {suspended.length} suspended</summary>
    <p class="sub">
      Your server no longer allows {plural(suspended.length, 'this', 'these')}, so the {noun}
      can’t use {plural(suspended.length, 'it', 'them')}. If the server allows
      {plural(suspended.length, 'it', 'them')} again, {plural(suspended.length, 'it comes', 'they come')}
      back without asking you.
    </p>
    <ul class="grants u-list-reset">
      {#each suspended as scope (scope.token)}{@render row(scope, 'suspended')}{/each}
    </ul>
  </details>
{/if}

<style>
  .section-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: var(--space-xs) 0 0;
  }
  .sub,
  .consent-foot {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.45;
  }
  .empty {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
  }
  .grants {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
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
  .grant--elevated {
    border-color: var(--color-warning);
    background: var(--color-warning-surface);
  }
  .grant--suspended {
    background: var(--color-surface-sunk);
    border-style: dashed;
  }
  .grant--suspended .grant-t {
    color: var(--color-muted);
    text-decoration: line-through;
  }
  .grant-row {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
  }
  .grant-row--sub {
    font-size: var(--text-label);
  }
  .grant-t {
    flex: 1;
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  .grant-token {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    overflow-wrap: anywhere;
  }
  .grant-warn {
    font-style: normal;
    font-weight: var(--weight-semibold);
    color: var(--color-warning);
  }
  .ic {
    flex-shrink: 0;
    display: inline-flex;
    margin-top: var(--space-3xs);
    color: var(--color-muted);
  }
  .ic--warn {
    color: var(--color-warning);
  }
  .ic--accent {
    color: var(--color-accent);
  }
  .tag {
    flex-shrink: 0;
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    background: var(--color-surface-sunk);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-sm);
    padding: var(--space-3xs) var(--space-xs);
  }
  .tag--accent {
    color: var(--color-accent);
    background: var(--color-bg);
    border-color: var(--color-accent);
  }

  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--size-tap-target);
    text-align: left;
    color: var(--color-ink);
    background: var(--color-surface);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    cursor: pointer;
  }
  .banner .ic {
    margin-top: 0;
  }
  .banner-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
    flex: 1;
  }
  .banner-t {
    font-weight: var(--weight-semibold);
  }
  .banner-s {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .chev {
    color: var(--color-muted);
    font-size: var(--text-title);
  }
  .done {
    margin: 0;
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--radius-lg);
    background: var(--color-safe-surface);
    color: var(--color-safe);
    font-size: var(--text-label);
  }

  .disclosure summary {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    min-height: var(--size-tap-target);
    cursor: pointer;
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .disclosure summary .ic {
    margin-top: 0;
  }
  .disclosure[open] {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  /* Its own screen over the detail view, not an inline expansion: consent gets the whole page. */
  .consent-screen {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    overflow-y: auto;
    background: var(--color-bg);
  }
  .consent-h {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .consent-p {
    font-size: var(--text-body);
    color: var(--color-ink);
    margin: 0;
    line-height: 1.5;
  }
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
</style>
