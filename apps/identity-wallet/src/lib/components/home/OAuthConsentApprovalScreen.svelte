<script lang="ts">
  import {
    previewOAuthConsent,
    confirmOAuthConsent,
    isCodedError,
    type ConsentPreview,
    type ConsentError,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { describeScope } from '$lib/agent-scopes';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';

  let {
    did,
    handle,
    onback,
    ondone,
  }: {
    did: string;
    /** The identity's handle, shown as "as @{handle}"; falls back to the DID when absent. */
    handle?: string;
    onback: () => void;
    /** Called after a recorded decision (approve or deny). */
    ondone: () => void;
  } = $props();

  type Phase = 'enter' | 'loading' | 'review' | 'approving' | 'denying' | 'approved' | 'denied';

  let phase = $state<Phase>('enter');
  let code = $state('');
  let codeError = $state<string | undefined>(undefined);
  let preview = $state<ConsentPreview | null>(null);
  /** Non-`atproto` scope tokens the user has left checked (scope reduction lives here). */
  let checked = $state<Set<string>>(new Set());
  let ceremonyError = $state<{ title: string; body: string } | null>(null);

  const asWho = $derived(handle ? `@${handle}` : did);
  const clientLabel = $derived(preview?.clientName ?? preview?.clientId ?? 'an app');
  const originLabel = $derived(preview ? originOf(preview) : '');
  /** Non-`atproto` requested tokens, each with a plain-language description, for the checkboxes. */
  let optionalScopes = $derived(
    preview
      ? preview.requestedScope.filter((t) => t !== 'atproto').map((t) => describeScope(t))
      : []
  );

  function originOf(p: ConsentPreview): string {
    if (p.origin) {
      try {
        return new URL(p.origin).host;
      } catch {
        return p.origin;
      }
    }
    try {
      return new URL(p.redirectUri).host;
    } catch {
      return p.redirectUri;
    }
  }

  function errorCode(e: unknown): ConsentError['code'] | 'UNEXPECTED' {
    if (isCodedError(e)) return (e as ConsentError).code;
    return 'UNEXPECTED';
  }

  function decisionFailure(codeName: string): { title: string; body: string } {
    switch (codeName) {
      case 'REQUEST_NOT_FOUND':
        return {
          title: 'This request expired',
          body: 'Sign-in requests are only valid for a few minutes. Return to the app and start again, then enter the new code.',
        };
      case 'ALREADY_RESOLVED':
        return {
          title: 'Already handled',
          body: 'This sign-in request has already been approved or denied. Return to the app and start again if needed.',
        };
      case 'APPROVAL_REJECTED':
        return {
          title: 'Your server rejected the approval',
          body: 'The signature could not be verified against your identity’s current keys. Nothing was granted.',
        };
      case 'RATE_LIMITED':
        return {
          title: 'Too many attempts',
          body: 'Your server paused sign-in checks for a few minutes. Wait, then try again.',
        };
      default:
        return {
          title: 'Could not complete the request',
          body: 'Your server could not record the decision. Nothing was granted — you can try again.',
        };
    }
  }

  /** The verbatim granted-scope string the wallet signs: `atproto` (always) + every checked token. */
  function grantedScopeString(): string {
    if (!preview) return 'atproto';
    return preview.requestedScope
      .filter((t) => t === 'atproto' || checked.has(t))
      .join(' ');
  }

  function toggle(token: string) {
    const next = new Set(checked);
    if (next.has(token)) next.delete(token);
    else next.add(token);
    checked = next;
  }

  async function loadPreview() {
    codeError = undefined;
    ceremonyError = null;
    const trimmed = code.trim().toUpperCase();
    if (!trimmed) {
      codeError = 'Enter the code shown on the sign-in page.';
      return;
    }
    phase = 'loading';
    try {
      preview = await previewOAuthConsent(did, trimmed);
      code = trimmed;
      // Scope reduction defaults to granting everything requested; the user unchecks to narrow.
      checked = new Set(preview.requestedScope.filter((t) => t !== 'atproto'));
      phase = 'review';
    } catch (e) {
      phase = 'enter';
      const c = errorCode(e);
      if (c === 'REQUEST_NOT_FOUND') {
        codeError = 'That code was not recognized or has expired. Check it and try again.';
      } else if (c === 'RATE_LIMITED') {
        ceremonyError = decisionFailure(c);
      } else {
        codeError = 'Could not reach your server. Check your connection and try again.';
      }
    }
  }

  async function approve() {
    if (!preview) return;
    ceremonyError = null;
    phase = 'approving';
    try {
      // The biometric prompt is the authorization boundary: rejecting it aborts before any
      // signing or network call, so cancel truly means nothing was granted.
      await authenticateBiometric(`Sign in to ${clientLabel} as ${asWho}`);
    } catch {
      phase = 'review';
      return;
    }
    try {
      await confirmOAuthConsent(did, preview.requestId, preview.clientId, 'approve', grantedScopeString());
      phase = 'approved';
      setTimeout(() => ondone(), 1200);
    } catch (e) {
      phase = 'review';
      ceremonyError = decisionFailure(errorCode(e));
    }
  }

  async function deny() {
    if (!preview) {
      onback();
      return;
    }
    ceremonyError = null;
    phase = 'denying';
    try {
      // Denial terminates the request on the server so the app stops waiting; it grants nothing.
      await confirmOAuthConsent(did, preview.requestId, preview.clientId, 'deny', '');
      phase = 'denied';
      setTimeout(() => ondone(), 1000);
    } catch (e) {
      phase = 'review';
      ceremonyError = decisionFailure(errorCode(e));
    }
  }
</script>

<div class="screen">
  <ScreenHeader title="Sign in to an app" {onback} />

  {#if phase === 'enter' || phase === 'loading'}
    <div class="body">
      <p class="lede">
        An app is asking to sign in as your identity. It will show you a short code on its sign-in
        page — enter it here to see exactly what it is asking for. Nothing happens until you approve.
      </p>

      <label class="field-label" for="consent-code">Code from the sign-in page</label>
      <TextField
        id="consent-code"
        bind:value={code}
        mono
        autocapitalize="characters"
        autocomplete="one-time-code"
        spellcheck="false"
        placeholder="e.g. 4QX9-TX7P"
        error={codeError}
        disabled={phase === 'loading'}
      />

      {#if ceremonyError}
        <div class="halt" role="alert">
          <span class="halt-ic" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          </span>
          <span class="halt-body">
            <span class="halt-t">{ceremonyError.title}</span>
            <span class="halt-s">{ceremonyError.body}</span>
          </span>
        </div>
      {/if}

      <div class="actions">
        <Button onclick={loadPreview} disabled={phase === 'loading'}>
          {#if phase === 'loading'}<Spinner size={18} /> Checking…{:else}Review request{/if}
        </Button>
      </div>
    </div>
  {:else if phase === 'review' || phase === 'approving' || phase === 'denying'}
    {#if preview}
      <div class="body">
        <div class="req-card">
          <p class="req-kicker">Sign-in request</p>
          <p class="req-type">
            Sign in to <strong>{clientLabel}</strong>
            {#if originLabel} at <strong>{originLabel}</strong>{/if}
            as <strong>{asWho}</strong>
          </p>
          <dl class="req-meta">
            <dt>App</dt><dd class="mono">{preview.clientId}</dd>
            {#if preview.ip}<dt>Requested from</dt><dd class="mono">{preview.ip}</dd>{/if}
          </dl>
        </div>

        <p class="section-label" id="grant-list-label">Choose what this app may do</p>
        <ul class="grants" aria-labelledby="grant-list-label">
          <li class="grant grant--base">
            <span class="grant-ic" aria-hidden="true">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>
            </span>
            <span class="grant-body">
              <span class="grant-t">Basic access to your account (always granted)</span>
              <code class="grant-token">atproto</code>
            </span>
          </li>
          {#each optionalScopes as scope (scope.token)}
            <li class="grant" class:grant--elevated={scope.elevated}>
              <label class="grant-check">
                <input
                  type="checkbox"
                  checked={checked.has(scope.token)}
                  onchange={() => toggle(scope.token)}
                  disabled={phase !== 'review'}
                />
                <span class="grant-body">
                  <span class="grant-t">{scope.summary}{#if scope.elevated} <em class="grant-warn">(elevated access)</em>{/if}</span>
                  <code class="grant-token">{scope.token}</code>
                </span>
              </label>
            </li>
          {/each}
        </ul>
        <p class="fine">
          Uncheck anything you don’t want to grant — the app will only be able to do what’s left
          checked. You can revoke this app’s access later from the app itself.
        </p>

        {#if ceremonyError}
          <div class="halt" role="alert">
            <span class="halt-ic" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
            </span>
            <span class="halt-body">
              <span class="halt-t">{ceremonyError.title}</span>
              <span class="halt-s">{ceremonyError.body}</span>
            </span>
          </div>
        {/if}

        <div class="actions">
          <Button onclick={approve} disabled={phase !== 'review'}>
            {#if phase === 'approving'}<Spinner size={18} /> Waiting for confirmation…{:else}Approve with biometrics{/if}
          </Button>
          <Button variant="secondary" onclick={deny} disabled={phase !== 'review'}>
            {#if phase === 'denying'}<Spinner size={18} /> Denying…{:else}Deny{/if}
          </Button>
        </div>
      </div>
    {/if}
  {:else if phase === 'approved'}
    <div class="done" role="status">
      <span class="done-seal" aria-hidden="true">
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      </span>
      <p class="done-t">Signed in</p>
      <p class="done-s">Return to {clientLabel} — it will finish signing you in.</p>
    </div>
  {:else if phase === 'denied'}
    <div class="done" role="status">
      <span class="done-seal done-seal--deny" aria-hidden="true">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
      </span>
      <p class="done-t">Request denied</p>
      <p class="done-s">Nothing was granted. The app was told the sign-in was declined.</p>
    </div>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-lg);
    overflow-y: auto;
  }

  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .lede {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .field-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }

  .req-card {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .req-kicker {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--color-muted);
    margin: 0;
  }
  .req-type {
    font-size: var(--text-title);
    color: var(--color-ink);
    margin: 0;
    line-height: 1.35;
  }
  .req-type strong {
    font-weight: var(--weight-semibold);
  }
  .req-meta {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 4px var(--space-sm);
    margin: var(--space-xs) 0 0;
  }
  .req-meta dt {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .req-meta dd {
    margin: 0;
    font-size: var(--text-data);
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
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .grant-check {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    width: 100%;
    cursor: pointer;
  }
  .grant-check input[type='checkbox'] {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    margin-top: var(--space-3xs);
    accent-color: var(--color-accent);
  }
  .grant-ic {
    color: var(--color-safe);
    flex-shrink: 0;
    margin-top: var(--space-3xs);
  }
  .grant--elevated {
    border-color: var(--color-warning);
    background: var(--color-warning-surface);
  }
  .grant-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    min-width: 0;
  }
  .grant-t {
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  .grant-warn {
    font-style: normal;
    font-weight: var(--weight-semibold);
    color: var(--color-warning);
  }
  .grant-token {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    overflow-wrap: anywhere;
  }

  .fine {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .halt {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-critical-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .halt-ic {
    color: var(--color-critical);
    flex-shrink: 0;
    margin-top: 1px;
  }
  .halt-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .halt-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
  }
  .halt-s {
    font-size: var(--text-label);
    color: var(--color-critical-soft);
    line-height: 1.45;
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin-top: var(--space-sm);
  }

  .done {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-sm);
    flex: 1;
    padding: var(--space-xl) var(--space-md);
  }
  .done-seal {
    width: 72px;
    height: 72px;
    border-radius: var(--radius-full);
    background: var(--color-safe-surface);
    color: var(--color-safe);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: var(--space-sm);
  }
  .done-seal--deny {
    background: var(--color-critical-surface);
    color: var(--color-critical);
  }
  .done-t {
    font-size: var(--text-headline);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .done-s {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    max-width: 30ch;
  }
</style>
