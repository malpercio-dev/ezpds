<script lang="ts">
  import { onMount } from 'svelte';
  import {
    previewAgentClaim,
    confirmAgentClaim,
    mintChildFromClaim,
    agentAccountsProvisioned,
    isCodedError,
    type AgentClaimPreview,
    type AgentsError,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { describeScopes } from '$lib/agent-scopes';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';

  let {
    did,
    onback,
    ondone,
    onprovision,
  }: {
    did: string;
    onback: () => void;
    /** Called after a confirmed claim, with the bound registration id. */
    ondone: (registrationId: string) => void;
    /**
     * Navigate to "Enable agent accounts". Taken when the user picks the own-account door on an
     * identity that holds no delegation seed — there would be no key to sign the child's genesis
     * operation with, so the mint is never attempted.
     */
    onprovision: () => void;
  } = $props();

  // Two branches share this screen. `choose` is the fork an anonymous registration reaches (the
  // only kind the server will mint a child for); `review` is the account-access branch, which a
  // bound registration lands on directly, unchanged. `handle` is the own-account branch's one
  // decision: what the agent's account will be called.
  type Phase =
    | 'enter'
    | 'loading'
    | 'choose'
    | 'review'
    | 'handle'
    | 'approving'
    | 'approved'
    | 'minting'
    | 'minted';

  let phase = $state<Phase>('enter');
  let code = $state('');
  let codeError = $state<string | undefined>(undefined);
  let preview = $state<AgentClaimPreview | null>(null);
  /** Terminal ceremony failures get their own explicit block, never a silent return. */
  let ceremonyError = $state<{ title: string; body: string } | null>(null);

  /** The handle the agent's own account will carry — the agent's proposal, until the user edits it. */
  let childHandle = $state('');
  let childHandleError = $state<string | undefined>(undefined);
  /** The minted child, for the confirmation panel. */
  let minted = $state<{ handle: string; did: string } | null>(null);

  // Whether this identity holds a delegation seed. Probed on mount rather than at the fork, so
  // the door can say up front that it needs setting up instead of failing after the choice.
  let provisioned = $state(false);

  let scopeDescriptions = $derived(preview ? describeScopes(preview.scopes) : []);

  const REGISTRATION_TYPE_LABELS: Record<string, string> = {
    service_auth: 'Requested for your account by this server',
    identity_assertion: 'Vouched for by a trusted identity provider',
    anonymous: 'Registered directly by the agent',
  };

  function errorCode(e: unknown): AgentsError['code'] | 'UNEXPECTED' {
    if (isCodedError(e)) return (e as AgentsError).code;
    return 'UNEXPECTED';
  }

  function ceremonyFailure(codeName: string): { title: string; body: string } | null {
    switch (codeName) {
      case 'CODE_EXPIRED':
        return {
          title: 'This code has expired',
          body: 'Codes are only valid for a short window. Ask the agent to restart its connection request, then enter the new code.',
        };
      case 'ALREADY_CLAIMED':
        return {
          title: 'This code was already used',
          body: 'The request behind this code has already been approved. Check My agents to review what is connected.',
        };
      case 'ACCESS_DENIED':
        return {
          title: 'This request belongs to a different account',
          body: 'The agent asked to connect to another account on this server. Nothing was approved.',
        };
      case 'RATE_LIMITED':
        return {
          title: 'Too many attempts',
          body: 'Your server paused code checks for a few minutes. Wait, then try again.',
        };
      default:
        return null;
    }
  }

  async function loadPreview() {
    codeError = undefined;
    ceremonyError = null;
    const trimmed = code.trim().toUpperCase();
    if (!trimmed) {
      codeError = 'Enter the code the agent showed you.';
      return;
    }
    phase = 'loading';
    try {
      preview = await previewAgentClaim(did, trimmed);
      code = trimmed;
      childHandle = preview.handleHint ?? '';
      phase = preview.registrationType === 'anonymous' ? 'choose' : 'review';
    } catch (e) {
      phase = 'enter';
      const c = errorCode(e);
      const terminal = ceremonyFailure(c);
      if (terminal) {
        ceremonyError = terminal;
      } else if (c === 'CODE_NOT_FOUND') {
        codeError = 'That code was not recognized. Check it and try again.';
      } else if (c === 'NOT_AUTHENTICATED' || c === 'SESSION_LOCKED') {
        codeError = 'Your session for this identity has expired. Reopen it from My agents and try again.';
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
      // network call, so cancel truly means nothing was granted.
      await authenticateBiometric('Approve this agent’s access to your identity');
    } catch {
      phase = 'review';
      return;
    }
    try {
      const confirmation = await confirmAgentClaim(did, code);
      phase = 'approved';
      // Give the sealed state a beat before handing control back.
      setTimeout(() => ondone(confirmation.registrationId), 1200);
    } catch (e) {
      phase = 'review';
      const terminal = ceremonyFailure(errorCode(e));
      ceremonyError = terminal ?? {
        title: 'Approval did not go through',
        body: 'Your server could not complete the approval. Nothing was granted — you can try again.',
      };
    }
  }

  /** The own-account door. Unprovisioned identities are routed to setup, never into a mint. */
  function chooseOwnAccount() {
    ceremonyError = null;
    if (!provisioned) {
      onprovision();
      return;
    }
    childHandleError = undefined;
    phase = 'handle';
  }

  async function mint() {
    const handle = childHandle.trim().toLowerCase();
    if (!handle) {
      childHandleError = 'Give the agent’s account a handle.';
      return;
    }
    childHandleError = undefined;
    ceremonyError = null;
    phase = 'minting';
    try {
      // Same authorization boundary as approving account access: the prompt precedes every
      // network call, so cancelling means no account was created.
      await authenticateBiometric('Create an account for this agent');
    } catch {
      phase = 'handle';
      return;
    }
    try {
      const child = await mintChildFromClaim(did, code, handle);
      minted = { handle: child.handle, did: child.did };
      phase = 'minted';
      setTimeout(() => ondone(child.registrationId), 1600);
    } catch (e) {
      phase = 'handle';
      const c = errorCode(e);
      if (c === 'HANDLE_REJECTED') {
        // The claim attempt is untouched, so this is a correction, not a restart. The server's
        // description says what to fix — a taken handle, a domain it doesn't host — so it is
        // shown verbatim on the field rather than replaced with a guess.
        const rejection = e as Extract<AgentsError, { code: 'HANDLE_REJECTED' }>;
        childHandleError =
          rejection.message || 'Your server would not accept that handle. Try another.';
        return;
      }
      if (c === 'NOT_PROVISIONED') {
        provisioned = false;
        phase = 'choose';
        ceremonyError = {
          title: 'Agent accounts are not set up yet',
          body: 'This identity needs its recovery shares checked once before it can give an agent an account. Nothing was created.',
        };
        return;
      }
      const terminal = ceremonyFailure(c);
      ceremonyError = terminal ?? {
        title: 'The account was not created',
        body: 'Your server could not finish creating the agent’s account. Nothing was created — you can try again.',
      };
    }
  }

  function deny() {
    // An explicit decision, not a silent back-swipe: denial simply never confirms the code,
    // and the pending request expires on the server.
    ceremonyError = null;
    preview = null;
    code = '';
    childHandle = '';
    phase = 'enter';
    onback();
  }

  onMount(async () => {
    provisioned = await agentAccountsProvisioned(did).catch((e) => {
      console.warn('[AgentClaimApprovalScreen] provisioning probe failed:', e);
      return false; // A gate we cannot confirm reads as closed; the setup route re-checks.
    });
  });
</script>

<div class="screen u-screen-lg">
  <ScreenHeader title="Approve an agent" {onback} />

  {#if phase === 'enter' || phase === 'loading'}
    <div class="body">
      <p class="lede u-body-copy">
        An app or agent asking to act on your behalf will show you a short code. Enter it here to
        see exactly what it is asking for — nothing is granted until you approve.
      </p>

      <label class="field-label u-label-muted" for="agent-code">Code from the agent</label>
      <TextField
        id="agent-code"
        bind:value={code}
        mono
        autocapitalize="characters"
        autocomplete="one-time-code"
        spellcheck="false"
        placeholder="e.g. 4QX9TX"
        error={codeError}
        disabled={phase === 'loading'}
      />

      {#if ceremonyError}
        <div class="halt" role="alert">
          <span class="halt-ic" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          </span>
          <span class="halt-body u-stack-2xs">
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
  {:else if phase === 'choose'}
    {#if preview}
      <div class="body">
        <div class="req-card">
          <p class="req-kicker">Connection request</p>
          <p class="req-type">{REGISTRATION_TYPE_LABELS[preview.registrationType] ?? preview.registrationType}</p>
        </div>

        <p class="lede u-body-copy">
          This agent registered on its own, so you can decide what it gets: a key to your identity,
          or an identity of its own that you hold the keys to.
        </p>

        <p class="section-label" id="door-list-label">Choose one</p>
        <div class="doors u-stack-sm" role="group" aria-labelledby="door-list-label">
          <NavRow
            title="Let it act as me"
            subtitle="It posts and reads as this identity, within the permissions on the next screen."
            onclick={() => (phase = 'review')}
          />
          <NavRow
            title="Give it an account of its own"
            subtitle={provisioned
              ? 'Its own handle and its own record, with the keys derived from your recovery seed.'
              : 'Needs setting up first — check two of your recovery shares, then come back.'}
            onclick={chooseOwnAccount}
          />
        </div>

        {#if ceremonyError}
          <div class="halt" role="alert">
            <span class="halt-ic" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
            </span>
            <span class="halt-body u-stack-2xs">
              <span class="halt-t">{ceremonyError.title}</span>
              <span class="halt-s">{ceremonyError.body}</span>
            </span>
          </div>
        {/if}

        <div class="actions">
          <Button variant="secondary" onclick={deny}>Deny</Button>
        </div>
      </div>
    {/if}
  {:else if phase === 'handle' || phase === 'minting'}
    <div class="body">
      <p class="lede u-body-copy">
        The agent gets its own account on your server — its own handle and its own record, separate
        from yours. Its recovery key is derived from your recovery seed, so this identity stays in
        control of it and no one else can take it over.
      </p>

      <label class="field-label u-label-muted" for="child-handle">Handle for the agent’s account</label>
      <TextField
        id="child-handle"
        bind:value={childHandle}
        mono
        autocapitalize="none"
        autocomplete="off"
        spellcheck="false"
        placeholder="e.g. scribe.example.com"
        error={childHandleError}
        disabled={phase === 'minting'}
      />
      <p class="fine u-fine">
        {#if preview?.handleHint}
          The agent proposed this handle. Change it to anything your server accepts — it is your
          decision, not its.
        {:else}
          Pick a handle your server accepts. You can change it later.
        {/if}
      </p>

      {#if ceremonyError}
        <div class="halt" role="alert">
          <span class="halt-ic" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          </span>
          <span class="halt-body u-stack-2xs">
            <span class="halt-t">{ceremonyError.title}</span>
            <span class="halt-s">{ceremonyError.body}</span>
          </span>
        </div>
      {/if}

      <div class="actions">
        <Button onclick={mint} disabled={phase === 'minting'}>
          {#if phase === 'minting'}<Spinner size={18} /> Creating the account…{:else}Create with biometrics{/if}
        </Button>
        <Button variant="secondary" onclick={() => (phase = 'choose')} disabled={phase === 'minting'}>
          Back
        </Button>
      </div>
    </div>
  {:else if phase === 'minted'}
    <div class="done" role="status">
      <span class="done-seal" aria-hidden="true">
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      </span>
      <p class="done-t">Account created</p>
      <p class="done-s">The agent now holds <span class="mono">{minted?.handle}</span>, and you hold its keys.</p>
      <p class="done-did mono">{minted?.did}</p>
    </div>
  {:else if phase === 'review' || phase === 'approving'}
    {#if preview}
      <div class="body">
        <div class="req-card">
          <p class="req-kicker">Connection request</p>
          <p class="req-type">{REGISTRATION_TYPE_LABELS[preview.registrationType] ?? preview.registrationType}</p>
          {#if preview.issuer || preview.subject}
            <dl class="req-meta">
              {#if preview.issuer}<dt>Issuer</dt><dd class="mono">{preview.issuer}</dd>{/if}
              {#if preview.subject}<dt>Agent</dt><dd class="mono">{preview.subject}</dd>{/if}
            </dl>
          {/if}
        </div>

        <p class="section-label" id="grant-list-label">If you approve, this agent can</p>
        <ul class="grants u-list-reset" aria-labelledby="grant-list-label">
          {#each scopeDescriptions as scope (scope.token)}
            <li class="grant" class:grant--elevated={scope.elevated}>
              <span class="grant-ic" aria-hidden="true">
                {#if scope.elevated}
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
                {:else}
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>
                {/if}
              </span>
              <span class="grant-body">
                <span class="grant-t">{scope.summary}{#if scope.elevated} <em class="grant-warn">(elevated access)</em>{/if}</span>
                <code class="grant-token">{scope.token}</code>
              </span>
            </li>
          {/each}
        </ul>
        <p class="fine u-fine">
          Every action it takes is recorded in an audit trail you can review, and you can revoke
          its access at any time from My agents.
        </p>

        {#if ceremonyError}
          <div class="halt" role="alert">
            <span class="halt-ic" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
            </span>
            <span class="halt-body u-stack-2xs">
              <span class="halt-t">{ceremonyError.title}</span>
              <span class="halt-s">{ceremonyError.body}</span>
            </span>
          </div>
        {/if}

        <div class="actions">
          <Button onclick={approve} disabled={phase === 'approving'}>
            {#if phase === 'approving'}<Spinner size={18} /> Waiting for confirmation…{:else}Approve with biometrics{/if}
          </Button>
          <Button variant="secondary" onclick={deny} disabled={phase === 'approving'}>Deny</Button>
        </div>
      </div>
    {/if}
  {:else if phase === 'approved'}
    <div class="done" role="status">
      <span class="done-seal" aria-hidden="true">
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      </span>
      <p class="done-t">Agent approved</p>
      <p class="done-s">Its access and full activity record are in My agents.</p>
    </div>
  {/if}
</div>

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
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
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
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

  .grant {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .grant-ic {
    color: var(--color-safe);
    flex-shrink: 0;
    margin-top: var(--space-3xs);
  }
  .grant--elevated .grant-ic {
    color: var(--color-warning);
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
  .done-did {
    font-size: var(--text-data);
    color: var(--color-muted);
    margin: var(--space-2xs) 0 0;
    overflow-wrap: anywhere;
    max-width: 34ch;
  }
</style>
