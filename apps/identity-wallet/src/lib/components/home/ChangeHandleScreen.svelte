<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import {
    composeHandle,
    isValidHandle,
    isValidLabel,
    normalizeDomain,
    normalizeHandle,
  } from '$lib/handle';
  import {
    getIdentityHandleDomains,
    changeHandle,
    checkCustomHandleDns,
    ensureIdentitySession,
    isCodedError,
    type CustomHandleDnsCheck,
    type HandleChangeError,
  } from '$lib/ipc';
  import { unlockIdentity, isUnlockCancelled } from '$lib/unlock';

  // The sovereign change-handle surface, reached from ManageIdentityScreen's "Change
  // handle" row (did:plc with the device key as top rotation key only — the wallet signs
  // the alsoKnownAs PLC op itself). Two modes: a served-domain picker (label + the hosting
  // PDS's `getIdentityHandleDomains`) and a custom-domain form for a domain the user owns,
  // where the handle must already resolve to the DID before the server will allocate it —
  // so the form shows the exact `_atproto` DNS TXT record required and hard-gates the
  // change on a passing `checkCustomHandleDns` pre-flight. Both paths pre-flight the
  // session, then run the biometric-gated `changeHandle`.
  let {
    did,
    currentHandle,
    onback,
    ondone,
  }: {
    did: string;
    /** The identity's current handle (from the cached DID doc), shown for context. */
    currentHandle: string | null;
    onback: () => void;
    /** Called after the handle change lands and the cache is refreshed. */
    ondone: () => void;
  } = $props();

  type Phase =
    | { kind: 'loading' }
    // The served domains offered by the hosting PDS; user picks a label under one.
    | { kind: 'ready'; domains: string[]; error?: string }
    | { kind: 'no_domains' }
    | { kind: 'load_error' }
    | { kind: 'working' }
    | { kind: 'success'; handle: string };

  let phase = $state<Phase>({ kind: 'loading' });
  let mode = $state<'served' | 'custom'>('served');
  let label = $state('');
  let selectedDomain = $state('');

  // ── Custom-domain state ─────────────────────────────────────────────────────
  let customHandle = $state('');
  let customError = $state<string | undefined>(undefined);
  // The DNS pre-flight result, tagged with the handle it was run for; a result for a
  // handle the user has since edited is stale and reads as 'idle' (see dnsCurrent).
  type DnsState =
    | { kind: 'idle' }
    | { kind: 'checking'; forHandle: string }
    | { kind: 'done'; forHandle: string; result: CustomHandleDnsCheck }
    | { kind: 'failed'; forHandle: string; message: string };
  let dns = $state<DnsState>({ kind: 'idle' });

  let isValid = $derived(
    phase.kind === 'ready' && selectedDomain !== '' && isValidLabel(label)
  );
  let preview = $derived(
    phase.kind === 'ready' && selectedDomain !== ''
      ? composeHandle(label.trim() || 'your-name', selectedDomain)
      : ''
  );

  let normalizedCustom = $derived(normalizeHandle(customHandle));
  let customValid = $derived(isValidHandle(customHandle));
  // A custom-typed handle that actually sits under one of this server's own domains
  // belongs to the served picker (the server allocates those directly, no DNS record).
  let customServedDomain = $derived.by(() => {
    if (phase.kind !== 'ready' || !customValid) return false;
    const dot = normalizedCustom.indexOf('.');
    const domain = normalizedCustom.slice(dot + 1);
    return phase.domains.some((d) => normalizeDomain(d).toLowerCase() === domain);
  });
  // The pre-flight result only counts while the typed handle still matches it.
  let dnsCurrent = $derived(
    dns.kind !== 'idle' && dns.forHandle === normalizedCustom ? dns : { kind: 'idle' as const }
  );
  let dnsVerified = $derived(
    dnsCurrent.kind === 'done' && dnsCurrent.result.status === 'VERIFIED'
  );
  // Shown before (and after) the check so the owner can create the record from it.
  let recordName = $derived(`_atproto.${normalizedCustom}`);
  let recordValue = $derived(`did=${did}`);

  async function loadDomains() {
    phase = { kind: 'loading' };
    try {
      const list = await getIdentityHandleDomains(did);
      if (list.length === 0) {
        phase = { kind: 'no_domains' };
        return;
      }
      selectedDomain = list[0];
      phase = { kind: 'ready', domains: list };
    } catch (e) {
      console.error('[ChangeHandleScreen] failed to load handle domains:', e);
      phase = { kind: 'load_error' };
    }
  }

  function messageFor(raw: unknown): string | null {
    // A dismissed unlock prompt is the user's decision, not a failure: say nothing.
    if (isUnlockCancelled(raw)) return null;
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as HandleChangeError;
    switch (err.code) {
      case 'HANDLE_NOT_AVAILABLE':
        return 'That handle is already taken. Try a different one.';
      case 'INVALID_HANDLE':
        // On the custom path a 400 usually means the server could not verify the
        // handle's resolution, not that the name is malformed — say so.
        return mode === 'custom'
          ? 'The server couldn’t verify this handle points at your identity. Re-check the DNS record and try again.'
          : 'That handle isn’t valid on this server. Try a different one.';
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet isn’t authorized to change this identity’s handle.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'GUARD_REJECTED':
        return 'The change was blocked by a safety check and was not signed.';
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The directory rejected the change. Please try again.';
      case 'UPDATE_HANDLE_FAILED':
        return 'The server rejected the handle change. Please try again.';
      case 'SERVER_ERROR':
        return 'The server couldn’t complete this step. Please try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  /** The shared change flow: session pre-flight (unlock if needed), biometric-gated change. */
  async function performChange(fullHandle: string): Promise<void> {
    // Pre-flight the session with no prompt. If it's locked, unlock it (biometric on a
    // Custos host, password prompt elsewhere) BEFORE the change-handle biometric —
    // avoids a wasted prompt.
    try {
      await ensureIdentitySession(did);
    } catch (e) {
      if (isCodedError(e) && e.code === 'NEEDS_UNLOCK') {
        await unlockIdentity(did);
      } else {
        throw e;
      }
    }

    try {
      await changeHandle(did, fullHandle);
    } catch (e) {
      // A live token can lapse between the pre-flight and the command. Unlock once and retry.
      if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
        await unlockIdentity(did);
        await changeHandle(did, fullHandle);
      } else {
        throw e;
      }
    }
  }

  async function submit() {
    if (phase.kind !== 'ready' || !isValid) return;
    // Preserve the loaded domain list so a failed attempt can rebuild the form.
    const domains = phase.domains;
    const fullHandle = composeHandle(label, selectedDomain);
    phase = { kind: 'working' };

    try {
      await performChange(fullHandle);
      phase = { kind: 'success', handle: fullHandle };
    } catch (e) {
      console.error('[ChangeHandleScreen] change handle failed:', e);
      // A dismissed unlock returns to the form with no error — the user chose not to proceed.
      phase = { kind: 'ready', domains, error: messageFor(e) ?? undefined };
    }
  }

  async function runDnsCheck() {
    if (!customValid || customServedDomain || dnsCurrent.kind === 'checking') return;
    const forHandle = normalizedCustom;
    customError = undefined;
    dns = { kind: 'checking', forHandle };
    try {
      const result = await checkCustomHandleDns(did, forHandle);
      dns = { kind: 'done', forHandle, result };
    } catch (e) {
      console.error('[ChangeHandleScreen] DNS check failed:', e);
      dns = {
        kind: 'failed',
        forHandle,
        message: messageFor(e) ?? 'Something went wrong. Please try again.',
      };
    }
  }

  async function submitCustom() {
    if (!customValid || !dnsVerified) return;
    const fullHandle = normalizedCustom;
    // Restore whatever the served-domain data phase was if the change fails.
    const returnPhase = phase;
    customError = undefined;
    phase = { kind: 'working' };

    try {
      await performChange(fullHandle);
      phase = { kind: 'success', handle: fullHandle };
    } catch (e) {
      console.error('[ChangeHandleScreen] custom handle change failed:', e);
      phase = returnPhase;
      customError = messageFor(e) ?? undefined;
    }
  }

  onMount(loadDomains);
</script>

{#if phase.kind === 'success'}
  <div class="screen success">
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
    </SealEmblem>
    <h1 class="s-title">Handle changed</h1>
    <p class="s-body">
      Your identity now resolves as
      <span class="handle">@{phase.handle}</span>.
      It may take a few minutes to propagate across the network.
    </p>
    <Button onclick={ondone}>Done</Button>
  </div>
{:else}
  <div class="screen">
    <ScreenHeader title="Change handle" onback={onback} backLabel="Back to identity" />

    {#if currentHandle}
      <p class="current">Current handle: <span class="handle">@{currentHandle}</span></p>
    {/if}

    {#if phase.kind === 'working'}
      <div class="center">
        <Spinner size={28} label="Changing your handle" />
        <p class="hint">Signing and publishing the change…</p>
      </div>
    {:else if mode === 'custom'}
      <div class="form">
        <TextField
          bind:value={customHandle}
          type="text"
          placeholder="example.com"
          autocomplete="off"
          autocapitalize="none"
          autocorrect="off"
          spellcheck={false}
          aria-label="New handle on a domain you own"
          error={customError}
        />
        <p class="explain">
          Use a domain you own — including the domain itself, like
          <span class="handle">example.com</span> — as this identity’s handle.
        </p>

        {#if customValid && customServedDomain}
          <p class="status" role="status">
            <span class="handle">{normalizedCustom}</span> is on this server’s own domain —
            use the server domain option below instead; no DNS record is needed.
          </p>
        {:else if customValid}
          <div class="dns-panel">
            <p class="dns-lead">
              Prove you own it: create this DNS record with your domain provider, then
              check it here. The change is enabled once the record verifies.
            </p>
            <dl class="dns-record" aria-label="Required DNS record">
              <div class="dns-row"><dt>Type</dt><dd class="handle">TXT</dd></div>
              <div class="dns-row"><dt>Name</dt><dd class="handle">{recordName}</dd></div>
              <div class="dns-row"><dt>Value</dt><dd class="handle">{recordValue}</dd></div>
            </dl>

            <div class="dns-result" aria-live="polite">
              {#if dnsCurrent.kind === 'checking'}
                <Spinner size={18} label="Checking the DNS record" />
                <p class="dns-msg">Checking the record…</p>
              {:else if dnsCurrent.kind === 'failed'}
                <p class="dns-msg verdict"><span class="glyph" aria-hidden="true">✕</span> {dnsCurrent.message}</p>
              {:else if dnsCurrent.kind === 'done'}
                {#if dnsCurrent.result.status === 'VERIFIED'}
                  <p class="dns-msg verdict"><span class="glyph" aria-hidden="true">✓</span>
                    Record verified — <span class="handle">{normalizedCustom}</span> points at this identity.</p>
                {:else if dnsCurrent.result.status === 'PROPAGATING'}
                  <p class="dns-msg verdict"><span class="glyph" aria-hidden="true">◔</span>
                    Record found, but your hosting server can’t see it yet. DNS changes can
                    take a few minutes to propagate — check again shortly.</p>
                {:else if dnsCurrent.result.status === 'WRONG_DID'}
                  <p class="dns-msg verdict"><span class="glyph" aria-hidden="true">!</span>
                    This handle currently points at a different identity:
                    <span class="handle">{dnsCurrent.result.foundDid}</span>. Update the TXT
                    record’s value to the one shown above, then check again.</p>
                {:else}
                  <p class="dns-msg verdict"><span class="glyph" aria-hidden="true">–</span>
                    No record found yet. Add the TXT record above, then check again.</p>
                {/if}
              {/if}
            </div>

            <Button
              variant="secondary"
              disabled={dnsCurrent.kind === 'checking'}
              onclick={runDnsCheck}
            >{dnsCurrent.kind === 'done' || dnsCurrent.kind === 'failed' ? 'Check again' : 'Check DNS record'}</Button>
          </div>
        {/if}

        <Button disabled={!dnsVerified || customServedDomain} onclick={submitCustom}>Change handle</Button>
        <button type="button" class="mode-toggle" onclick={() => (mode = 'served')}>
          Use a server domain instead
        </button>
      </div>
    {:else if phase.kind === 'loading'}
      <div class="center"><Spinner size={28} label="Loading available handle domains" /></div>
    {:else if phase.kind === 'load_error'}
      <p class="status">Couldn’t reach the hosting server to load handle domains.</p>
      <Button onclick={loadDomains}>Try again</Button>
      <button type="button" class="mode-toggle" onclick={() => (mode = 'custom')}>
        Use a domain you own instead
      </button>
    {:else if phase.kind === 'no_domains'}
      <p class="status">This identity’s hosting server has no handle domains configured.</p>
      <button type="button" class="mode-toggle" onclick={() => (mode = 'custom')}>
        Use a domain you own instead
      </button>
    {:else}
      <div class="form">
        <TextField
          bind:value={label}
          type="text"
          placeholder="alice"
          autocomplete="off"
          autocapitalize="none"
          autocorrect="off"
          spellcheck={false}
          aria-label="New handle"
          error={phase.error}
        />

        {#if phase.domains.length > 1}
          <label class="domain-label" for="domain-select">Domain</label>
          <select id="domain-select" class="domain-select" bind:value={selectedDomain}>
            {#each phase.domains as domain}
              <option value={domain}>.{normalizeDomain(domain)}</option>
            {/each}
          </select>
        {:else}
          <p class="suffix">Domain: <span class="handle">.{normalizeDomain(selectedDomain)}</span></p>
        {/if}

        <p class="preview">New handle: <span class="handle">{preview}</span></p>
        <Button disabled={!isValid} onclick={submit}>Change handle</Button>
        <button type="button" class="mode-toggle" onclick={() => (mode = 'custom')}>
          Use a domain you own instead
        </button>
      </div>
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
  .current {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
  .center {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-xl) 0;
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    text-align: center;
    margin: 0;
  }
  .hint {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .domain-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .domain-select {
    width: 100%;
    padding: var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
  }
  .suffix,
  .preview,
  .explain {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .handle {
    font-family: var(--font-mono);
    color: var(--color-ink);
  }

  .mode-toggle {
    align-self: center;
    background: none;
    border: none;
    padding: var(--space-sm);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-primary);
    cursor: pointer;
  }

  .dns-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding: var(--space-md);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
  }
  .dns-lead {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: 1.5;
  }
  .dns-record {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    padding: var(--space-sm) var(--space-md);
    background: var(--color-bg);
    border-radius: var(--radius-sm);
  }
  .dns-row {
    display: flex;
    gap: var(--space-sm);
    align-items: baseline;
  }
  .dns-row dt {
    flex: 0 0 3.5rem;
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .dns-row dd {
    margin: 0;
    font-size: var(--text-label);
    overflow-wrap: anywhere;
    user-select: all;
  }
  .dns-result {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    min-height: 1.25rem;
  }
  .dns-msg {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: 1.5;
  }
  .glyph {
    font-weight: var(--weight-bold);
  }

  .success {
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-lg);
  }
  .s-title {
    font-size: var(--text-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }
  .s-body {
    font-size: var(--text-body);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: 1.5;
    max-width: 32ch;
  }
</style>
