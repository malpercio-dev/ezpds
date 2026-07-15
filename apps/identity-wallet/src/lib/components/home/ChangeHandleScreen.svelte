<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import { composeHandle, isValidLabel } from '$lib/handle';
  import {
    getIdentityHandleDomains,
    changeHandle,
    ensureIdentitySession,
    sovereignLogin,
    isCodedError,
    type HandleChangeError,
  } from '$lib/ipc';

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
  let label = $state('');
  let selectedDomain = $state('');

  // describeServer may return domains with a leading dot (".ezpds.com"); normalize so the
  // composed handle never gets a doubled separator ("alice..ezpds.com").
  const cleanDomain = (domain: string) => domain.replace(/^\.+/, '');

  let isValid = $derived(
    phase.kind === 'ready' && selectedDomain !== '' && isValidLabel(label)
  );
  let preview = $derived(
    phase.kind === 'ready' && selectedDomain !== ''
      ? composeHandle(label.trim() || 'your-name', cleanDomain(selectedDomain))
      : ''
  );

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

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as HandleChangeError;
    switch (err.code) {
      case 'HANDLE_NOT_AVAILABLE':
        return 'That handle is already taken. Try a different one.';
      case 'INVALID_HANDLE':
        return 'That handle isn’t valid on this server. Try a different one.';
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
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  async function submit() {
    if (phase.kind !== 'ready' || !isValid) return;
    // Preserve the loaded domain list so a failed attempt can rebuild the form.
    const domains = phase.domains;
    const fullHandle = composeHandle(label, cleanDomain(selectedDomain));
    phase = { kind: 'working' };

    try {
      // Pre-flight the session with no prompt. If it's locked, unlock it passwordlessly
      // (biometric) BEFORE the change-handle biometric — avoids a wasted prompt.
      try {
        await ensureIdentitySession(did);
      } catch (e) {
        if (isCodedError(e) && e.code === 'NEEDS_UNLOCK') {
          await sovereignLogin(did);
        } else {
          throw e;
        }
      }

      let result;
      try {
        result = await changeHandle(did, fullHandle);
      } catch (e) {
        // A live token can lapse between the pre-flight and the command. Unlock once and retry.
        if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
          await sovereignLogin(did);
          result = await changeHandle(did, fullHandle);
        } else {
          throw e;
        }
      }
      void result;
      phase = { kind: 'success', handle: fullHandle };
    } catch (e) {
      console.error('[ChangeHandleScreen] change handle failed:', e);
      phase = { kind: 'ready', domains, error: messageFor(e) };
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

    {#if phase.kind === 'loading'}
      <div class="center"><Spinner size={28} label="Loading available handle domains" /></div>
    {:else if phase.kind === 'load_error'}
      <p class="status">Couldn’t reach the hosting server to load handle domains.</p>
      <Button onclick={loadDomains}>Try again</Button>
    {:else if phase.kind === 'no_domains'}
      <p class="status">This identity’s hosting server has no handle domains configured.</p>
    {:else if phase.kind === 'working'}
      <div class="center">
        <Spinner size={28} label="Changing your handle" />
        <p class="hint">Signing and publishing the change…</p>
      </div>
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
              <option value={domain}>.{cleanDomain(domain)}</option>
            {/each}
          </select>
        {:else}
          <p class="suffix">Domain: <span class="handle">.{cleanDomain(selectedDomain)}</span></p>
        {/if}

        <p class="preview">New handle: <span class="handle">{preview}</span></p>
        <Button disabled={!isValid} onclick={submit}>Change handle</Button>
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
  .preview {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .handle {
    font-family: var(--font-mono);
    color: var(--color-ink);
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
