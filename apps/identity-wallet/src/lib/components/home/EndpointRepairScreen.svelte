<script lang="ts">
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import {
    repairHostingEndpoint,
    isCodedError,
    type EndpointRepairError,
    type EndpointRepairResult,
  } from '$lib/ipc';

  let {
    did,
    currentEndpoint,
    onback,
    ondone,
  }: {
    did: string;
    /** The endpoint the cached DID document points at (the presumed-dead one). */
    currentEndpoint: string | null;
    onback: () => void;
    /** Called after the repair lands and the cache is refreshed. */
    ondone: () => void;
  } = $props();

  type Phase =
    | { kind: 'ready'; error?: string }
    | { kind: 'working' }
    | { kind: 'success'; result: EndpointRepairResult };

  let phase = $state<Phase>({ kind: 'ready' });
  let newEndpoint = $state('');

  // A permissive pre-check only — the backend normalizer is authoritative.
  let looksValid = $derived(/^https?:\/\/\S+\.\S+/.test(newEndpoint.trim()));

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as EndpointRepairError;
    switch (err.code) {
      case 'INVALID_ENDPOINT':
        return 'Enter the server’s address as a plain https origin, like https://pds.example.org.';
      case 'DESTINATION_UNREACHABLE':
        return 'Couldn’t reach that server. Check the address and your connection.';
      case 'DESTINATION_NOT_HOSTING':
        return 'That server answered, but it doesn’t host this identity. Check the address.';
      case 'WALLET_NOT_AUTHORIZED':
        return 'This wallet isn’t authorized to repair this identity’s endpoint.';
      case 'GUARD_REJECTED':
        return 'The repair was blocked by a safety check and was not signed.';
      case 'RATE_LIMITED':
        return 'Too many attempts. Please wait a moment and try again.';
      case 'PLC_DIRECTORY_ERROR':
        return 'The directory rejected the repair. Please try again.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the directory. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  async function submit() {
    if (phase.kind !== 'ready' || !looksValid) return;
    phase = { kind: 'working' };
    try {
      const result = await repairHostingEndpoint(did, newEndpoint.trim());
      phase = { kind: 'success', result };
    } catch (e) {
      console.error('[EndpointRepairScreen] endpoint repair failed:', e);
      phase = { kind: 'ready', error: messageFor(e) };
    }
  }
</script>

{#if phase.kind === 'success'}
  <div class="screen success u-screen">
    <SealEmblem>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
    </SealEmblem>
    <h1 class="s-title">Endpoint repaired</h1>
    {#if phase.result.opCid === null}
      <p class="s-body u-body-copy">
        Your identity already pointed at
        <span class="endpoint">{phase.result.newEndpoint}</span> — nothing needed signing.
      </p>
    {:else}
      <p class="s-body u-body-copy">
        Your identity now points at
        <span class="endpoint">{phase.result.newEndpoint}</span>.
        Apps may take a few minutes to notice the change.
      </p>
    {/if}
    <Button onclick={ondone}>Done</Button>
  </div>
{:else}
  <div class="screen u-screen">
    <ScreenHeader title="Repair hosting endpoint" onback={onback} backLabel="Back to identity" />

    <p class="explain u-body-copy">
      If your hosting server moved to a new address, your identity record still points at
      the old one, so apps can’t find your account. This signs an update with your device
      key pointing it at the new address — nothing else about your identity changes.
    </p>

    {#if currentEndpoint}
      <p class="current">Currently points at: <span class="endpoint">{currentEndpoint}</span></p>
    {/if}

    {#if phase.kind === 'working'}
      <div class="center">
        <Spinner size={28} label="Repairing your hosting endpoint" />
        <p class="hint">Checking the new server, signing, and publishing…</p>
      </div>
    {:else}
      <div class="form">
        <TextField
          bind:value={newEndpoint}
          type="url"
          placeholder="https://pds.example.org"
          autocomplete="off"
          autocapitalize="none"
          autocorrect="off"
          spellcheck={false}
          aria-label="New server address"
          error={phase.kind === 'ready' ? phase.error : undefined}
        />
        <p class="hint">
          The new server must already host this account — that’s verified before anything
          is signed.
        </p>
        <Button disabled={!looksValid} onclick={submit}>Repair endpoint</Button>
      </div>
    {/if}
  </div>
{/if}

<style>
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
  .hint {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .endpoint {
    font-family: var(--font-mono);
    color: var(--color-ink);
    word-break: break-all;
  }
  .success {
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: var(--space-lg);
  }
  .s-title {
    font-size: var(--text-title);
    margin: 0;
  }
</style>
