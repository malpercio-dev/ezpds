<script lang="ts">
  import { resolveIdentity, isCodedError, type IdentityInfo } from '$lib/ipc';
  import { truncateDid } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    value = $bindable(''),
    onnext,
    onback,
  }: {
    value: string;
    onnext: (info: IdentityInfo) => void;
    onback: () => void;
  } = $props();

  let resolving = $state(false);
  let resolved = $state<IdentityInfo | null>(null);
  let error = $state<string | null>(null);

  async function resolve() {
    if (!value.trim()) return;

    resolving = true;
    error = null;
    resolved = null;

    try {
      const info = await resolveIdentity(value.trim());
      resolved = info;
      error = null;
    } catch (raw: unknown) {
      console.error('Identity resolution failed:', raw);

      if (isCodedError(raw)) {
        switch (raw.code) {
          case 'HANDLE_NOT_FOUND':
            error = 'Handle not found. Check the spelling and try again.';
            break;
          case 'DID_NOT_FOUND':
            error = 'DID not found on PLC directory.';
            break;
          case 'PDS_UNREACHABLE':
            error = 'Could not reach the PDS. It may be temporarily offline.';
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = `An unexpected error occurred (${raw.code}). Please try again.`;
        }
      } else {
        error = 'An unexpected error occurred. Please try again.';
      }
      resolved = null;
    } finally {
      resolving = false;
    }
  }

  function handleInputChange() {
    if (resolved || error) {
      resolved = null;
      error = null;
    }
  }

  let displayDid = $derived(truncateDid(resolved?.did ?? ''));
</script>

<OnboardingShell title="Import identity" subtitle="Enter a handle or DID to import an existing identity.">
  <TextField
    bind:value
    type="text"
    placeholder="alice.example.com or did:plc:…"
    autocomplete="off"
    autocapitalize="none"
    autocorrect="off"
    spellcheck={false}
    aria-label="Handle or DID"
    error={error ?? undefined}
    oninput={handleInputChange}
  />
  <Button disabled={resolving || !value.trim()} onclick={resolve}>
    {resolving ? 'Resolving…' : 'Resolve'}
  </Button>

  {#if resolved}
    <div class="preview">
      <div class="row"><span class="k">Handle</span><span class="v">@{resolved.handle}</span></div>
      <div class="row"><span class="k">DID</span><span class="v mono">{displayDid}</span></div>
      <div class="row"><span class="k">PDS</span><span class="v">{resolved.pdsUrl}</span></div>
      <div class="row">
        <span class="k">Rotation key</span>
        <span class="v" class:ok={resolved.deviceKeyIsRoot}>
          {resolved.deviceKeyIsRoot ? 'Your device is the root key' : 'Device key is not the root key'}
        </span>
      </div>
    </div>
    <Button onclick={() => onnext(resolved!)}>Continue</Button>
  {/if}

  <Button variant="secondary" onclick={onback}>Back</Button>
</OnboardingShell>

<style>
  .preview {
    width: 100%;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    text-align: left;
  }
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
  }
  .k {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .v {
    font-size: var(--text-body);
    color: var(--color-ink);
    word-break: break-word;
  }
  .v.mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
  }
  .v.ok {
    color: var(--color-safe);
    font-weight: var(--weight-semibold);
  }
</style>
