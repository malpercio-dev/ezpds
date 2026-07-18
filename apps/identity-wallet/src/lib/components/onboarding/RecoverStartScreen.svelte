<script lang="ts">
  import { startShareRecovery, isCodedError, type RecoveryTarget, type ShareRecoveryError } from '$lib/ipc';
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
    onnext: (target: RecoveryTarget) => void;
    onback: () => void;
  } = $props();

  let starting = $state(false);
  let target = $state<RecoveryTarget | null>(null);
  let error = $state<string | null>(null);

  async function start() {
    if (!value.trim()) return;
    starting = true;
    error = null;
    target = null;
    try {
      target = await startShareRecovery(value.trim());
    } catch (raw: unknown) {
      console.error('Recovery start failed:', raw);
      if (isCodedError(raw)) {
        switch ((raw as ShareRecoveryError).code) {
          case 'HANDLE_NOT_FOUND':
            error = 'Handle not found. Check the spelling and try again.';
            break;
          case 'DID_NOT_FOUND':
            error = 'This identity was not found on the PLC directory.';
            break;
          case 'UNSUPPORTED_IDENTITY':
            error = 'Only did:plc identities can be recovered from backup shares.';
            break;
          case 'RATE_LIMITED':
            error = 'Too many attempts. Wait a moment and try again.';
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
    } finally {
      starting = false;
    }
  }

  function handleInputChange() {
    if (target || error) {
      target = null;
      error = null;
    }
  }

  let displayDid = $derived(truncateDid(target?.did ?? ''));
</script>

<OnboardingShell
  title="Recover an identity"
  subtitle="Any two of your three backup shares can bring your identity to this device."
  {onback}
>
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
  <Button disabled={starting || !value.trim()} onclick={start}>
    {starting ? 'Looking up…' : 'Find my identity'}
  </Button>

  {#if target}
    <div class="preview">
      {#if target.handle}
        <div class="row"><span class="k">Handle</span><span class="v">@{target.handle}</span></div>
      {/if}
      <div class="row"><span class="k">DID</span><span class="v mono">{displayDid}</span></div>
      <div class="row">
        <span class="k">Share 1 · iCloud Keychain</span>
        <span class="v" class:ok={target.share1Loaded}>
          {target.share1Loaded
            ? '✓ Found on this device'
            : 'Not found — you can enter a share manually'}
        </span>
      </div>
    </div>
    <Button onclick={() => onnext(target!)}>Continue</Button>
  {/if}
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
