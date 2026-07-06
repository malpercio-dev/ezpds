<script lang="ts">
  import {
    detectMigrationPath,
    prepareMigration,
    type MigrationPathDecision,
  } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    did,
    onnext,
    onback,
  }: {
    did: string;
    onnext: (result: {
      destPdsUrl: string;
      email: string;
      inviteCode: string | undefined;
      decision: MigrationPathDecision;
    }) => void;
    onback: () => void;
  } = $props();

  let destPdsUrl = $state('');
  let email = $state('');
  let inviteCode = $state('');

  let checking = $state(false);
  // Field-level error (shown inline near the destination PDS field).
  let error = $state<string | null>(null);
  // Terminal-path message: no retry offered (interop not yet supported).
  let terminalMessage = $state<string | null>(null);
  // Recoverable-path message: retry offered (cannot_determine).
  let retryMessage = $state<string | null>(null);

  function describePrepareError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch (raw.code) {
        case 'DESTINATION_UNREACHABLE':
          return "Couldn't reach the destination PDS. Check the URL and try again.";
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        case 'MIGRATION_NOT_READY':
          return 'Migration is not ready yet. Please try again.';
        default:
          return `Couldn't prepare the migration (${raw.code}). Please try again.`;
      }
    }
    return "Couldn't reach the server. Check your connection.";
  }

  function describeDetectError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch (raw.code) {
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        case 'IDENTITY_NOT_FOUND':
          return 'This identity could not be found.';
        case 'MIGRATION_NOT_READY':
          return 'Migration is not ready yet. Please try again.';
        case 'PLC_DIRECTORY_ERROR':
          return 'The PLC directory rejected the request. Please try again.';
        default:
          return `Couldn't check this destination (${raw.code}). Please try again.`;
      }
    }
    return "Couldn't reach the server. Check your connection.";
  }

  async function submit() {
    if (!destPdsUrl.trim() || !email.trim()) return;

    checking = true;
    error = null;
    terminalMessage = null;
    retryMessage = null;

    try {
      const decision = await detectMigrationPath(did);

      switch (decision.path) {
        case 'self_signed':
          await prepareMigration(did, destPdsUrl.trim());
          onnext({
            destPdsUrl: destPdsUrl.trim(),
            email: email.trim(),
            inviteCode: inviteCode.trim() || undefined,
            decision,
          });
          break;
        case 'interop':
          terminalMessage =
            "This identity needs the PDS-signed path, which isn't supported yet.";
          break;
        case 'cannot_determine':
          retryMessage =
            "Couldn't verify this identity's keys — check your connection and try again.";
          break;
      }
    } catch (raw: unknown) {
      console.error('Migration path detection/preparation failed:', raw);
      error = describeDetectError(raw);
      // prepareMigration failures reuse MigrationError codes, which overlap in shape
      // with MigrateError (both are `{ code, message? }`) — the same describer covers
      // both since the messages are generic-enough fallbacks per code.
      if (isCodedError(raw) && 'message' in raw) {
        error = describePrepareError(raw);
      }
    } finally {
      checking = false;
    }
  }
</script>

<OnboardingShell
  title="Migrate to another PDS"
  subtitle="Move this identity to a new PDS. Your DID stays the same — only where it lives changes."
  onback={terminalMessage ? undefined : onback}
>
  {#if terminalMessage}
    <div class="notice notice--terminal" role="alert">
      <p class="notice-text">{terminalMessage}</p>
    </div>
    <Button variant="secondary" onclick={onback}>Back</Button>
  {:else}
    <TextField
      bind:value={destPdsUrl}
      type="url"
      placeholder="https://new-pds.example.com"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination PDS URL"
      disabled={checking}
      error={error ?? undefined}
    />
    <TextField
      bind:value={email}
      type="email"
      placeholder="you@example.com"
      autocomplete="email"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination email"
      disabled={checking}
    />
    <TextField
      bind:value={inviteCode}
      type="text"
      placeholder="Invite code (optional)"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination invite code (optional)"
      disabled={checking}
    />

    {#if retryMessage}
      <div class="notice notice--retry" role="alert">
        <p class="notice-text">{retryMessage}</p>
      </div>
    {/if}

    <Button
      disabled={checking || !destPdsUrl.trim() || !email.trim()}
      onclick={submit}
    >
      {checking ? 'Checking…' : retryMessage ? 'Retry' : 'Continue'}
    </Button>
    <Button variant="secondary" onclick={onback} disabled={checking}>Back</Button>
  {/if}
</OnboardingShell>

<style>
  .notice {
    width: 100%;
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
  }
  .notice--terminal {
    background: var(--color-surface-sunk);
  }
  .notice--retry {
    background: var(--color-warning-surface);
  }
  .notice-text {
    font-size: var(--text-label);
    margin: 0;
    line-height: 1.4;
  }
  .notice--terminal .notice-text {
    color: var(--color-muted);
  }
  .notice--retry .notice-text {
    color: var(--color-warning);
  }
</style>
