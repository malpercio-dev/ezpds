<script lang="ts">
  import {
    armIdentityLeg,
    buildMigrationOp,
    authenticateBiometric,
    submitMigrationOp,
    finalizeMigration,
    type SignedMigrationOp,
    type ClaimResult,
    type MigrationError,
    type MigrateError,
  } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    did,
    onnext,
    oncancel,
  }: {
    did: string;
    onnext: (result: ClaimResult) => void;
    oncancel: () => void;
  } = $props();

  let loading = $state(true);
  let loadError = $state<string | null>(null);
  // Whether the on-mount load failure is terminal (no retry offered). CodeRabbit fix:
  // persist this alongside the message so the Retry button can be hidden/disabled.
  let loadErrorIsTerminal = $state(false);
  let signedOp = $state<SignedMigrationOp | null>(null);

  let submitting = $state(false);
  // Recoverable (retryable) vs terminal (no retry — a different path or state is needed).
  let error = $state<string | null>(null);
  let errorIsTerminal = $state(false);
  // The PLC identity op is submitted exactly once. Once it lands, `migration_state` is cleared and
  // re-submitting fails terminally — so a resumed cutover (finalize failed, user retries) must skip
  // straight to finalize. The submit result is kept so a resumed attempt still resolves onnext.
  let submitted = $state(false);
  let submitResult = $state<ClaimResult | null>(null);

  let hasChanges = $derived(
    signedOp
      ? signedOp.diff.addedKeys.length > 0 ||
          signedOp.diff.removedKeys.length > 0 ||
          signedOp.diff.changedServices.length > 0
      : false
  );

  // Terminal codes shared by both MigrationError (armIdentityLeg) and MigrateError
  // (buildMigrationOp/submitMigrationOp): these mean "this can't be retried from here" —
  // either the wallet/state isn't authorized to proceed, or the identity/migration
  // session itself is gone, so hammering Retry would just fail the same way again.
  const TERMINAL_CODES = new Set([
    'WALLET_NOT_AUTHORIZED',
    'GUARD_REJECTED',
    'IDENTITY_NOT_FOUND',
    'MIGRATION_NOT_READY',
    'DESTINATION_CONFLICT',
    'INVALID_RECOMMENDED_CREDENTIALS',
    'INVALID_AUDIT_LOG',
  ]);

  function describeError(raw: unknown): { message: string; terminal: boolean } {
    if (isCodedError(raw)) {
      const err = raw as MigrationError | MigrateError;
      const terminal = TERMINAL_CODES.has(err.code);
      switch (err.code) {
        case 'WALLET_NOT_AUTHORIZED':
          return {
            message: 'Your device key is not authorized to sign for this identity.',
            terminal: true,
          };
        case 'GUARD_REJECTED':
          return {
            message: `This operation was rejected for safety: ${('reason' in err && err.reason) || 'unexpected change'}.`,
            terminal: true,
          };
        case 'INVALID_RECOMMENDED_CREDENTIALS':
        case 'INVALID_AUDIT_LOG':
          return { message: `Couldn't build the migration operation (${err.code}).`, terminal: true };
        case 'SIGNING_FAILED':
          return { message: 'Signing failed. Please try again.', terminal: false };
        case 'PLC_DIRECTORY_ERROR':
          return { message: 'The PLC directory rejected the operation. Please try again.', terminal: false };
        case 'NETWORK_ERROR':
          return { message: 'Network error. Check your connection and try again.', terminal: false };
        case 'IDENTITY_NOT_FOUND':
          return { message: 'This identity could not be found.', terminal: true };
        case 'MIGRATION_NOT_READY':
          return { message: 'Migration is not ready yet. Please restart the migration flow.', terminal: true };
        case 'DESTINATION_CONFLICT':
          return { message: 'The destination account conflicts with this identity.', terminal: true };
        case 'DESTINATION_UNREACHABLE':
          return { message: "Couldn't reach the destination PDS.", terminal: false };
        case 'ACTIVATION_FAILED':
          return { message: 'Activating your new account failed. Please try again.', terminal: false };
        case 'SOVEREIGN_LOGIN_FAILED':
          return { message: 'Securing your new session failed. Your old account is untouched — please try again.', terminal: false };
        case 'SESSION_PERSIST_FAILED':
          return { message: "Couldn't save your new session. Your old account is untouched — please try again.", terminal: false };
        case 'DEACTIVATION_FAILED':
          return { message: 'Deactivating your old account failed. Please try again.', terminal: false };
        case 'SOURCE_AUTH_FAILED':
          return { message: 'Your source-PDS session expired. Please restart the migration flow.', terminal: true };
        default:
          return { message: `Something went wrong (${err.code}).`, terminal };
      }
    }
    return { message: 'Something went wrong. Please try again.', terminal: false };
  }

  async function loadOp() {
    loading = true;
    loadError = null;
    loadErrorIsTerminal = false;
    try {
      await armIdentityLeg(did);
      signedOp = await buildMigrationOp(did);
    } catch (raw: unknown) {
      console.error('Migration review load failed:', raw);
      const described = describeError(raw);
      loadError = described.message;
      loadErrorIsTerminal = described.terminal;
    } finally {
      loading = false;
    }
  }

  async function approve() {
    error = null;
    errorIsTerminal = false;

    try {
      await authenticateBiometric('Approve the identity change to migrate your account');
    } catch {
      // Biometric cancel/failure returns to the diff — no submission attempted.
      return;
    }

    submitting = true;
    try {
      // Submit the PLC identity op exactly once; a resumed attempt skips straight to finalize
      // (re-submitting after the op landed fails terminally). The biometric gate above still runs
      // on every attempt, so a resumed cutover re-authorizes before finalize's device-key signature.
      if (!submitted) {
        submitResult = await submitMigrationOp(did);
        submitted = true;
      }
      await finalizeMigration(did);
      onnext(submitResult!);
    } catch (raw: unknown) {
      console.error('Migration submission failed:', raw);
      const described = describeError(raw);
      error = described.message;
      errorIsTerminal = described.terminal;
      submitting = false;
    }
  }

  loadOp();
</script>

<div class="screen">
  <div class="content">
    <div class="hero">
      <h1 class="hero-title">Review the migration</h1>
      <p class="hero-sub">This is the exact operation that will be signed and submitted to move your identity.</p>
    </div>

    {#if loading}
      <div class="centered">
        <Spinner size={36} label="Loading" />
      </div>
    {:else if loadError}
      <div class="error-box" role="alert">
        <p class="error-text">{loadError}</p>
        {#if loadErrorIsTerminal}
          <p class="error-sub">This can't be retried from here.</p>
        {/if}
      </div>
      {#if !loadErrorIsTerminal}
        <Button onclick={loadOp}>Retry</Button>
      {/if}
    {:else if signedOp}
      <div class="block">
        <p class="block-label">This will</p>
        {#if !hasChanges}
          <p class="no-changes">No key or service changes to apply.</p>
        {:else}
          {#each signedOp.diff.addedKeys as key}
            <DiffRow variant="restore" title="Add rotation key" value={key} />
          {/each}
          {#each signedOp.diff.removedKeys as key}
            <DiffRow variant="remove" title="Remove key" value={key} />
          {/each}
          {#each signedOp.diff.changedServices as service}
            {#if service.changeType === 'added'}
              <DiffRow variant="restore" title="Add service {service.id}" value={service.newEndpoint ?? undefined} />
            {:else if service.changeType === 'removed'}
              <DiffRow variant="remove" title="Remove service {service.id}" value="was {service.oldEndpoint}" />
            {:else if service.changeType === 'modified'}
              <DiffRow variant="modify" title="Change service {service.id}" value="{service.oldEndpoint} → {service.newEndpoint}" />
            {/if}
          {/each}
        {/if}
      </div>

      {#if error}
        <div class="error-box" role="alert">
          <p class="error-text">{error}</p>
          {#if errorIsTerminal}
            <p class="error-sub">This can't be retried from here.</p>
          {/if}
        </div>
      {/if}
    {/if}
  </div>

  <div class="actions">
    {#if signedOp && !loadError}
      <Button
        disabled={submitting || (!!error && errorIsTerminal)}
        onclick={approve}
      >
        {submitting ? 'Submitting…' : error && !errorIsTerminal ? 'Retry' : 'Approve with biometrics'}
      </Button>
    {/if}
    <Button variant="secondary" onclick={oncancel} disabled={submitting}>Cancel</Button>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-lg) var(--space-md) var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .hero-title {
    font-family: var(--font-display);
    font-weight: var(--weight-regular);
    font-size: var(--text-display);
    line-height: var(--leading-display);
    color: var(--color-ink);
    margin: 0 0 var(--space-sm);
  }
  .hero-sub {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .centered {
    display: flex;
    justify-content: center;
    padding: var(--space-xl) 0;
  }

  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .block-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .no-changes {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
  }
  .error-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }
  .error-sub {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: var(--space-xs) 0 0;
    font-weight: var(--weight-semibold);
  }

  .actions {
    flex-shrink: 0;
    border-top: 1px solid var(--color-line);
    background: var(--color-surface);
    padding: var(--space-md) var(--space-md) var(--space-xl);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
</style>
