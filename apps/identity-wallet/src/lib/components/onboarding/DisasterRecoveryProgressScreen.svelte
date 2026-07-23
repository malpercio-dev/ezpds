<script lang="ts">
  import { onDestroy } from 'svelte';
  import {
    enrollRecoverySigningKey,
    awaitRecoveryKeyVisibility,
    createRecoveryDestinationAccount,
    recoveryTransferRepo,
    transferBlobs,
    transferPreferences,
    verifyImport,
    isCodedError,
    type AccountStatus,
    type BlobLoss,
    type MigrationError,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import { describeBlobLoss } from '$lib/migration-errors';

  let {
    did,
    email,
    inviteCode,
    onnext,
    onerror,
  }: {
    did: string;
    email: string;
    inviteCode?: string;
    onnext: (status: AccountStatus) => void;
    onerror: (err: unknown) => void;
  } = $props();

  type LegId = 'enroll' | 'propagate' | 'account' | 'repo' | 'blobs' | 'preferences' | 'verify';
  type LegState = 'pending' | 'active' | 'done' | 'failed';

  const LEGS: { id: LegId; label: string }[] = [
    { id: 'enroll', label: 'Enroll a recovery signing key' },
    { id: 'propagate', label: 'Wait for the directory to publish it' },
    { id: 'account', label: 'Create destination account' },
    { id: 'repo', label: 'Restore posts from backup' },
    { id: 'blobs', label: 'Restore media from backup' },
    { id: 'preferences', label: 'Preferences (nothing to restore)' },
    { id: 'verify', label: 'Verify destination' },
  ];

  let legStates = $state<Record<LegId, LegState>>({
    enroll: 'pending',
    propagate: 'pending',
    account: 'pending',
    repo: 'pending',
    blobs: 'pending',
    preferences: 'pending',
    verify: 'pending',
  });

  let failure = $state<string | null>(null);
  let failureDetail = $state<string | null>(null);
  let lossManifest = $state<BlobLoss[] | null>(null);
  let acceptBlobLoss = $state(false);

  // Stop the propagation poll if the screen is torn down mid-wait.
  let destroyed = false;
  onDestroy(() => {
    destroyed = true;
  });

  /** Sentinel thrown when the user cancels the biometric gate — nothing was signed. */
  const BIOMETRIC_CANCELLED = Symbol('biometric-cancelled');

  /** How often to re-check plc.directory for op #1, and how long before giving up. */
  const POLL_INTERVAL_MS = 3000;
  const MAX_POLLS = 100; // ~5 minutes — propagation is normally near-instant.

  function statusGlyph(state: LegState): string {
    switch (state) {
      case 'pending':
        return '○';
      case 'active':
        return '◐';
      case 'done':
        return '✓';
      case 'failed':
        return '✕';
    }
  }

  function statusWord(state: LegState): string {
    switch (state) {
      case 'pending':
        return 'Waiting';
      case 'active':
        return 'In progress';
      case 'done':
        return 'Done';
      case 'failed':
        return 'Failed';
    }
  }

  function describeError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch (raw.code) {
        case 'WALLET_NOT_AUTHORIZED':
          return "This wallet doesn't hold a rotation key for this identity.";
        case 'GUARD_REJECTED':
          return 'The safety check refused to sign the key-enroll operation.';
        case 'KEY_NOT_ENROLLED':
          return 'The recovery signing key is missing. Restart the recovery.';
        case 'PLC_DIRECTORY_ERROR':
          return 'The PLC directory rejected the request.';
        case 'RATE_LIMITED':
          return 'The PLC directory is rate-limiting requests. Wait a moment and retry.';
        case 'SERVICE_AUTH_FAILED':
          return "Couldn't authorize with the destination PDS.";
        case 'ACCOUNT_CREATION_FAILED':
          return "Couldn't create the account on the destination PDS.";
        case 'DESTINATION_CONFLICT':
          return 'An account already exists on the destination PDS with a conflicting identity.';
        case 'BACKUP_UNAVAILABLE':
          return 'No valid backup was found on this device — the account cannot be rebuilt without one.';
        case 'REPO_TRANSFER_FAILED':
          return "Couldn't restore the posts backup to the destination.";
        case 'BLOB_TRANSFER_FAILED':
          return "Couldn't restore one or more media files.";
        case 'BLOB_DRAIN_INCOMPLETE':
          return "Some media couldn't be restored from the backup.";
        case 'VERIFICATION_INCOMPLETE': {
          const err = raw as Extract<MigrationError, { code: 'VERIFICATION_INCOMPLETE' }>;
          return `Import incomplete: ${err.imported}/${err.expected} blobs imported so far.`;
        }
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        case 'MIGRATION_NOT_READY':
        case 'RECOVERY_NOT_READY':
          return 'The recovery session was lost. Please restart the recovery flow.';
        default:
          return `Something went wrong (${raw.code}).`;
      }
    }
    if (raw === BIOMETRIC_CANCELLED) {
      return 'Authentication was cancelled. Nothing was signed — retry when ready.';
    }
    return 'An unexpected error occurred.';
  }

  function describeErrorDetail(raw: unknown): string | null {
    if (!isCodedError(raw)) return null;
    if (!('message' in raw) || typeof raw.message !== 'string') return null;
    const message = raw.message.trim();
    return message.length > 0 ? message : null;
  }

  async function runLeg(id: LegId, fn: () => Promise<void>) {
    // Resume, don't repeat: retries skip legs that already succeeded (the backend
    // commands are individually idempotent/reconciling).
    if (legStates[id] === 'done') return;
    legStates[id] = 'active';
    await fn();
    legStates[id] = 'done';
  }

  async function pollUntilVisible() {
    for (let i = 0; i < MAX_POLLS; i++) {
      if (destroyed) return;
      const { visible } = await awaitRecoveryKeyVisibility(did);
      if (visible) return;
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    throw {
      code: 'PLC_DIRECTORY_ERROR',
      message: 'the enrolled key did not become visible in time; retry to keep waiting',
    };
  }

  async function runRecovery() {
    failure = null;
    failureDetail = null;
    lossManifest = null;
    try {
      await runLeg('enroll', async () => {
        // The enroll signs a PLC operation with the device key — gate it behind
        // user presence, like every other irreversible signing action.
        try {
          await authenticateBiometric('Approve enrolling a recovery signing key');
        } catch {
          throw BIOMETRIC_CANCELLED;
        }
        await enrollRecoverySigningKey(did);
      });
      await runLeg('propagate', pollUntilVisible);
      await runLeg('account', async () => {
        // Creating the destination account mints the service-auth JWT with the
        // Keychain-held recovery signing key — a signing action, so it gets the
        // same user-presence gate as the enroll.
        try {
          await authenticateBiometric('Approve creating the account on the new PDS');
        } catch {
          throw BIOMETRIC_CANCELLED;
        }
        await createRecoveryDestinationAccount(did, email, inviteCode);
      });
      await runLeg('repo', () => recoveryTransferRepo(did));
      await runLeg('blobs', () => transferBlobs(did, acceptBlobLoss));
      await runLeg('preferences', () => transferPreferences(did));

      legStates.verify = 'active';
      const status = await verifyImport(did);
      legStates.verify = 'done';

      onnext(status);
    } catch (raw: unknown) {
      if (destroyed) return;
      console.error('Recovery leg failed:', raw);
      for (const leg of LEGS) {
        if (legStates[leg.id] === 'active') {
          legStates[leg.id] = 'failed';
        }
      }

      if (isCodedError(raw) && raw.code === 'BLOB_DRAIN_INCOMPLETE') {
        lossManifest = (raw as Extract<MigrationError, { code: 'BLOB_DRAIN_INCOMPLETE' }>).losses;
      } else {
        failure = describeError(raw);
        failureDetail = describeErrorDetail(raw);
      }
      onerror(raw);
    }
  }

  function retry() {
    for (const leg of LEGS) {
      if (legStates[leg.id] === 'failed') legStates[leg.id] = 'pending';
    }
    runRecovery();
  }

  // Accept the loss manifest: blobs missing from the backup mirror stay lost (the
  // source is gone — there is nowhere else to fetch them from).
  function continueWithLoss() {
    acceptBlobLoss = true;
    lossManifest = null;
    for (const leg of LEGS) {
      if (legStates[leg.id] === 'failed') legStates[leg.id] = 'pending';
    }
    runRecovery();
  }

  runRecovery();
</script>

<div class="screen">
  <div class="header">
    <Spinner size={40} label="Rebuilding" />
    <h1 class="title">Rebuilding your account</h1>
    <p class="subtitle">
      Restoring from your backup — your old PDS is never contacted. Don't close the app.
    </p>
  </div>

  <ul class="checklist">
    {#each LEGS as leg (leg.id)}
      <li class="leg leg--{legStates[leg.id]}">
        <span class="leg-glyph" aria-hidden="true">{statusGlyph(legStates[leg.id])}</span>
        <span class="leg-body">
          <span class="leg-label">{leg.label}</span>
          <span class="leg-status">{statusWord(legStates[leg.id])}</span>
        </span>
      </li>
    {/each}
  </ul>

  {#if lossManifest}
    <div class="loss-box" role="alert">
      <p class="loss-title">
        {lossManifest.length}
        {lossManifest.length === 1 ? 'file' : 'files'} couldn't be restored
      </p>
      <p class="loss-lede">
        These media files aren't in your backup, and the old PDS is gone — they can't be
        recovered. Posts that use them will show a broken image. You can continue without them.
      </p>
      <ul class="loss-list">
        {#each lossManifest as loss (loss.cid)}
          <li class="loss-item">
            <span class="loss-detail">{describeBlobLoss(loss)}</span>
            <span class="loss-record">Used by {loss.recordUri}</span>
            <span class="loss-cid">{loss.cid}</span>
          </li>
        {/each}
      </ul>
      <div class="loss-actions">
        <Button onclick={continueWithLoss}>Continue without them</Button>
        <Button variant="secondary" onclick={retry}>Try again</Button>
      </div>
    </div>
  {:else if failure}
    <div class="error-box" role="alert">
      <p class="error-text">{failure}</p>
      {#if failureDetail}
        <p class="error-detail">{failureDetail}</p>
      {/if}
    </div>
    <Button onclick={retry}>Retry</Button>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-xl) var(--space-lg);
    gap: var(--space-lg);
    overflow-y: auto;
  }
  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--space-sm);
  }
  .title {
    font-family: var(--font-sans);
    font-size: var(--text-headline);
    line-height: var(--leading-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }
  .subtitle {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    max-width: 32ch;
  }

  .checklist {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .leg {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .leg-glyph {
    font-size: var(--text-title);
    line-height: var(--leading-headline);
    width: 22px;
    flex-shrink: 0;
    text-align: center;
    color: var(--color-muted);
  }
  .leg--done .leg-glyph {
    color: var(--color-safe);
  }
  .leg--active .leg-glyph {
    color: var(--color-primary-deep);
  }
  .leg--failed .leg-glyph {
    color: var(--color-critical);
  }
  .leg-body {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  .leg-label {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .leg-status {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .leg--done .leg-status {
    color: var(--color-safe);
  }
  .leg--failed .leg-status {
    color: var(--color-critical);
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
  .error-detail {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-critical-soft);
    margin: var(--space-xs) 0 0;
    line-height: 1.4;
    word-break: break-word;
  }

  .loss-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .loss-title {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
    margin: 0;
  }
  .loss-lede {
    font-size: var(--text-label);
    color: var(--color-ink);
    margin: 0;
    line-height: 1.4;
  }
  .loss-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    max-height: 40vh;
    overflow-y: auto;
  }
  .loss-item {
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    min-width: 0;
  }
  .loss-detail {
    font-size: var(--text-label);
    color: var(--color-ink);
    line-height: 1.4;
    word-break: break-word;
  }
  .loss-record {
    font-size: var(--text-label);
    color: var(--color-muted);
    word-break: break-all;
  }
  .loss-cid {
    font-family: var(--font-mono);
    font-size: var(--text-label);
    color: var(--color-muted);
    word-break: break-all;
  }
  .loss-actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
</style>
