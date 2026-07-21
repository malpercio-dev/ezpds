<script lang="ts">
  import {
    createDestinationAccount,
    transferRepo,
    transferBlobs,
    transferPreferences,
    verifyImport,
    isCodedError,
    type AccountStatus,
    type BlobLoss,
    type MigrationError,
  } from '$lib/ipc';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import { describeBlobLoss, describeBlobTransferDetail } from '$lib/migration-errors';

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
    onerror: (err: MigrationError) => void;
  } = $props();

  type LegId = 'account' | 'repo' | 'blobs' | 'preferences' | 'verify';
  type LegState = 'pending' | 'active' | 'done' | 'failed';

  const LEGS: { id: LegId; label: string }[] = [
    { id: 'account', label: 'Create destination account' },
    { id: 'repo', label: 'Transfer repository' },
    { id: 'blobs', label: 'Transfer blobs' },
    { id: 'preferences', label: 'Transfer preferences' },
    { id: 'verify', label: 'Verify destination' },
  ];

  let legStates = $state<Record<LegId, LegState>>({
    account: 'pending',
    repo: 'pending',
    blobs: 'pending',
    preferences: 'pending',
    verify: 'pending',
  });

  // The failed leg's error message, surfaced inline (CodeRabbit fix: don't rely solely
  // on the caller rewinding via onerror — show the failure here with a Retry action).
  let failure = $state<string | null>(null);
  // The carried err.message, rendered as subordinate diagnostic detail beneath the headline
  // (e.g. which blob CID, and whether the source or destination side broke).
  let failureDetail = $state<string | null>(null);
  // The BLOB_DRAIN_INCOMPLETE loss manifest (MM-433): blobs that couldn't be transferred after
  // per-blob retries. Non-null renders the manifest UI — an informed choice between "continue
  // without them" and "try again" — instead of the generic single-error box.
  let lossManifest = $state<BlobLoss[] | null>(null);
  // Set once the user chooses to proceed past a loss manifest: re-runs the blobs leg with
  // acceptLoss=true so the orchestrator records the skip and advances (verify then tolerates it).
  let acceptBlobLoss = $state(false);

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
      const err = raw as MigrationError;
      switch (err.code) {
        case 'DESTINATION_UNREACHABLE':
          return "Couldn't reach the destination PDS.";
        case 'SOURCE_AUTH_FAILED':
          return 'Your source-PDS session expired. Please sign in again.';
        case 'SERVICE_AUTH_FAILED':
          return "Couldn't authorize with the destination PDS.";
        case 'ACCOUNT_CREATION_FAILED':
          return "Couldn't create the account on the destination PDS.";
        case 'DESTINATION_CONFLICT':
          return 'An account already exists on the destination PDS with a conflicting identity.';
        case 'REPO_TRANSFER_FAILED':
          return "Couldn't transfer the repository.";
        case 'BLOB_TRANSFER_FAILED':
          return "Couldn't transfer one or more blobs.";
        case 'BLOB_DRAIN_INCOMPLETE':
          return "Some media couldn't be transferred.";
        case 'PREFERENCES_TRANSFER_FAILED':
          return "Couldn't transfer preferences.";
        case 'VERIFICATION_INCOMPLETE':
          return `Import incomplete: ${err.imported}/${err.expected} blobs imported so far.`;
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        case 'MIGRATION_NOT_READY':
          return 'Migration is not ready yet. Please restart the migration flow.';
        default:
          return `Something went wrong (${err.code}).`;
      }
    }
    return 'An unexpected error occurred.';
  }

  // The headline above stays a fixed, human sentence per code; this pulls out the carried
  // `err.message` (the orchestrator's real cause — which CID, which server, which XRPC status)
  // as subordinate detail. Most codes just show it verbatim; BLOB_TRANSFER_FAILED gets the
  // fetch-vs-upload mapping so "source couldn't serve it" and "destination refused it" read as
  // distinct, actionable causes rather than one undifferentiated blob failure.
  function describeErrorDetail(raw: unknown): string | null {
    if (!isCodedError(raw)) return null;
    const err = raw as MigrationError;
    if (!('message' in err) || typeof err.message !== 'string') return null;
    const message = err.message.trim();
    if (message.length === 0) return null;
    return err.code === 'BLOB_TRANSFER_FAILED' ? describeBlobTransferDetail(message) : message;
  }

  function toMigrationError(raw: unknown): MigrationError {
    if (isCodedError(raw)) return raw as MigrationError;
    return { code: 'NETWORK_ERROR', message: 'An unexpected error occurred.' };
  }

  async function runLeg(id: LegId, fn: () => Promise<void>) {
    // Resume, don't repeat: a Retry after a mid-flow failure must not re-run legs that already
    // succeeded — re-importing the repo would 409 and re-creating the account can trip
    // DESTINATION_CONFLICT. Completed legs stay 'done' and are skipped.
    if (legStates[id] === 'done') return;
    legStates[id] = 'active';
    await fn();
    legStates[id] = 'done';
  }

  async function runMigration() {
    failure = null;
    failureDetail = null;
    lossManifest = null;
    try {
      await runLeg('account', () => createDestinationAccount(did, email, inviteCode));
      await runLeg('repo', () => transferRepo(did));
      // acceptBlobLoss stays false on a normal run and each Retry, so a dead blob surfaces the
      // manifest; "Continue without them" flips it true and re-runs so the leg advances anyway.
      await runLeg('blobs', () => transferBlobs(did, acceptBlobLoss));
      await runLeg('preferences', () => transferPreferences(did));

      legStates.verify = 'active';
      const status = await verifyImport(did);
      legStates.verify = 'done';

      onnext(status);
    } catch (raw: unknown) {
      console.error('Migration leg failed:', raw);
      // Mark whichever leg is still 'active' as failed.
      for (const leg of LEGS) {
        if (legStates[leg.id] === 'active') {
          legStates[leg.id] = 'failed';
        }
      }

      // A drain that only partially failed isn't a dead end: render the loss manifest and let the
      // user make an informed choice, rather than the generic single-error box.
      if (isCodedError(raw) && (raw as MigrationError).code === 'BLOB_DRAIN_INCOMPLETE') {
        lossManifest = (raw as Extract<MigrationError, { code: 'BLOB_DRAIN_INCOMPLETE' }>).losses;
      } else {
        failure = describeError(raw);
        failureDetail = describeErrorDetail(raw);
      }
      onerror(toMigrationError(raw));
    }
  }

  function retry() {
    for (const leg of LEGS) {
      if (legStates[leg.id] === 'failed') legStates[leg.id] = 'pending';
    }
    runMigration();
  }

  // Accept the loss manifest: skip the blobs that couldn't be transferred and resume. Re-runs the
  // blobs leg with acceptLoss=true (the orchestrator records the skip and advances; verify then
  // subtracts the accepted loss), then carries on through preferences + verify.
  function continueWithLoss() {
    acceptBlobLoss = true;
    lossManifest = null;
    for (const leg of LEGS) {
      if (legStates[leg.id] === 'failed') legStates[leg.id] = 'pending';
    }
    runMigration();
  }

  runMigration();
</script>

<div class="screen">
  <div class="header">
    <Spinner size={40} label="Migrating" />
    <h1 class="title">Migrating your identity</h1>
    <p class="subtitle">This can take a few minutes. Don't close the app.</p>
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
        {lossManifest.length === 1 ? 'file' : 'files'} couldn't be transferred
      </p>
      <p class="loss-lede">
        These media files couldn't be moved and won't appear on your new account. Posts that use
        them will show a broken image. You can continue without them or try the transfer again.
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
