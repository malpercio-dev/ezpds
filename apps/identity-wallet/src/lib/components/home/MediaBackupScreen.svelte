<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import { formatTimestamp } from '$lib/datetime';
  import {
    getBlobBackupStatus,
    setBlobBackupEnabled,
    runBlobBackup,
    restoreBlobBackup,
    getRepoBackupStatus,
    setRepoBackupEnabled,
    runRepoBackup,
    ensureIdentitySession,
    sovereignLogin,
    isCodedError,
    type BlobBackupStatus,
    type BlobBackupRunReport,
    type BlobRestoreReport,
    type BlobBackupError,
    type RepoBackupStatus,
    type RepoBackupRunReport,
    type RepoBackupError,
  } from '$lib/ipc';

  let {
    did,
    onback,
  }: {
    did: string;
    onback: () => void;
  } = $props();

  // A user-held mirror of this account's media in the wallet's iCloud Drive folder —
  // the one copy that survives the server itself failing. Content-addressed, so a
  // restore is byte-exact: posts keep pointing at the same media without rewriting.

  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let status = $state<BlobBackupStatus | null>(null);

  let toggling = $state(false);
  let backingUp = $state(false);
  let backupReport = $state<BlobBackupRunReport | null>(null);
  let backupError = $state<string | null>(null);

  let confirmingRestore = $state(false);
  let restoring = $state(false);
  let restoreReport = $state<BlobRestoreReport | null>(null);
  let restoreError = $state<string | null>(null);

  // "Back up your posts" — the user-held CAR snapshot of this account's repo (its signed
  // commit + every post/like/follow), the sibling of the media mirror. Public read, so no
  // session or biometric; the same iCloud location as media.
  let repoStatus = $state<RepoBackupStatus | null>(null);
  let repoTogglingOrBackingUp = $state(false);
  let repoReport = $state<RepoBackupRunReport | null>(null);
  let repoError = $state<string | null>(null);

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function shortCid(cid: string): string {
    return cid.length > 16 ? `${cid.slice(0, 8)}…${cid.slice(-6)}` : cid;
  }

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as BlobBackupError;
    switch (err.code) {
      case 'BACKUP_UNAVAILABLE':
        return 'iCloud Drive isn’t available. Turn it on in Settings → your name → iCloud, then try again.';
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'RATE_LIMITED':
        return formatRateLimitMessage(err.retryAfter);
      case 'IDENTITY_NOT_FOUND':
        return 'This identity isn’t registered in the wallet.';
      case 'PLC_DIRECTORY_ERROR':
        return 'Couldn’t look up where this identity is hosted. Try again in a moment.';
      case 'SERVER_ERROR':
        return formatServerErrorMessage(err.message);
      case 'STORAGE_ERROR':
        return 'Couldn’t write to the backup folder. Check your iCloud storage and try again.';
      case 'MANIFEST_CORRUPT':
        return 'The backup’s index file is unreadable. The backed-up media is untouched — contact support before changing anything.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  function messageForRepo(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as RepoBackupError;
    switch (err.code) {
      case 'BACKUP_UNAVAILABLE':
        return 'iCloud Drive isn’t available. Turn it on in Settings → your name → iCloud, then try again.';
      case 'RATE_LIMITED':
        return formatRateLimitMessage(err.retryAfter);
      case 'IDENTITY_NOT_FOUND':
        return 'This identity isn’t registered in the wallet.';
      case 'PLC_DIRECTORY_ERROR':
        return 'Couldn’t look up where this identity is hosted. Try again in a moment.';
      case 'SERVER_ERROR':
        return formatServerErrorMessage(err.message);
      case 'STORAGE_ERROR':
        return 'Couldn’t write to the backup folder. Check your iCloud storage and try again.';
      case 'MANIFEST_CORRUPT':
        return 'The backup’s index file is unreadable. The backed-up snapshot is untouched — contact support before changing anything.';
      case 'CAR_INVALID':
        return 'The server sent a snapshot that failed our integrity check, so it wasn’t saved. Your last good backup is untouched. Try again in a moment.';
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  async function load() {
    loading = true;
    loadError = null;
    // The repo snapshot shares the same iCloud location; load both so the screen shows the
    // whole self-custody picture. A repo-status failure is non-fatal — the media section
    // still renders, and the posts section surfaces its own error.
    try {
      const [blob, repo] = await Promise.allSettled([
        getBlobBackupStatus(did),
        getRepoBackupStatus(did),
      ]);
      if (blob.status === 'fulfilled') {
        status = blob.value;
      } else {
        throw blob.reason;
      }
      if (repo.status === 'fulfilled') {
        repoStatus = repo.value;
      } else {
        console.error('[MediaBackupScreen] failed to load repo backup status:', repo.reason);
        repoError = messageForRepo(repo.reason);
      }
    } catch (e) {
      console.error('[MediaBackupScreen] failed to load backup status:', e);
      loadError = messageFor(e);
    } finally {
      loading = false;
    }
  }

  async function enableAndBackUpRepo() {
    if (repoTogglingOrBackingUp) return;
    repoTogglingOrBackingUp = true;
    repoError = null;
    repoReport = null;
    try {
      repoStatus = await setRepoBackupEnabled(did, true);
      // Opting in captures the first snapshot immediately — an enabled-but-empty backup
      // protects nothing.
      repoReport = await runRepoBackup(did);
      repoStatus = await getRepoBackupStatus(did);
    } catch (e) {
      console.error('[MediaBackupScreen] repo backup failed:', e);
      repoError = messageForRepo(e);
    } finally {
      repoTogglingOrBackingUp = false;
    }
  }

  async function backUpRepo() {
    if (repoTogglingOrBackingUp) return;
    repoTogglingOrBackingUp = true;
    repoError = null;
    repoReport = null;
    try {
      repoReport = await runRepoBackup(did);
      repoStatus = await getRepoBackupStatus(did);
    } catch (e) {
      console.error('[MediaBackupScreen] repo backup pass failed:', e);
      repoError = messageForRepo(e);
    } finally {
      repoTogglingOrBackingUp = false;
    }
  }

  async function disableRepo() {
    if (repoTogglingOrBackingUp) return;
    repoTogglingOrBackingUp = true;
    try {
      repoStatus = await setRepoBackupEnabled(did, false);
      repoReport = null;
    } catch (e) {
      console.error('[MediaBackupScreen] disabling repo backup failed:', e);
      repoError = messageForRepo(e);
    } finally {
      repoTogglingOrBackingUp = false;
    }
  }

  async function runBackup() {
    if (backingUp) return;
    backingUp = true;
    backupError = null;
    backupReport = null;
    restoreReport = null;
    try {
      backupReport = await runBlobBackup(did);
      status = await getBlobBackupStatus(did);
    } catch (e) {
      console.error('[MediaBackupScreen] backup pass failed:', e);
      backupError = messageFor(e);
    } finally {
      backingUp = false;
    }
  }

  async function enableAndBackUp() {
    if (toggling) return;
    toggling = true;
    backupError = null;
    try {
      status = await setBlobBackupEnabled(did, true);
    } catch (e) {
      console.error('[MediaBackupScreen] enabling backup failed:', e);
      backupError = messageFor(e);
      toggling = false;
      return;
    }
    toggling = false;
    // Opting in runs the first pass immediately — an enabled-but-empty mirror
    // protects nothing.
    await runBackup();
  }

  async function disable() {
    if (toggling) return;
    toggling = true;
    try {
      status = await setBlobBackupEnabled(did, false);
      backupReport = null;
      restoreReport = null;
    } catch (e) {
      console.error('[MediaBackupScreen] disabling backup failed:', e);
      backupError = messageFor(e);
    } finally {
      toggling = false;
    }
  }

  async function doRestore() {
    if (restoring) return;
    restoring = true;
    restoreError = null;
    restoreReport = null;
    backupReport = null;
    try {
      // Pre-flight the session with no prompt. If it's locked, unlock it passwordlessly
      // (biometric) BEFORE the restore's own biometric gate — avoids a wasted prompt.
      try {
        await ensureIdentitySession(did);
      } catch (e) {
        if (isCodedError(e) && e.code === 'NEEDS_UNLOCK') {
          await sovereignLogin(did);
        } else {
          throw e;
        }
      }

      let report: BlobRestoreReport;
      try {
        report = await restoreBlobBackup(did);
      } catch (e) {
        // A live token can lapse between the pre-flight and the command. Unlock once
        // (passwordless biometric sovereign login) and retry.
        if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
          await sovereignLogin(did);
          report = await restoreBlobBackup(did);
        } else {
          throw e;
        }
      }
      restoreReport = report;
      confirmingRestore = false;
    } catch (e) {
      console.error('[MediaBackupScreen] restore failed:', e);
      restoreError = messageFor(e);
    } finally {
      restoring = false;
    }
  }

  onMount(load);
</script>

<div class="screen">
  <ScreenHeader title="Media backup" {onback} backLabel="Back to identity" />

  <p class="lede">
    Keep your own copy of this account’s photos and videos in iCloud Drive. If your
    server ever loses them, you can put them back — byte for byte, with every post
    still pointing at the right media.
  </p>

  {#if loading}
    <div class="loading">
      {#each [0, 1] as i (i)}
        <SkeletonCard />
      {/each}
    </div>
  {:else if loadError}
    <div class="notice" role="alert">
      <p class="notice-text">{loadError}</p>
      <Button variant="secondary" onclick={load}>Try again</Button>
    </div>
  {:else if status && status.location === null}
    <div class="notice notice--muted">
      <p class="notice-text notice-text--ink">
        iCloud Drive isn’t available on this device. Turn it on in Settings → your name →
        iCloud → iCloud Drive, then come back here.
      </p>
      <Button variant="secondary" onclick={load}>Check again</Button>
    </div>
  {:else if status}
    <div class="status-card">
      <div class="stat-row">
        <span class="stat">
          <span class="stat-n">{status.backedUpCount}</span>
          <span class="stat-l">items backed up</span>
        </span>
        <span class="stat">
          <span class="stat-n">{formatBytes(status.backedUpBytes)}</span>
          <span class="stat-l">of iCloud storage</span>
        </span>
      </div>
      <p class="status-meta">
        {#if status.location === 'icloud'}
          Stored in your iCloud Drive — visible in the Files app under “Obsign”.
        {:else}
          Stored in a local folder (development build — no iCloud on this platform).
        {/if}
        {#if status.lastBackupAt}
          Last backed up {formatTimestamp(status.lastBackupAt)}.
        {/if}
      </p>
    </div>

    {#if !status.enabled}
      <p class="explain">
        Backups are optional and count against your iCloud storage (the free plan is 5 GB,
        shared with everything else). Accounts with lots of video can be large. Turning
        this on backs up your media now and keeps it topped up each time you open the app.
      </p>
      {#if backupError}<p class="error" role="alert">{backupError}</p>{/if}
      <Button onclick={enableAndBackUp} disabled={toggling || backingUp}>
        {#if toggling || backingUp}<Spinner size={16} /> Backing up…{:else}Turn on media backup{/if}
      </Button>
    {:else}
      {#if backupReport}
        <div class="report" role="status">
          <p class="report-title">
            {#if backupReport.fetched > 0}
              Backed up {backupReport.fetched} new
              {backupReport.fetched === 1 ? 'item' : 'items'}
              ({formatBytes(backupReport.fetchedBytes)}).
            {:else}
              Everything is already backed up.
            {/if}
          </p>
          <p class="report-sub">
            {backupReport.backedUpCount} of {backupReport.listed} items mirrored.
          </p>
          {#if backupReport.failed.length > 0}
            <p class="report-fail-title" role="alert">
              {backupReport.failed.length}
              {backupReport.failed.length === 1 ? 'item' : 'items'} couldn’t be backed up:
            </p>
            <ul class="fail-list">
              {#each backupReport.failed as f (f.cid)}
                <li><code>{shortCid(f.cid)}</code> — {f.reason}</li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}
      {#if restoreReport}
        <div class="report" role="status">
          <p class="report-title">
            Restored {restoreReport.uploaded} of {restoreReport.manifestCount}
            {restoreReport.manifestCount === 1 ? 'item' : 'items'} to your server.
          </p>
          {#if restoreReport.downloadedFromIcloud > 0}
            <p class="report-sub">
              Downloaded {restoreReport.downloadedFromIcloud}
              {restoreReport.downloadedFromIcloud === 1 ? 'file' : 'files'} from iCloud first.
            </p>
          {/if}
          {#if restoreReport.failed.length > 0}
            <p class="report-fail-title" role="alert">
              {restoreReport.failed.length}
              {restoreReport.failed.length === 1 ? 'item' : 'items'} couldn’t be restored:
            </p>
            <ul class="fail-list">
              {#each restoreReport.failed as f (f.cid)}
                <li><code>{shortCid(f.cid)}</code> — {f.reason}</li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}
      {#if backupError}<p class="error" role="alert">{backupError}</p>{/if}

      <Button onclick={runBackup} disabled={backingUp || restoring}>
        {#if backingUp}<Spinner size={16} /> Backing up…{:else}Back up now{/if}
      </Button>

      {#if !confirmingRestore}
        <Button
          variant="secondary"
          onclick={() => {
            confirmingRestore = true;
            restoreError = null;
          }}
          disabled={backingUp || restoring || status.backedUpCount === 0}
        >
          Restore to server…
        </Button>
      {:else}
        <div class="confirm">
          <p class="confirm-text">
            This uploads your {status.backedUpCount} backed-up
            {status.backedUpCount === 1 ? 'item' : 'items'} to the server this identity
            lives on now. Media the server already has is simply kept — nothing is
            overwritten or deleted.
          </p>
          {#if restoreError}<p class="error" role="alert">{restoreError}</p>{/if}
          <div class="confirm-actions">
            <Button onclick={doRestore} disabled={restoring}>
              {#if restoring}<Spinner size={16} /> Restoring…{:else}Restore with biometrics{/if}
            </Button>
            <Button
              variant="secondary"
              onclick={() => {
                confirmingRestore = false;
                restoreError = null;
              }}
              disabled={restoring}
            >
              Cancel
            </Button>
          </div>
        </div>
      {/if}

      <button class="disable-link" onclick={disable} disabled={toggling || backingUp || restoring}>
        Turn off media backup
      </button>
      <p class="disable-note">
        Turning it off stops future backups. Media already in iCloud Drive stays there
        until you delete it in the Files app.
      </p>
    {/if}

    <!-- Back up your posts — the user-held CAR snapshot of the account's repo. -->
    <div class="section-divider" role="separator"></div>
    <h2 class="section-title">Back up your posts</h2>
    <p class="lede">
      Keep your own copy of your timeline — every post, like, follow, and profile edit — in
      iCloud Drive. It’s the one part of your account held only on your server, so this is the
      copy that survives your server itself losing it.
    </p>

    {#if repoStatus}
      <div class="status-card">
        <div class="stat-row">
          <span class="stat">
            <span class="stat-n">{repoStatus.rev ? formatBytes(repoStatus.sizeBytes) : '—'}</span>
            <span class="stat-l">snapshot size</span>
          </span>
          <span class="stat">
            <span class="stat-n">{repoStatus.rev ? 'Backed up' : 'Not yet'}</span>
            <span class="stat-l">of your posts</span>
          </span>
        </div>
        <p class="status-meta">
          {#if repoStatus.location === 'icloud'}
            Stored in your iCloud Drive — visible in the Files app under “Obsign”.
          {:else}
            Stored in a local folder (development build — no iCloud on this platform).
          {/if}
          {#if repoStatus.lastBackupAt}
            Last backed up {formatTimestamp(repoStatus.lastBackupAt)}.
          {/if}
        </p>
      </div>

      {#if repoReport}
        <div class="report" role="status">
          <p class="report-title">
            {#if repoReport.updated}
              Backed up your posts ({formatBytes(repoReport.sizeBytes)}).
            {:else}
              Your posts are already backed up.
            {/if}
          </p>
        </div>
      {/if}
      {#if repoError}<p class="error" role="alert">{repoError}</p>{/if}

      {#if !repoStatus.enabled}
        <p class="explain">
          This backs up your posts now and keeps the copy current each time you open the app.
          It’s small — just text and structure, not your media (backed up above) — so it barely
          touches your iCloud storage.
        </p>
        <Button onclick={enableAndBackUpRepo} disabled={repoTogglingOrBackingUp}>
          {#if repoTogglingOrBackingUp}<Spinner size={16} /> Backing up…{:else}Turn on post backup{/if}
        </Button>
      {:else}
        <Button onclick={backUpRepo} disabled={repoTogglingOrBackingUp}>
          {#if repoTogglingOrBackingUp}<Spinner size={16} /> Backing up…{:else}Back up posts now{/if}
        </Button>
        <button
          class="disable-link"
          onclick={disableRepo}
          disabled={repoTogglingOrBackingUp}
        >
          Turn off post backup
        </button>
        <p class="disable-note">
          Turning it off stops future backups. The snapshot already in iCloud Drive stays there
          until you delete it in the Files app.
        </p>
      {/if}
    {:else if repoError}
      <p class="error" role="alert">{repoError}</p>
    {/if}
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }

  .lede {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .section-divider {
    height: 1px;
    background: var(--color-line);
    margin: var(--space-sm) 0;
  }
  .section-title {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }

  .loading {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .status-card {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .stat-row {
    display: flex;
    gap: var(--space-lg);
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
  }
  .stat-n {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    font-variant-numeric: tabular-nums;
  }
  .stat-l {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .status-meta {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .explain {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .report {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    background: var(--color-safe-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .report-title {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .report-sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }
  .report-fail-title {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
    margin: var(--space-xs) 0 0;
  }
  .fail-list {
    margin: 0;
    padding-left: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .fail-list li {
    font-size: var(--text-label);
    color: var(--color-ink);
    line-height: 1.45;
    overflow-wrap: anywhere;
  }
  .fail-list code {
    font-family: var(--font-mono);
  }

  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    line-height: 1.45;
    margin: 0;
  }

  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .confirm-text {
    font-size: var(--text-label);
    color: var(--color-ink);
    line-height: 1.5;
    margin: 0;
  }
  .confirm-actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .disable-link {
    background: none;
    border: none;
    padding: var(--space-sm) var(--space-xs);
    min-height: 44px;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
    cursor: pointer;
    align-self: flex-start;
  }
  .disable-link:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .disable-note {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.45;
    margin: calc(-1 * var(--space-sm)) 0 0;
  }

  .notice {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    background: var(--color-critical-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    text-align: center;
  }
  .notice--muted {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
  }
  .notice-text {
    font-size: var(--text-body);
    color: var(--color-critical);
    margin: 0;
  }
  .notice-text--ink {
    color: var(--color-ink);
  }
</style>
