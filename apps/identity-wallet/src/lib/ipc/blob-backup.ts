import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { UnlockReason } from './identity';

// ── Media backup (user-held blob mirror in iCloud Drive) ─────────────────────
//
// A content-addressed mirror of the account's blobs in the wallet's iCloud Drive
// ubiquity container — the one backup layer that survives the PDS itself failing.
// Content addressing makes it trustless: restored bytes re-hash to the same CID,
// so records never need rewriting. Opt-in (iCloud's free tier is 5 GB shared and
// video accounts get large), with the mirror size always shown. On non-device
// builds (simulator, desktop, the browser harness) the mirror lands in a local
// directory instead, reported as `location: 'local'`.

/** Where the mirror lives. `null` (in {@link BlobBackupStatus}) = no location available. */
export type BackupLocation = 'icloud' | 'local';

/** The Media Backup screen's status readout. */
export type BlobBackupStatus = {
  /** The user's explicit opt-in flag (drives the opportunistic pass on app open). */
  enabled: boolean;
  /** Mirror location, or null when none is available (iOS with iCloud Drive off). */
  location: BackupLocation | null;
  /** Blobs currently recorded in the backup manifest. */
  backedUpCount: number;
  /** Total mirrored bytes — shown before opting in (iCloud free tier is 5 GB shared). */
  backedUpBytes: number;
  /** When the last backup pass completed (RFC 3339), or null if never run. */
  lastBackupAt: string | null;
};

/** One per-blob failure in a backup or restore run — the run continues past it. */
export type BlobFailure = {
  cid: string;
  reason: string;
};

/** Report from one backup sync pass. */
export type BlobBackupRunReport = {
  /** CIDs the PDS listed for the account. */
  listed: number;
  /** Already mirrored (skipped — the pass is incremental). */
  alreadyPresent: number;
  /** Newly fetched, CID-verified, and written this run. */
  fetched: number;
  fetchedBytes: number;
  /** Per-blob failures (fetch errors, CID mismatches). */
  failed: BlobFailure[];
  /** Mirror totals after the run. */
  backedUpCount: number;
  backedUpBytes: number;
};

/** Report from one restore pass. */
export type BlobRestoreReport = {
  /** Entries in the backup manifest. */
  manifestCount: number;
  /** Blobs uploaded back to the PDS this run. */
  uploaded: number;
  /**
   * Evicted iCloud placeholders this run downloaded before it could read them — the
   * "downloaded from iCloud first" count, so a restore that took longer on a
   * mostly-evicted device explains itself.
   */
  downloadedFromIcloud: number;
  /** Per-blob failures (files with no local copy and no placeholder, failed placeholder
   * downloads, corrupt files, upload refusals). */
  failed: BlobFailure[];
};

/**
 * Error returned by the blob-backup commands.
 * Matches `BlobBackupError` in `blob_backup.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * `SESSION_LOCKED` (restore only) is the cue to run the passwordless
 * {@link sovereignLogin} (biometric) and retry.
 */
export type BlobBackupError =
  // No backup location on this device — iCloud Drive is off (or the entitlement is absent).
  | { code: 'BACKUP_UNAVAILABLE' }
  // The identity is locked — run sovereignLogin(did) and retry. `reason` mirrors ensureIdentitySession.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  // The hosting PDS or plc.directory rate-limited the request; `retryAfter` is the server's Retry-After.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  // plc.directory refused the hosting-PDS discovery (e.g. the DID is unknown).
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  // A server-side step failed for a non-connectivity reason; `status` is the HTTP code when
  // the server refused the request, null for a non-HTTP failure; `message` is its own text.
  | { code: 'SERVER_ERROR'; status: number | null; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  // Local file I/O on the mirror failed.
  | { code: 'STORAGE_ERROR'; message: string }
  // The backup manifest is unreadable; it is preserved, never rebuilt over.
  | { code: 'MANIFEST_CORRUPT'; message: string }
  | { code: 'KEYCHAIN_ERROR'; message: string };

/**
 * App-global settings for the iOS background media-backup sweep (distinct from the per-DID
 * opt-in above). App-wide because the sweep is one BGProcessingTask covering every opted-in
 * identity. Matches `BackgroundBackupSettings` in `bg_backup.rs` (camelCase fields).
 */
export type BackgroundBackupSettings = {
  /** Whether iOS may wake the app to run a backup sweep. Off keeps only the app-open pass. */
  backgroundEnabled: boolean;
  /** Only run the background sweep while charging. */
  requireExternalPower: boolean;
  /** Skip the background sweep on a cellular (metered) connection. */
  wifiOnly: boolean;
};

/**
 * Error from `setBackgroundBackupSettings`. Serialized as `{ code: "..." }` by
 * `BackgroundBackupError` in `bg_backup.rs` — codes must match exactly.
 */
export type BackgroundBackupError =
  | { code: 'KEYCHAIN_ERROR'; message: string }
  | { code: 'SERIALIZATION_ERROR'; message: string };

/** The current background-backup settings (defaults: background on, no power/Wi-Fi gate). */
export const getBackgroundBackupSettings = (): Promise<BackgroundBackupSettings> =>
  invoke('get_background_backup_settings');

/**
 * Persist the background-backup settings and (on device) re-apply the schedule: submit or
 * cancel the BGProcessingTask to match. Returns the stored settings. Throws
 * {@link BackgroundBackupError} on a Keychain/encode failure.
 */
export const setBackgroundBackupSettings = (
  settings: BackgroundBackupSettings
): Promise<BackgroundBackupSettings> =>
  invoke('set_background_backup_settings', { settings });

/** The Media Backup screen's status readout: location, opt-in flag, mirror size. */
export const getBlobBackupStatus = (did: string): Promise<BlobBackupStatus> =>
  invoke('get_blob_backup_status', { did });

/** Flip the explicit opt-in flag. Returns the refreshed status. */
export const setBlobBackupEnabled = (did: string, enabled: boolean): Promise<BlobBackupStatus> =>
  invoke('set_blob_backup_enabled', { did, enabled });

/**
 * Run one incremental backup sync pass: list the account's blobs on its PDS, fetch
 * what the mirror lacks, verify each against its CID before writing, record in the
 * manifest. Reads only public sync endpoints, so it needs no session or biometric.
 * Also invoked opportunistically (fire-and-forget) on app open for opted-in identities.
 */
export const runBlobBackup = (did: string): Promise<BlobBackupRunReport> =>
  invoke('run_blob_backup', { did });

/**
 * Restore the mirrored blobs to the identity's CURRENT hosting PDS (`uploadBlob`
 * with each blob's stored MIME type; CIDs recompute identically, records untouched).
 * Files iOS has evicted to iCloud placeholders are downloaded on demand first (counted
 * in {@link BlobRestoreReport.downloadedFromIcloud}), so an evicted mirror restores
 * without the user hand-downloading each file in the Files app.
 *
 * The biometric prompt precedes the IPC invocation: a restore writes many blobs
 * into the account, so cancellation must reach neither Rust nor the network.
 */
export const restoreBlobBackup = async (did: string): Promise<BlobRestoreReport> => {
  await authenticateBiometric('Restore your backed-up media to your server');
  return invoke('restore_blob_backup', { did });
};
