import { invoke } from '@tauri-apps/api/core';
import type { BackupLocation } from './blob-backup';

// ── Repo backup (user-held CAR snapshot in iCloud Drive) ─────────────────────
//
// A full-CAR snapshot of the account's ATProto repo (its signed commit + MST +
// record blocks — every post, like, follow, profile edit) mirrored into the
// wallet's iCloud Drive ubiquity container, the sibling of the media (blob) backup.
// The repo is otherwise the one account asset held only on the PDS. The CAR is the
// portable, importable artifact (`importRepo`/`transfer_repo` consume exactly these
// bytes), so the snapshot doubles as the account's portable exit.
//
// Fetched over the public, unauthenticated `getRepo` — so, unlike media restore,
// nothing here needs a session or biometric. Every fetched CAR is validated
// client-side (framing + per-block hash + single signed commit bound to this DID +
// an intact MST walk) before it replaces the prior snapshot; a bad fetch is
// rejected as `CAR_INVALID` and the good snapshot is left untouched. The repo is
// public data, so the mirror is plaintext (same posture as the blob mirror).

/** The "Back up your posts" surface's status readout. */
export type RepoBackupStatus = {
  /** The user's explicit opt-in flag (drives the opportunistic pass on app open). */
  enabled: boolean;
  /** Mirror location, or null when none is available (iOS with iCloud Drive off). */
  location: BackupLocation | null;
  /** The backed-up commit's root CID, or null if never backed up. */
  rootCid: string | null;
  /** The backed-up repo revision (TID), or null if never backed up. */
  rev: string | null;
  /** The snapshot size on disk — always shown (iCloud free tier is 5 GB shared; the
   *  import cap is 100 MiB, a documented limit for extreme accounts). */
  sizeBytes: number;
  /** When the last backup pass completed (RFC 3339), or null if never run. */
  lastBackupAt: string | null;
};

/** Report from one repo-backup pass. */
export type RepoBackupRunReport = {
  rootCid: string;
  rev: string;
  sizeBytes: number;
  /** false when the fetched rev matched the stored snapshot and the CAR was not
   *  rewritten (the idempotent no-op re-backup); the timestamp still advances. */
  updated: boolean;
  lastBackupAt: string;
};

/** The validated, re-exported snapshot handed to a caller to import. */
export type RepoExport = {
  rootCid: string;
  rev: string;
  sizeBytes: number;
  lastBackupAt: string | null;
  /** The full CARv1 snapshot, base64 (standard alphabet) encoded. */
  carBase64: string;
};

/**
 * Error returned by the repo-backup commands.
 * Matches `RepoBackupError` in `repo_backup.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * There is deliberately **no `SESSION_LOCKED`**: backup reads a public endpoint and
 * export reads local disk, so neither path needs a full-access session.
 */
export type RepoBackupError =
  // No backup location on this device — iCloud Drive is off (or the entitlement is absent).
  | { code: 'BACKUP_UNAVAILABLE' }
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
  // A fetched (or stored) CAR failed validation; the prior good snapshot is left intact.
  | { code: 'CAR_INVALID'; message: string }
  | { code: 'KEYCHAIN_ERROR'; message: string };

/** The backup surface's status readout: location, opt-in flag, snapshot size + rev. */
export const getRepoBackupStatus = (did: string): Promise<RepoBackupStatus> =>
  invoke('get_repo_backup_status', { did });

/** Flip the explicit opt-in flag. Returns the refreshed status. */
export const setRepoBackupEnabled = (did: string, enabled: boolean): Promise<RepoBackupStatus> =>
  invoke('set_repo_backup_enabled', { did, enabled });

/**
 * Run one backup pass: discover the identity's hosting PDS, fetch the full repo CAR
 * over public `getRepo`, validate it (framing + per-block hash + single signed commit
 * bound to this DID + an intact MST walk), and atomically replace the snapshot. Reads
 * only a public endpoint, so it needs no session or biometric. Also invoked
 * opportunistically (fire-and-forget) on app open for opted-in identities.
 */
export const runRepoBackup = (did: string): Promise<RepoBackupRunReport> =>
  invoke('run_repo_backup', { did });

/**
 * Read + re-validate the stored snapshot and return its bytes (base64) + metadata for
 * a caller to import. Reads local disk only — no session, no network. (A repo import
 * requires a *deactivated* account, so there is no "push my repo back to my live PDS"
 * button; a restore flows through the existing import/migration machinery.)
 */
export const exportRepoBackup = (did: string): Promise<RepoExport> =>
  invoke('export_repo_backup', { did });
