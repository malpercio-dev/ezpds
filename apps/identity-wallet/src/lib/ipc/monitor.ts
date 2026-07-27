import { invoke } from '@tauri-apps/api/core';

// ── PLC Monitoring ──────────────────────────────────────────────────────────

/**
 * An unauthorized PLC operation detected by the monitor.
 * Matches UnauthorizedChange struct in plc_monitor.rs with #[serde(rename_all = "camelCase")].
 */
export interface UnauthorizedChange {
  /** CID of the unauthorized operation. */
  cid: string;
  /** ISO 8601 timestamp when plc.directory accepted the operation. */
  createdAt: string;
  /** did:key URI of the key that signed this operation, if identified. */
  signingKey: string | null;
  /** The raw PLC operation JSON for display in alert detail. */
  operation: unknown;
}

/**
 * Result of checking a single identity's PLC status.
 * Matches IdentityStatus struct in plc_monitor.rs with #[serde(rename_all = "camelCase")].
 */
export interface IdentityStatus {
  did: string;
  checkFailed: boolean;
  unauthorizedChanges: UnauthorizedChange[];
}

/**
 * Check all managed identities for unauthorized PLC operations.
 * Returns a list of IdentityStatus, one per managed DID.
 *
 * This is the foreground check command — called by the frontend when the app
 * becomes visible (visibilitychange event). It supplements the background
 * polling timer (interval defined by MONITOR_INTERVAL_SECS) with immediate checks on app foreground.
 */
export const checkIdentityStatus = (): Promise<IdentityStatus[]> =>
  invoke('check_identity_status');

// ── Monitor history ─────────────────────────────────────────────────────────

/** What started a sweep. Matches SweepTrigger in plc_monitor.rs. */
export type SweepTrigger = 'background' | 'foreground';

/**
 * One completed pass over every managed identity.
 * Matches SweepRecord in plc_monitor.rs with #[serde(rename_all = "camelCase")].
 */
export interface SweepRecord {
  /** ISO 8601 (UTC) — when the pass finished. */
  at: string;
  trigger: SweepTrigger;
  identitiesChecked: number;
  /** Of those, the ones plc.directory did not answer for. */
  identitiesFailed: number;
  /** Unauthorized changes standing at the end of the pass, across all identities. */
  unauthorizedFound: number;
}

/**
 * When the directory last answered for one identity.
 * Matches IdentityLastChecked in plc_monitor.rs.
 */
export interface IdentityLastChecked {
  did: string;
  /** ISO 8601, or null if the directory has never answered for this DID. */
  lastVerifiedAt: string | null;
}

/**
 * The monitor's own record of its work.
 * Matches MonitorHistory in plc_monitor.rs.
 */
export interface MonitorHistory {
  /** Newest first. */
  sweeps: SweepRecord[];
  /** One entry per identity in the most recent sweep. */
  identities: IdentityLastChecked[];
  /** How often the unattended sweep runs, in seconds. */
  intervalSecs: number;
}

/**
 * What the background monitor has been doing — the evidence behind the Protection
 * surface. A read of a local record; it performs no check of its own, so a screen that
 * wants a fresh reading calls `checkIdentityStatus()` as well.
 */
export const getMonitorHistory = (): Promise<MonitorHistory> => invoke('get_monitor_history');
