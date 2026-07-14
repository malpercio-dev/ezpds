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
