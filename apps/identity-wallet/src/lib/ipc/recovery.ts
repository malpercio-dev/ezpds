import { invoke } from '@tauri-apps/api/core';
import type { ClaimResult, OpDiff } from './claim';

// ── recovery_override ─────────────────────────────────────────────────────────

/**
 * Error returned by recovery override commands.
 * Matches RecoveryError enum in recovery.rs with #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")].
 */
export type RecoveryError =
  | { code: 'RECOVERY_WINDOW_EXPIRED' }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'UNAUTHORIZED_CHANGE_NOT_FOUND' };

/**
 * Signed recovery operation ready for review and submission.
 * Matches SignedRecoveryOp struct in recovery.rs with #[serde(rename_all = "camelCase")].
 */
export interface SignedRecoveryOp {
  /** Human-readable diff of what the recovery operation changes. */
  diff: OpDiff;
  /** The signed PLC operation JSON, ready to POST to plc.directory. */
  signedOp: Record<string, unknown>;
}

/**
 * Build a recovery override operation for an unauthorized PLC change.
 *
 * Fetches the audit log, identifies the fork point, builds a counter-operation
 * that restores the pre-unauthorized state, and signs it with the device key.
 *
 * The built operation is stored in RecoveryState for subsequent submission
 * via submitRecoveryOverride().
 */
export const buildRecoveryOverride = (did: string, operationCid: string): Promise<SignedRecoveryOp> =>
  invoke('build_recovery_override_cmd', { did, operationCid });

/**
 * Submit the pending recovery override operation to plc.directory.
 *
 * Must be called after buildRecoveryOverride() — submits the stored signed
 * operation, updates the cached PLC audit log, and returns the updated DID document.
 */
export const submitRecoveryOverride = (did: string): Promise<ClaimResult> =>
  invoke('submit_recovery_override_cmd', { did });
