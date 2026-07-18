import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';

// ── Share-recovery ("Recover existing identity") types ─────────────────────
//
// The consuming inverse of the create-flow share ceremony: two shares of the
// 2-of-3 split reconstruct the recovery seed, whose derived key re-anchors the
// identity on this device. Distinct from `recovery.ts`, which is the PLC
// unauthorized-change override flow.

/** Metadata of one collected share envelope (never the share material itself). */
export interface CollectedShare {
  setId: number;
  index: number;
}

/** Result of starting a recovery ceremony for a handle or did:plc. */
export interface RecoveryTarget {
  did: string;
  handle: string | null;
  /** Whether Share 1 auto-loaded from the iCloud-synced Keychain slot. */
  share1Loaded: boolean;
  collected: CollectedShare[];
}

/** Escrow release state: the delay window is open, or Share 2 was collected. */
export interface EscrowReleaseStatus {
  status: 'pending' | 'released';
  /** Server timestamp after which the share becomes collectable (pending only). */
  availableAt: string | null;
  /** The collected Share 2's metadata (released only). */
  share: CollectedShare | null;
}

/** Successful reconstruction, verified against plc.directory before anything signs. */
export interface RecoveredIdentity {
  did: string;
  handle: string | null;
  recoveryKeyId: string;
  rotationKeys: string[];
}

/** Result of the re-anchor op (fresh device key at rotationKeys[0]). */
export interface RecoveryAnchor {
  did: string;
  opCid: string | null;
  alreadyAnchored: boolean;
}

/** The rotation epilogue's outcome: the NEW Share 3 for the backup walkthrough. */
export interface EpilogueResult {
  share3: string;
  share3Words: string;
  escrowDeposited: boolean;
  escrowSkipped: boolean;
}

/** A pending (interrupted) rotation epilogue found at launch. */
export interface PendingEpilogue {
  did: string;
  opSubmitted: boolean;
  escrowDeposited: boolean;
  escrowSkipped: boolean;
  share1Written: boolean;
}

/**
 * Error returned by the share-recovery commands.
 *
 * The share-validation failures are deliberately distinct so the screens can say
 * "this share is corrupted" (SHARE_CHECKSUM) vs "these shares are from different
 * backups" (SHARE_SET_MISMATCH) vs "these shares don't match this identity"
 * (SHARES_DO_NOT_MATCH_IDENTITY) — each before anything is signed.
 */
export type ShareRecoveryError =
  | { code: 'SHARE_FORMAT'; message: string }
  | { code: 'SHARE_CHECKSUM' }
  | { code: 'SHARE_VERSION' }
  | { code: 'SHARE_SET_MISMATCH'; expectedSetId: number; gotSetId: number }
  | { code: 'DUPLICATE_SHARE'; index: number }
  | { code: 'SHARES_INCOMPLETE' }
  | { code: 'SHARES_DO_NOT_MATCH_IDENTITY' }
  | { code: 'NO_RECOVERY_SESSION' }
  | { code: 'UNSUPPORTED_IDENTITY' }
  | { code: 'HANDLE_NOT_FOUND' }
  | { code: 'DID_NOT_FOUND' }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'RELEASE_UNAUTHORIZED' }
  | { code: 'ESCROW_DEPOSIT_FAILED'; message: string }
  | { code: 'SESSION_FAILED'; message: string }
  | { code: 'KEYCHAIN_ERROR'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'NO_PENDING_EPILOGUE' }
  | { code: 'EPILOGUE_CORRUPT'; message: string }
  | { code: 'INVALID_RESPONSE'; message: string };

// ── IPC wrappers ───────────────────────────────────────────────────────────

/**
 * Begin a recovery ceremony for a handle or did:plc. Resolves the identity from
 * plc.directory (the authoritative rotationKeys source) and auto-loads Share 1
 * from the iCloud Keychain slot when present.
 */
export const startShareRecovery = (identifier: string): Promise<RecoveryTarget> =>
  invoke('start_share_recovery', { identifier });

/** Add a manually entered share — base32 envelope or the Share 3 word phrase. */
export const addRecoveryShare = (share: string): Promise<CollectedShare> =>
  invoke('add_recovery_share', { share });

/** Drop a collected share (user correction). Returns the remaining collection. */
export const removeRecoveryShare = (index: number): Promise<CollectedShare[]> =>
  invoke('remove_recovery_share', { index });

/**
 * Ask the account's PDS to email an escrow-release code. Always succeeds for any
 * identifier (the server never reveals whether an account exists).
 */
export const initiateEscrowRelease = (): Promise<void> => invoke('initiate_escrow_release');

/**
 * Open (with the emailed code) or poll (without it) the escrow release. A pending
 * result carries the server's availableAt; a released result collects Share 2.
 */
export const requestEscrowRelease = (otp?: string): Promise<EscrowReleaseStatus> =>
  invoke('request_escrow_release', { otp });

/**
 * Combine the two collected shares and verify the derived recovery key against
 * the DID's authoritative current rotationKeys. Nothing signs before this passes.
 */
export const verifyRecoveryShares = (): Promise<RecoveredIdentity> =>
  invoke('verify_recovery_shares');

/**
 * Re-anchor the identity: a fresh device key on this device, installed at
 * rotationKeys[0] by a recovery-key-signed PLC op. Biometric-gated — the gate
 * precedes the IPC call so cancellation signs and submits nothing.
 */
export const recoverIdentity = async (): Promise<RecoveryAnchor> => {
  await authenticateBiometric('Recover this identity on this device');
  return invoke('recover_identity');
};

/**
 * Run (or resume) the mandatory rotation epilogue: new share set, new recovery
 * key swapped into the doc, Share 2 re-escrowed, Share 1 rewritten. Idempotent
 * and resumable — safe to re-invoke after any failure or an app restart.
 */
export const runRecoveryEpilogue = (skipEscrow = false): Promise<EpilogueResult> =>
  invoke('run_recovery_epilogue', { skipEscrow });

/** Launch-time resume hook: a pending (interrupted) rotation epilogue, if any. */
export const getPendingRecoveryEpilogue = (): Promise<PendingEpilogue | null> =>
  invoke('get_pending_recovery_epilogue');

/**
 * Teardown gate: verifies the NEW Share 1 is durably stored, then destroys the
 * epilogue record (the new seed material's last transient home). Idempotent.
 */
export const confirmRecoveryBackup = (): Promise<void> => invoke('confirm_recovery_backup');
