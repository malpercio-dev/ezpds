import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { OpDiff } from './claim';
import type { UnlockReason } from './identity';

// ── Old-model re-key migration (MM-411) ───────────────────────────────────────
//
// Moves a pre-existing account off the voided server-generated split and onto the
// client-generated recovery model: generate a new seed, insert its recovery key at
// rotationKeys[1] via a device-key-signed PLC op (device stays [0], PDS shifts to [2]),
// escrow the new Share 2, rewrite the local Share 1, and walk the user through saving the
// new Share 3. Additive and resumable — see `rekey.rs`.

/**
 * Error returned by the re-key flow. Matches `RekeyError` in `rekey.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * `SESSION_LOCKED` is the cue to run the passwordless {@link sovereignLogin} (biometric) and
 * retry, exactly as in the rotation/migration flows.
 */
export type RekeyError =
  // The DID is a did:web identity — the recovery-key model does not apply.
  | { code: 'NOT_DID_PLC' }
  // The identity already carries a recovery key (new-model) — nothing to re-key.
  | { code: 'ALREADY_REKEYED' }
  // The wallet's device key is not rotationKeys[0], so it cannot additively re-key.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The identity is locked — run sovereignLogin(did) and retry.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // The strict additive pre-sign guard rejected the op.
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SHARE_GENERATION_FAILED'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_SUBMISSION_FAILED'; message: string }
  // plc.directory answered a read with an HTTP failure (outage/verdict, not connectivity).
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  // A server-side step failed for a non-connectivity reason (session refresh verdict,
  // unsupported host, malformed response, or session storage). Details in `message`.
  | { code: 'SERVER_ERROR'; message: string }
  | { code: 'ESCROW_FAILED'; status: number; message: string }
  | { code: 'SHARE_STORAGE_FAILED'; message: string }
  // Confirm was called before Share 1 reached its durable slot.
  | { code: 'SHARE_NOT_STORED' }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string };

/**
 * Preview of a re-key, driving the review screen. Matches `RekeyPreview` in `rekey.rs`
 * (`#[serde(rename_all = "camelCase")]`).
 */
export interface RekeyPreview {
  /** The additive key diff — `addedKeys: [recovery]`, `removedKeys: []` (nothing is lost). */
  diff: OpDiff;
  /** The recovery `did:key` that will be inserted at rotationKeys[1]. */
  recoveryKeyId: string;
}

/**
 * Result of a completed re-key. Matches `RekeyResult` in `rekey.rs`
 * (`#[serde(rename_all = "camelCase")]`).
 */
export interface RekeyResult {
  /** The refreshed DID document (PLC data shape) so the home card updates immediately. */
  updatedDidDoc: Record<string, unknown>;
  /** The new Share 3 envelope (base32/QR form) for the user to save. */
  share3: string;
  /** The new Share 3 rendered as the BIP-39-style word phrase. */
  share3Words: string;
}

/**
 * Build the re-key preview: generate + stage the new recovery share set, prove the account is
 * an eligible old-model did:plc identity, and return the additive diff for review.
 *
 * Idempotent — the staged set is reused across retries. Signs nothing (submit does that).
 * Rejects with `SESSION_LOCKED` only downstream in {@link submitRekey}; build touches only the
 * public audit log.
 */
export const buildRekey = (did: string): Promise<RekeyPreview> => invoke('build_rekey_cmd', { did });

/**
 * Run the re-key: post the additive rotation op (device-key-signed) to plc.directory, escrow
 * the new Share 2, overwrite the durable Share 1, and refresh the cache. Returns the new Share 3.
 *
 * The biometric prompt precedes the IPC invocation (the owner gate on an identity operation);
 * cancellation never reaches the network. Idempotent/resumable: a lost response or interrupted
 * run is healed by calling this again — every step converges on the same terminal state, and no
 * intermediate state drops recovery capability below the pre-re-key baseline.
 *
 * On `SESSION_LOCKED`, run {@link sovereignLogin} and retry.
 */
export const submitRekey = async (did: string): Promise<RekeyResult> => {
  await authenticateBiometric('Confirm your recovery-key upgrade');
  return invoke('submit_rekey_cmd', { did });
};

/**
 * Confirm the user has saved the new Share 3 and tear down the staging slot. Idempotent; called
 * when the Shamir backup screen's confirmation completes. Rejects with `SHARE_NOT_STORED` if
 * Share 1 is not durably present (the staging record must survive until then).
 */
export const confirmRekey = (did: string): Promise<void> => invoke('confirm_rekey_cmd', { did });

/**
 * Whether a re-key is mid-flight for this DID (a per-DID staging slot exists). The home surface
 * treats this as "prompt the upgrade" even when the identity already reads as new-model — it
 * resurfaces an interrupted re-key whose PLC op landed but whose escrow/Share 1 did not finish.
 */
export const rekeyInProgress = (did: string): Promise<boolean> =>
  invoke('rekey_in_progress_cmd', { did });
