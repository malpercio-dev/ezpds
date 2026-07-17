import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { ClaimResult, OpDiff } from './claim';
import type { UnlockReason } from './identity';

// ── Repo signing-key rotation (sovereign key-swap PLC op) ─────────────────────

/**
 * Error returned by the sovereign repo signing-key rotation flow.
 * Matches `RotationError` in `rotate_repo_key.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * `SESSION_LOCKED` is the cue to run the passwordless {@link sovereignLogin} (biometric) and retry:
 * the identity's full-access session could not be restored/refreshed without a fresh device-key proof.
 */
export type RotationError =
  // The wallet holds no authorized rotation key for this DID, so it cannot self-sign.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The identity is locked — run sovereignLogin(did) and retry. `reason` mirrors ensureIdentitySession.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  // The hosting PDS or plc.directory rate-limited the request; `retryAfter` is the server's Retry-After.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // The strict pre-sign guard rejected the op (something other than the repo key would change).
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  // The hosting PDS rejected a rotation call (begin or complete).
  | { code: 'ROTATION_FAILED'; status: number; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  // submit was called with no built rotation op pending for this DID.
  | { code: 'NO_PENDING_ROTATION' };

/**
 * Signed rotation operation ready for review and submission.
 * Matches `SignedRotationOp` in rotate_repo_key.rs with #[serde(rename_all = "camelCase")].
 */
export interface SignedRotationOp {
  /** Human-readable diff of what the rotation changes (the key swap). */
  diff: OpDiff;
  /** The signed PLC operation JSON, submitted via the hosting PDS. */
  signedOp: Record<string, unknown>;
}

/**
 * Build the repo signing-key rotation operation for review.
 *
 * Asks the hosting PDS to stage a FRESH replacement signing key, composes the rotation
 * op (device key stays `rotationKeys[0]`, the staged key takes the PDS slot and the
 * `atproto` verification method; services and handles untouched), runs the strict
 * pre-sign guard, and signs with the per-DID device key. The built operation is stored
 * in RotationState for subsequent submission via {@link submitRepoKeyRotation}.
 *
 * If the identity's session is locked, rejects with `SESSION_LOCKED` — run
 * {@link sovereignLogin} and retry.
 */
export const buildRepoKeyRotation = (did: string): Promise<SignedRotationOp> =>
  invoke('build_repo_key_rotation_cmd', { did });

/**
 * Hand the pending rotation op to the hosting PDS, which submits it to plc.directory
 * and atomically cuts its commit signer over to the new key — the wallet never posts
 * this op to plc.directory itself, so no commit is ever signed by a key absent from
 * the DID document. Refreshes the cached PLC log + DID document on success.
 *
 * The biometric prompt precedes the IPC invocation (the deliberate owner gate on an
 * irreversible identity operation); cancellation therefore never reaches the network.
 * The PDS side is retry-safe: a lost response is healed by calling this again.
 */
export const submitRepoKeyRotation = async (did: string): Promise<ClaimResult> => {
  await authenticateBiometric('Confirm your signing-key rotation');
  return invoke('submit_repo_key_rotation_cmd', { did });
};
