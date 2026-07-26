import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { OpDiff } from './claim';

// ── Self-held Shamir kit (MM-456) ─────────────────────────────────────────────
//
// The escrow-less recovery-key install for an identity the wallet holds the root key for but
// that lives on a PDS which is not Custos. Same ceremony as the re-key — new seed, 2-of-3
// split, recovery key inserted right after the device key via a device-key-signed PLC op —
// minus the escrow deposit, which a non-Custos host has no route for. Share 1 goes to the
// iCloud Keychain; Shares 2 AND 3 go to the user, who then holds two of the three.
//
// Talks to plc.directory and nothing else. That is why this surface has no SESSION_LOCKED:
// there is no session to lock. See `self_held_kit.rs`.

/**
 * Error returned by the self-held kit. Matches `SelfHeldKitError` in `self_held_kit.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 */
export type SelfHeldKitError =
  // A did:web identity — the recovery-key model does not apply.
  | { code: 'NOT_DID_PLC' }
  // The wallet's device key is not rotationKeys[0], so it cannot additively install a key.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The host advertises `escrow` — the escrow-backed re-key belongs there instead.
  | { code: 'HOST_OFFERS_ESCROW' }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // The strict additive pre-sign guard rejected the op.
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SHARE_GENERATION_FAILED'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_SUBMISSION_FAILED'; message: string }
  // plc.directory answered a read with an HTTP failure (outage/verdict, not connectivity).
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'SHARE_STORAGE_FAILED'; message: string }
  // Confirm was called before Share 1 reached its durable slot.
  | { code: 'SHARE_NOT_STORED' }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string };

/**
 * Preview of a kit install, driving the review screen. Matches `SelfHeldKitPreview`
 * (`#[serde(rename_all = "camelCase")]`).
 */
export interface SelfHeldKitPreview {
  /** The additive key diff — `addedKeys: [recovery]`, `removedKeys: []`. */
  diff: OpDiff;
  /** The recovery `did:key` that will be inserted at rotationKeys[1]. */
  recoveryKeyId: string;
  /** The identity's hosting PDS — the server that will hold none of this. */
  pdsUrl: string;
}

/**
 * Result of a completed kit. Matches `SelfHeldKitResult` (`#[serde(rename_all = "camelCase")]`).
 *
 * Carries **two** shares, unlike the escrow-backed ceremonies: with no escrow, Shares 2 and 3
 * are both the user's to keep.
 */
export interface SelfHeldKitResult {
  /** The refreshed DID document (PLC data shape) so the identity card updates immediately. */
  updatedDidDoc: Record<string, unknown>;
  /** Share 2 envelope (base32/QR form). */
  share2: string;
  /** Share 2 as the BIP-39-style word phrase. */
  share2Words: string;
  /** Share 3 envelope (base32/QR form). */
  share3: string;
  /** Share 3 as the BIP-39-style word phrase. */
  share3Words: string;
}

/**
 * Build the kit preview: generate + stage the share set, prove the identity and host are
 * eligible, and return the additive diff for review.
 *
 * Idempotent — the staged set is reused across retries. Signs nothing; {@link submitSelfHeldKit}
 * does the single device-key signature.
 */
export const buildSelfHeldKit = (did: string): Promise<SelfHeldKitPreview> =>
  invoke('build_self_held_kit_cmd', { did });

/**
 * Install the kit: post the additive rotation op (device-key-signed) to plc.directory, write the
 * durable Share 1, and refresh the cache. Returns Shares 2 and 3 for the user to save.
 *
 * The biometric prompt precedes the IPC invocation (the owner gate on an identity operation);
 * cancellation never reaches the network. Idempotent/resumable — every step converges on the
 * same terminal state, and no intermediate state drops recovery capability below the pre-kit
 * baseline.
 */
export const submitSelfHeldKit = async (did: string): Promise<SelfHeldKitResult> => {
  await authenticateBiometric('Confirm your recovery kit');
  return invoke('submit_self_held_kit_cmd', { did });
};

/**
 * Confirm the user has saved Shares 2 and 3, and tear down the staging slot. Idempotent.
 * Rejects with `SHARE_NOT_STORED` if Share 1 is not durably present — the staging record is the
 * last local home of the seed until then.
 */
export const confirmSelfHeldKit = (did: string): Promise<void> =>
  invoke('confirm_self_held_kit_cmd', { did });

/**
 * Whether a kit is mid-flight for this DID (a per-DID staging slot exists). The identity surface
 * treats this as "finish your recovery kit" even when the document already shows the recovery
 * key — it resurfaces a kit whose PLC op landed but whose Share 1 or confirmation did not.
 */
export const selfHeldKitInProgress = (did: string): Promise<boolean> =>
  invoke('self_held_kit_in_progress_cmd', { did });

/**
 * The upsell **seam**: should this identity be offered escrow-assisted recovery, once?
 *
 * True only when the identity carries a self-held kit *and* its current host advertises
 * `escrow` — i.e. the user has since moved to a server that can hold a share for them. Never
 * true right after a kit completes, so this is a hook for a real later upgrade, not a nag.
 */
export const selfHeldKitEscrowOffer = (did: string): Promise<boolean> =>
  invoke('self_held_kit_escrow_offer_cmd', { did });
