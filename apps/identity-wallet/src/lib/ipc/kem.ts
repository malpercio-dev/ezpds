import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { ClaimResult } from './claim';
import type { SharedFailure } from './errors';

// ── Update identity for Spaces (publish the Spaces KEM key, ADR-0043) ─────────
//
// Two commands, mirroring the server's stage/complete ceremony (`publish_kem_key.rs` walks
// through each step). The biometric prompt sits in front of whichever call makes the change:
// `complete` for a did:plc (the signed op leaves the phone), `prepare` for a did:web (on a
// Custos-hosted document, staging is the publication).

/**
 * Error returned by the KEM-key update. Matches `KemKeyError` in `publish_kem_key.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`).
 */
export type KemKeyError =
  // The wallet holds no rotation key for this DID, so it cannot sign the update.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The strict pre-sign guard refused: the op or document would change more than the KEM key.
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  // The live did.json could not be read as this identity's document.
  | { code: 'INVALID_DID_DOCUMENT'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  // Custos refused a stage or complete call (for did:web: the live copy doesn't match yet).
  | { code: 'KEM_KEY_FAILED'; status: number; message: string }
  // complete ran with nothing prepared for this DID.
  | { code: 'NO_PENDING_KEM_KEY' }
  // Neither a did:plc nor a hostname-form did:web.
  | { code: 'UNSUPPORTED_IDENTITY' }
  | SharedFailure;

/** What the update changes. Matches `KemKeyDiff`. Keys are `did:key:z…`. */
export interface KemKeyDiff {
  kemKey: string;
  replacedKemKey: string | null;
  removedSpaceKey: string | null;
  removedSpaceHost: string | null;
}

/** What prepare produced. Matches `KemKeyPlan` (`#[serde(tag = "kind")]`). */
export type KemKeyPlan =
  // did:plc: a device-key-signed op is waiting for approval.
  | { kind: 'plcOperation'; diff: KemKeyDiff }
  // Self-hosted did:web: export `documentText`, upload it to `documentUrl`, then complete.
  | { kind: 'didWebDocument'; diff: KemKeyDiff; documentText: string; documentUrl: string }
  // Custos-hosted did:web: already published. Nothing to complete.
  | { kind: 'published'; kemKey: string };

/**
 * Ask the hosting server for a fresh KEM key and prepare its publication. For a did:plc this
 * builds, checks, and signs the op locally and changes nothing yet. For a did:web it asks for
 * biometrics first, because a Custos-hosted document is published by this very call.
 */
export const prepareKemKeyPublish = async (did: string): Promise<KemKeyPlan> => {
  if (did.startsWith('did:web:')) {
    await authenticateBiometric('Approve updating your identity for Spaces');
  }
  return invoke('prepare_kem_key_publish_cmd', { did });
};

/**
 * Publish the prepared update. For a did:plc, biometrics first: this hands the signed op to the
 * server, which submits it to the identity directory. For a did:web, the server checks the live
 * did.json and finishes only if it carries the new key. Safe to retry.
 */
export const completeKemKeyPublish = async (did: string): Promise<ClaimResult> => {
  if (did.startsWith('did:plc:')) {
    await authenticateBiometric('Approve updating your identity for Spaces');
  }
  return invoke('complete_kem_key_publish_cmd', { did });
};
