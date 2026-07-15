import { invoke } from '@tauri-apps/api/core';
import type { UnlockReason } from './identity';

// ── identity_removal ──────────────────────────────────────────────────────────
//
// Permanent removal of a managed identity: delete the account on the PDS, tombstone
// the did:plc on plc.directory, and wipe local Keychain material. Backs the
// RemoveIdentityScreen. Mirrors `identity_removal.rs`.

/**
 * Error returned by the identity-removal commands.
 * Matches `RemovalError` in `identity_removal.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`).
 */
export type RemovalError =
  /** The identity needs a passwordless unlock (`sovereignLogin`) before removal. */
  | { code: 'SESSION_REQUIRED'; reason: UnlockReason }
  /** `requestAccountDelete` failed (could not mint/send the confirmation code). */
  | { code: 'REQUEST_DELETE_FAILED'; message: string }
  /** The PDS rejected the account password or the emailed confirmation code. */
  | { code: 'INVALID_TOKEN' }
  /** `deleteAccount` failed for a reason other than bad credentials. */
  | { code: 'ACCOUNT_DELETE_FAILED'; message: string }
  /** The DID's PLC audit log could not be read for the tombstone `prev`. */
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  /** Building or signing the tombstone with the device key failed. */
  | { code: 'TOMBSTONE_SIGNING_FAILED'; message: string }
  /** plc.directory rejected the tombstone — the account is already deleted; retry via `tombstoneIdentity`. */
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  /** The DID's device key / managed-dids entry is missing. */
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  /** The account was deleted and tombstoned, but the local Keychain wipe failed. */
  | { code: 'LOCAL_WIPE_FAILED'; message: string }
  /** A server rate-limited a step. */
  | { code: 'RATE_LIMITED'; retryAfter?: string }
  /** Transport failure reaching the PDS or plc.directory. */
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Result of a successful removal (or a `tombstoneIdentity` resume).
 * Matches `RemovalOutcome` in `identity_removal.rs` (`#[serde(rename_all = "camelCase")]`).
 */
export interface RemovalOutcome {
  /** CID of the submitted did:plc tombstone operation. */
  tombstoneCid: string;
  /** `true` if this was the last managed identity — the UI returns to onboarding. */
  wasLastIdentity: boolean;
}

/**
 * Step 1 — request permanent deletion. Obtains a full-access session for the DID (the
 * caller runs `sovereignLogin` first if this rejects with `SESSION_REQUIRED`) and asks
 * the PDS to email a single-use confirmation code to the account address.
 */
export const requestIdentityRemoval = (did: string): Promise<void> =>
  invoke('request_identity_removal', { did });

/**
 * Step 2 — confirm removal. Deletes the account on the PDS (using the account
 * `password` + emailed `token`), then tombstones the did:plc and wipes local material.
 * A wrong password/code rejects with `INVALID_TOKEN` and mutates nothing, so the UI can
 * re-prompt. MUST be gated behind {@link authenticateBiometric} by the caller.
 */
export const confirmIdentityRemoval = (
  did: string,
  password: string,
  token: string,
): Promise<RemovalOutcome> => invoke('confirm_identity_removal', { did, password, token });

/**
 * Resume path — the PDS account was already deleted but the tombstone or local wipe
 * failed (the single-use deletion token is spent, so re-running confirm would fail).
 * Retries only the tombstone + wipe. MUST be gated behind {@link authenticateBiometric}.
 */
export const tombstoneIdentity = (did: string): Promise<RemovalOutcome> =>
  invoke('tombstone_identity', { did });
