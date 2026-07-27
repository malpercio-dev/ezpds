import { invoke } from '@tauri-apps/api/core';
import type { UnlockReason } from './identity';

// ── identity_removal ──────────────────────────────────────────────────────────
//
// Permanent removal of a managed identity: delete the account on the PDS, tombstone
// the did:plc on plc.directory, and wipe local Keychain material. Backs the
// RemoveIdentityScreen. Mirrors `identity_removal.rs`.
//
// Method-aware: only a did:plc has a tombstone. A did:web is deleted on the PDS and
// wiped locally, with no plc.directory step — retiring the DID network-wide means taking
// its `did.json` off the domain, which only its operator can do. The backend reports that
// as a null `tombstoneCid`.

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
  /**
   * The passwordless sibling of `INVALID_TOKEN`: the PDS rejected the emailed code or the
   * device-key removal proof. The server's refusal is identical either way (it is not a
   * credential oracle) — the wallet distinguishes them because it knows what it sent, so an
   * identity with no password is never told to check one.
   */
  | { code: 'INVALID_CONFIRMATION_CODE' }
  /** The identity's host does not accept a device-key removal proof; the password is required. */
  | { code: 'PASSWORD_REQUIRED' }
  /** The removal proof could not be signed with the identity's device key. */
  | { code: 'PROOF_SIGNING_FAILED'; message: string }
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
  /**
   * CID of the submitted did:plc tombstone operation, or `null` when the removed DID has
   * no tombstone leg (a did:web). `null` is the cue to show the "take your did.json down"
   * epilogue rather than claim the identity was retired network-wide.
   */
  tombstoneCid: string | null;
  /** `true` if this was the last managed identity — the UI returns to onboarding. */
  wasLastIdentity: boolean;
}

/**
 * Which credential this identity's removal needs.
 * Matches `RemovalRoute` in `identity_removal.rs` (`#[serde(rename_all = "camelCase")]`).
 */
export interface RemovalRoute {
  /**
   * Whether the confirm step must ask for the account password. `false` when the identity's
   * host advertises `walletAccountDelete` and the wallet signs a device-key removal proof
   * instead — an account created without a password has nothing to type, and one that has a
   * password does not need to.
   */
  requiresPassword: boolean;
  /** The identity's current hosting PDS. */
  pdsUrl: string;
}

/**
 * Step 0 — ask which credential removal needs on this identity's host, so the confirm step
 * shows a password field only where one is actually used. Resolved through the same host the
 * deletion request will address, so the screen and the request can never disagree. A host that
 * could not be described reports `requiresPassword: true`.
 */
export const getIdentityRemovalRoute = (did: string): Promise<RemovalRoute> =>
  invoke('get_identity_removal_route', { did });

/**
 * Step 1 — request permanent deletion. Obtains a full-access session for the DID (the
 * caller runs `sovereignLogin` first if this rejects with `SESSION_REQUIRED`) and asks
 * the PDS to email a single-use confirmation code to the account address.
 */
export const requestIdentityRemoval = (did: string): Promise<void> =>
  invoke('request_identity_removal', { did });

/**
 * Step 2 — confirm removal. Deletes the account on the PDS, then runs the method-appropriate
 * tail: tombstone the did:plc and wipe locally, or — for a did:web — wipe locally with no PLC
 * step at all.
 *
 * `password` is `null` for an identity that has none (see {@link getIdentityRemovalRoute}); the
 * wallet then signs a device-key removal proof instead, which only a host advertising
 * `walletAccountDelete` accepts. A wrong credential rejects with `INVALID_TOKEN` (password sent)
 * or `INVALID_CONFIRMATION_CODE` (proof sent) and mutates nothing, so the UI can re-prompt. MUST
 * be gated behind {@link authenticateBiometric} by the caller.
 */
export const confirmIdentityRemoval = (
  did: string,
  password: string | null,
  token: string,
): Promise<RemovalOutcome> => invoke('confirm_identity_removal', { did, password, token });

/**
 * Resume path — the PDS account was already deleted but the tombstone or local wipe
 * failed (the single-use deletion token is spent, so re-running confirm would fail).
 * Retries only the tombstone + wipe; for a did:web (which has no tombstone) it retries
 * the local wipe alone. MUST be gated behind {@link authenticateBiometric}.
 */
export const tombstoneIdentity = (did: string): Promise<RemovalOutcome> =>
  invoke('tombstone_identity', { did });

/**
 * List DIDs with a pending post-delete removal — the PDS account was deleted but the
 * tombstone + local wipe never finished (e.g. iOS killed the app mid-flow). The launch
 * path reconciles each straight to {@link tombstoneIdentity} rather than the request
 * flow, which would fail against the already-deleted account. Infallible: any Keychain
 * trouble resolves to an empty list, so it is safe to call unconditionally on launch.
 */
export const listPendingRemovals = (): Promise<string[]> => invoke('list_pending_removals');

/**
 * Escape hatch — forget an identity from THIS device only, with no network step.
 *
 * For an identity whose PDS account no longer exists (deleted from another device, purged
 * server-side, or migrated away), the normal delete flow can never complete: the PDS answers
 * an already-gone account with the same opaque 401 as a wrong password, so it can't be
 * treated as success. This wipes the DID's local Keychain material and clears any pending
 * marker. It does NOT delete a server account or tombstone the did:plc — the identity may
 * still be live elsewhere. Resolves to `wasLastIdentity` (like {@link RemovalOutcome}). MUST
 * be gated behind {@link authenticateBiometric} by the caller.
 */
export const forgetIdentityLocally = (did: string): Promise<boolean> =>
  invoke('forget_identity_locally', { did });
