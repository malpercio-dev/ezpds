import { invoke } from '@tauri-apps/api/core';

// ── Sovereign disaster recovery (rebuild from the iCloud backups) ─────────────
//
// The credible-exit guarantee: rebuild the account on a new (or the same) PDS from the
// iCloud repo CAR + blob mirror when the source PDS is gone or uncooperative. The
// identity side (these commands) enrolls a self-controlled `atproto` signing key via a
// device-key-signed PLC op and mints the `createAccount` service-auth JWT offline; the
// transfer side reuses the migration orchestrator wrappers (`transferBlobs`,
// `verifyImport`, `armIdentityLeg`, `finalizeMigration`) against the same session.

/**
 * Error returned by the identity-side disaster-recovery commands.
 * Matches DisasterRecoveryError in disaster_recovery.rs with
 * #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")] — codes must match exactly.
 */
export type DisasterRecoveryError =
  | { code: 'WALLET_NOT_AUTHORIZED' }
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'KEYCHAIN_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'KEY_NOT_ENROLLED'; message: string }
  | { code: 'DESTINATION_UNREACHABLE'; message: string }
  | { code: 'RECOVERY_NOT_READY'; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * What `prepareDisasterRecovery` resolved — mirrors the Rust `PreparedRecovery`
 * (`#[serde(rename_all = "camelCase")]`).
 */
export type PreparedRecovery = {
  /** The handle the destination account will be created with. */
  handle: string;
  /** The destination server's DID (`did:web:<host>`) — the offline JWT's `aud`. */
  destDid: string;
  /** The dead source PDS endpoint from the DID document (display only). */
  sourcePdsUrl: string;
};

/**
 * Outcome of `enrollRecoverySigningKey` — mirrors the Rust `RecoveryEnrollment`
 * (`#[serde(rename_all = "camelCase")]`).
 */
export type RecoveryEnrollment = {
  /** The enrolled self-controlled signing key's did:key URI. */
  signingKeyId: string;
  /** The submitted enroll op's CID (or the current head when already enrolled). */
  opCid: string;
  /** True when the key was already enrolled (a reconciled retry) — nothing was signed. */
  alreadyEnrolled: boolean;
};

/** Outcome of one `awaitRecoveryKeyVisibility` poll. */
export type RecoveryKeyStatus = {
  /** Whether the enrolled key is now the DID's `atproto` method on plc.directory. */
  visible: boolean;
};

/**
 * Resolve the destination and the DID's current PLC state (from plc.directory alone —
 * the dead source PDS is never contacted) and open a recovery session.
 *
 * `handleOverride` covers the offline-handle-domain edge case: when the old PDS served
 * the handle's domain, pass a destination-served handle to create the account with.
 */
export const prepareDisasterRecovery = (
  did: string,
  destPdsUrl: string,
  handleOverride?: string,
): Promise<PreparedRecovery> =>
  invoke('prepare_disaster_recovery', { did, destPdsUrl, handleOverride });

/**
 * PLC op #1: enroll a fresh self-controlled `atproto` signing key via a
 * device-key-signed PLC op submitted directly to plc.directory. The strict guard
 * proves the op changes nothing else (rotationKeys — wallet device key at [0] —
 * alsoKnownAs, and services are all preserved). Idempotent across retries.
 *
 * Callers gate this behind `authenticateBiometric()` — it signs with the device key.
 */
export const enrollRecoverySigningKey = (did: string): Promise<RecoveryEnrollment> =>
  invoke('enroll_recovery_signing_key', { did });

/**
 * One poll of the plc.directory audit log: is the enrolled key visible yet?
 * `createAccount` cannot succeed before op #1 propagates, so the flow polls this
 * until `visible` is true (which also advances the recovery session's phase gate).
 */
export const awaitRecoveryKeyVisibility = (did: string): Promise<RecoveryKeyStatus> =>
  invoke('await_recovery_key_visibility', { did });

/**
 * Mint the service-auth JWT offline with the self-controlled signing key
 * (`iss` = account DID, `aud` = destination server DID, `lxm` = createAccount) and
 * create the (deactivated) destination account through the standard migration path.
 */
export const createRecoveryDestinationAccount = (
  did: string,
  email: string,
  inviteCode?: string,
): Promise<void> => invoke('create_recovery_destination_account', { did, email, inviteCode });

/**
 * Import the repo into the destination from the validated iCloud CAR snapshot — the
 * sourceless twin of `transferRepo`. Rejects with `BACKUP_UNAVAILABLE` when no valid
 * snapshot exists.
 */
export const recoveryTransferRepo = (did: string): Promise<void> =>
  invoke('recovery_transfer_repo', { did });
