import { invoke } from '@tauri-apps/api/core';
import type { ClaimResult, OpDiff } from './claim';

// ── did:web migration document ────────────────────────────────────────────────

export type DidWebMigrationDocument = {
  documentText: string;
  deviceKey: string;
  repoKey: string;
  pdsEndpoint: string;
};

/** Compose the reviewed did:web update for an armed migration identity leg. */
export const buildDidWebMigrationDocument = (did: string): Promise<DidWebMigrationDocument> =>
  invoke('build_did_web_migration_document_cmd', { did });

/** Verify and adopt the published did:web migration document. */
export const submitDidWebMigrationDocument = (
  did: string,
  documentText: string,
  enableManagedHosting: boolean,
): Promise<ClaimResult> =>
  invoke('submit_did_web_migration_document_cmd', { did, documentText, enableManagedHosting });

// ── migrate (self-signed identity leg) ────────────────────────────────────────

/**
 * Error returned by the self-signed migration identity-leg commands.
 * Matches MigrateError enum in migrate.rs with #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")].
 *
 * WALLET_NOT_AUTHORIZED is the signal to fall back to the PDS-signed interop path:
 * the wallet holds no authorized key for this DID, so it cannot self-sign.
 */
export type MigrateError =
  | { code: 'WALLET_NOT_AUTHORIZED' }
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_RECOMMENDED_CREDENTIALS'; message: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'MIGRATION_NOT_READY'; message: string };

/**
 * A locally-built, device-key-signed migration operation ready for review + submission.
 * Matches SignedMigrationOp struct in migrate.rs with #[serde(rename_all = "camelCase")].
 */
export interface SignedMigrationOp {
  /** Human-readable diff: the atproto_pds endpoint change plus the rotation-key swap. */
  diff: OpDiff;
  /** The signed PLC operation JSON, ready to POST to plc.directory. */
  signedOp: Record<string, unknown>;
}

export type MigrationPath = 'self_signed' | 'interop' | 'cannot_determine';

/**
 * Decision for ADR-0002 outbound migration path selection.
 * `rotationKeyIndex` is present when the wallet device key is authorized; index 0
 * means it is the primary rotation key, while later indexes are still self-signable.
 */
export interface MigrationPathDecision {
  path: MigrationPath;
  deviceKeyId: string | null;
  rotationKeyIndex: number | null;
  reason: string;
}

/**
 * Decide whether a DID can use wallet-authorized self-signed migration or must
 * fall back to the PDS-signed interop path. Returns `cannot_determine` when
 * plc.directory or local key material cannot be checked safely.
 */
export const detectMigrationPath = (did: string): Promise<MigrationPathDecision> =>
  invoke('detect_migration_path_cmd', { did });

/**
 * Build + locally sign the migration identity leg (repoint the DID to a new PDS).
 *
 * Requires the migration orchestrator to have first authenticated to the destination
 * PDS and populated MigrationState; otherwise this rejects with MIGRATION_NOT_READY.
 * The built operation is parked in MigrationState for subsequent submitMigrationOp().
 */
export const buildMigrationOp = (did: string): Promise<SignedMigrationOp> =>
  invoke('build_migration_op_cmd', { did });

/**
 * Submit the pending migration operation to plc.directory.
 *
 * Must be called after buildMigrationOp() — submits the stored signed operation,
 * refreshes the cached PLC audit log + DID document, and returns the updated DID document.
 */
export const submitMigrationOp = (did: string): Promise<ClaimResult> =>
  invoke('submit_migration_op_cmd', { did });

// ── migration orchestrator (wallet-authorized outbound migration) ─────────────

/**
 * Mirrors the Rust AccountStatus (GET com.atproto.server.checkAccountStatus, ezpds shape)
 * with #[serde(rename_all = "camelCase")]. Returned by verifyImport().
 */
export type AccountStatus = {
  activated: boolean;
  validDid: boolean;
  // Rust `Option<String>` without skip_serializing_if → serializes to `null` (present, not absent).
  repoCommit: string | null;
  repoRev: string | null;
  /** ezpds returns "storedBlocks" (not the canonical "repoBlocks"). */
  storedBlocks: number;
  indexedRecords: number;
  privateStateValues: number;
  expectedBlobs: number;
  importedBlobs: number;
};

/**
 * Error returned by the migration orchestrator commands.
 * Matches MigrationError in migration_orchestrator.rs with
 * #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")] — codes must match exactly.
 */
export type MigrationError =
  | { code: 'MIGRATION_NOT_READY'; message: string }
  | { code: 'DESTINATION_UNREACHABLE'; message: string }
  | { code: 'SOURCE_AUTH_FAILED'; message: string }
  // The source account has email 2FA: createSession returned AuthFactorTokenRequired and the PDS
  // emailed a code. The screen prompts for it and re-invokes with the code — not a wrong password.
  | { code: 'TWO_FACTOR_REQUIRED' }
  // The entered credentials signed in to a different account than the one being migrated.
  | { code: 'ACCOUNT_MISMATCH' }
  // Refused to send the password to a non-HTTPS source PDS (loopback excepted).
  | { code: 'INSECURE_SOURCE_URL' }
  // The source PDS rate-limited the login (HTTP 429); `retryAfter` is the server's Retry-After.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // The source PDS rejected the login with a non-2xx the wallet doesn't model; `message` is verbatim.
  | { code: 'SERVER_ERROR'; message: string }
  | { code: 'SERVICE_AUTH_FAILED'; message: string }
  | { code: 'ACCOUNT_CREATION_FAILED'; message: string }
  | { code: 'DESTINATION_CONFLICT'; message: string }
  | { code: 'REPO_TRANSFER_FAILED'; message: string }
  | { code: 'BLOB_TRANSFER_FAILED'; message: string }
  | { code: 'PREFERENCES_TRANSFER_FAILED'; message: string }
  | { code: 'VERIFICATION_INCOMPLETE'; imported: number; expected: number }
  | { code: 'ACTIVATION_FAILED'; message: string }
  // Cutover: minting the destination sovereign session failed (proof rejected / rate-limited /
  // 5xx / transport). Retryable — the source stays active and finalize can be retried.
  | { code: 'SOVEREIGN_LOGIN_FAILED'; message: string }
  // Cutover: persisting the destination session to the Keychain failed. Retryable — the source
  // stays active; the prior valid token record (if any) is left intact.
  | { code: 'SESSION_PERSIST_FAILED'; message: string }
  | { code: 'DEACTIVATION_FAILED'; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Resolved source identity returned by `prepareMigration` — mirrors the Rust `PreparedMigration`
 * (`#[serde(rename_all = "camelCase")]`). Used by MigrationSourceAuthScreen to prefill the login
 * identifier and show which PDS it is signing into.
 */
export type PreparedMigration = {
  handle: string;
  sourcePdsUrl: string;
};

/**
 * Resolve the destination + source PDS and open the migration session (in-memory).
 * Resolves with the source identity (`{ handle, sourcePdsUrl }`) for the source-auth screen.
 * Rejects with MigrationError (e.g. DESTINATION_UNREACHABLE).
 */
export const prepareMigration = (
  did: string,
  destPdsUrl: string,
): Promise<PreparedMigration> => invoke('prepare_migration', { did, destPdsUrl });

/**
 * Authenticate with the OUTBOUND-migration **source** PDS using the account password
 * (`createSession`), mirroring the claim flow's `authenticateSourcePds` (ADR-0021).
 *
 * A password is required — not the wallet's OAuth token — because creating the destination account
 * mints a `com.atproto.server.createAccount` service-auth token from the source PDS, and a
 * spec-strict PDS (bsky.social) gates that mint behind a full session; a `transition:generic` grant
 * is refused. The password is sent once to the source PDS and never stored.
 *
 * `authFactorToken` is the email 2FA code: omit it first; if the account has email 2FA the call
 * rejects with `TWO_FACTOR_REQUIRED` (and the PDS emails a code), then re-invoke with the code.
 */
export const authenticateMigrationSource = (
  did: string,
  identifier: string,
  password: string,
  authFactorToken?: string,
): Promise<void> =>
  invoke('authenticate_migration_source', { did, identifier, password, authFactorToken });

/** Reserve the signing key, mint service-auth, and create the deactivated destination account. */
export const createDestinationAccount = (
  did: string,
  email: string,
  inviteCode?: string,
): Promise<void> => invoke('create_destination_account', { did, email, inviteCode });

/** Export the source repo CAR and import it into the destination. */
export const transferRepo = (did: string): Promise<void> => invoke('transfer_repo', { did });

/** Drain the destination's missing-blob set from the source (cursor-paginated). */
export const transferBlobs = (did: string): Promise<void> => invoke('transfer_blobs', { did });

/** Copy the source account preferences to the destination. */
export const transferPreferences = (did: string): Promise<void> =>
  invoke('transfer_preferences', { did });

/** Verify the import completed; resolves with the destination AccountStatus. */
export const verifyImport = (did: string): Promise<AccountStatus> => invoke('verify_import', { did });

/** Arm the reused migrate.rs identity leg with the destination Bearer client. */
export const armIdentityLeg = (did: string): Promise<void> => invoke('arm_identity_leg', { did });

/** Activate the destination account, then deactivate the source (in that order). */
export const finalizeMigration = (did: string): Promise<void> =>
  invoke('finalize_migration', { did });
