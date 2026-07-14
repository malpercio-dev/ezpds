import { invoke } from '@tauri-apps/api/core';

// ── Claim flow types ──────────────────────────────────────────────────────

/**
 * Identity information resolved from a handle or DID.
 *
 * Returned by `resolveIdentity` command. Contains the DID, handle, PDS endpoint,
 * current rotation keys from the DID document, and whether the device key is
 * the primary rotation key (rotationKeys[0]).
 */
export interface IdentityInfo {
  /** The DID (e.g., "did:plc:abc123...") */
  did: string;
  /** The handle (e.g., "alice.test") */
  handle: string;
  /** The PDS endpoint URL (e.g., "https://pds.example.com") */
  pdsUrl: string;
  /** Current rotation keys from the DID document */
  currentRotationKeys: string[];
  /** Whether the device key is a rotation key (true if device key == rotationKeys[0]) */
  deviceKeyIsRoot: boolean;
}

/**
 * Verified claim operation ready for submission.
 *
 * Returned by `signAndVerifyClaim` command. Contains the diff between the
 * current DID document and the proposed operation, the signed operation
 * itself (as a JSON object), and any warnings from verification.
 */
export interface VerifiedClaimOp {
  /** Diff of keys and services between current DID doc and proposed operation */
  diff: OpDiff;
  /** Signed operation (ready for PLC submission) as a JSON object */
  signedOp: Record<string, unknown>;
  /** Warnings from verification (e.g., "This operation will break X") */
  warnings: string[];
}

/**
 * Diff of changes between current DID document and proposed operation.
 *
 * Shows which keys and services are being added, removed, or modified
 * in the claim operation, along with the previous CID for verification.
 */
export interface OpDiff {
  /** Keys being added in this operation */
  addedKeys: string[];
  /** Keys being removed in this operation */
  removedKeys: string[];
  /** Service endpoint changes (added/removed/modified) */
  changedServices: ServiceChange[];
  /** Previous CID (content identifier) of the DID document, or null if no prior operation */
  prevCid: string | null;
}

/**
 * Type of change to a service endpoint.
 */
export type ChangeType = 'added' | 'removed' | 'modified';

/**
 * Change to a service endpoint in the DID document.
 *
 * Represents a single service change with the service ID, type of change,
 * and the old/new endpoint URLs (where applicable).
 */
export interface ServiceChange {
  /** Service ID (e.g., "atproto_pds") */
  id: string;
  /** Type of change: added, removed, or modified */
  changeType: ChangeType;
  /** Old endpoint URL (null if added) */
  oldEndpoint: string | null;
  /** New endpoint URL (null if removed) */
  newEndpoint: string | null;
}

/**
 * Result of a successful claim submission.
 *
 * Returned by `submitClaim` command. Contains the updated DID document
 * after the claim was applied.
 */
export interface ClaimResult {
  /** Updated DID document after claim was applied */
  updatedDidDoc: Record<string, unknown>;
}

// ── Claim flow error types ────────────────────────────────────────────────

/**
 * Error returned by `resolveIdentity` command.
 *
 * Serialized as `{ code: "HANDLE_NOT_FOUND" }` etc. by the Rust backend.
 */
export type ResolveError =
  | { code: 'HANDLE_NOT_FOUND' }
  | { code: 'DID_NOT_FOUND' }
  | { code: 'PDS_UNREACHABLE' }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Error returned by claim flow commands.
 *
 * Serialized as `{ code: "INVALID_TOKEN" }` etc. by the Rust backend.
 * Variants with a `message` field are serialized with that field as well.
 */
export type ClaimError =
  | { code: 'INVALID_TOKEN' }
  | { code: 'VERIFICATION_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'UNAUTHORIZED' }
  | { code: 'SOURCE_AUTH_FAILED'; message: string }
  | { code: 'TWO_FACTOR_REQUIRED' }
  | { code: 'ACCOUNT_MISMATCH' }
  | { code: 'INSECURE_SOURCE_URL' }
  | { code: 'INSUFFICIENT_SCOPE'; message: string }
  // The source PDS rate-limited a claim-flow request (HTTP 429). `retryAfter` is the server's
  // `Retry-After` value (seconds or an HTTP date) when present, else null.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // A non-2xx the wallet doesn't model specially; `message` is the server's own error text, shown
  // verbatim rather than as connectivity boilerplate.
  | { code: 'SERVER_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

// ── Claim flow IPC wrappers ────────────────────────────────────────────────

/**
 * Resolve a handle or DID to identity information.
 *
 * This is the first command in the claim flow. Returns identity info including
 * the DID, handle, PDS endpoint, and current rotation keys from the DID document.
 * Stores claim state internally for use by subsequent claim commands.
 */
export const resolveIdentity = (handleOrDid: string): Promise<IdentityInfo> =>
  invoke('resolve_identity', { handleOrDid });

/**
 * Authenticate with the identity's existing PDS using the account **password** (`createSession`).
 *
 * The claim flow's next steps — requesting and signing a PLC operation — are identity operations
 * that a spec-strict PDS (bsky.social) gates behind a full session. No OAuth `transition:generic`
 * token can drive them, so the wallet does a one-shot password `createSession` to obtain a
 * full-session Bearer client. The password is sent once to the user's own PDS and never stored;
 * an app password is a lesser scope and is rejected (`SOURCE_AUTH_FAILED`).
 *
 * `authFactorToken` is the email 2FA one-time code. Omit it on the first attempt; if the account
 * has email two-factor enabled the call rejects with `TWO_FACTOR_REQUIRED` (and the PDS emails a
 * code), and the caller re-invokes with the code.
 *
 * Rejects with a typed `ClaimError` — notably `SOURCE_AUTH_FAILED` for a wrong password and
 * `TWO_FACTOR_REQUIRED` when a 2FA code is needed.
 */
export const authenticateSourcePds = (
  did: string,
  identifier: string,
  password: string,
  authFactorToken?: string,
): Promise<void> =>
  invoke('authenticate_source_pds', { did, identifier, password, authFactorToken });

/**
 * Request email verification for the PLC operation.
 *
 * Calls `requestPlcOperationSignature` on the old PDS to trigger email verification.
 * Must be called after `authenticateSourcePds` succeeds.
 */
export const requestClaimVerification = (did: string): Promise<void> =>
  invoke('request_claim_verification', { did });

/**
 * Sign and verify a PLC operation.
 *
 * Coordinates three systems: old PDS (for signing), plc.directory (for audit log),
 * and local verification (4-point checks). Returns a verified operation ready for
 * submission.
 */
export const signAndVerifyClaim = (did: string, token: string): Promise<VerifiedClaimOp> =>
  invoke('sign_and_verify_claim', { did, token });

/**
 * Submit a verified signed claim operation to plc.directory.
 *
 * This is the final step in the claim flow. POSTs the signed operation to
 * plc.directory and persists the claimed identity to the local identity store.
 */
export const submitClaim = (did: string): Promise<ClaimResult> =>
  invoke('submit_claim', { did });
