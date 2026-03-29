import { invoke } from '@tauri-apps/api/core';

// ── create_account ──────────────────────────────────────────────────────────

export interface CreateAccountParams extends Record<string, unknown> {
  claimCode: string;
  email: string;
  handle: string;
}

/**
 * Successful result from the `create_account` Rust command.
 * This is a pure data shape returned on success.
 */
export type CreateAccountResult = {
  nextStep: 'did_creation';
};

/**
 * Error returned by the `create_account` Rust command.
 *
 * Serialized as `{ code: "EXPIRED_CODE" }` etc. by the Rust backend.
 * The `message` field is present only on variants that include it in their Rust definition.
 * This is a pure data shape used for error handling.
 */
export type CreateAccountError = {
  code:
    | 'EXPIRED_CODE'
    | 'REDEEMED_CODE'
    | 'EMAIL_TAKEN'
    | 'HANDLE_TAKEN'
    | 'KEYCHAIN_ERROR'
    | 'NETWORK_ERROR'
    | 'UNKNOWN';
  message?: string;
};

/**
 * Create a new account via the relay.
 *
 * On success, tokens are stored in the iOS Keychain by the Rust backend.
 * On failure, the Promise rejects with a `CreateAccountError`.
 */
export const createAccount = (
  params: CreateAccountParams
): Promise<CreateAccountResult> =>
  invoke('create_account', params);

// ── Device Key types ──────────────────────────────────────────────────────────

/**
 * Device public key returned by the `get_or_create_device_key` Rust command.
 * Matches DevicePublicKey struct with #[serde(rename_all = "camelCase")].
 */
export type DevicePublicKey = {
  /** 'z' + base58btc(33-byte compressed P-256 public key point). */
  multibase: string;
  /** Full did:key URI: 'did:key:z...' */
  keyId: string;
};

/**
 * Error returned by device key commands.
 *
 * Serialized as `{ code: "KEY_GENERATION_FAILED" }` etc. by the Rust backend.
 * `message` is present only for KEYCHAIN_ERROR.
 */
export type DeviceKeyError = {
  code:
    | 'KEY_GENERATION_FAILED'
    | 'KEY_NOT_FOUND'
    | 'SIGNING_FAILED'
    | 'INVALID_SIGNATURE'
    | 'KEYCHAIN_ERROR';
  message?: string;
};

// ── get_or_create_device_key ─────────────────────────────────────────────────

/**
 * Get or create the device's SE-backed (or simulator-fallback) P-256 keypair.
 *
 * Idempotent — returns the same key on every call for a given device.
 * On failure, the Promise rejects with a `DeviceKeyError`.
 */
export const getOrCreateDeviceKey = (): Promise<DevicePublicKey> =>
  invoke('get_or_create_device_key');

// ── sign_with_device_key ─────────────────────────────────────────────────────

/**
 * Sign arbitrary bytes using the device's SE-backed (or simulator-fallback) P-256 key.
 *
 * Returns the raw 64-byte ECDSA r||s signature as a Uint8Array.
 *
 * IMPORTANT: `data` is converted to `number[]` before passing to Tauri's IPC
 * because Tauri v2's JSON deserializer cannot accept a `Uint8Array` nested inside
 * an object property — it must be a plain number array. See tauri#10336.
 *
 * On failure, the Promise rejects with a `DeviceKeyError` (code: KEY_NOT_FOUND
 * if `getOrCreateDeviceKey` has never been called for this device).
 */
export const signWithDeviceKey = (data: Uint8Array): Promise<Uint8Array> =>
  (invoke('sign_with_device_key', { data: Array.from(data) }) as Promise<number[]>).then(
    (bytes) => new Uint8Array(bytes),
  );

// ── perform_did_ceremony ─────────────────────────────────────────────────────

/**
 * Successful result from the `perform_did_ceremony` Rust command.
 * This is a pure data shape returned on success.
 */
export type DIDCeremonyResult = {
  did: string;
  /**
   * Share 3 of 3 — the user's manual backup share.
   * Base32-encoded (RFC 4648, no padding), 52 uppercase A-Z/2-7 characters.
   * Share 1 has already been stored in iCloud Keychain by the Rust backend.
   */
  share3: string;
};

/**
 * Error returned by the `perform_did_ceremony` Rust command.
 *
 * Serialized as `{ code: "NO_RELAY_SIGNING_KEY" }` etc. by the Rust backend.
 * The `message` field is present only on the NETWORK_ERROR variant.
 * This is a pure data shape used for error handling.
 */
export type DIDCeremonyError = {
  code:
    | 'KEY_NOT_FOUND'
    | 'RELAY_KEY_FETCH_FAILED'
    | 'NO_RELAY_SIGNING_KEY'
    | 'SIGNING_FAILED'
    | 'DID_CREATION_FAILED'
    | 'KEYCHAIN_ERROR'
    /** DID was committed at the relay but Share 1 Keychain write failed. Retrying the
     *  ceremony will fail (DID already exists). Share storage can be retried separately. */
    | 'SHARE_STORAGE_FAILED'
    | 'NETWORK_ERROR';
  message?: string;
};

/**
 * Perform the DID ceremony: fetch relay key, build signed genesis op, post to relay,
 * persist DID and upgraded session token in Keychain.
 *
 * On success, the DID and new session token are stored in Keychain by the Rust backend.
 * On failure, the Promise rejects with a `DIDCeremonyError`.
 */
export const performDIDCeremony = (
  handle: string,
  password: string,
): Promise<DIDCeremonyResult> =>
  invoke('perform_did_ceremony', { handle, password });

// ── register_handle ──────────────────────────────────────────────────────────

/**
 * Successful result from the `register_handle` Rust command.
 * `handle` is the full `alice.your-domain.com` form.
 * `dnsStatus` is `"propagating"` when a DNS record was created, or `"not_configured"` when
 * the relay has no DNS provider (handle still resolves via HTTP well-known).
 */
export type RegisterHandleResult = {
  handle: string;
  dnsStatus: 'propagating' | 'not_configured';
};

/**
 * Error returned by the `register_handle` Rust command.
 * Serialized as `{ code: "HANDLE_TAKEN" }` etc. by the Rust backend.
 * Variants that carry a message have it as a required field on their branch.
 */
export type RegisterHandleError =
  | { code: 'HANDLE_TAKEN' }
  | { code: 'INVALID_HANDLE' }
  | { code: 'DNS_ERROR' }
  | { code: 'KEYCHAIN_ERROR' }
  | { code: 'SESSION_EXPIRED' }
  | { code: 'NO_DOMAINS' }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'UNKNOWN'; message: string };

/**
 * Register the user's handle with the relay.
 *
 * `handleLabel` is the label portion only (e.g. `"alice"`).
 * The Rust backend fetches the relay's primary domain from `describeServer`,
 * reads the DID and session token from Keychain, and POSTs to `/v1/handles`.
 *
 * On failure, the Promise rejects with a `RegisterHandleError`.
 */
export const registerHandle = (handleLabel: string): Promise<RegisterHandleResult> =>
  invoke('register_handle', { handleLabel });

/**
 * Check whether `handle` resolves to `expectedDid` via the relay's `resolveHandle` endpoint.
 *
 * Returns `true` when the relay resolves the handle to the expected DID.
 * Returns `false` for any other outcome (not yet propagated, relay unreachable, DID mismatch).
 * Never rejects — safe to call on a polling interval.
 */
export const checkHandleResolution = (handle: string, expectedDid: string): Promise<boolean> =>
  invoke('check_handle_resolution', { handle, expectedDid });

// ── OAuth ───────────────────────────────────────────────────────────────────
//
// These variants must exactly match the Rust `OAuthError` enum in oauth.rs.
// Rust serializes them as `{ "code": "SCREAMING_SNAKE_CASE" }` via:
//   #[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]

export type OAuthError =
  | { code: 'DPOP_KEY_GEN_FAILED' }
  | { code: 'DPOP_KEY_INVALID' }
  | { code: 'DPOP_PROOF_FAILED' }
  | { code: 'KEYCHAIN_ERROR' }
  | { code: 'STATE_MISMATCH' }
  | { code: 'CALLBACK_ABANDONED' }
  | { code: 'PAR_FAILED' }
  | { code: 'TOKEN_EXCHANGE_FAILED' }
  | { code: 'TOKEN_REFRESH_FAILED' }
  | { code: 'INVALID_GRANT' }
  | { code: 'NOT_AUTHENTICATED' };

export const startOAuthFlow = (): Promise<void> => invoke('start_oauth_flow');

// ── Home screen ──────────────────────────────────────────────────────────
//
// These types must exactly match the Rust structs in home.rs.
// Rust serializes them with #[serde(rename_all = "camelCase")].

/**
 * Session info returned by com.atproto.server.getSession.
 * null fields (email, emailConfirmed) default to empty string / false
 * when the relay omits them.
 */
export type SessionInfo = {
  did: string;
  handle: string;
  email: string;
  emailConfirmed: boolean;
  /** Full DID document object, or null when the relay has none for this DID. */
  didDoc: Record<string, unknown> | null;
};

/**
 * Home screen data payload from the `load_home_data` Rust command.
 *
 * Always resolves (never rejects) — partial failures are encoded as fields
 * so the UI can render whatever is available.
 */
export type HomeData = {
  relayHealthy: boolean;
  /** null when getSession failed or no session exists */
  session: SessionInfo | null;
  /** SCREAMING_SNAKE_CASE error code when session is null */
  sessionError: string | null;
  share1InKeychain: boolean;
};

/**
 * Load relay health, session info, and Keychain share status concurrently.
 *
 * Always resolves — never rejects. Partial failures encoded in HomeData fields.
 */
export const loadHomeData = (): Promise<HomeData> =>
  invoke<HomeData>('load_home_data').catch(
    (): HomeData => ({ relayHealthy: false, session: null, sessionError: 'UNKNOWN', share1InKeychain: false })
  );

/**
 * Clear OAuth access token, refresh token, and DID from Keychain and wipe
 * the in-memory session.
 *
 * Always resolves. Frontend should unconditionally navigate to the welcome screen.
 */
export const logOut = (): Promise<void> => invoke('log_out').then(() => undefined);

// ── Relay URL Configuration ──────────────────────────────────────────────

/**
 * Error from relay URL configuration commands.
 * Serialized as `{ code: "INVALID_URL" }` etc. by the Rust backend.
 */
export type RelayConfigError =
  | { code: 'INVALID_URL' }
  | { code: 'UNREACHABLE' }
  | { code: 'KEYCHAIN_ERROR' };

/**
 * Returns the saved relay base URL, or null if not yet configured.
 * Call this on app mount to decide whether to show the relay config screen.
 */
export const getRelayUrl = (): Promise<string | null> =>
  invoke('get_relay_url');

/**
 * Validates url, pings /xrpc/_health, saves to Keychain, and initializes the
 * runtime relay client. After this resolves, all relay IPC commands use url.
 * Throws RelayConfigError on failure.
 */
export const saveRelayUrl = (url: string): Promise<void> =>
  invoke('save_relay_url', { url });

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
 * Authenticate with the old PDS via OAuth 2.0 PKCE + DPoP.
 *
 * Opens Safari for user authentication and handles the OAuth callback via deep-link.
 * On success, stores the OAuth client in claim state for use by subsequent commands.
 * Emits `pds_auth_ready` event when complete.
 */
export const startPdsAuth = (pdsUrl: string): Promise<void> =>
  invoke('start_pds_auth', { pdsUrl });

/**
 * Request email verification for the PLC operation.
 *
 * Calls `requestPlcOperationSignature` on the old PDS to trigger email verification.
 * Must be called after `startPdsAuth` succeeds.
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
