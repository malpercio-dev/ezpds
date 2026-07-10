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
 * Create a new account via the PDS.
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
 * Serialized as `{ code: "NO_PDS_SIGNING_KEY" }` etc. by the Rust backend.
 * The `message` field is present only on the NETWORK_ERROR variant.
 * This is a pure data shape used for error handling.
 */
export type DIDCeremonyError = {
  code:
    | 'KEY_NOT_FOUND'
    | 'PDS_KEY_FETCH_FAILED'
    | 'NO_PDS_SIGNING_KEY'
    | 'SIGNING_FAILED'
    | 'DID_CREATION_FAILED'
    | 'KEYCHAIN_ERROR'
    /** DID was committed at the PDS but Share 1 Keychain write failed. Retrying the
     *  ceremony will fail (DID already exists). Share storage can be retried separately. */
    | 'SHARE_STORAGE_FAILED'
    | 'NETWORK_ERROR';
  message?: string;
};

/**
 * Perform the DID ceremony: fetch PDS key, build signed genesis op, post to PDS,
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
 * the PDS has no DNS provider (handle still resolves via HTTP well-known).
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
 * Register the user's handle with the PDS.
 *
 * `handle` is the FULL handle (e.g. `"alice.ezpds.com"`), assembled on the client from the
 * PDS's `availableUserDomains` before the DID ceremony so it matches the published genesis op.
 * The Rust backend reads the DID and session token from Keychain and POSTs to `/v1/handles`.
 *
 * On failure, the Promise rejects with a `RegisterHandleError`.
 */
export const registerHandle = (handle: string): Promise<RegisterHandleResult> =>
  invoke('register_handle', { handle });

/**
 * Fetch the PDS's configured handle domains (`availableUserDomains` from describeServer).
 *
 * The handle screen uses this to show the domain suffix and assemble the full handle BEFORE
 * the DID ceremony, so the genesis op's `alsoKnownAs` carries the real, resolvable handle.
 * Resolves to the (possibly empty) domain list; rejects with a message string on failure.
 */
export const getAvailableUserDomains = (): Promise<string[]> =>
  invoke('get_available_user_domains');

/**
 * Error returned by the `register_created_identity` Rust command.
 * Serialized as `{ code: "KEYCHAIN_ERROR" }` by the Rust backend.
 */
export type RegisterIdentityError = { code: 'KEYCHAIN_ERROR' };

/**
 * Register a just-created identity in IdentityStore so it appears on the home
 * screen (IdentityListHome lists identities from IdentityStore alone).
 *
 * Call this once the create flow's DID and handle both exist (i.e. after handle
 * registration). Mirrors what the import flow does in submit_claim; also aliases
 * the per-DID device key to the genesis rotation key on the Rust side. Idempotent.
 * On failure the Promise rejects with a RegisterIdentityError.
 */
export const registerCreatedIdentity = (did: string, handle: string): Promise<void> =>
  invoke('register_created_identity', { did, handle });

/**
 * Check whether `handle` resolves to `expectedDid` via the PDS's `resolveHandle` endpoint.
 *
 * Returns `true` when the PDS resolves the handle to the expected DID.
 * Returns `false` for any other outcome (not yet propagated, PDS unreachable, DID mismatch).
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

/**
 * Drive the create-flow PDS login via the native in-app auth session (ASWebAuthenticationSession
 * on iOS, via the auth-session plugin). Three steps: `prepare_oauth_flow` (Rust) does PKCE + PAR
 * and returns the authorize URL; the plugin opens the in-app session and returns the
 * custom-scheme callback URL; `complete_oauth_flow` (Rust) validates the CSRF state and exchanges
 * the code for tokens. The PKCE verifier and CSRF state never leave the Rust backend — only the
 * authorize URL and (briefly) the callback URL transit the webview.
 *
 * This replaces the old external-Safari + deep-link flow, which iOS Safari blocks: it will not
 * auto-launch the app from a server-side redirect to a custom URL scheme.
 */
export const startOAuthFlow = async (): Promise<void> => {
  const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_oauth_flow');
  let callbackUrl: string;
  try {
    callbackUrl = await invoke<string>('plugin:auth-session|start', {
      authUrl: prepared.authUrl,
      callbackUrlScheme: prepared.callbackScheme,
    });
  } catch {
    // The auth-session plugin rejects with a plain string ("user_cancelled", "Invalid auth
    // URL: ..."), not the OAuthError shape. Normalize so the UI's error handling stays uniform;
    // a dismissed sheet reads as an abandoned callback.
    throw { code: 'CALLBACK_ABANDONED' } as OAuthError;
  }
  await invoke('complete_oauth_flow', { callbackUrl });
};

// ── Home screen ──────────────────────────────────────────────────────────
//
// These types must exactly match the Rust structs in home.rs.
// Rust serializes them with #[serde(rename_all = "camelCase")].

/**
 * Session info returned by com.atproto.server.getSession.
 * null fields (email, emailConfirmed) default to empty string / false
 * when the PDS omits them.
 */
export type SessionInfo = {
  did: string;
  handle: string;
  email: string;
  emailConfirmed: boolean;
  /** Full DID document object, or null when the PDS has none for this DID. */
  didDoc: Record<string, unknown> | null;
};

/**
 * Home screen data payload from the `load_home_data` Rust command.
 *
 * Always resolves (never rejects) — partial failures are encoded as fields
 * so the UI can render whatever is available.
 */
export type HomeData = {
  pdsHealthy: boolean;
  /** null when getSession failed or no session exists */
  session: SessionInfo | null;
  /** SCREAMING_SNAKE_CASE error code when session is null */
  sessionError: string | null;
  share1InKeychain: boolean;
};

/**
 * Load PDS health, session info, and Keychain share status concurrently.
 *
 * Always resolves — never rejects. Partial failures encoded in HomeData fields.
 */
export const loadHomeData = (): Promise<HomeData> =>
  invoke<HomeData>('load_home_data').catch(
    (): HomeData => ({ pdsHealthy: false, session: null, sessionError: 'UNKNOWN', share1InKeychain: false })
  );

/**
 * Clear OAuth access token, refresh token, and DID from Keychain and wipe
 * the in-memory session.
 *
 * Always resolves. Frontend should unconditionally navigate to the welcome screen.
 */
export const logOut = (): Promise<void> => invoke('log_out').then(() => undefined);

// ── PDS URL Configuration ──────────────────────────────────────────────

/**
 * Error from PDS URL configuration commands.
 * Serialized as `{ code: "INVALID_URL" }` etc. by the Rust backend.
 */
export type PdsConfigError =
  | { code: 'INVALID_URL' }
  | { code: 'UNREACHABLE' }
  | { code: 'KEYCHAIN_ERROR' };

/**
 * Returns the saved PDS base URL, or null if not yet configured.
 * Call this on app mount to decide whether to show the PDS config screen.
 */
export const getPdsUrl = (): Promise<string | null> =>
  invoke('get_pds_url');

/**
 * Validates url, pings /xrpc/_health, saves to Keychain, and initializes the
 * runtime PDS client. After this resolves, all PDS IPC commands use url.
 * Throws PdsConfigError on failure.
 */
export const savePdsUrl = (url: string): Promise<void> =>
  invoke('save_pds_url', { url });

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
 * Map a `plugin:auth-session|start` rejection to the flow's typed error. The plugin
 * rejects with plain strings, and both platform implementations use the exact sentinel
 * "user_cancelled" for a dismissed sheet — only that may read as the flow's cancellation
 * error. Anything else ("Auth session error: …", "No browser available…") surfaces as
 * NETWORK_ERROR carrying the plugin's message, so a network drop or platform failure
 * is never presented as a cancellation the user didn't make.
 */
const classifyAuthSessionRejection = (
  raw: unknown,
  cancellation: ClaimError | MigrationError,
): ClaimError | MigrationError =>
  raw === 'user_cancelled' ? cancellation : { code: 'NETWORK_ERROR', message: String(raw) };

/**
 * Authenticate with the identity's existing PDS via OAuth 2.0 PKCE + DPoP, using the native
 * in-app auth session (ASWebAuthenticationSession) — same three-step shape as `startOAuthFlow`:
 * `prepare_pds_auth` (Rust) discovers the auth server + PAR and returns the authorize URL; the
 * auth-session plugin opens the in-app session and returns the callback URL; `complete_pds_auth`
 * (Rust) validates it, exchanges the code, and stores the OAuth client in claim state. Resolves
 * when complete.
 *
 * Replaces the old external-Safari + deep-link flow (iOS blocks the custom-scheme redirect).
 */
export const startPdsAuth = async (pdsUrl: string): Promise<void> => {
  const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_pds_auth', {
    pdsUrl,
  });
  let callbackUrl: string;
  try {
    callbackUrl = await invoke<string>('plugin:auth-session|start', {
      authUrl: prepared.authUrl,
      callbackUrlScheme: prepared.callbackScheme,
    });
  } catch (raw: unknown) {
    // A dismissed sheet reads as unauthorized; anything else surfaces as retryable.
    throw classifyAuthSessionRejection(raw, { code: 'UNAUTHORIZED' });
  }
  await invoke('complete_pds_auth', { callbackUrl });
};

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

// ── Identity Store ──────────────────────────────────────────────────────────

export type IdentityStoreError =
  | { code: 'IDENTITY_NOT_FOUND' }
  | { code: 'IDENTITY_ALREADY_EXISTS' }
  | { code: 'KEYCHAIN_ERROR'; message: string }
  | { code: 'KEY_GENERATION_FAILED'; message: string }
  | { code: 'SERIALIZATION_ERROR'; message: string };

export const listIdentities = (): Promise<string[]> =>
  invoke('list_identities');

export const getStoredDidDoc = (did: string): Promise<Record<string, unknown> | null> =>
  invoke('get_stored_did_doc', { did });

export const getDeviceKeyId = (did: string): Promise<string> =>
  invoke('get_device_key_id', { did });

// ── PLC Monitoring ──────────────────────────────────────────────────────────

/**
 * An unauthorized PLC operation detected by the monitor.
 * Matches UnauthorizedChange struct in plc_monitor.rs with #[serde(rename_all = "camelCase")].
 */
export interface UnauthorizedChange {
  /** CID of the unauthorized operation. */
  cid: string;
  /** ISO 8601 timestamp when plc.directory accepted the operation. */
  createdAt: string;
  /** did:key URI of the key that signed this operation, if identified. */
  signingKey: string | null;
  /** The raw PLC operation JSON for display in alert detail. */
  operation: unknown;
}

/**
 * Result of checking a single identity's PLC status.
 * Matches IdentityStatus struct in plc_monitor.rs with #[serde(rename_all = "camelCase")].
 */
export interface IdentityStatus {
  did: string;
  checkFailed: boolean;
  unauthorizedChanges: UnauthorizedChange[];
}

/**
 * Check all managed identities for unauthorized PLC operations.
 * Returns a list of IdentityStatus, one per managed DID.
 *
 * This is the foreground check command — called by the frontend when the app
 * becomes visible (visibilitychange event). It supplements the background
 * polling timer (interval defined by MONITOR_INTERVAL_SECS) with immediate checks on app foreground.
 */
export const checkIdentityStatus = (): Promise<IdentityStatus[]> =>
  invoke('check_identity_status');

// ── recovery_override ─────────────────────────────────────────────────────────

/**
 * Error returned by recovery override commands.
 * Matches RecoveryError enum in recovery.rs with #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")].
 */
export type RecoveryError =
  | { code: 'RECOVERY_WINDOW_EXPIRED' }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'UNAUTHORIZED_CHANGE_NOT_FOUND' };

/**
 * Signed recovery operation ready for review and submission.
 * Matches SignedRecoveryOp struct in recovery.rs with #[serde(rename_all = "camelCase")].
 */
export interface SignedRecoveryOp {
  /** Human-readable diff of what the recovery operation changes. */
  diff: OpDiff;
  /** The signed PLC operation JSON, ready to POST to plc.directory. */
  signedOp: Record<string, unknown>;
}

/**
 * Build a recovery override operation for an unauthorized PLC change.
 *
 * Fetches the audit log, identifies the fork point, builds a counter-operation
 * that restores the pre-unauthorized state, and signs it with the device key.
 *
 * The built operation is stored in RecoveryState for subsequent submission
 * via submitRecoveryOverride().
 */
export const buildRecoveryOverride = (did: string, operationCid: string): Promise<SignedRecoveryOp> =>
  invoke('build_recovery_override_cmd', { did, operationCid });

/**
 * Submit the pending recovery override operation to plc.directory.
 *
 * Must be called after buildRecoveryOverride() — submits the stored signed
 * operation, updates the cached PLC audit log, and returns the updated DID document.
 */
export const submitRecoveryOverride = (did: string): Promise<ClaimResult> =>
  invoke('submit_recovery_override_cmd', { did });

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
 * Requires the W1 orchestrator (MM-228) to have first authenticated to the destination
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
  | { code: 'SERVICE_AUTH_FAILED'; message: string }
  | { code: 'ACCOUNT_CREATION_FAILED'; message: string }
  | { code: 'DESTINATION_CONFLICT'; message: string }
  | { code: 'REPO_TRANSFER_FAILED'; message: string }
  | { code: 'BLOB_TRANSFER_FAILED'; message: string }
  | { code: 'PREFERENCES_TRANSFER_FAILED'; message: string }
  | { code: 'VERIFICATION_INCOMPLETE'; imported: number; expected: number }
  | { code: 'ACTIVATION_FAILED'; message: string }
  | { code: 'DEACTIVATION_FAILED'; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Resolve the destination + source PDS and open the migration session (in-memory).
 * Rejects with MigrationError (e.g. DESTINATION_UNREACHABLE).
 */
export const prepareMigration = (did: string, destPdsUrl: string): Promise<void> =>
  invoke('prepare_migration', { did, destPdsUrl });

/**
 * Source-PDS OAuth: prepare -> in-app auth session -> complete (mirrors startPdsAuth).
 * Drives the ASWebAuthenticationSession via the auth-session plugin between the two Rust commands.
 */
export const startSourceAuth = async (did: string): Promise<void> => {
  const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_source_auth', {
    did,
  });
  let callbackUrl: string;
  try {
    callbackUrl = await invoke<string>('plugin:auth-session|start', {
      authUrl: prepared.authUrl,
      callbackUrlScheme: prepared.callbackScheme,
    });
  } catch (raw: unknown) {
    // A dismissed sheet reads as a cancellation; anything else surfaces as retryable.
    throw classifyAuthSessionRejection(raw, {
      code: 'SOURCE_AUTH_FAILED',
      message: 'auth session cancelled',
    });
  }
  await invoke('complete_source_auth', { did, callbackUrl });
};

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

/**
 * Prompt for biometric authentication (Face ID / Touch ID) via `@tauri-apps/plugin-biometric`.
 * Gates the PLC-op submission in the migration review screen — the user is the signer, so this
 * is the authorization boundary for an irreversible identity change, not decorative confirmation.
 *
 * Because it is a security boundary it must fail CLOSED. The plugin exists only on iOS/Android,
 * so it is imported dynamically. The ONLY case we skip is the dynamic import itself throwing —
 * the plugin module is genuinely unloadable (a host build with no plugin), so there is nothing
 * to gate against and we resolve. Whenever the plugin IS present we ALWAYS run `authenticate()`:
 * it presents Face ID / Touch ID, or — via `allowDeviceCredential` — the device passcode, and
 * rejects on cancel/failure so the caller aborts the submission.
 *
 * We deliberately do NOT pre-check `checkStatus().isAvailable` and skip when it is false: on iOS
 * that flag is false when biometrics aren't *enrolled* even though the device still has a
 * passcode that `authenticate()` would gate on, so skipping there would drop the approval gate on
 * a real device. `authenticate()` alone is the authoritative gate. (A simulator with neither an
 * enrolled biometric nor a passcode set will reject here and block — enroll one to test the
 * flow.)
 */
export const authenticateBiometric = async (reason: string): Promise<void> => {
  let plugin: typeof import('@tauri-apps/plugin-biometric');
  try {
    plugin = await import('@tauri-apps/plugin-biometric');
  } catch {
    return; // plugin module not loadable (host build) — nothing to gate against.
  }
  await plugin.authenticate(reason, { allowDeviceCredential: true });
};

// ── Agent consent + audit (auth.md claim ceremony, "My agents") ──────────────

/** One agent identity bound to this account. */
export type AgentSummary = {
  registrationId: string;
  registrationType: 'service_auth' | 'identity_assertion' | 'anonymous';
  issuer?: string;
  subject?: string;
  scopes: string[];
  /** `active` = registered, awaiting the claim ceremony; then `claimed` or `revoked`. */
  status: 'active' | 'claimed' | 'revoked';
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
};

/** One entry of an agent's append-only audit trail. */
export type AgentAuditEvent = {
  id: string;
  eventType:
    | 'registered'
    | 'claim_initiated'
    | 'claim_confirmed'
    | 'claim_expired'
    | 'token_exchanged'
    | 'repo_write'
    | 'blob_upload'
    | 'revoked';
  did?: string;
  detail?: Record<string, unknown>;
  createdAt: string;
};

/** One page of audit events, newest first; `cursor` present means more pages exist. */
export type AgentAuditPage = {
  events: AgentAuditEvent[];
  cursor?: string;
};

/** What confirming a claim-ceremony code would grant. */
export type AgentClaimPreview = {
  registrationId: string;
  registrationType: 'service_auth' | 'identity_assertion' | 'anonymous';
  issuer?: string;
  subject?: string;
  scopes: string[];
  userCodeExpiresAt: string;
};

/** Result of a confirmed claim ceremony. */
export type AgentClaimConfirmation = {
  registrationId: string;
  status: string;
  did: string;
};

/** Errors from the agent consent/management commands. */
export type AgentsError = {
  code:
    | 'NOT_AUTHENTICATED'
    | 'CODE_NOT_FOUND'
    | 'CODE_EXPIRED'
    | 'ALREADY_CLAIMED'
    | 'ACCESS_DENIED'
    | 'AGENT_NOT_FOUND'
    | 'RATE_LIMITED'
    | 'NETWORK_ERROR'
    | 'UNKNOWN';
};

/** List the agent identities bound to this account. */
export const listAgents = (): Promise<AgentSummary[]> => invoke('list_agents');

/** Revoke an agent identity (idempotent; the next token exchange is refused immediately). */
export const revokeAgent = (registrationId: string): Promise<void> =>
  invoke('revoke_agent', { registrationId });

/** Page an agent's audit trail, newest first. Pass the previous page's cursor to continue. */
export const getAgentAudit = (
  registrationId: string,
  cursor?: string
): Promise<AgentAuditPage> => invoke('get_agent_audit', { registrationId, cursor });

/**
 * Preview what confirming a claim-ceremony code would grant. Call this BEFORE the biometric
 * gate — the approval screen must show the agent's type and scope list first (informed consent).
 */
export const previewAgentClaim = (userCode: string): Promise<AgentClaimPreview> =>
  invoke('preview_agent_claim', { userCode });

/**
 * Confirm a claim ceremony — the human gate that binds the agent to this account. Callers gate
 * this behind `authenticateBiometric()`; it is the authorization boundary for granting an agent
 * standing access to the identity.
 */
export const confirmAgentClaim = (userCode: string): Promise<AgentClaimConfirmation> =>
  invoke('confirm_agent_claim', { userCode });
