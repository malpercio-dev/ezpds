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
  | { code: 'NOT_AUTHENTICATED' };

export const startOAuthFlow = (): Promise<void> => invoke('start_oauth_flow');
