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

// ── perform_did_ceremony ─────────────────────────────────────────────────────

/**
 * Successful result from the `perform_did_ceremony` Rust command.
 * This is a pure data shape returned on success.
 */
export type DIDCeremonyResult = {
  did: string;
  /**
   * Share 3 of 3 — the user's manual backup share, in machine form (base32 v2 share
   * envelope; legacy did:web ceremonies still return the older bare-base32 form).
   * Used for the QR rendering. Share 1 has already been stored in iCloud Keychain
   * by the Rust backend.
   */
  share3: string;
  /**
   * Share 3 rendered as the BIP-39-style word phrase (the same envelope bytes) — the
   * primary human-custody rendering on the backup screen. Empty string on the legacy
   * did:web ceremony, whose share format predates the word rendering; the screen
   * falls back to the machine form.
   */
  share3Words: string;
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
    /** Client-side recovery seed generation / share split failed before any network call. */
    | 'SHARE_GENERATION_FAILED'
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

/**
 * Error returned by the `confirm_share_backup` Rust command.
 * Serialized as `{ code: "SHARE_NOT_STORED" }` etc. by the Rust backend.
 */
export type ShareBackupError =
  | { code: 'SHARE_NOT_STORED' }
  | { code: 'KEYCHAIN_ERROR' };

/**
 * Confirm the user saved Share 3 and tear down the ceremony's Keychain staging slot
 * (the seed's and Share 2's last local copy). The Rust side refuses (SHARE_NOT_STORED)
 * if the ceremony DID's Share 1 is not durably stored yet — the staging material must
 * outlive any state where it is the only home of the seed. Pass the DID returned by the
 * ceremony so the durability check reads that identity's per-DID slot. Idempotent.
 */
export const confirmShareBackup = (did: string): Promise<void> =>
  invoke('confirm_share_backup', { did });

export type DidWebPreparation = {
  deviceKeyMultibase: string;
  repoKeyMultibase: string;
  pdsUrl: string;
};

/** Load the device, repository, and PDS values needed to compose a new did:web document. */
export const prepareDidWebCeremony = (): Promise<DidWebPreparation> =>
  invoke('prepare_did_web_ceremony');

/** Verify the live did:web bytes and promote the pending account. */
export const completeDidWebCeremony = (
  documentText: string,
  password: string,
  enableManagedHosting: boolean,
): Promise<DIDCeremonyResult> =>
  invoke('complete_did_web_ceremony', { documentText, password, enableManagedHosting });

/** Open the native platform share sheet for a text document. */
export const shareTextNative = (text: string): Promise<void> =>
  invoke('plugin:sharesheet|share_text', { text });

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
