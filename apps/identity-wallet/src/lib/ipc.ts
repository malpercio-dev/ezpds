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
