import { invoke } from '@tauri-apps/api/core';

export const greet = (name: string): Promise<string> =>
  invoke('greet', { name });

// ── create_account ──────────────────────────────────────────────────────────

export interface CreateAccountParams {
  claimCode: string;
  email: string;
  handle: string;
}

export interface CreateAccountResult {
  nextStep: string;
}

/**
 * Error returned by the `create_account` Rust command.
 *
 * Serialized as `{ code: "EXPIRED_CODE" }` etc. by the Rust backend.
 * The `message` field is present only on NETWORK_ERROR and UNKNOWN variants.
 */
export interface CreateAccountError {
  code:
    | 'EXPIRED_CODE'
    | 'REDEEMED_CODE'
    | 'EMAIL_TAKEN'
    | 'HANDLE_TAKEN'
    | 'NETWORK_ERROR'
    | 'UNKNOWN';
  message?: string;
}

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
