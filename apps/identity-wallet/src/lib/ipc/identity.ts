import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';

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

/**
 * Re-fetch an identity's PLC data document from plc.directory and re-store it in
 * the per-identity cache. The cache self-heal for docs written by earlier builds
 * without `rotationKeys` (which starve the custody badge and hide the migrate
 * entry). Best-effort callers should fall back to the cached doc on failure.
 */
export const refreshDidDoc = (did: string): Promise<Record<string, unknown>> =>
  invoke('refresh_did_doc', { did });

export const getDeviceKeyId = (did: string): Promise<string> =>
  invoke('get_device_key_id', { did });

// ── Per-DID sovereign session ───────────────────────────────────────────────

export type SovereignLoginResult = {
  did: string;
  pdsUrl: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
};

export type SovereignLoginError = {
  code:
    | 'IDENTITY_NOT_FOUND'
    | 'UNSUPPORTED_HOST'
    | 'AUTHORIZATION_FAILED'
    | 'RATE_LIMITED'
    | 'TRANSPORT_FAILURE'
    | 'KEYCHAIN_FAILURE'
    | 'SIGNING_FAILED'
    | 'DID_MISMATCH'
    | 'SERVER_MISMATCH'
    | 'INVALID_RESPONSE'
    | 'SERVER_FAILURE';
  message?: string;
  retryAfter?: string;
  status?: number;
};

/**
 * Prove control of one managed identity's device key and persist its full-access session.
 * The biometric prompt deliberately precedes the IPC invocation: cancellation therefore
 * reaches neither Rust signing code nor the network.
 */
export const sovereignLogin = async (did: string): Promise<SovereignLoginResult> => {
  await authenticateBiometric('Sign in to your identity’s hosting server');
  return invoke('sovereign_login', { did });
};
