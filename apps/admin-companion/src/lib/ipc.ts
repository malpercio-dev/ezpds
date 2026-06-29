/**
 * Typed wrappers for all Tauri IPC commands.
 *
 * This is the ONLY file that calls `invoke()` directly; page components import
 * these functions instead. Mirrors the identity-wallet `ipc.ts` convention.
 *
 * Phase 6 exposes only the device-key primitives. Pairing, request signing, and
 * the operator commands are added in Phases 7–8.
 */
import { invoke } from '@tauri-apps/api/core';

/** The device's admin public key, as returned by the Rust backend. */
export interface DevicePublicKey {
  /** Multibase base58btc-encoded compressed P-256 point ('z'…). */
  multibase: string;
  /** Full did:key URI ('did:key:z…'). */
  keyId: string;
}

/** Tagged error from device-key operations: `{ code: "SCREAMING_SNAKE_CASE" }`. */
export interface DeviceKeyError {
  code:
    | 'KEY_GENERATION_FAILED'
    | 'KEY_NOT_FOUND'
    | 'SIGNING_FAILED'
    | 'INVALID_SIGNATURE'
    | 'KEYCHAIN_ERROR';
  message?: string;
}

/**
 * Get-or-create this device's admin key (Secure Enclave on a real device,
 * software key on the simulator/macOS). Idempotent.
 */
export function getOrCreateDeviceKey(): Promise<DevicePublicKey> {
  return invoke<DevicePublicKey>('get_or_create_device_key');
}

/**
 * Sign arbitrary bytes with the device's admin key. Returns a raw 64-byte
 * (r‖s, low-S) P-256 signature. The canonical request envelope is built in Phase 7.
 */
export function signWithDeviceKey(data: Uint8Array): Promise<Uint8Array> {
  return invoke<number[]>('sign_with_device_key', { data: Array.from(data) }).then(
    (bytes) => Uint8Array.from(bytes),
  );
}
