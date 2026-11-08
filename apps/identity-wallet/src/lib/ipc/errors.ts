import type { UnlockReason } from './identity';

/**
 * Type guard for Tauri IPC error objects with a `code` field.
 * Use in catch blocks to distinguish typed IPC errors from generic JS errors.
 */
export function isCodedError(raw: unknown): raw is { code: string } {
  return (
    typeof raw === 'object' &&
    raw !== null &&
    'code' in raw &&
    typeof (raw as { code: unknown }).code === 'string'
  );
}

/**
 * The failures every wallet command shares — session resolution, the local identity
 * store, PDS discovery, and plc.directory reads. Matches `SharedFailure` in
 * `crates/obsign-core/src/failure.rs`; each command's error union includes it, so these
 * codes mean the same thing on every screen.
 *
 * Every `message` is diagnostic (ADR-0031): log it, never put it in the user's sentence.
 * `SESSION_LOCKED` is the cue to run `unlockIdentity(did)` and retry.
 */
export type SharedFailure =
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'IDENTITY_NOT_FOUND' }
  // A transport failure — no well-formed HTTP response came back.
  | { code: 'NETWORK_ERROR'; message: string }
  // The hosting server answered with an HTTP failure.
  | { code: 'SERVER_ERROR'; status: number; message: string }
  // The DID or its host could not be resolved into something usable.
  | { code: 'UNSUPPORTED_HOST' }
  // A response this client could not use, or a local clock fault — not the server's verdict.
  | { code: 'INVALID_RESPONSE'; message: string }
  // A local Keychain failure — never the server's.
  | { code: 'KEYCHAIN_ERROR'; message: string }
  // plc.directory answered a read with an HTTP failure — an outage, not connectivity.
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  // The identity's Secure Enclave key is gone (a backup restore); retrying cannot help.
  | { code: 'DEVICE_KEY_UNUSABLE' };
