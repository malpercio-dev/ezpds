import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { UnlockReason } from './identity';

// ── App passwords ("Sign in to Bluesky and other apps") ───────────────────────
//
// A key-sovereign Custos account is passwordless, so the official Bluesky app —
// which signs into a third-party PDS with password `createSession`, not OAuth —
// has nothing to type. The app password minted here is that missing credential:
// a scoped, revocable password that opens a `com.atproto.appPass` session. That
// session can post, like, follow, and browse via the AppView, but can never touch
// account management, identity/PLC operations, agents, or app passwords themselves.
// Direct messages (chat) additionally require the `privileged` flag at mint time.

/** Result of minting an app password. `password` is shown ONCE — never retrievable again. */
export type AppPasswordCreated = {
  name: string;
  /** The generated `xxxx-xxxx-xxxx-xxxx` secret. Display once, offer copy, then drop it. */
  password: string;
  createdAt: string;
  privileged: boolean;
};

/** One existing app password — metadata only, never the secret. */
export type AppPasswordEntry = {
  name: string;
  createdAt: string;
  privileged: boolean;
};

/**
 * Error returned by the app-password commands.
 * Matches `AppPasswordsError` in `app_passwords.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * `SESSION_LOCKED` is the cue to run the passwordless {@link sovereignLogin} (biometric) and retry.
 */
export type AppPasswordsError =
  // The identity is locked — run sovereignLogin(did) and retry. `reason` mirrors ensureIdentitySession.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  // The hosting PDS rate-limited the request; `retryAfter` is the server's Retry-After.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // An app password with this name already exists — pick a different name.
  | { code: 'DUPLICATE_NAME' }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  // A server-side step failed for a non-connectivity reason. `status` is the HTTP code when
  // the hosting PDS refused the request, or null for a non-HTTP session failure (unsupported
  // host, keychain, malformed response); `message` is the server's own error text.
  | { code: 'SERVER_ERROR'; status: number | null; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Mint a named app password for the identity. Resolves with the generated secret,
 * which is surfaced ONCE — the server stores only a hash.
 *
 * The biometric prompt precedes the IPC invocation: minting creates a durable login
 * credential for the account, so cancellation must reach neither Rust nor the network.
 * Set `privileged` only when the credential needs direct-message (chat) access.
 */
export const createAppPassword = async (
  did: string,
  name: string,
  privileged: boolean
): Promise<AppPasswordCreated> => {
  await authenticateBiometric('Create an app password for this identity');
  return invoke('create_app_password', { did, name, privileged });
};

/** List the identity's app passwords — names, creation times, privilege; never secrets. */
export const listAppPasswords = (did: string): Promise<AppPasswordEntry[]> =>
  invoke('list_app_passwords', { did });

/**
 * Revoke a named app password. The server deletes the credential and its
 * sessions/refresh tokens atomically, so a signed-in app is cut off immediately.
 * Callers gate this behind `authenticateBiometric()` in the confirming screen.
 */
export const revokeAppPassword = (did: string, name: string): Promise<void> =>
  invoke('revoke_app_password', { did, name });
