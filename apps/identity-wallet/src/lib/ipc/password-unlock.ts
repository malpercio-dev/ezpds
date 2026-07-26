/**
 * Opening a locked identity whose host is not Custos.
 *
 * A locked identity — no persisted session, a revoked refresh chain, or a host that moved —
 * used to have exactly one way back: the biometric, passwordless `sovereignLogin`, which only
 * a host advertising `sovereignSessions` can serve. On any other spec-compliant PDS that left
 * app passwords, change handle, identity removal, and blob restore dark, despite all four
 * being plain standard-lexicon features.
 *
 * These two commands supply the second route. {@link getIdentityUnlockRoute} asks which unlock
 * the identity's *current* host can serve; {@link unlockIdentityWithPassword} runs the password
 * `createSession` and persists the resulting pair into the same record the session provider
 * already reads — so everything downstream (refresh, rotation, host-change discard) is
 * unchanged. Callers should reach for {@link unlockIdentity} in `$lib/unlock` rather than these
 * wrappers directly; it owns the branch.
 */
import { invoke } from '@tauri-apps/api/core';

import type { SessionReady } from './identity';

/** Which unlock a host can serve. */
export type UnlockMethod = 'SOVEREIGN' | 'PASSWORD';

/** The unlock route for one identity, plus what its prompt needs to say. */
export type UnlockRoute = {
  method: UnlockMethod;
  /** The identity's current hosting PDS, named in the prompt so the ask is unambiguous. */
  pdsUrl: string;
  /** The account's handle, prefilled as the identifier; null when the DID document has none. */
  handle: string | null;
};

export type UnlockError = {
  code:
    | 'IDENTITY_NOT_FOUND'
    | 'UNSUPPORTED_HOST'
    | 'TWO_FACTOR_REQUIRED'
    | 'INVALID_CREDENTIALS'
    | 'ACCOUNT_MISMATCH'
    | 'INSECURE_HOST_URL'
    | 'RATE_LIMITED'
    | 'SERVER_ERROR'
    | 'NETWORK_ERROR'
    | 'KEYCHAIN'
    | 'INVALID_RESPONSE';
  retryAfter?: string;
  message?: string;
};

/**
 * Which unlock should this identity's screen offer?
 *
 * A host that could not be reached reports `SOVEREIGN`: an unanswered capability probe means
 * the network blinked, not that the server lacks sovereign sessions, and asking for a password
 * on that basis would be a false claim about the user's server.
 */
export const getIdentityUnlockRoute = (did: string): Promise<UnlockRoute> =>
  invoke('get_identity_unlock_route', { did });

/**
 * Open a locked identity with the account's password.
 *
 * Deliberately not biometric-gated — the password is itself the presence proof, and nothing is
 * signed with the device key here. The irreversible operations this unlocks keep their own
 * gates, exactly as they do after a sovereign unlock. The password is sent once and never
 * stored; only the returned JWT pair is persisted.
 *
 * Rejects with `TWO_FACTOR_REQUIRED` when the account has email 2FA and no code was supplied —
 * the host has emailed one, and the caller re-invokes with `authFactorToken`.
 */
export const unlockIdentityWithPassword = (
  did: string,
  identifier: string,
  password: string,
  authFactorToken?: string,
): Promise<SessionReady> =>
  invoke('unlock_identity_with_password', { did, identifier, password, authFactorToken });
