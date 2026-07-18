import { invoke } from '@tauri-apps/api/core';

// ── Wallet-confirmed OAuth consent (Phase A) ─────────────────────────────────
//
// Per-identity: both commands take the selected `did` and resolve that identity's hosting PDS.
// `confirmOAuthConsent` signs a device-key envelope over the pending request; callers gate it
// behind `authenticateBiometric()`, so a cancelled prompt signs and sends nothing.

/** A pending OAuth authorization the wallet previews before the biometric gate. */
export type ConsentPreview = {
  requestId: string;
  clientId: string;
  clientName?: string;
  redirectUri: string;
  /** The origin the consent page was requested from (for display). */
  origin?: string;
  /** The requesting IP (for display). */
  ip?: string;
  /** The scope tokens the client requested — the wallet may uncheck individual ones. */
  requestedScope: string[];
  /** If set, the request is pre-bound to this DID; approving as a different DID is refused. */
  loginHint?: string;
};

/** The recorded decision for a consent request. */
export type ConsentDecision = {
  status: 'approved' | 'denied';
  did: string;
};

/**
 * Errors from the consent commands. Matches `ConsentError` in `oauth_consent.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`) — codes must match exactly.
 */
export type ConsentError =
  | { code: 'IDENTITY_NOT_FOUND' }
  | { code: 'UNSUPPORTED_HOST' }
  | { code: 'REQUEST_NOT_FOUND' }
  | { code: 'APPROVAL_REJECTED' }
  | { code: 'ALREADY_RESOLVED' }
  | { code: 'RATE_LIMITED'; retryAfter?: string }
  | { code: 'TRANSPORT_FAILURE'; message: string }
  | { code: 'KEYCHAIN_FAILURE'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'DID_MISMATCH' }
  | { code: 'SERVER_MISMATCH' }
  | { code: 'INVALID_RESPONSE'; message: string }
  | { code: 'SERVER_FAILURE'; status: number };

/**
 * Preview a pending authorization by its typed `userCode`, against the selected DID's hosting PDS.
 * Call this BEFORE the biometric gate — the approval screen must show the client, origin, and
 * scope list first (informed consent).
 */
export const previewOAuthConsent = (did: string, userCode: string): Promise<ConsentPreview> =>
  invoke('preview_oauth_consent', { did, userCode });

/**
 * Sign and submit a decision for a previewed authorization. `grantedScope` is the space-joined
 * scope set the wallet chose (empty for a denial). Gate this behind `authenticateBiometric()` — it
 * is the authorization boundary that signs the consent envelope with the identity's device key.
 */
export const confirmOAuthConsent = (
  did: string,
  requestId: string,
  clientId: string,
  decision: 'approve' | 'deny',
  grantedScope: string
): Promise<ConsentDecision> =>
  invoke('confirm_oauth_consent', { did, requestId, clientId, decision, grantedScope });
