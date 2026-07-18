import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';
import type { ClaimResult } from './claim';
import type { UnlockReason } from './identity';

// ── Change handle (sovereign alsoKnownAs PLC op) ──────────────────────────────

/**
 * Error returned by the sovereign change-handle flow.
 * Matches `HandleChangeError` in `handle_change.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 *
 * `SESSION_LOCKED` is the cue to run the passwordless {@link sovereignLogin} (biometric) and retry:
 * the identity's full-access session could not be restored/refreshed without a fresh device-key proof.
 */
export type HandleChangeError =
  // The wallet holds no authorized rotation key for this DID, so it cannot self-sign.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The identity is locked — run sovereignLogin(did) and retry. `reason` mirrors ensureIdentitySession.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  // The hosting PDS or plc.directory rate-limited the request; `retryAfter` is the server's Retry-After.
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  // The requested handle is already taken / reserved on the hosting PDS.
  | { code: 'HANDLE_NOT_AVAILABLE'; message: string }
  // The requested handle is syntactically invalid or not a served domain.
  | { code: 'INVALID_HANDLE'; message: string }
  // updateHandle failed for a reason the wallet doesn't model specially (e.g. 401/403/5xx).
  | { code: 'UPDATE_HANDLE_FAILED'; status: number; message: string }
  // The strict pre-sign guard rejected the op (something other than alsoKnownAs would change).
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  // A server-side step failed for a non-connectivity reason (session refresh verdict,
  // unsupported host, malformed response, or session storage). Details in `message`.
  | { code: 'SERVER_ERROR'; message: string }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string };

/**
 * List the served handle domains the DID's HOSTING PDS offers
 * (`describeServer.availableUserDomains`, e.g. `[".ezpds-staging.up.railway.app"]`).
 *
 * Distinct from the create flow's `getAvailableUserDomains` (which targets the single configured
 * Custos): this discovers the identity's actual host, so a claimed/migrated DID gets the right list.
 */
export const getIdentityHandleDomains = (did: string): Promise<string[]> =>
  invoke('get_identity_handle_domains', { did });

/**
 * Change a wallet-custodied did:plc identity's handle: `updateHandle` on the hosting PDS, then a
 * device-key-signed `alsoKnownAs` PLC op to plc.directory, then a cache refresh — passwordless
 * end to end.
 *
 * The biometric prompt precedes the IPC invocation (it gates the Secure-Enclave signing of the PLC
 * op); cancellation therefore reaches neither Rust signing code nor the network. If the identity's
 * session is locked, the call rejects with `SESSION_LOCKED` — run {@link sovereignLogin} and retry.
 *
 * `handle` is the full handle (e.g. `alice.ezpds-staging.up.railway.app`), NOT the bare label.
 * Resolves with the updated DID document.
 */
export const changeHandle = async (did: string, handle: string): Promise<ClaimResult> => {
  await authenticateBiometric('Confirm your handle change');
  return invoke('change_handle_cmd', { did, handle });
};
