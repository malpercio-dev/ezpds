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

// ── Custom-handle DNS pre-flight ──────────────────────────────────────────────

/**
 * Where a custom-domain handle currently points.
 * Matches `CustomHandleDnsStatus` in `handle_change.rs` — values must match exactly.
 *
 * - `VERIFIED` — the hosting PDS resolves the handle to this DID; `updateHandle`'s gate will pass.
 * - `PROPAGATING` — the wallet's own DNS lookup sees the record but the hosting PDS doesn't yet.
 * - `WRONG_DID` — the handle currently resolves to a different DID (`foundDid`).
 * - `NOT_FOUND` — no `_atproto` TXT record (or well-known fallback) found from either vantage.
 */
export type CustomHandleDnsStatus = 'VERIFIED' | 'PROPAGATING' | 'WRONG_DID' | 'NOT_FOUND';

/** Result of {@link checkCustomHandleDns}. Matches `CustomHandleDnsCheck` in `handle_change.rs`. */
export type CustomHandleDnsCheck = {
  status: CustomHandleDnsStatus;
  /** The DID the handle currently resolves to when it isn't this identity's (status `WRONG_DID`). */
  foundDid: string | null;
  /** The DNS record name the domain owner must create: `_atproto.<handle>`. */
  recordName: string;
  /** The exact TXT record value: `did=<did>`. */
  recordValue: string;
};

/**
 * Read-only pre-flight for a handle on a domain the user owns: reports where the handle
 * currently points (the hosting PDS's vantage — the gate `updateHandle` enforces — plus the
 * wallet's own DNS TXT lookup) and the exact `_atproto` TXT record required. No biometric
 * gate: nothing is signed or changed. Rejections use the same {@link HandleChangeError} union
 * as {@link changeHandle}.
 */
export const checkCustomHandleDns = (did: string, handle: string): Promise<CustomHandleDnsCheck> =>
  invoke('check_custom_handle_dns', { did, handle });
