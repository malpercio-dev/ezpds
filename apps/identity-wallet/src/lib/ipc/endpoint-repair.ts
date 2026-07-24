import { invoke } from '@tauri-apps/api/core';
import { authenticateBiometric } from '$lib/biometric';

// ── Repair hosting endpoint (sovereign atproto_pds PLC op) ────────────────────

/**
 * Error returned by the sovereign endpoint-repair flow.
 * Matches `EndpointRepairError` in `endpoint_repair.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]`) —
 * codes must match exactly.
 */
export type EndpointRepairError =
  // The wallet holds no authorized rotation key for this DID, so it cannot self-sign.
  | { code: 'WALLET_NOT_AUTHORIZED' }
  // The proposed URL is not https (loopback excepted) or not a bare origin.
  | { code: 'INVALID_ENDPOINT'; message: string }
  // The new endpoint did not answer the hosting probe.
  | { code: 'DESTINATION_UNREACHABLE'; message: string }
  // The new endpoint answered, but does not host this account.
  | { code: 'DESTINATION_NOT_HOSTING'; message: string }
  // The strict pre-sign guard rejected the op (something other than the endpoint would change).
  | { code: 'GUARD_REJECTED'; reason: string }
  | { code: 'INVALID_AUDIT_LOG'; message: string }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'IDENTITY_NOT_FOUND'; message: string };

/** Outcome of a hosting-endpoint repair. Matches `EndpointRepairResult` (camelCase). */
export interface EndpointRepairResult {
  /** The endpoint the DID document pointed at before the repair. */
  oldEndpoint: string;
  /** The endpoint it points at now. */
  newEndpoint: string;
  /** The submitted op's CID, or null when the document already pointed at the new endpoint. */
  opCid: string | null;
}

/**
 * Repoint a wallet-custodied did:plc identity's `atproto_pds` endpoint to the hosting
 * server's new public URL: device-key-signed PLC op, submitted directly to
 * plc.directory. Needs no session and never contacts the old (dead) endpoint — the
 * repair for "my server changed hostname and now nothing can reach my account".
 *
 * The biometric prompt precedes the IPC invocation (it gates the Secure-Enclave signing
 * of the PLC op); cancellation therefore reaches neither Rust signing code nor the network.
 */
export const repairHostingEndpoint = async (
  did: string,
  newEndpoint: string
): Promise<EndpointRepairResult> => {
  await authenticateBiometric('Confirm your hosting endpoint repair');
  return invoke('repair_hosting_endpoint', { did, newEndpoint });
};
