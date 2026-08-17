// Reconstructs the account's plc.directory audit log from the genesis operation the ceremony
// signed, so the mock directory can answer `GET /{did}/log/audit` with the real thing.
//
// Nothing is invented here. The ceremony's genesis op is rebuilt from the key material interop
// persisted, and this refuses to return a log whose derived DID is not the account's — a total
// check, not a spot check: a did:plc *is* the hash of its signed genesis operation, so a
// matching DID means these bytes are the exact bytes the PDS accepted. If the ceremony ever
// changes shape (a different rotation-key order, a fourth key, another service entry), this
// throws with both DIDs rather than serving a plausible-looking log whose `rotationKeys` would
// then quietly reject every wallet approval as "consent approval rejected".
//
// Rebuilding rather than capturing is what the material allows: `POST /v1/dids` does not hand
// the signed op back, and `describeRepo`'s `didDoc` carries no `rotationKeys` at all. PLC
// signing is deterministic (RFC 6979), so the rebuild is byte-identical rather than merely
// equivalent — and the DID check is what proves it.

import { buildGenesisOp, keypairFromHex } from 'ezpds-interop/src/crypto.js';

import type { AuditEntry } from './mock-plc.ts';

/** The ceremony outputs the audit log is rebuilt from; all persisted by `createAccount`. */
export interface AccountKeyMaterial {
  did: string;
  handle: string;
  rotationKeyId: string;
  rotationKeyPrivateHex: string;
  recoveryKeyId: string;
  repoSigningKeyId: string;
}

/**
 * Rebuild the account's genesis operation and wrap it as a one-entry audit log.
 *
 * `pdsUrl` must be the base URL the ceremony used — it is inside the signed operation, so a
 * different one derives a different DID and trips the check.
 */
export async function buildAccountAuditLog(
  account: AccountKeyMaterial,
  pdsUrl: string,
): Promise<AuditEntry[]> {
  const { did, signedOp, cid } = await buildGenesisOp({
    rotationKeyId: account.rotationKeyId,
    recoveryKeyId: account.recoveryKeyId,
    repoSigningKeyId: account.repoSigningKeyId,
    rotationKeypair: await keypairFromHex(account.rotationKeyPrivateHex),
    handle: account.handle,
    pdsUrl,
  });

  if (did !== account.did) {
    throw new Error(
      `rebuilt genesis operation derives ${did}, but the account is ${account.did}. The ` +
        'interop account ceremony no longer produces the operation this module reconstructs, ' +
        'so the audit log it would serve is not the account\'s real PLC state. Re-check ' +
        'buildGenesisOp() in tools/interop/src/crypto.js against tools/interop/src/account.js.',
    );
  }

  return [
    {
      did,
      cid,
      // Fixed rather than "now": nothing reads it, and a frozen value keeps the log
      // reproducible across runs.
      createdAt: '2026-01-01T00:00:00.000Z',
      nullified: false,
      operation: signedOp,
    },
  ];
}
