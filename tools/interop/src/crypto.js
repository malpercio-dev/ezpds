// P-256 key handling and did:plc genesis-op construction. ezpds never mints a
// server-custodied DID: the client builds and signs the genesis operation itself
// (rotationKeys[0] = our locally-held rotation key), so the private keys the CLI
// generates here are the real root of control for test accounts — they are
// persisted in the local state file and must never be committed.

import * as crypto from 'node:crypto';
import * as dagCbor from '@ipld/dag-cbor';
import { P256Keypair } from '@atproto/crypto';

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32Encode(buffer) {
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return result;
}

/** Generate a fresh exportable P-256 keypair. */
export async function newKeypair() {
  const keypair = await P256Keypair.create({ exportable: true });
  const exported = await keypair.export();
  const privateKey = exported instanceof Uint8Array ? exported : exported.bytes ?? exported;
  return {
    keypair,
    keyId: keypair.did(), // did:key:zDn...
    privateKeyHex: Buffer.from(privateKey).toString('hex'),
    publicKeyBase64: Buffer.from(keypair.publicKeyBytes()).toString('base64'),
  };
}

/** Rehydrate a keypair from the hex private key stored in the state file. */
export async function keypairFromHex(privateKeyHex) {
  return P256Keypair.import(privateKeyHex, { exportable: true });
}

/**
 * Sign a did:plc operation (genesis or migration) with a rotation keypair.
 *
 * The signing primitive shared by every PLC op: DAG-CBOR encode the unsigned op,
 * sign those bytes with the rotation key, and append the signature as base64url.
 * Returns the signed op (all unsigned fields plus `sig`). This is the single
 * source of truth for PLC signing — genesis and migration both consume it, so
 * the two paths cannot silently diverge.
 */
export async function signPlcOp(unsignedOp, rotationKeypair) {
  const unsignedBytes = dagCbor.encode(unsignedOp);
  const signature = await rotationKeypair.sign(unsignedBytes);
  return { ...unsignedOp, sig: Buffer.from(signature).toString('base64url') };
}

/**
 * Build and sign a did:plc genesis operation for the client-share ceremony.
 *
 * rotationKeys = [rotation, recovery, PDS] (the recovery slot mirrors the wallet's
 * client-share ceremony: the device/rotation key stays highest-priority, the
 * wallet-derived recovery key sits in the middle, the PDS repo signing key last):
 *   rotationKeys[0] = the locally-held rotation key (signs this op),
 *   rotationKeys[1] = the recovery rotation key (its did:key is declared as
 *                     `recoveryKey` to POST /v1/dids; the server verifies it appears here),
 *   rotationKeys[2] = the PDS-issued per-account repo signing key, which is also
 *                     verificationMethods.atproto (it signs repo commits on the PDS).
 *
 * Returns the derived DID (`did:plc:` + first 24 chars of base32(sha256(signed
 * op DAG-CBOR))) and the signed op as a JSON-ready object.
 */
export async function buildGenesisOp({
  rotationKeyId,
  recoveryKeyId,
  repoSigningKeyId,
  rotationKeypair,
  handle,
  pdsUrl,
}) {
  const unsignedOp = {
    prev: null,
    type: 'plc_operation',
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: pdsUrl,
      },
    },
    alsoKnownAs: [`at://${handle}`],
    rotationKeys: [rotationKeyId, recoveryKeyId, repoSigningKeyId],
    verificationMethods: {
      atproto: repoSigningKeyId,
    },
  };

  const signedOp = await signPlcOp(unsignedOp, rotationKeypair);

  const signedBytes = dagCbor.encode(signedOp);
  const hash = crypto.createHash('sha256').update(signedBytes).digest();
  const did = `did:plc:${base32Encode(hash).slice(0, 24)}`;

  return { did, signedOp };
}

/**
 * Build a structurally-valid v2 Shamir Share 2 envelope for the client-share
 * `escrowShare` field of POST /v1/dids.
 *
 * The server (crates/crypto `ShareEnvelope::decode_share`) validates only the
 * envelope's structure — version, index, and trailing checksum — and that the index
 * is 2; it never reconstructs a secret from it. The interop harness provisions
 * accounts to exercise other surfaces and does not test recovery, so a fresh random
 * payload under a random set_id is sufficient (the recovery key in `rotationKeys`
 * is likewise an independent keypair). The wire layout mirrors the Rust envelope:
 * `version(1)=2 || set_id(4 BE) || index(1)=2 || payload(32) || checksum(4 =
 * sha256(preceding 38)[..4])`, uppercase base32 (RFC 4648, no padding).
 */
export function encodeEscrowShare() {
  const preimage = Buffer.alloc(38);
  preimage.writeUInt8(2, 0); // version
  crypto.randomBytes(4).copy(preimage, 1); // set_id (4B big-endian; random bytes are fine)
  preimage.writeUInt8(2, 5); // index — the escrow slot holds Share 2 only
  crypto.randomBytes(32).copy(preimage, 6); // payload
  const checksum = crypto.createHash('sha256').update(preimage).digest().subarray(0, 4);
  const envelope = Buffer.concat([preimage, checksum]); // 42 bytes
  return base32Encode(envelope).toUpperCase();
}

/** Cryptographically random password suitable for a test account. */
export function randomPassword() {
  return crypto.randomBytes(18).toString('base64url'); // 24 chars
}

/** Short random suffix for handles/names. */
export function randomSuffix(len = 6) {
  return crypto.randomBytes(8).toString('base64url').replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, len).padEnd(len, '0');
}
