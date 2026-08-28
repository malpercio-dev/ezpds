// CARv1 parsing. `parseCarHeader` is enough for the plain sync check (one root,
// compared against getLatestCommit); the space export needs the full walk, because
// its whole contract is structural: two roots in order (signed commit, then the
// DRISL record index) with the record blocks following in the index's order.
//
// A length check would pass a foreign host's malformed CAR, which is exactly the
// bug an interop harness exists to catch — so blocks are verified against the CIDs
// that name them.

import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

const SHA2_256 = 0x12;

function readVarint(bytes, offset) {
  let value = 0n;
  let shift = 0n;
  let pos = offset;
  for (;;) {
    const byte = bytes[pos++];
    if (byte === undefined) throw new Error('CAR varint runs past end of file');
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return [Number(value), pos];
}

/** Parse a CARv1 header and return { version, roots: [cidString], size }. */
export function parseCarHeader(bytes) {
  const [headerLen, bodyStart] = readVarint(bytes, 0);
  const header = dagCbor.decode(bytes.subarray(bodyStart, bodyStart + headerLen));
  return {
    version: header.version,
    roots: (header.roots ?? []).map((cid) => cid.toString()),
    size: bytes.length,
    bodyStart: bodyStart + headerLen,
  };
}

/**
 * Parse a whole CARv1: header plus every block, each verified against its own CID.
 *
 * @returns {Promise<{version: number, roots: string[], blocks: Map<string, Uint8Array>}>}
 */
export async function parseCar(bytes) {
  const header = parseCarHeader(bytes);
  if (header.version !== 1) throw new Error(`unsupported CAR version ${header.version}`);

  const blocks = new Map();
  let offset = header.bodyStart;
  while (offset < bytes.length) {
    const [frameLen, cidStart] = readVarint(bytes, offset);
    const frameEnd = cidStart + frameLen;
    if (frameEnd > bytes.length) throw new Error('CAR block frame runs past end of file');
    const [cid, block] = CID.decodeFirst(bytes.subarray(cidStart, frameEnd));
    // atproto is sha-256 everywhere; anything else is a foreign host we cannot verify,
    // and passing it silently would defeat the point of parsing at all.
    if (cid.multihash.code !== SHA2_256) throw new Error(`CAR block ${cid} uses non-sha256 multihash ${cid.multihash.code}`);
    const digest = await sha256.digest(block);
    if (Buffer.compare(Buffer.from(digest.bytes), Buffer.from(cid.multihash.bytes)) !== 0) {
      throw new Error(`CAR block ${cid} does not hash to its CID`);
    }
    blocks.set(cid.toString(), block);
    offset = frameEnd;
  }
  return { version: header.version, roots: header.roots, blocks };
}

/** Decode a DAG-CBOR block from a parsed CAR by root/CID string. */
export function decodeBlock(car, cidString) {
  const block = car.blocks.get(cidString);
  if (!block) throw new Error(`CAR is missing the block for ${cidString}`);
  return dagCbor.decode(block);
}
