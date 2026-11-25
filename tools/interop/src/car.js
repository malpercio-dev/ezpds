// CARv1 header parsing, enough for the plain sync check (one root, compared
// against getLatestCommit). The space export is a STAR archive (`star.js`).

import * as dagCbor from '@ipld/dag-cbor';

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
