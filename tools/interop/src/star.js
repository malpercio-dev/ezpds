// STAR archive parsing (https://dasl.ing/star.html), for a space repo export:
//
//   [ magic | len | meta ] [ 1 | len | key | len | val ] ... [ 0 ]
//
// The `atproto-space-repo` profile puts the commit in the metadata and requires
// record keys in strict bytewise order, which `parseStar` checks rather than trusts.

import * as dagCbor from '@ipld/dag-cbor';

const MAGIC = [0x2a, 0x6c, 0x01, 0x00];

function readVarint(bytes, offset) {
  let value = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    const byte = bytes[pos++];
    if (byte === undefined) throw new Error('STAR varint runs past end of archive');
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [value, pos];
    shift += 7;
  }
}

function readFrame(bytes, offset) {
  const [len, start] = readVarint(bytes, offset);
  if (start + len > bytes.length) throw new Error('STAR frame runs past end of archive');
  return [bytes.subarray(start, start + len), start + len];
}

/**
 * Parse a whole STAR archive, refusing duplicate or unsorted keys.
 *
 * @returns {{meta: object, pairs: {key: string, value: Uint8Array}[]}}
 */
export function parseStar(bytes) {
  if (!MAGIC.every((b, i) => bytes[i] === b)) throw new Error('not a STAR archive (bad magic)');
  const [metaBytes, afterMeta] = readFrame(bytes, MAGIC.length);
  const meta = dagCbor.decode(metaBytes);
  const pairs = [];
  let offset = afterMeta;
  let prev;
  for (;;) {
    const control = bytes[offset++];
    if (control === 0x00) break;
    if (control !== 0x01) throw new Error(`STAR control byte ${control} is not a pair or the end`);
    const [key, afterKey] = readFrame(bytes, offset);
    const [value, afterValue] = readFrame(bytes, afterKey);
    if (prev && Buffer.compare(Buffer.from(key), Buffer.from(prev)) <= 0) {
      throw new Error(`STAR key ${Buffer.from(key).toString()} is duplicated or out of order`);
    }
    prev = key;
    pairs.push({ key: Buffer.from(key).toString(), value });
    offset = afterValue;
  }
  if (offset !== bytes.length) throw new Error('STAR archive has bytes after its end');
  return { meta, pairs };
}
