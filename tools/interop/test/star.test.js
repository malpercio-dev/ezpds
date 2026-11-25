// The space export check parses the STAR archive rather than counting its bytes,
// so a malformed or misordered export from a foreign host fails loudly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as dagCbor from '@ipld/dag-cbor';

import { parseStar } from '../src/star.js';

function varint(n) {
  const out = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return Buffer.from(out);
}

function frame(bytes) {
  return Buffer.concat([varint(bytes.length), Buffer.from(bytes)]);
}

function buildStar(meta, keys) {
  const parts = [Buffer.from([0x2a, 0x6c, 0x01, 0x00]), frame(dagCbor.encode(meta))];
  for (const key of keys) {
    parts.push(Buffer.from([0x01]), frame(Buffer.from(key)), frame(dagCbor.encode({ text: key })));
  }
  parts.push(Buffer.from([0x00]));
  return new Uint8Array(Buffer.concat(parts));
}

const META = { $type: 'atproto-space-repo', ver: 1, rev: '3l', data: new Uint8Array(32) };

test('parseStar reads the commit and the records in order', () => {
  const { meta, pairs } = parseStar(buildStar(META, ['x.note/a', 'x.note/b']));
  assert.equal(meta.$type, 'atproto-space-repo');
  assert.deepEqual(pairs.map((p) => p.key), ['x.note/a', 'x.note/b']);
  assert.equal(dagCbor.decode(pairs[1].value).text, 'x.note/b');
});

test('parseStar rejects keys out of order and a truncated archive', () => {
  assert.throws(() => parseStar(buildStar(META, ['x.note/b', 'x.note/a'])), /out of order/);
  const full = buildStar(META, ['x.note/a']);
  assert.throws(() => parseStar(full.subarray(0, full.length - 4)), /past end/);
});
