// The two pieces of the spaces client with logic worth pinning: DPoP proof
// construction (a wrong claim is a 401 with no useful message) and CAR parsing
// (whose whole point is rejecting a malformed export the old length check passed).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHash } from 'node:crypto';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

import { newDpopKey, dpopProof } from '../src/dpop.js';
import { parseCar, decodeBlock } from '../src/car.js';

const DAG_CBOR = 0x71;

function decodeJwt(jwt) {
  const [header, claims] = jwt.split('.').slice(0, 2).map((p) => JSON.parse(Buffer.from(p, 'base64url')));
  return { header, claims };
}

test('resource proof: htu drops the query, ath hashes the bound token, signature verifies', async () => {
  const key = await newDpopKey();
  const jwt = await dpopProof(key, {
    method: 'get',
    url: 'https://space.example/xrpc/com.atproto.space.getRepo?space=at%3A%2F%2Fx&repo=did%3Aplc%3Ay',
    boundToken: 'the-credential',
  });
  const { header, claims } = decodeJwt(jwt);

  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'ES256');
  assert.deepEqual(Object.keys(header.jwk), ['crv', 'kty', 'x', 'y']); // RFC 7638 members, in order
  assert.equal(claims.htm, 'GET');
  assert.equal(claims.htu, 'https://space.example/xrpc/com.atproto.space.getRepo');
  assert.equal(claims.ath, createHash('sha256').update('the-credential').digest('base64url'));
  assert.ok(claims.jti);

  const publicKey = await webcrypto.subtle.importKey('jwk', { ...header.jwk, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const [h, c, sig] = jwt.split('.');
  const ok = await webcrypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    Buffer.from(sig, 'base64url'),
    Buffer.from(`${h}.${c}`),
  );
  assert.ok(ok, 'ES256 signature must verify against the embedded JWK');
});

test('mint-time proof carries no ath', async () => {
  const key = await newDpopKey();
  const { claims } = decodeJwt(await dpopProof(key, {
    method: 'POST',
    url: 'https://space.example/xrpc/com.atproto.space.getSpaceCredential',
  }));
  assert.equal(claims.ath, undefined);
  assert.equal(claims.htm, 'POST');
});

test('each proof gets a fresh jti', async () => {
  const key = await newDpopKey();
  const one = decodeJwt(await dpopProof(key, { method: 'GET', url: 'https://h/x' })).claims.jti;
  const two = decodeJwt(await dpopProof(key, { method: 'GET', url: 'https://h/x' })).claims.jti;
  assert.notEqual(one, two);
});

function varint(n) {
  const out = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return Uint8Array.from(out);
}

async function block(value) {
  const bytes = dagCbor.encode(value);
  return { cid: CID.create(1, DAG_CBOR, await sha256.digest(bytes)), bytes };
}

function buildCar(roots, blocks) {
  const header = dagCbor.encode({ version: 1, roots: roots.map((r) => r.cid) });
  const parts = [varint(header.length), header];
  for (const b of blocks) {
    const frame = Buffer.concat([Buffer.from(b.cid.bytes), Buffer.from(b.bytes)]);
    parts.push(varint(frame.length), frame);
  }
  return new Uint8Array(Buffer.concat(parts.map(Buffer.from)));
}

test('parseCar walks a two-root space export and resolves the index', async () => {
  const record = await block({ $type: 'x.note', text: 'hi' });
  const commit = await block({ rev: '3l', sig: new Uint8Array([1, 2, 3]) });
  const index = await block({ 'x.note/abc': record.cid });

  const car = await parseCar(buildCar([commit, index], [commit, index, record]));
  assert.deepEqual(car.roots, [commit.cid.toString(), index.cid.toString()]);
  assert.equal(car.blocks.size, 3);
  assert.equal(decodeBlock(car, commit.cid.toString()).rev, '3l');
  assert.equal(decodeBlock(car, index.cid.toString())['x.note/abc'].toString(), record.cid.toString());
});

test('parseCar rejects a block that does not hash to its CID', async () => {
  const commit = await block({ rev: '3l', sig: new Uint8Array([1]) });
  const index = await block({});
  const liar = { cid: index.cid, bytes: dagCbor.encode({ tampered: true }) };
  await assert.rejects(
    () => parseCar(buildCar([commit, index], [commit, liar])),
    /does not hash to its CID/,
  );
});

test('parseCar rejects a truncated block frame', async () => {
  const commit = await block({ rev: '3l', sig: new Uint8Array([1]) });
  const index = await block({});
  const full = buildCar([commit, index], [commit, index]);
  await assert.rejects(() => parseCar(full.subarray(0, full.length - 5)), /runs past end of file/);
});
