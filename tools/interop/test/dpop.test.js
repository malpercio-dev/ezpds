// OAuth DPoP proof construction, pinned because a wrong claim is a 401 with no
// useful message. Spaces credentials are no longer DPoP-bound — they carry an
// RFC 9421 signature (src/space-signature.js), so the DPoP builder here is
// OAuth's alone.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHash } from 'node:crypto';

import { newDpopKey, dpopProof } from '../src/dpop.js';

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
