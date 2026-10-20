// The Atproto Spaces RFC 9421 signer: a wrong signature base is a bare 401 from the
// server, so pin the exact base and the header shapes here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifySignature } from '@atproto/crypto';

import { newSpaceKey, spaceSigHeaders } from '../src/space-signature.js';

function signatureBytes(headers) {
  const match = /^atproto-space=:([A-Za-z0-9+/=]+):$/.exec(headers.Signature);
  assert.ok(match, headers.Signature);
  return new Uint8Array(Buffer.from(match[1], 'base64'));
}

test('credential use covers authorization then the audience, signed by the bound key', async () => {
  const key = await newSpaceKey();
  const headers = await spaceSigHeaders(key, {
    authorization: 'Atproto-Space the-credential',
    audience: 'did:plc:repo',
  });
  assert.equal(headers.Authorization, 'Atproto-Space the-credential');
  assert.equal(headers['Atproto-Space-Audience'], 'did:plc:repo');
  assert.equal(headers['Signature-Input'], 'atproto-space=("authorization" "atproto-space-audience")');

  const base = '"authorization": Atproto-Space the-credential\n'
    + '"atproto-space-audience": did:plc:repo\n'
    + '"@signature-params": ("authorization" "atproto-space-audience")';
  const sig = signatureBytes(headers);
  assert.equal(sig.length, 64);
  assert.ok(await verifySignature(key.did(), new TextEncoder().encode(base), sig));
});

test('the credential exchange covers authorization alone and names its key', async () => {
  const key = await newSpaceKey();
  const headers = await spaceSigHeaders(key, { authorization: 'Bearer delegation' });
  assert.equal(headers['Atproto-Space-Audience'], undefined);
  const input = `("authorization");keyid="${key.did()}"`;
  assert.equal(headers['Signature-Input'], `atproto-space=${input}`);
  assert.match(key.did(), /^did:key:zDn/);

  const base = `"authorization": Bearer delegation\n"@signature-params": ${input}`;
  assert.ok(await verifySignature(key.did(), new TextEncoder().encode(base), signatureBytes(headers)));
});
