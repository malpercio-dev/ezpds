// The space-credential request signer: a wrong signature base is a bare 401 from the
// server, so pin the exact base and the header shapes here (the pin's createSpaceSigHeaders).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifySignature } from '@atproto/crypto';

import { newSpaceKey, spaceSigHeaders } from '../src/space-signature.js';

test('credential use covers authorization then the audience, signed by the bound key', async () => {
  const key = await newSpaceKey();
  const headers = await spaceSigHeaders(key, { credential: 'the-credential', audience: 'did:plc:repo' });
  assert.equal(headers.Authorization, 'Atproto-Space-Credential the-credential');
  assert.equal(headers['Atproto-Space-Audience'], 'did:plc:repo');
  const params = '("authorization" "atproto-space-audience");tag="atproto-space-credential"';
  assert.equal(headers['Signature-Input'], `sig=${params}`);

  const match = /^sig=:([A-Za-z0-9+/=]+):$/.exec(headers.Signature);
  assert.ok(match, headers.Signature);
  const sig = new Uint8Array(Buffer.from(match[1], 'base64'));
  assert.equal(sig.length, 64);
  const base = '"authorization": Atproto-Space-Credential the-credential\n'
    + '"atproto-space-audience": did:plc:repo\n'
    + `"@signature-params": ${params}`;
  assert.ok(await verifySignature(key.did(), new TextEncoder().encode(base), sig));
});
