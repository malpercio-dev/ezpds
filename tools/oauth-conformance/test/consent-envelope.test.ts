// Pins the JavaScript consent-envelope port against the same golden vector the Rust encoder is
// pinned against (`crates/crypto/src/oauth_consent.rs`'s
// `canonical_envelope_has_a_stable_golden_vector`).
//
// This is the whole justification for having a second implementation of the format at all: the
// two are held to one file neither of them owns, so a change to the encoding fails on both
// sides instead of showing up as a wallet approval the server rejects with its deliberately
// uninformative "consent approval rejected".
//
// No fixture here — this file spawns nothing, so it is exempt from the one-fixture-per-file
// rule the rest of the suite follows.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  consentNonce,
  encodeOAuthConsentEnvelope,
  grantedScopeHash,
  type ConsentEnvelopeFields,
} from '../src/consent-envelope.ts';

const VECTOR_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test-vectors/oauth-consent-envelope-v1.json',
);

interface EnvelopeVector extends ConsentEnvelopeFields {
  envelope: string;
}

const vector = JSON.parse(fs.readFileSync(VECTOR_PATH, 'utf8')) as EnvelopeVector;

test('the port reproduces the golden envelope byte for byte', () => {
  const encoded = encodeOAuthConsentEnvelope(vector);
  assert.equal(
    encoded.toString('utf8'),
    vector.envelope,
    'the JS port has drifted from test-vectors/oauth-consent-envelope-v1.json. Either the ' +
      'encoding changed (then crates/crypto/src/oauth_consent.rs and the vector must change ' +
      'with it, under a new domain) or this port is wrong.',
  );
});

test('length prefixes count UTF-8 bytes, not characters', () => {
  // A client_name or handle carrying multi-byte characters is the case a character-count
  // prefix gets wrong, and it fails as an opaque signature rejection rather than a parse error.
  const encoded = encodeOAuthConsentEnvelope({
    ...vector,
    clientId: 'https://ünïcøde.example/client-metadata.json',
  }).toString('utf8');
  const client = 'https://ünïcøde.example/client-metadata.json';
  assert.ok(
    encoded.includes(`client:${Buffer.byteLength(client, 'utf8')}:${client}\n`),
    `expected a byte-length prefix of ${Buffer.byteLength(client, 'utf8')}, not ${client.length}`,
  );
});

test('every binding changes the bytes', () => {
  // The security property the envelope exists for: an approval cannot be replayed onto another
  // request, re-pointed at another client, flipped from a denial, or widened.
  const base = encodeOAuthConsentEnvelope(vector).toString('utf8');
  const variants: Array<Partial<ConsentEnvelopeFields>> = [
    { requestId: 'req_ffffffffffffffffffffffffffffffff' },
    { clientId: 'https://evil.example.com/client-metadata.json' },
    { decision: 'deny' },
    { grantedScope: 'atproto transition:generic transition:chat.bsky' },
    { accountDid: 'did:plc:zzzzzzzzzzzzzzzzzzzzzzzz' },
    { signingKeyDid: 'did:key:zOther' },
    { serverDid: 'did:web:attacker.example' },
    { timestamp: vector.timestamp + 1 },
    { nonce: 'B'.repeat(43) },
  ];
  for (const change of variants) {
    assert.notEqual(
      encodeOAuthConsentEnvelope({ ...vector, ...change }).toString('utf8'),
      base,
      `changing ${Object.keys(change)[0]} must change the signed bytes`,
    );
  }
});

test('the granted-scope hash is lowercase hex over the verbatim string', () => {
  const hash = grantedScopeHash('atproto');
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(hash, grantedScopeHash('atproto'));
  // Token order and whitespace are part of the string, not normalized away — both sides hash
  // whatever the wallet actually puts in `grantedScope`.
  assert.notEqual(hash, grantedScopeHash('transition:generic atproto'));
  assert.notEqual(hash, grantedScopeHash(''));
});

test('a minted nonce is canonical unpadded base64url of 32 bytes', () => {
  // `auth/signed_proof.rs` re-encodes and requires the result to reproduce the input, so a
  // padded or otherwise non-canonical spelling is refused before any signature check.
  const nonce = consentNonce();
  assert.equal(nonce.length, 43, 'a 32-byte value is 43 unpadded base64url characters');
  assert.equal(Buffer.from(nonce, 'base64url').length, 32);
  assert.equal(Buffer.from(nonce, 'base64url').toString('base64url'), nonce);
});
