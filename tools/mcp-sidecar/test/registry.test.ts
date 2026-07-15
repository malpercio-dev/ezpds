// AC2.4 — the singleton AgentSession is replaced by a per-caller registry that
// tracks distinct authenticated callers but stores no credential: each resolve
// mints a FRESH, request-scoped session bound to that request's token. Distinct
// callers are isolated; an unauthenticated request gets none; and — critically —
// two overlapping requests (even from the same caller) receive independent
// sessions that cannot clobber each other's token. Also covers idle eviction and
// the caller cap so a long-running process can't accumulate callers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { SessionRegistry } from '../src/registry.ts';
import { fakeToken } from './support.ts';

const PDS = 'http://pds.railway.internal:8080';

function auth(token: string, scopes: string[] = []): AuthInfo {
  return { token, clientId: 'test', scopes };
}

test('AC2.4: a caller is tracked once across repeated resolves', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  const token = fakeToken({ sub: 'did:plc:alice' });
  const first = registry.resolve(auth(token));
  const second = registry.resolve(auth(token));
  assert.ok(first && second);
  assert.equal(first.did(), 'did:plc:alice');
  assert.equal(second.did(), 'did:plc:alice');
  assert.equal(registry.size(), 1, 'one caller, one tracking entry');
});

test('AC2.4: overlapping requests get independent, isolated credential leases', async () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  // Same caller (same subject), two different in-flight request tokens.
  const t1 = fakeToken({ sub: 'did:plc:alice', scope: 'atproto repo:*' });
  const t2 = fakeToken({ sub: 'did:plc:alice', scope: 'atproto' });
  const s1 = registry.resolve(auth(t1, ['atproto', 'repo:*']));
  const s2 = registry.resolve(auth(t2, ['atproto']));
  assert.ok(s1 && s2);
  assert.notStrictEqual(s1, s2, 'each request gets its own session object');
  // s2 minting must NOT overwrite s1's token — the old race.
  assert.equal(await s1.accessToken(), t1);
  assert.equal(await s2.accessToken(), t2);
  assert.deepEqual(s1.scopes(), ['atproto', 'repo:*']);
  assert.deepEqual(s2.scopes(), ['atproto']);
  assert.equal(registry.size(), 1, 'still one caller');
});

test('AC2.4: distinct callers resolve to sessions with their own identity', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  const alice = registry.resolve(auth(fakeToken({ sub: 'did:plc:alice' })));
  const bob = registry.resolve(auth(fakeToken({ sub: 'did:plc:bob' })));
  assert.ok(alice && bob);
  assert.equal(alice.did(), 'did:plc:alice');
  assert.equal(bob.did(), 'did:plc:bob');
  assert.equal(registry.size(), 2);
});

test('AC2.4: an unauthenticated request resolves to no session', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  assert.equal(registry.resolve(undefined), null);
  assert.equal(registry.resolve({ token: '', clientId: 'x', scopes: [] }), null);
  assert.equal(registry.size(), 0, 'no caller is tracked for an unauthenticated request');
});

test('AC2.4: a caller is evicted after its idle TTL', () => {
  let now = 1_000_000;
  const registry = new SessionRegistry({ pdsOrigin: PDS, idleTtlMs: 1_000, clock: () => now });
  registry.resolve(auth(fakeToken({ sub: 'did:plc:alice' })));
  assert.equal(registry.size(), 1);
  now += 2_000; // past the idle TTL
  registry.resolve(auth(fakeToken({ sub: 'did:plc:bob' })));
  assert.equal(registry.size(), 1, 'the idle alice caller was evicted; only bob remains');
});

test('AC2.4: the caller map is capped so it cannot grow without bound', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS, maxCallers: 2 });
  registry.resolve(auth(fakeToken({ sub: 'did:plc:a' })));
  registry.resolve(auth(fakeToken({ sub: 'did:plc:b' })));
  registry.resolve(auth(fakeToken({ sub: 'did:plc:c' })));
  assert.equal(registry.size(), 2, 'the least-recently-seen caller is dropped at capacity');
});
