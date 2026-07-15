// AC2.4 — the singleton AgentSession is replaced by a per-caller map keyed by
// authenticated caller: same caller → same session object; distinct callers →
// distinct objects; an unauthenticated request → none. Also covers idle
// eviction so a long-running process can't accumulate sessions.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { SessionRegistry } from '../src/registry.ts';
import { fakeToken } from './support.ts';

const PDS = 'http://pds.railway.internal:8080';

function auth(token: string): AuthInfo {
  return { token, clientId: 'test', scopes: [] };
}

test('AC2.4: same caller resolves to the same session object', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  const token = fakeToken({ sub: 'did:plc:alice' });
  const first = registry.resolve(auth(token));
  const second = registry.resolve(auth(token));
  assert.ok(first);
  assert.strictEqual(first, second, 'one caller keeps one session across calls');
  assert.equal(registry.size(), 1);
});

test('AC2.4: distinct callers resolve to distinct sessions', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  const alice = registry.resolve(auth(fakeToken({ sub: 'did:plc:alice' })));
  const bob = registry.resolve(auth(fakeToken({ sub: 'did:plc:bob' })));
  assert.ok(alice && bob);
  assert.notStrictEqual(alice, bob, 'two callers get two sessions');
  assert.equal(alice.did(), 'did:plc:alice');
  assert.equal(bob.did(), 'did:plc:bob');
  assert.equal(registry.size(), 2);
});

test('AC2.4: an unauthenticated request resolves to no session', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS });
  assert.equal(registry.resolve(undefined), null);
  assert.equal(registry.resolve({ token: '', clientId: 'x', scopes: [] }), null);
  assert.equal(registry.size(), 0, 'no session is minted for an unauthenticated request');
});

test('AC2.4: a caller session is evicted after its idle TTL', () => {
  let now = 1_000_000;
  const registry = new SessionRegistry({ pdsOrigin: PDS, idleTtlMs: 1_000, clock: () => now });
  const token = fakeToken({ sub: 'did:plc:alice' });
  registry.resolve(auth(token));
  assert.equal(registry.size(), 1);

  now += 2_000; // past the idle TTL
  // A resolve for a *different* caller sweeps the idle one first.
  registry.resolve(auth(fakeToken({ sub: 'did:plc:bob' })));
  assert.equal(registry.size(), 1, 'the idle alice session was evicted; only bob remains');
});

test('AC2.4: the map is capped so it cannot grow without bound', () => {
  const registry = new SessionRegistry({ pdsOrigin: PDS, maxSessions: 2 });
  registry.resolve(auth(fakeToken({ sub: 'did:plc:a' })));
  registry.resolve(auth(fakeToken({ sub: 'did:plc:b' })));
  registry.resolve(auth(fakeToken({ sub: 'did:plc:c' })));
  assert.equal(registry.size(), 2, 'the least-recently-used session is dropped at capacity');
});
