// AC2.6 — logs/traces/errors redact authorization material. ADR-0024: avoiding
// durable storage is not sufficient; a bearer or assertion substring must never
// reach a log line or a client-surfaced error.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactValue, redactError } from '../src/log.ts';
import { fakeToken } from './support.ts';

const token = fakeToken({ sub: 'did:plc:alice', scope: 'atproto repo:*' });

test('AC2.6: a Bearer header is scrubbed', () => {
  const out = redact(`Authorization: Bearer ${token}`);
  assert.doesNotMatch(out, new RegExp(escapeRe(token)), 'token gone');
  assert.match(out, /Bearer «redacted»/);
});

test('AC2.6: a bare JWT anywhere in a string is scrubbed', () => {
  const out = redact(`token exchange returned ${token} for the caller`);
  assert.doesNotMatch(out, new RegExp(escapeRe(token)));
  assert.match(out, /«redacted»/);
});

test('AC2.6: authorization-named object keys are dropped from structured logs', () => {
  const scrubbed = redactValue({
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    access_token: token,
    nested: [{ assertion: token }],
  }) as any;
  const serialized = JSON.stringify(scrubbed);
  assert.doesNotMatch(serialized, new RegExp(escapeRe(token)), 'no token in any field');
  assert.equal(scrubbed.headers.authorization, '«redacted»');
  assert.equal(scrubbed.access_token, '«redacted»');
  assert.equal(scrubbed.nested[0].assertion, '«redacted»');
  assert.equal(scrubbed.method, 'POST', 'non-sensitive fields survive');
});

test('AC2.6: an error carrying a token is scrubbed before it reaches a client', () => {
  const err = new Error(`HTTP 401 with Authorization: Bearer ${token}`);
  const message = redactError(err);
  assert.doesNotMatch(message, new RegExp(escapeRe(token)));
  assert.match(message, /«redacted»/);
});

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
