// Resource-server error shapes — the highest-value assertions in the suite.
//
// After login, a client's whole session depends on recognising *why* a call failed. atproto
// clients dispatch on the flat error string: `@atproto/api` and indigo refresh only when a 401
// body carries `"error": "ExpiredToken"`. We shipped a nested envelope with a SCREAMING_SNAKE
// code instead, so every third-party session died unrecoverably a few minutes after login and
// the client never even tried to refresh. No Rust unit test caught it, because those tests
// asserted our own envelope — which is what made the bug permanent.
//
// This file runs its own PDS with a near-instant access-token TTL so a real token can actually
// lapse mid-test. It is a separate file from flow.test.ts on purpose: one fixture per file
// (interop caches EZPDS_BASE_URL at first import), and flow.test.ts asserts the *production*
// default lifetime, which this fixture deliberately does not use.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { approveConsent } from '../src/consent.ts';
import {
  discover,
  generateDpopKey,
  par,
  pkce,
  tokenRequestWithNonceRetry,
  xrpc,
  type ServerMetadata,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';
import { login as fullLogin } from './login.ts';

/** Short enough that a token lapses within one test, long enough to use it once first. */
const ACCESS_TOKEN_TTL_SECS = 2;

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;

before(async () => {
  fixture = await startFixture({ accessTokenTtlSecs: ACCESS_TOKEN_TTL_SECS });
  client = await startClientHost();
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200);
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

/**
 * Every atproto XRPC error is a flat object with a string `error`. A nested
 * `{"error": {"code": ...}}` is the shape this server used to emit, and it is invisible to
 * every client library in the ecosystem.
 */
function assertFlatXrpcError(body: unknown, context: string): asserts body is { error: string } {
  assert.ok(body && typeof body === 'object', `${context}: expected a JSON object body`);
  const error = (body as Record<string, unknown>).error;
  assert.equal(
    typeof error,
    'string',
    `${context}: "error" must be a string, not ${JSON.stringify(error)} — ` +
      'atproto clients read body.error, never body.error.code',
  );
}

test('the configured access-token lifetime is what the token endpoint reports', async () => {
  // Guards the fixture itself: if the knob silently stopped applying, the expiry test below
  // would wait out a 15-minute token and fail as an opaque timeout instead of a clear result.
  const key = await generateDpopKey();
  const { verifier, challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto',
  });
  assert.equal(pushed.status, 201, `PAR must succeed: ${pushed.text}`);
  const approval = await approveConsent(
    fixture.baseUrl,
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(client.clientId)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code, `consent must yield a code: ${approval.location}`);
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
  });
  assert.equal(exchange.final.status, 200, `token exchange must succeed: ${exchange.final.text}`);
  assert.equal(exchange.final.json.expires_in, ACCESS_TOKEN_TTL_SECS);
});

test('an expired access token yields a flat ExpiredToken error', async () => {
  // REGRESSION: this is the "logs in fine, then every action fails" bug. The token expiring is
  // normal and recoverable — but only if the client can tell that is what happened.
  const { accessToken, key } = await fullLogin(fixture, client, metadata);

  const whileValid = await xrpc(fixture.baseUrl, 'com.atproto.server.getSession', key, accessToken);
  assert.equal(whileValid.status, 200, 'the token must work before it expires');

  await new Promise((resolve) => setTimeout(resolve, (ACCESS_TOKEN_TTL_SECS + 1) * 1000));

  const onceExpired = await xrpc(fixture.baseUrl, 'com.atproto.server.getSession', key, accessToken);
  assert.equal(onceExpired.status, 401, `an expired token must 401, got ${onceExpired.status}`);
  assertFlatXrpcError(onceExpired.json, 'expired token');
  assert.equal(
    onceExpired.json.error,
    'ExpiredToken',
    'clients trigger their refresh on exactly this string; any other value strands the session',
  );
});

test('a malformed access token yields a flat InvalidToken error', async () => {
  const key = await generateDpopKey();
  const res = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    key,
    'not.a.valid.jwt',
  );
  assert.equal(res.status, 401);
  assertFlatXrpcError(res.json, 'malformed token');
  assert.equal(res.json.error, 'InvalidToken');
});

test('a missing Authorization header yields a flat AuthMissing error', async () => {
  // The reference PDS answers exactly this (verified against bsky.social, 2026-08-03).
  const res = await fetch(`${fixture.baseUrl}/xrpc/com.atproto.server.getSession`);
  assert.equal(res.status, 401);
  const body = await res.json();
  assertFlatXrpcError(body, 'missing authorization');
  assert.equal(body.error, 'AuthMissing');
});

test('a DPoP-bound token presented as Bearer is refused', async () => {
  // The binding is worthless if the scheme is negotiable: a stolen token must not become
  // usable simply by dropping the proof and relabelling the header.
  const { accessToken, key } = await fullLogin(fixture, client, metadata);

  // Establish that this exact token and key work under the DPoP scheme first. Without this
  // the test would pass just as happily if the proof were malformed or the token already
  // expired — a 401 for the wrong reason looks identical to a 401 for the right one.
  const asDpop = await xrpc(fixture.baseUrl, 'com.atproto.server.getSession', key, accessToken);
  assert.equal(asDpop.status, 200, `the token must be usable as DPoP first: ${asDpop.text}`);

  const asBearer = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    key,
    accessToken,
    { scheme: 'Bearer' },
  );
  assert.equal(
    asBearer.status,
    401,
    'the only difference from the accepted request is the scheme, so this must be refused',
  );
  assertFlatXrpcError(asBearer.json, 'bearer-presented DPoP token');
});

test('an expired token is refused on a proxied endpoint too, not just a local one', async () => {
  // The error envelope is applied at the router seam, so a proxied NSID takes a different
  // code path to the same 401. A client hitting only appview reads must see the same string.
  const { accessToken, key } = await fullLogin(fixture, client, metadata);
  await new Promise((resolve) => setTimeout(resolve, (ACCESS_TOKEN_TTL_SECS + 1) * 1000));

  const res = await xrpc(fixture.baseUrl, 'app.bsky.actor.getPreferences', key, accessToken);
  assert.equal(res.status, 401);
  assertFlatXrpcError(res.json, 'expired token on a proxied endpoint');
  assert.equal(res.json.error, 'ExpiredToken');
});
