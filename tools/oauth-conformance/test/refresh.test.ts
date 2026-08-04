// Refresh-token rotation, from the client's side.
//
// Rotation is where a session quietly dies. A client that refreshes correctly but gets
// `invalid_grant` back has no recovery path: it is holding a token the server has already
// invalidated, so it logs the user out. That makes the failure modes here indistinguishable
// from "the app randomly signed me out", which is exactly how they go unreported for months.
//
// The case that matters most is the concurrent duplicate refresh: two requests carrying the
// same refresh token, which any client with more than one in-flight request produces —
// a multi-tab web app, or a mobile app resuming from background while a retry is already
// running. Strict single-use rotation strands whichever one loses the race.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  discover,
  generateDpopKey,
  tokenRequestWithNonceRetry,
  xrpc,
  type ServerMetadata,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';
import { login } from './login.ts';

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;

before(async () => {
  fixture = await startFixture();
  client = await startClientHost();
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200);
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

/** Exchange a refresh token, doing the nonce dance a conformant client would. */
function refresh(key: Awaited<ReturnType<typeof generateDpopKey>>, refreshToken: string) {
  return tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: client.clientId,
  });
}

test('a refresh rotates both tokens and the new access token works', async () => {
  const session = await login(fixture, client, metadata);

  const rotated = await refresh(session.key, session.refreshToken);
  assert.equal(rotated.final.status, 200, `refresh must succeed: ${rotated.final.text}`);

  assert.ok(rotated.final.json.access_token, 'a refresh must return a new access token');
  assert.ok(rotated.final.json.refresh_token, 'a refresh must return a rotated refresh token');
  assert.notEqual(
    rotated.final.json.refresh_token,
    session.refreshToken,
    'the refresh token must actually rotate',
  );

  // REGRESSION: the atproto profile requires `sub` on *every* refresh, not just the initial
  // exchange — a client re-verifies the DID each time. Omitting it 500'd tangled.org.
  assert.equal(
    rotated.final.json.sub,
    fixture.account.did,
    'the refresh response must carry the account DID in sub',
  );
  assert.equal(rotated.final.json.token_type, 'DPoP');
  assert.equal(
    rotated.final.json.scope,
    session.tokenResponse.scope,
    'rotation must carry the granted scope forward, not silently narrow it',
  );

  const call = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    session.key,
    rotated.final.json.access_token,
  );
  assert.equal(call.status, 200, `the rotated access token must work: ${call.text}`);
  assert.equal(call.json.did, fixture.account.did);
});

test('the rotated refresh token can itself be refreshed', async () => {
  // A session lives by chaining rotations; if only the first one worked, every client would
  // die at the second refresh instead of the first.
  const session = await login(fixture, client, metadata);

  const first = await refresh(session.key, session.refreshToken);
  assert.equal(first.final.status, 200);

  const second = await refresh(session.key, first.final.json.refresh_token);
  assert.equal(second.final.status, 200, `the second rotation must succeed: ${second.final.text}`);
  assert.notEqual(second.final.json.refresh_token, first.final.json.refresh_token);
});

test('two concurrent refreshes with the same token both succeed', async () => {
  // REGRESSION: this is the silent-logout bug. Strict single-use rotation deletes the token
  // on the first request, so the second — already in flight, carrying the same token, sent by
  // a correctly-written client — got invalid_grant and the session was gone. Inside the reuse
  // grace window both must be serviced.
  const session = await login(fixture, client, metadata);

  const [a, b] = await Promise.all([
    refresh(session.key, session.refreshToken),
    refresh(session.key, session.refreshToken),
  ]);

  assert.equal(a.final.status, 200, `first concurrent refresh failed: ${a.final.text}`);
  assert.equal(
    b.final.status,
    200,
    `second concurrent refresh failed: ${b.final.text} — a client with two in-flight ` +
      'requests would be logged out here',
  );
  assert.notEqual(
    a.final.json.refresh_token,
    b.final.json.refresh_token,
    'each concurrent refresh gets its own rotated token',
  );

  // Both sides must end up holding a usable session, not just a 200.
  for (const [label, result] of [
    ['first', a],
    ['second', b],
  ] as const) {
    const call = await xrpc(
      fixture.baseUrl,
      'com.atproto.server.getSession',
      session.key,
      result.final.json.access_token,
    );
    assert.equal(call.status, 200, `the ${label} refresh's access token must work: ${call.text}`);
  }
});

test('a refresh presented with a different DPoP key is refused', async () => {
  // The refresh token is bound to the key that obtained it (RFC 9449). Without this, a stolen
  // refresh token alone would be enough to mint sessions forever.
  const session = await login(fixture, client, metadata);
  const attackerKey = await generateDpopKey();

  const stolen = await refresh(attackerKey, session.refreshToken);
  assert.equal(stolen.final.status, 400, 'a refresh with the wrong key must be refused');
  assert.equal(stolen.final.json.error, 'invalid_grant');

  // The legitimate holder is unaffected by the attempt.
  const legitimate = await refresh(session.key, session.refreshToken);
  assert.equal(
    legitimate.final.status,
    200,
    'a failed attempt by someone else must not consume the real client’s token',
  );
});

test('a refresh naming the wrong client_id is refused without consuming the token', async () => {
  const session = await login(fixture, client, metadata);

  const wrongClient = await tokenRequestWithNonceRetry(metadata, session.key, {
    grant_type: 'refresh_token',
    refresh_token: session.refreshToken,
    client_id: 'https://someone-else.example/client-metadata.json',
  });
  assert.equal(wrongClient.final.status, 400);
  assert.equal(wrongClient.final.json.error, 'invalid_grant');

  const legitimate = await refresh(session.key, session.refreshToken);
  assert.equal(
    legitimate.final.status,
    200,
    'a rejected refresh must leave the token usable — otherwise a bad request from anywhere ' +
      'becomes a denial of service against the real client',
  );
});

test('an unknown refresh token is refused', async () => {
  const session = await login(fixture, client, metadata);
  // Same shape as a real token (43-char base64url) so this exercises the lookup, not the
  // decoder's rejection of malformed input.
  const bogus = 'A'.repeat(43);

  const res = await refresh(session.key, bogus);
  assert.equal(res.final.status, 400);
  assert.equal(res.final.json.error, 'invalid_grant');
});

test('a refresh requires the DPoP nonce dance', async () => {
  // Refresh happens on a schedule rather than in response to a user action, so a client that
  // only implements the nonce retry at initial login appears to work and then dies days later.
  // The server must challenge, and must hand back a nonce to retry with.
  const session = await login(fixture, client, metadata);

  const exchange = await refresh(session.key, session.refreshToken);
  assert.ok(exchange.challenge, 'the refresh should be challenged for a fresh nonce');
  assert.equal(exchange.challenge.json.error, 'use_dpop_nonce');
  assert.ok(
    exchange.challenge.headers.get('dpop-nonce'),
    'the challenge must carry a DPoP-Nonce header or the client cannot retry',
  );
  assert.equal(exchange.final.status, 200);
});
