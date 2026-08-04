// Confidential clients: RFC 7523 `private_key_jwt` authentication at the token endpoint.
//
// This is the gap that mattered most for security rather than usability. The server had
// advertised `private_key_jwt` in its metadata from the beginning, but the token endpoint had
// no `client_assertion` field at all — serde dropped it silently and every client was treated
// as public. A confidential client's key was decorative: anyone holding a leaked authorization
// code or refresh token could exchange it without ever proving possession of that key.
//
// tangled.org is a real confidential client, and it "worked" throughout — which is the
// uncomfortable part. Nothing observable distinguishes an assertion that was verified from one
// that was thrown away, so only a test that deliberately withholds the assertion can tell the
// difference. That is exactly what this file does.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { approveConsent } from '../src/consent.ts';
import {
  CLIENT_ASSERTION_TYPE,
  clientAssertion,
  discover,
  generateClientKey,
  generateDpopKey,
  par,
  pkce,
  tokenRequestWithNonceRetry,
  xrpc,
  type ClientKey,
  type ServerMetadata,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;
let clientKey: ClientKey;

before(async () => {
  fixture = await startFixture();
  clientKey = await generateClientKey();
  // A confidential client publishes its verification key inline. `jwks_uri` cannot be
  // exercised hermetically: it would have to point at loopback, and the SSRF-hardened client
  // that fetches it refuses loopback in production — correctly. That branch is covered by
  // `client_auth.rs`'s wiremock tests instead.
  client = await startClientHost({
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: { keys: [clientKey.publicJwk] },
  });
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200);
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

test('the server advertises private_key_jwt', () => {
  // Advertising a method the endpoint does not implement is what made this gap invisible:
  // a conformant client reads the metadata and trusts it.
  assert.ok(
    (metadata.token_endpoint_auth_methods_supported as string[]).includes('private_key_jwt'),
    'private_key_jwt must be advertised if confidential clients are to use it',
  );
});

/** Drive PAR + consent, returning the authorization code and its PKCE verifier. */
async function authorizeAndGetCode(): Promise<{ code: string; verifier: string }> {
  const { verifier, challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto transition:generic',
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
  return { code, verifier };
}

test('a confidential client completes a full flow with a valid assertion', async () => {
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  const assertion = await clientAssertion(clientKey, client.clientId, metadata.issuer);
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  });
  assert.equal(exchange.final.status, 200, `exchange must succeed: ${exchange.final.text}`);
  assert.equal(exchange.final.json.sub, fixture.account.did);

  const call = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    key,
    exchange.final.json.access_token,
  );
  assert.equal(call.status, 200, `the issued token must work: ${call.text}`);
});

test('a confidential client cannot exchange a code without its assertion', async () => {
  // REGRESSION: before client authentication was implemented this succeeded, which meant a
  // leaked code was redeemable by anyone. It is the whole point of the mechanism.
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
  });
  assert.equal(
    exchange.final.status,
    400,
    `a confidential client with no assertion must be refused, got ${exchange.final.status}: ` +
      `${exchange.final.text}`,
  );
  assert.equal(exchange.final.json.error, 'invalid_client');
});

test('an assertion signed by the wrong key is refused', async () => {
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  // Same `kid` the client published, but a different private key behind it — an attacker who
  // has read the public metadata and guessed the rest.
  const imposter = await generateClientKey(clientKey.publicJwk.kid);
  const assertion = await clientAssertion(imposter, client.clientId, metadata.issuer);

  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  });
  assert.equal(exchange.final.status, 400);
  assert.equal(exchange.final.json.error, 'invalid_client');
});

test('an assertion minted for a different audience is refused', async () => {
  // Otherwise a hostile authorization server could collect assertions from clients that talk
  // to it and replay them here.
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  const assertion = await clientAssertion(
    clientKey,
    client.clientId,
    'https://another-authorization-server.example',
  );
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  });
  assert.equal(exchange.final.status, 400);
  assert.equal(exchange.final.json.error, 'invalid_client');
});

test('an expired assertion is refused', async () => {
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  const assertion = await clientAssertion(clientKey, client.clientId, metadata.issuer, {
    exp: Math.floor(Date.now() / 1000) - 300,
  });
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  });
  assert.equal(exchange.final.status, 400);
  assert.equal(exchange.final.json.error, 'invalid_client');
});

test('a refresh also requires the client assertion', async () => {
  // REGRESSION: client authentication that only guards the initial exchange is barely
  // authentication at all — a refresh token is the longer-lived credential of the two, and a
  // stolen one would mint sessions indefinitely without ever proving key possession.
  const key = await generateDpopKey();
  const { code, verifier } = await authorizeAndGetCode();

  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await clientAssertion(clientKey, client.clientId, metadata.issuer),
  });
  assert.equal(exchange.final.status, 200);
  const refreshToken = exchange.final.json.refresh_token;

  const unauthenticated = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: client.clientId,
  });
  assert.equal(
    unauthenticated.final.status,
    400,
    `a refresh without the assertion must be refused: ${unauthenticated.final.text}`,
  );
  assert.equal(unauthenticated.final.json.error, 'invalid_client');

  // With the assertion it works, and the refresh token was not consumed by the failed attempt.
  const authenticated = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: client.clientId,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await clientAssertion(clientKey, client.clientId, metadata.issuer),
  });
  assert.equal(
    authenticated.final.status,
    200,
    `an authenticated refresh must succeed: ${authenticated.final.text}`,
  );
});
