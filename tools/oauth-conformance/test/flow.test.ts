// The full authorization-code flow, driven by a hand-rolled client.
//
// Each assertion names the regression it guards. Assertions marked "REGRESSION:" correspond
// to a bug that actually reached production and is documented in
// docs/2026-08-03-oauth-interop-audit.md — those exist because a green unit-test suite did
// not catch them, and they should not be deleted without a replacement.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { approveConsent } from '../src/consent.ts';
import {
  decodeJwtPayload,
  discover,
  generateDpopKey,
  par,
  pkce,
  tokenRequestWithNonceRetry,
  xrpc,
  type ServerMetadata,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;
let CLIENT_ID: string;
let REDIRECT_URI: string;

before(async () => {
  fixture = await startFixture();
  client = await startClientHost();
  CLIENT_ID = client.clientId;
  REDIRECT_URI = client.redirectUri;
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200, 'authorization-server metadata must be served');
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

test('metadata advertises a same-origin issuer and S256 PKCE', () => {
  assert.equal(
    metadata.issuer,
    fixture.baseUrl,
    'issuer must be exactly the origin — no trailing slash, no path (RFC 8414)',
  );
  assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
  assert.ok(
    (metadata.scopes_supported as string[]).includes('atproto'),
    'the atproto base scope must be advertised',
  );
  for (const endpoint of [
    metadata.authorization_endpoint,
    metadata.token_endpoint,
    metadata.pushed_authorization_request_endpoint,
  ]) {
    assert.ok(
      endpoint.startsWith(fixture.baseUrl),
      `advertised endpoint ${endpoint} must be same-origin with the issuer`,
    );
  }
});

test('metadata states the request_uri capability fields explicitly', () => {
  // REGRESSION: pckt.blog's client gates its PAR flow on these fields' *presence* — with
  // them absent it read the server as legacy/non-PAR, downgraded to a direct authorization
  // request, and its callback then failed before ever calling the token endpoint. The
  // OpenID Connect Discovery absent-field defaults are not enough; the keys must exist on
  // the wire.
  assert.equal(metadata.request_uri_parameter_supported, true);
  assert.equal(metadata.require_request_uri_registration, true);
  // Deliberately false: JAR (RFC 9101) request objects are not implemented, and metadata
  // must not advertise them even though the reference provider says true.
  assert.equal(metadata.request_parameter_supported, false);
});

test('a full flow issues a DPoP-bound session and reaches an authenticated endpoint', async () => {
  const key = await generateDpopKey();
  const { verifier, challenge } = pkce();

  // ── Pushed authorization request ────────────────────────────────────────────
  const pushed = await par(metadata, {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto transition:generic',
    state: 'conformance-state',
  });
  assert.equal(pushed.status, 201, `PAR must succeed, got ${pushed.status}: ${pushed.text}`);
  const requestUri = pushed.json.request_uri as string;
  assert.ok(requestUri, 'PAR must return a request_uri');

  // ── Consent ─────────────────────────────────────────────────────────────────
  const authorizeUrl =
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&request_uri=${encodeURIComponent(requestUri)}`;
  const approval = await approveConsent(fixture.baseUrl, authorizeUrl, {
    identifier: fixture.account.did,
    password: fixture.account.password,
  });

  const code = approval.params.get('code');
  assert.ok(code, `authorization response must carry a code: ${approval.location}`);
  assert.equal(
    approval.params.get('state'),
    'conformance-state',
    'state must round-trip to the client',
  );
  assert.equal(
    approval.params.get('iss'),
    metadata.issuer,
    'RFC 9207: the authorization response must identify the issuer',
  );

  // ── Token exchange ──────────────────────────────────────────────────────────
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });

  // The nonce dance is the single most common hand-rolled-client failure: assert the server
  // both demanded a nonce and supplied one to retry with.
  assert.ok(exchange.challenge, 'the first token request should be challenged for a nonce');
  assert.equal(exchange.challenge.json.error, 'use_dpop_nonce');
  assert.ok(
    exchange.challenge.headers.get('dpop-nonce'),
    'a use_dpop_nonce challenge must carry the DPoP-Nonce header, or the client cannot retry',
  );

  const token = exchange.final;
  assert.equal(token.status, 200, `token exchange must succeed: ${token.text}`);

  // REGRESSION: the atproto profile requires the account DID in `sub`. Omitting it 500'd
  // tangled.org's callback (see project memory: oauth-token-sub-did).
  assert.equal(
    token.json.sub,
    fixture.account.did,
    'the token response must carry the account DID in sub',
  );
  assert.equal(token.json.token_type, 'DPoP', 'atproto tokens are DPoP-bound, never Bearer');
  assert.ok(token.json.refresh_token, 'a refresh token must be issued');

  // REGRESSION: 300-second access tokens killed real sessions minutes after login.
  assert.ok(
    token.json.expires_in >= 600,
    `access tokens must live at least 10 minutes, got ${token.json.expires_in}s`,
  );

  // The access token must be bound to the key that redeemed the code.
  const claims = decodeJwtPayload(token.json.access_token);
  assert.equal(claims.sub, fixture.account.did, 'the JWT sub must match the response sub');
  assert.equal(claims.cnf?.jkt, key.thumbprint, 'the token must be bound to the DPoP key');

  // ── Authenticated call ──────────────────────────────────────────────────────
  const session = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    key,
    token.json.access_token,
  );
  assert.equal(session.status, 200, `an authenticated call must succeed: ${session.text}`);
  assert.equal(session.json.did, fixture.account.did);
});

test('an authorization code cannot be redeemed twice', async () => {
  const key = await generateDpopKey();
  const { verifier, challenge } = pkce();

  const pushed = await par(metadata, {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto',
    state: 'replay-test',
  });
  assert.equal(pushed.status, 201);

  const approval = await approveConsent(
    fixture.baseUrl,
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code);

  const params = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  };
  const first = await tokenRequestWithNonceRetry(metadata, key, params);
  assert.equal(first.final.status, 200, 'the first redemption must succeed');

  const second = await tokenRequestWithNonceRetry(metadata, key, params);
  assert.equal(second.final.status, 400, 'a replayed code must be refused');
  assert.equal(second.final.json.error, 'invalid_grant');
});

test('PAR does not require state (PKCE already binds the flow)', async () => {
  // REGRESSION: requiring `state` turned away conformant clients that rely on PKCE alone.
  const { challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto',
  });
  assert.equal(pushed.status, 201, `PAR without state must succeed: ${pushed.text}`);
});

test('a token request with no DPoP proof at all is refused', async () => {
  const res = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'nonexistent',
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: 'x'.repeat(43),
    }).toString(),
  });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, 'invalid_dpop_proof');
});

test('unparseable scopes are rejected at PAR rather than silently dropped', async () => {
  const { challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto not-a-real-scope:::',
  });
  assert.equal(pushed.status, 400);
  assert.equal(pushed.json.error, 'invalid_scope');
});

test('a PAR DPoP proof is accepted, but the password consent path drops the binding', async () => {
  // Written to prove the DPoP key binding end-to-end; it proved the opposite, which is worth
  // pinning. PAR accepts the proof and records the key — but the password consent path cannot
  // carry it: its PAR row is consumed by the GET that renders the form, and the POST rebuilds
  // the request from attacker-controllable hidden fields, so `oauth_authorize.rs` deliberately
  // issues the code with no binding rather than trusting one an attacker could omit.
  //
  // `dpop_jkt` enforcement is therefore reachable only through the *wallet* consent path,
  // which keeps its pending request server-side. That path is now covered — see
  // `wallet-consent.test.ts`'s "a code issued through the wallet path is bound to the PAR-time
  // DPoP key", which drives PAR → consent → token and watches a second key be refused. So the
  // control has end-to-end evidence; what this test pins is the deliberate *absence* of the
  // binding on the other branch of the same page, which is otherwise invisible.
  //
  // If the password path ever starts binding, this fails and someone updates it deliberately.
  const flowKey = await generateDpopKey();
  const otherKey = await generateDpopKey();
  const { verifier, challenge } = pkce();

  const pushed = await par(
    metadata,
    {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      scope: 'atproto',
    },
    // PAR must accept a proof without a server nonce — a client has none on first contact.
    { dpopKey: flowKey },
  );
  assert.equal(pushed.status, 201, `a PAR carrying a DPoP proof must succeed: ${pushed.text}`);

  const approval = await approveConsent(
    fixture.baseUrl,
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code, `consent must yield a code: ${approval.location}`);

  const redeemed = await tokenRequestWithNonceRetry(metadata, otherKey, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });
  assert.equal(
    redeemed.final.status,
    200,
    'documents deliberate behaviour: a code issued through the password consent path carries ' +
      'no PAR-time key binding, so a different key redeems it. The wallet path does bind ' +
      '(wallet-consent.test.ts). Change this to expect 400 only when the password path can ' +
      'carry the binding without trusting an attacker-controllable field.',
  );
  // The issued token is still sender-constrained to whoever redeemed it — the binding that
  // is missing is to the key that *pushed the request*, not to the presenter.
  const claims = decodeJwtPayload(redeemed.final.json.access_token);
  assert.equal(claims.cnf?.jkt, otherKey.thumbprint);
});
