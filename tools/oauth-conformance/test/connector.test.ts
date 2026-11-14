// MCP connectors, from the client's side.
//
// A connector is an MCP client such as Claude. The MCP authorization spec gives it a plain
// authorization-code flow with PKCE and an RFC 8707 `resource`: no pushed authorization
// request, and no DPoP. This server requires both of everyone else, so a connector could not
// sign in at all until the operator's `[oauth] connector_resources` made a request naming one
// of those resources the exception (ADR-0042).
//
// What this file pins is both halves of that bargain. The handshake has to work exactly as an
// MCP client performs it, or the feature does not exist. And every relaxation has to stop at
// the connector resource, or the feature is a way around PAR and DPoP for anyone who asks.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { approveConsent } from '../src/consent.ts';
import {
  decodeJwtPayload,
  discover,
  par,
  pkce,
  type ServerMetadata,
  type WireResponse,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';

const MCP_RESOURCE = 'https://mcp.example.test/mcp';

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;

before(async () => {
  fixture = await startFixture({ connectorResources: [MCP_RESOURCE] });
  client = await startClientHost();
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200);
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

/** A plain authorization URL, as an MCP client builds one: every parameter inline. */
function authorizeUrl(challenge: string, extra: Record<string, string>): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'connector-state',
    ...extra,
  });
  return `${metadata.authorization_endpoint}?${params}`;
}

/** POST to the token endpoint with no DPoP header, as an MCP client does. */
async function tokenRequestWithoutDpop(params: Record<string, string>): Promise<WireResponse> {
  const res = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: res.headers, json, text };
}

/** Drive the connector handshake as far as an authorization code. */
async function authorize(scope: string): Promise<{ code: string; verifier: string }> {
  const { verifier, challenge } = pkce();
  const approval = await approveConsent(
    fixture.baseUrl,
    authorizeUrl(challenge, { scope, resource: MCP_RESOURCE }),
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code, `consent must yield a code: ${approval.location}`);
  return { code, verifier };
}

function redeem(code: string, verifier: string, extra: Record<string, string> = {}) {
  return tokenRequestWithoutDpop({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
    ...extra,
  });
}

/** An XRPC GET with a plain Bearer token — all a connector, or the sidecar, can send. */
function bearerGet(nsid: string, accessToken: string): Promise<Response> {
  return fetch(`${fixture.baseUrl}/xrpc/${nsid}`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
}

function assertConnectorToken(response: any, scope: string): void {
  assert.equal(response.token_type, 'Bearer', 'an unbound token must not claim to be DPoP');
  assert.equal(response.expires_in, 300, 'a connector access token lasts five minutes');
  assert.equal(response.scope, scope);
  const claims = decodeJwtPayload(response.access_token);
  assert.equal(claims.cnf, undefined, 'no key binding: the connector never proved a key');
  assert.equal(claims.aud, MCP_RESOURCE, 'the token names the resource it was issued for');
  assert.equal(claims.sub, fixture.account.did, 'a connector acts as the user');
  assert.equal(claims.exp - claims.iat, 300);
}

test('a connector signs in without PAR or DPoP and its Bearer token works at the PDS', async () => {
  const scope = 'atproto repo:app.bsky.feed.post';
  const { code, verifier } = await authorize(scope);

  // The MCP client repeats `resource` on the token request.
  const exchange = await redeem(code, verifier, { resource: MCP_RESOURCE });
  assert.equal(exchange.status, 200, `token exchange must succeed: ${exchange.text}`);
  assertConnectorToken(exchange.json, scope);

  const status = await bearerGet('com.atproto.server.checkAccountStatus', exchange.json.access_token);
  assert.equal(status.status, 200, 'the PDS must accept the token the sidecar forwards');

  const refreshed = await tokenRequestWithoutDpop({
    grant_type: 'refresh_token',
    refresh_token: exchange.json.refresh_token,
    client_id: client.clientId,
    resource: MCP_RESOURCE,
  });
  assert.equal(refreshed.status, 200, `refresh must succeed: ${refreshed.text}`);
  assertConnectorToken(refreshed.json, scope);
  assert.notEqual(refreshed.json.refresh_token, exchange.json.refresh_token, 'refresh rotates');
});

test('a connector is never granted identity, account or transition scopes', async () => {
  // What a generic client asks for. The page offers, and the token carries, only what is
  // under the connector ceiling — the request is narrowed, not refused, so sign-in completes.
  const { code, verifier } = await authorize(
    'atproto transition:generic identity:* account:email repo:app.bsky.feed.post',
  );
  const exchange = await redeem(code, verifier);
  assert.equal(exchange.status, 200, exchange.text);
  assertConnectorToken(exchange.json, 'atproto repo:app.bsky.feed.post');
});

test('a connector token is refused on an account-owner route', async () => {
  const { code, verifier } = await authorize('atproto');
  const exchange = await redeem(code, verifier);
  assert.equal(exchange.status, 200, exchange.text);

  const res = await bearerGet('com.atproto.server.listAppPasswords', exchange.json.access_token);
  assert.ok(
    res.status === 401 || res.status === 403,
    `app-password management is the account holder's alone, got ${res.status}`,
  );
});

test('a plain authorization request that names no connector resource is refused', async () => {
  // The relaxation is the resource and nothing else: PAR stays mandatory for a request that
  // names no resource, this server, or a resource the operator never configured.
  const { challenge } = pkce();
  for (const extra of [
    {},
    { resource: fixture.baseUrl },
    { resource: 'https://elsewhere.example.test/mcp' },
  ] as Record<string, string>[]) {
    const res = await fetch(authorizeUrl(challenge, { scope: 'atproto', ...extra }), {
      redirect: 'manual',
    });
    assert.equal(res.status, 400, `must not reach consent: ${JSON.stringify(extra)}`);
  }
});

test('a pushed request for an unknown resource is invalid_target', async () => {
  const { challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto',
    resource: 'https://elsewhere.example.test/mcp',
  });
  assert.equal(pushed.status, 400);
  assert.equal(pushed.json?.error, 'invalid_target');
});

test('a grant for this server still needs DPoP at the token endpoint', async () => {
  // A normal pushed flow, redeemed the way a connector would: the missing proof is refused,
  // so naming no connector resource never yields an unbound token.
  const { verifier, challenge } = pkce();
  const pushed = await par(metadata, {
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'atproto',
  });
  assert.equal(pushed.status, 201, pushed.text);
  const approval = await approveConsent(
    fixture.baseUrl,
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(client.clientId)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code);

  const exchange = await redeem(code, verifier);
  assert.equal(exchange.status, 400);
  assert.equal(exchange.json?.error, 'invalid_dpop_proof');

  // Nor can the token request turn the grant into a connector's after the fact.
  const retargeted = await redeem(code, verifier, { resource: MCP_RESOURCE });
  assert.equal(retargeted.status, 400);
  assert.equal(retargeted.json?.error, 'invalid_target');
});

test('a connector grant cannot be redeemed or refreshed for another target', async () => {
  const { code, verifier } = await authorize('atproto');
  const targets = [fixture.baseUrl, 'https://elsewhere.example.test/mcp'];
  for (const resource of targets) {
    const exchange = await redeem(code, verifier, { resource });
    assert.equal(exchange.status, 400, resource);
    assert.equal(exchange.json?.error, 'invalid_target', resource);
  }

  // A refused exchange does not burn the code, so it still redeems for its own target —
  // and the refresh family it starts is held to that target too.
  const exchange = await redeem(code, verifier);
  assert.equal(exchange.status, 200, exchange.text);
  for (const resource of targets) {
    const refreshed = await tokenRequestWithoutDpop({
      grant_type: 'refresh_token',
      refresh_token: exchange.json.refresh_token,
      client_id: client.clientId,
      resource,
    });
    assert.equal(refreshed.status, 400, resource);
    assert.equal(refreshed.json?.error, 'invalid_target', resource);
  }
});
