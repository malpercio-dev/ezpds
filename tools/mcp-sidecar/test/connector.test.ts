// The full MCP OAuth handshake, end to end, with the real MCP SDK client: the
// path a connector such as Claude takes to reach a user's account through the
// hosted sidecar (ADR-0042).
//
//   connect, no token      → the sidecar's 401 names its protected-resource metadata
//   discovery              → the metadata names Custos as the authorization server
//                            and the scopes to request
//   plain authorize + PKCE → no pushed request; the user approves on the consent page
//   token exchange         → no DPoP; an unbound Bearer token for the sidecar's resource
//   tool call              → the sidecar forwards that token and the PDS accepts it
//
// Nothing here is hand-built except the user's approval: the SDK client performs
// every request a connector would. The other e2e files forward an agent's token;
// this one is the only place the sign-in itself is exercised.

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformation,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { approveConsent } from '../../oauth-conformance/src/consent.ts';
import { decodeJwtPayload } from '../../mcp/src/auth.ts';
import { startE2eFixture, xrpcGet, type E2eFixture } from './e2e-fixture.ts';
import { toolJson } from './support.ts';

let fx: E2eFixture;
let clientHost: { clientId: string; redirectUri: string; close: () => void };

/**
 * Publish a connector's client metadata document on loopback. A connector
 * registers this way (a Client ID Metadata Document), and its document carries
 * none of the atproto-specific fields — no `dpop_bound_access_tokens`, no scope.
 */
function startClientHost(): Promise<typeof clientHost> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const { port } = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${port}`;
      if (req.url === '/client.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            client_id: `${origin}/client.json`,
            client_name: 'Connector e2e',
            redirect_uris: [`${origin}/callback`],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'none',
          }),
        );
        return;
      }
      res.writeHead(204).end();
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${port}`;
      resolve({
        clientId: `${origin}/client.json`,
        redirectUri: `${origin}/callback`,
        close: () => {
          server.closeAllConnections();
          server.close();
        },
      });
    });
  });
}

/** An in-memory OAuth provider: what an MCP host application supplies to the SDK. */
class MemoryProvider implements OAuthClientProvider {
  authorizationUrl: URL | undefined;
  savedTokens: OAuthTokens | undefined;
  private verifier = '';

  get redirectUrl(): string {
    return clientHost.redirectUri;
  }
  get clientMetadata(): OAuthClientMetadata {
    return { redirect_uris: [clientHost.redirectUri], client_name: 'Connector e2e' };
  }
  clientInformation(): OAuthClientInformation {
    return { client_id: clientHost.clientId };
  }
  tokens(): OAuthTokens | undefined {
    return this.savedTokens;
  }
  saveTokens(tokens: OAuthTokens): void {
    this.savedTokens = tokens;
  }
  redirectToAuthorization(url: URL): void {
    this.authorizationUrl = url;
  }
  saveCodeVerifier(verifier: string): void {
    this.verifier = verifier;
  }
  codeVerifier(): string {
    return this.verifier;
  }
}

before(async () => {
  fx = await startE2eFixture({ connector: true });
  clientHost = await startClientHost();
});

after(async () => {
  clientHost?.close();
  await fx?.close();
});

test('HV-3: an MCP client signs in through the sidecar and calls a tool as the user', async (t) => {
  const mcpUrl = new URL(`${fx.sidecar.url}/mcp`);
  const provider = new MemoryProvider();

  // 1. No token yet: the SDK reads the 401 challenge, discovers Custos, and asks
  //    the host to send the user to the authorization endpoint.
  const first = new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider });
  await assert.rejects(
    new Client({ name: 'connector-e2e', version: '0.0.0' }).connect(first),
    UnauthorizedError,
  );
  const authorizationUrl = provider.authorizationUrl;
  assert.ok(authorizationUrl, 'the SDK must have built an authorization URL');
  assert.equal(
    authorizationUrl.origin,
    new URL(fx.pds.baseUrl).origin,
    'sign-in happens at Custos, the authorization server the sidecar names',
  );
  assert.equal(authorizationUrl.searchParams.get('resource'), `${fx.sidecar.url}/mcp`);
  assert.equal(
    authorizationUrl.searchParams.get('request_uri'),
    null,
    'an MCP client sends a plain request, not a pushed one',
  );

  // 2. The user approves on the consent page.
  const approval = await approveConsent(fx.pds.baseUrl, authorizationUrl.toString(), {
    identifier: fx.parent.did,
    password: fx.parent.password,
  });
  const code = approval.params.get('code');
  assert.ok(code, `consent must yield a code: ${approval.location}`);

  // 3. The SDK redeems the code. It sends no DPoP proof.
  await first.finishAuth(code);
  const tokens = provider.savedTokens;
  assert.ok(tokens, 'the SDK must have stored tokens');
  assert.equal(tokens.token_type, 'Bearer');
  const claims = decodeJwtPayload(tokens.access_token);
  assert.equal(claims.aud, `${fx.sidecar.url}/mcp`, 'the token is for the sidecar resource');
  assert.equal(claims.sub, fx.parent.did, 'a connector acts as the user');
  assert.equal(claims.cnf, undefined, 'the token is not bound to a key');

  // 4. Connected: the sidecar forwards the token and the PDS accepts it.
  const client = new Client({ name: 'connector-e2e', version: '0.0.0' });
  await client.connect(new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider }));
  t.after(() => client.close());

  const who = toolJson(await client.callTool({ name: 'whoami', arguments: {} }));
  assert.equal(who.did, fx.parent.did);

  const result = await client.callTool({
    name: 'create_post',
    arguments: { text: 'hello from a connector (hermetic e2e)' },
  });
  assert.notEqual(result.isError, true, `create_post failed: ${JSON.stringify(result.content)}`);
  const created = toolJson(result);
  const record = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.getRecord', {
    repo: fx.parent.did,
    collection: 'app.bsky.feed.post',
    rkey: created.uri.split('/').pop()!,
  });
  assert.equal(record.value.text, 'hello from a connector (hermetic e2e)');
});
