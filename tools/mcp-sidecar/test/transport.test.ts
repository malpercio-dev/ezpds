// AC2.1 — the shared tool surface is served over Streamable HTTP, not stdio.
// An MCP StreamableHTTPClientTransport client connects to the sidecar's HTTP
// listener, lists tools, and sees the same tool names the stdio server exposes.
// Also checks the MCP-spec protected-resource metadata that points a caller at
// Custos as the authorization server (ADR-0019).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  startStubPds,
  startSidecar,
  connectClient,
  fakeToken,
  STUB_PDS_ISSUER,
  type StubPds,
  type RunningSidecar,
} from './support.ts';

let pds: StubPds;
let sidecar: RunningSidecar;

before(async () => {
  pds = await startStubPds();
  sidecar = await startSidecar({
    MCP_SIDECAR_PDS_ORIGIN: pds.url, // stands in for the private forwarding origin
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org',
  });
});

after(async () => {
  await sidecar.close();
  await pds.close();
});

test('AC2.1: the sidecar serves the shared tool surface over Streamable HTTP', async () => {
  let client: Client | undefined;
  try {
    client = await connectClient(sidecar.url, fakeToken({ sub: 'did:plc:alice', scope: 'atproto' }));
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    // The same non-destructive surface the stdio server exposes by default.
    assert.deepEqual(names, [
      'account_status',
      'create_post',
      'get_record',
      'list_records',
      'list_spaces',
      'search_timeline',
      'space_create_record',
      'space_get_record',
      'space_list_records',
      'update_bluesky_profile',
      'upload_blob',
      'whoami',
    ]);
  } finally {
    await client?.close();
  }
});

test('AC2.1: the protected-resource metadata names the PUBLIC Custos AS, not the private origin', async () => {
  // REGRESSION: the advertised AS is read from the PDS's own `issuer`, not from a
  // hand-set env copy of it. A copy is what dead-ended discovery (it still named
  // the pre-migration apex, which serves no OAuth metadata at all).
  // RFC 9728 §3.1: the metadata for `<origin>/mcp` lives at the path-suffixed
  // well-known; the root is an alias serving the same document.
  for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
    const res = await fetch(`${sidecar.url}${path}`);
    assert.equal(res.status, 200, path);
    const body = (await res.json()) as {
      resource: string;
      authorization_servers: string[];
      scopes_supported: string[];
    };
    // The MCP server URL, which is what the PDS's `connector_resources` names.
    assert.equal(body.resource, 'https://mcp.obsign.org/mcp', path);
    assert.deepEqual(body.authorization_servers, [STUB_PDS_ISSUER]);
    assert.ok(
      !body.authorization_servers.includes(pds.url),
      'the private forwarding origin is never advertised to clients',
    );
    // An MCP client with no scope of its own requests this list verbatim, and the
    // PDS refuses a request without `atproto`.
    assert.ok(body.scopes_supported.includes('atproto'), path);
  }
});

test('an unauthenticated MCP request is challenged with where to find the metadata', async () => {
  // An MCP client starts its OAuth sign-in only from this 401.
  const res = await fetch(`${sidecar.url}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  assert.equal(res.status, 401);
  assert.equal(
    res.headers.get('www-authenticate'),
    'Bearer resource_metadata="https://mcp.obsign.org/.well-known/oauth-protected-resource/mcp"',
  );
});

test('discovery fails loudly (503) when the PDS publishes no usable issuer', async () => {
  // A guessed authorization server would dead-end the client silently; a
  // retryable 503 says the sidecar could not answer and why.
  const brokenPds = await startStubPds({ asMetadata: 'missing-issuer' });
  const brokenSidecar = await startSidecar({
    MCP_SIDECAR_PDS_ORIGIN: brokenPds.url,
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org',
  });
  try {
    const res = await fetch(`${brokenSidecar.url}/.well-known/oauth-protected-resource`);
    assert.equal(res.status, 503);
  } finally {
    await brokenSidecar.close();
    await brokenPds.close();
  }
});

test('the request body is bounded (oversized payloads are refused with 413)', async () => {
  const res = await fetch(`${sidecar.url}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${fakeToken({ sub: 'did:plc:alice', scope: 'atproto' })}`,
    },
    // Just over the 8 MiB ceiling (sized for a maximum inline upload_blob).
    body: 'x'.repeat(8 * 1024 * 1024 + 1024),
  });
  assert.equal(res.status, 413);
});
