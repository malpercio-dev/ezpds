// AC2.1 — the shared tool surface is served over Streamable HTTP, not stdio.
// An MCP StreamableHTTPClientTransport client connects to the sidecar's HTTP
// listener, lists tools, and sees the same tool names the stdio server exposes.
// Also checks the MCP-spec protected-resource metadata that points a caller at
// Custos as the authorization server (ADR-0019).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { startStubPds, startSidecar, connectClient, type StubPds, type RunningSidecar } from './support.ts';

let pds: StubPds;
let sidecar: RunningSidecar;

before(async () => {
  pds = await startStubPds();
  sidecar = await startSidecar({
    MCP_SIDECAR_PDS_ORIGIN: pds.url, // stands in for the private forwarding origin
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org',
    MCP_SIDECAR_AUTH_SERVER_ORIGIN: 'https://obsign.org', // the public Custos AS
  });
});

after(async () => {
  await sidecar.close();
  await pds.close();
});

test('AC2.1: the sidecar serves the shared tool surface over Streamable HTTP', async () => {
  let client: Client | undefined;
  try {
    client = await connectClient(sidecar.url);
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    // The same non-destructive surface the stdio server exposes by default.
    assert.deepEqual(names, [
      'account_status',
      'create_post',
      'get_record',
      'list_records',
      'search_timeline',
      'whoami',
    ]);
  } finally {
    await client?.close();
  }
});

test('AC2.1: the protected-resource metadata names the PUBLIC Custos AS, not the private origin', async () => {
  const res = await fetch(`${sidecar.url}/.well-known/oauth-protected-resource`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as { resource: string; authorization_servers: string[] };
  assert.equal(body.resource, 'https://mcp.obsign.org');
  assert.deepEqual(body.authorization_servers, ['https://obsign.org']);
  assert.ok(
    !body.authorization_servers.includes(pds.url),
    'the private forwarding origin is never advertised to clients',
  );
});

test('the request body is bounded (oversized payloads are refused with 413)', async () => {
  const res = await fetch(`${sidecar.url}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'x'.repeat(1024 * 1024 + 1024), // just over the 1 MiB ceiling
  });
  assert.equal(res.status, 413);
});
