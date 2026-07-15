// AC2.2 / AC2.5 — credential forwarding: each caller authenticates via OAuth
// against Custos; the caller's token rides each tool call to the PDS; nothing
// durable is cached and no token lingers after the request resolves.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  startStubPds,
  startSidecar,
  connectClient,
  fakeToken,
  callerSubjectOf,
  type StubPds,
  type RunningSidecar,
} from './support.ts';

let pds: StubPds;
let sidecar: RunningSidecar;
let stateDir: string;

const CALLER_DID = 'did:plc:alice';
const token = fakeToken({ sub: CALLER_DID, scope: 'atproto repo:*?action=create' });

before(async () => {
  // A state-dir path the sidecar must never create: proof no on-disk cache is
  // written (the stdio server's `0600` path is absent in the sidecar).
  stateDir = path.join(os.tmpdir(), `mcp-sidecar-state-${process.pid}`);
  pds = await startStubPds();
  sidecar = await startSidecar({
    MCP_SIDECAR_PDS_ORIGIN: pds.url,
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org',
    CUSTOS_MCP_STATE_DIR: stateDir,
  });
});

after(async () => {
  await sidecar.close();
  await pds.close();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('AC2.5: the caller token rides each forwarded XRPC call', async () => {
  pds.respondWith(200, { uri: `at://${CALLER_DID}/app.bsky.feed.post/abc`, cid: 'bafycid' });
  const client = await connectClient(sidecar.url, token);
  try {
    await client.callTool({ name: 'create_post', arguments: { text: 'forwarded post' } });
  } finally {
    await client.close();
  }

  const createRecord = pds.requests.find((r) => r.path.includes('com.atproto.repo.createRecord'));
  assert.ok(createRecord, 'the forwarded createRecord reached the PDS');
  assert.equal(
    createRecord.authorization,
    `Bearer ${token}`,
    'the caller token was forwarded verbatim as a Bearer credential',
  );
});

test('AC2.2: no credential file is written under any state dir', () => {
  // The sidecar imports the shared config module (which computes the stdio
  // `0600` state path), but nothing on the forwarding path ever writes it.
  assert.ok(!fs.existsSync(stateDir), 'the sidecar wrote no credential cache directory');
});

test('AC2.5: no token lingers in memory after the request resolves', async () => {
  const client = await connectClient(sidecar.url, token);
  try {
    pds.respondWith(200, { uri: `at://${CALLER_DID}/app.bsky.feed.post/def`, cid: 'bafy2' });
    await client.callTool({ name: 'create_post', arguments: { text: 'second post' } });
    // Let the sidecar's post-request `release` run.
    await new Promise((r) => setTimeout(r, 50));
    const session = sidecar.registry.peek(callerSubjectOf(token));
    assert.ok(session, 'the caller session object is retained for identity/reuse');
    assert.equal(session.hasBoundToken(), false, 'but it holds no token between requests');
  } finally {
    await client.close();
  }
});
