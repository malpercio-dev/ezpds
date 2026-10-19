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
  toolJson,
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

test('AC2.5: the registry retains caller identity but no credential', async () => {
  const client = await connectClient(sidecar.url, token);
  try {
    pds.respondWith(200, { uri: `at://${CALLER_DID}/app.bsky.feed.post/def`, cid: 'bafy2' });
    await client.callTool({ name: 'create_post', arguments: { text: 'second post' } });
    // The caller is tracked for eviction/metrics, but the registry stores no
    // credential — the forwarding session is request-scoped and unreachable
    // once the call resolves. `size()` is the only state it exposes; there is no
    // API that could hand back a retained token (ADR-0024).
    assert.equal(sidecar.registry.size(), 1, 'caller tracked');
    assert.equal(
      typeof (sidecar.registry as unknown as { peek?: unknown }).peek,
      'undefined',
      'the registry exposes no accessor that could return a stored token',
    );
  } finally {
    await client.close();
  }
});

test('inline upload_blob decodes base64 and forwards real bytes with the caller token', async () => {
  // The remote-client path: no CUSTOS_MCP_IMAGE_DIR exists on this sidecar,
  // so only inline data can work — which is the point of the test. The payload
  // is text (not binary) because the stub PDS records bodies as UTF-8; if the
  // tool wrongly forwarded the base64 text instead of the decoded bytes, the
  // recorded body would be the base64 itself.
  const payload = 'hello blob';
  const dataUrl = `data:text/plain;base64,${Buffer.from(payload).toString('base64')}`;
  assert.notEqual(dataUrl.slice(dataUrl.indexOf(',') + 1), payload);
  pds.respondWith(200, {
    blob: { $type: 'blob', ref: { $link: 'bafytest' }, mimeType: 'text/plain', size: payload.length },
  });
  const client = await connectClient(sidecar.url, token);
  try {
    const uploaded = toolJson(
      await client.callTool({
        name: 'upload_blob',
        arguments: { data: dataUrl },
      }),
    );
    assert.equal(uploaded.blob.ref.$link, 'bafytest');
  } finally {
    await client.close();
  }

  const upload = pds.requests.find((r) => r.path.includes('com.atproto.repo.uploadBlob'));
  assert.ok(upload, 'the forwarded uploadBlob reached the PDS');
  assert.equal(
    upload.authorization,
    `Bearer ${token}`,
    'the caller token was forwarded verbatim as a Bearer credential',
  );
  assert.equal(upload.body, payload, 'the decoded bytes (not the base64 text) were forwarded');
});
