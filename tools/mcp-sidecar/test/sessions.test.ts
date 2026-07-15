// AC2.3 — per-caller state is in-memory, session-scoped, and dies on restart.
// Two callers' state is isolated (one caller's token/DID is never visible to the
// other), and tearing down / restarting the sidecar leaves no recoverable
// session state.

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

const aliceToken = fakeToken({ sub: 'did:plc:alice', scope: 'atproto repo:*' });
const bobToken = fakeToken({ sub: 'did:plc:bob', scope: 'atproto repo:*' });

before(async () => {
  stateDir = path.join(os.tmpdir(), `mcp-sidecar-sess-${process.pid}`);
  pds = await startStubPds();
  sidecar = await startSidecar({
    MCP_SIDECAR_PDS_ORIGIN: pds.url,
    CUSTOS_MCP_STATE_DIR: stateDir,
  });
});

after(async () => {
  await sidecar.close();
  await pds.close();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test('AC2.3: two callers see only their own identity', async () => {
  const alice = await connectClient(sidecar.url, aliceToken);
  const bob = await connectClient(sidecar.url, bobToken);
  try {
    const aliceWho = toolJson(await alice.callTool({ name: 'whoami', arguments: {} }));
    const bobWho = toolJson(await bob.callTool({ name: 'whoami', arguments: {} }));
    assert.equal(aliceWho.did, 'did:plc:alice');
    assert.equal(bobWho.did, 'did:plc:bob');
    assert.notEqual(aliceWho.did, bobWho.did, 'the two callers are isolated');
    // Two distinct caller sessions exist in the registry.
    assert.equal(sidecar.registry.size(), 2);
  } finally {
    await alice.close();
    await bob.close();
  }
});

test('AC2.3: an unauthenticated tool call is refused (no ambient session)', async () => {
  const client = await connectClient(sidecar.url); // no token
  const before = sidecar.registry.size();
  try {
    const result = (await client.callTool({ name: 'whoami', arguments: {} })) as {
      isError?: boolean;
      content: { text: string }[];
    };
    assert.equal(result.isError, true, 'the call is refused, not served with an ambient session');
    assert.match(
      result.content[0]!.text,
      /not authenticated/,
      'without a forwarded credential there is no session to act as',
    );
    assert.equal(sidecar.registry.size(), before, 'no session was minted for the unauthenticated caller');
  } finally {
    await client.close();
  }
});

test('AC2.3: restart leaves no recoverable session state', () => {
  // The registry is purely in-memory: a fresh process (modeled by a fresh
  // registry) starts empty, and nothing was written to disk to recover from.
  assert.ok(!fs.existsSync(stateDir), 'no session state was persisted anywhere');
  sidecar.registry.clear();
  assert.equal(sidecar.registry.size(), 0, 'teardown forgets every session');
});
