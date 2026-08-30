// Conformance suite: the client half of the auth.md agent-auth story. Drives
// discovery → register → claim → exchange → tool calls end-to-end through the
// real MCP server against a locally spawned PDS (the server half is covered by
// crates/pds/src/routes/agent_auth_test.rs).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  startMockPlc,
  spawnPds,
  provisionAccount,
  confirmClaim,
  type SpawnedPds,
  type TestAccount,
} from './harness.ts';

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serverBin = path.join(packageDir, 'bin', 'custos-mcp');

let tmp: string;
let plc: Awaited<ReturnType<typeof startMockPlc>>;
let pds: SpawnedPds;
let account: TestAccount;
let mcpStateDir: string;

function credsFile(): string {
  const host = new URL(pds.baseUrl).host.replace(/[^a-zA-Z0-9.-]/g, '_');
  return path.join(mcpStateDir, `${host}.json`);
}

function serverEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '',
    HOME: tmp,
    // Trust the test TLS proxy's throwaway cert (set up by test/run.ts).
    NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS ?? '',
    CUSTOS_PDS_URL: pds.baseUrl,
    CUSTOS_MCP_EMAIL: account.email,
    CUSTOS_MCP_STATE_DIR: mcpStateDir,
    CUSTOS_MCP_PACE_MS: '25',
    ...extra,
  };
}

async function connectClient(extra: Record<string, string> = {}): Promise<Client> {
  const client = new Client({ name: 'conformance-test', version: '0.0.0' });
  const transport = new StdioClientTransport({
    command: serverBin,
    env: serverEnv(extra),
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (chunk: Buffer) => {
    process.stderr.write(`  [server] ${String(chunk)}`);
  });
  await client.connect(transport);
  return client;
}

function toolJson(result: any): any {
  const content = result.content as { type: string; text: string }[];
  assert.ok(content?.[0]?.type === 'text', 'tool result has text content');
  try {
    return JSON.parse(content[0]!.text);
  } catch {
    // A relayed error is plain text; surface it instead of a bare parse error.
    throw new Error(`tool returned non-JSON content: ${content[0]!.text}`);
  }
}

before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-mcp-test-'));
  mcpStateDir = path.join(tmp, 'mcp-state');
  plc = await startMockPlc();
  pds = await spawnPds({
    dir: tmp,
    plcUrl: plc.url,
    agentAuthEnabled: true,
    // A DELIBERATELY NARROWED profile: the shipped default also carries
    // `repo:*?action=delete`, which this fixture omits so AC2.2 can still
    // exercise the InsufficientScope relay against a real refusal. Plus a
    // blanket space grant, so the space tools' happy path is exercised.
    // The explicit params matter: a bare `space:*` confers reads but never a
    // write target (no type declaration to draw collections from), and
    // authority defaults to `self`, which an unfiltered listSpaces (authority
    // `*`) does not match.
    grantedScopes: [
      'atproto',
      'repo:*?action=create&action=update',
      'blob:*/*',
      'space:*?authority=*&collection=*',
    ],
  });
  account = await provisionAccount(pds.baseUrl, path.join(tmp, 'interop-state'));
});

after(() => {
  pds?.stop();
  plc?.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('discovery: PRM → AS metadata advertises the agent_auth surface', async () => {
  const prm: any = await (
    await fetch(`${pds.baseUrl}/.well-known/oauth-protected-resource`)
  ).json();
  assert.ok(Array.isArray(prm.authorization_servers) && prm.authorization_servers.length > 0);

  const asUrl = prm.authorization_servers[0].replace(/\/+$/, '');
  const as: any = await (await fetch(`${asUrl}/.well-known/oauth-authorization-server`)).json();
  assert.ok(as.agent_auth, 'AS metadata has an agent_auth block');
  assert.equal(as.agent_auth.identity_endpoint, `${pds.baseUrl}/agent/identity`);
  assert.ok(as.agent_auth.identity_types_supported.includes('service_auth'));
  assert.ok(
    as.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:jwt-bearer') &&
      as.grant_types_supported.includes('urn:workos:agent-auth:grant-type:claim'),
    'token endpoint advertises both agent grants',
  );

  const authMd = await fetch(as.agent_auth.skill);
  assert.ok(authMd.ok, 'auth.md skill document is served');
  assert.match(await authMd.text(), /agent/i);
});

test('onboarding ceremony, tool surface, and credential hygiene', async (t) => {
  const client = await connectClient();
  t.after(() => client.close());

  // AC1.1 — first launch reaches "waiting for claim" and surfaces the code.
  const waiting = toolJson(await client.callTool({ name: 'whoami', arguments: {} }));
  assert.equal(waiting.state, 'onboarding');
  assert.match(waiting.userCode, /^[A-Z0-9]{6}$/);
  assert.ok(waiting.verificationUri.startsWith(pds.baseUrl));

  // AC2.3 — with CUSTOS_MCP_ALLOW_DESTRUCTIVE unset, destructive tools are not offered.
  const tools = (await client.listTools()).tools.map((tool) => tool.name);
  for (const expected of [
    'whoami',
    'create_post',
    'get_record',
    'list_records',
    'search_timeline',
    'account_status',
    'list_spaces',
    'space_get_record',
    'space_list_records',
    'space_create_record',
  ]) {
    assert.ok(tools.includes(expected), `tool list includes ${expected}`);
  }
  for (const destructive of [
    'delete_record',
    'put_record',
    'space_put_record',
    'space_delete_record',
  ]) {
    assert.ok(!tools.includes(destructive), `${destructive} not offered by default`);
  }

  // The human confirms in the wallet (here: the claim/confirm endpoint directly).
  await confirmClaim(pds.baseUrl, account.accessJwt, waiting.userCode);

  // AC1.2 — polling completes and the server transitions to ready without restart.
  let ready: any;
  const deadline = Date.now() + 60_000;
  for (;;) {
    ready = toolJson(await client.callTool({ name: 'whoami', arguments: {} }));
    if (ready.state === 'ready') break;
    assert.ok(Date.now() < deadline, `never became ready; last status: ${JSON.stringify(ready)}`);
    await new Promise((r) => setTimeout(r, 2_000));
  }
  assert.equal(ready.did, account.did);
  assert.equal(ready.handle, account.handle);
  assert.ok(ready.scopes.length > 0, 'granted scopes are reported');

  // AC3.1 — the token cache is 0600 and tokens never surface in MCP responses.
  const stat = fs.statSync(credsFile());
  assert.equal(stat.mode & 0o777, 0o600, 'credential cache file is 0600');
  const creds = JSON.parse(fs.readFileSync(credsFile(), 'utf8'));
  assert.ok(creds.accessToken && creds.assertion, 'tokens are cached');
  const whoamiText = JSON.stringify(ready);
  assert.ok(!whoamiText.includes(creds.accessToken), 'access token not in whoami output');
  assert.ok(!whoamiText.includes(creds.assertion), 'assertion not in whoami output');

  // AC2.1 — create_post produces a record visible via getRecord.
  const post = toolJson(
    await client.callTool({
      name: 'create_post',
      arguments: { text: 'custos-mcp conformance post' },
    }),
  );
  assert.ok(post.uri?.startsWith(`at://${account.did}/app.bsky.feed.post/`));
  assert.ok(post.cid, 'createRecord returned a cid');

  const rkey = post.uri.split('/').pop();
  const fetched = toolJson(
    await client.callTool({
      name: 'get_record',
      arguments: { collection: 'app.bsky.feed.post', rkey },
    }),
  );
  assert.equal(fetched.value.text, 'custos-mcp conformance post');

  const listed = toolJson(
    await client.callTool({
      name: 'list_records',
      arguments: { collection: 'app.bsky.feed.post' },
    }),
  );
  assert.ok(listed.records.some((record: any) => record.uri === post.uri));

  const status = toolJson(await client.callTool({ name: 'account_status', arguments: {} }));
  assert.equal(typeof status.activated, 'boolean');
});

test('jwt-bearer exchange returns a renewed identity_assertion (sliding window)', async () => {
  // Pin the renewal on the wire: every successful exchange must hand back a fresh
  // assertion so a sporadic agent never needs a second claim ceremony.
  const creds = JSON.parse(fs.readFileSync(credsFile(), 'utf8'));
  const res = await fetch(`${pds.baseUrl}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: creds.assertion,
    }),
  });
  assert.equal(res.status, 200);
  const body: any = await res.json();
  assert.equal(typeof body.identity_assertion, 'string', 'exchange returns a renewed assertion');
  assert.notEqual(body.identity_assertion, creds.assertion, 'the renewal is freshly minted');
  assert.equal(typeof body.assertion_expires, 'string', 'the renewal carries its expiry');
  assert.ok(new Date(body.assertion_expires).getTime() > Date.now(), 'the renewal is unexpired');
});

test('AC2.2: out-of-scope calls relay the 403 as a comprehensible error', async (t) => {
  // Same cached credentials, destructive tools enabled: delete needs the repo
  // delete action, which this fixture's narrowed profile withholds (the shipped
  // default grants it). This asserts the refusal is comprehensible when an
  // operator narrows scopes — not that delete is unavailable out of the box.
  const client = await connectClient({ CUSTOS_MCP_ALLOW_DESTRUCTIVE: '1' });
  t.after(() => client.close());

  const tools = (await client.listTools()).tools.map((tool) => tool.name);
  assert.ok(tools.includes('delete_record'), 'delete_record offered when explicitly enabled');

  const result = await client.callTool({
    name: 'delete_record',
    arguments: { collection: 'app.bsky.feed.post', rkey: 'whatever' },
  });
  assert.equal(result.isError, true);
  const message = (result.content as { text: string }[])[0]!.text;
  assert.match(message, /InsufficientScope/, 'names the refusal');
  assert.match(message, /Granted scopes:/, 'reports the granted scopes');
  assert.doesNotMatch(message, /\n\s+at /, 'no stack trace');
});

test('spaces: the agent tool surface drives a permissioned space end-to-end', async (t) => {
  // The space is the account's own simplespace, created by the owner (full
  // session) the way the wallet would — the agent then reads and writes it
  // under its space:* grant.
  const spaceUri = `at://${account.did}/space/org.example.bucket/main`;
  const createSpace = await fetch(`${pds.baseUrl}/xrpc/com.atproto.simplespace.createSpace`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${account.accessJwt}`,
    },
    body: JSON.stringify({
      type: 'org.example.bucket',
      skey: 'main',
      policy: { $type: 'com.atproto.simplespace.defs#publicPolicy' },
      appAccess: { $type: 'com.atproto.simplespace.defs#open' },
    }),
  });
  assert.ok(createSpace.ok, `createSpace failed: ${await createSpace.text()}`);

  const client = await connectClient();
  t.after(() => client.close());

  const created = toolJson(
    await client.callTool({
      name: 'space_create_record',
      arguments: {
        space: spaceUri,
        collection: 'org.example.note',
        record: { text: 'custos-mcp space conformance note' },
      },
    }),
  );
  assert.ok(created.uri, 'space createRecord returned a uri');
  assert.ok(created.cid, 'space createRecord returned a cid');

  const rkey = created.uri.split('/').pop();
  const fetched = toolJson(
    await client.callTool({
      name: 'space_get_record',
      arguments: { space: spaceUri, collection: 'org.example.note', rkey },
    }),
  );
  assert.equal(fetched.value.text, 'custos-mcp space conformance note');

  const listed = toolJson(
    await client.callTool({
      name: 'space_list_records',
      arguments: { space: spaceUri, collection: 'org.example.note' },
    }),
  );
  // listRecords entries are keyed by collection + rkey (space records carry no per-record uri).
  assert.ok(listed.records.some((record: any) => record.rkey === rkey && record.cid));

  const spaces = toolJson(await client.callTool({ name: 'list_spaces', arguments: {} }));
  assert.ok(
    spaces.spaces.some((space: any) => space.uri === spaceUri),
    `list_spaces reports the space (got ${JSON.stringify(spaces)})`,
  );
});

/**
 * The cooperative arm of the claim ceremony (auth.md §3.5): an anonymous agent proposes a handle,
 * the human confirms with a wallet-signed genesis op, and the agent's *unchanged* claim poll hands
 * back a credential for an account of its own. Driven over raw HTTP rather than through the MCP
 * client because the MCP server only speaks `service_auth` — this pins the protocol the wallet and
 * a child-aware agent will speak.
 */
test('cooperative mint: handle_hint → claim as child → the agent writes as itself', async () => {
  const { newKeypair, buildGenesisOp } = await import('ezpds-interop/src/crypto.js');
  const handle = `scribe-${Math.random().toString(36).slice(2, 8)}.localhost`;

  const registered: any = await (
    await fetch(`${pds.baseUrl}/agent/identity`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'anonymous', handle_hint: handle }),
    })
  ).json();
  assert.equal(registered.registration_type, 'anonymous');
  const claimToken = registered.claim_token;

  const started: any = await (
    await fetch(`${pds.baseUrl}/agent/identity/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ claim_token: claimToken }),
    })
  ).json();
  const userCode = started.claim_attempt.user_code;

  // The approval screen sees the agent's proposal before the human decides.
  const preview: any = await (
    await fetch(`${pds.baseUrl}/v1/agents/claim-preview`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${account.accessJwt}`,
      },
      body: JSON.stringify({ userCode }),
    })
  ).json();
  assert.equal(preview.handleHint, handle, 'claim-preview surfaces the proposed handle');

  // The wallet's half: reserve the repo signing key, then sign the child's genesis op with a
  // rotation key it holds. `buildGenesisOp` also fills a middle recovery slot the server does not
  // inspect for children — only rotationKeys[0] (the signer) and the atproto key matter here.
  const reserved: any = await (
    await fetch(`${pds.baseUrl}/xrpc/com.atproto.server.reserveSigningKey`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    })
  ).json();
  const rotationKey = await newKeypair();
  const spare = await newKeypair();
  const { signedOp } = await buildGenesisOp({
    rotationKeyId: rotationKey.keyId,
    recoveryKeyId: spare.keyId,
    repoSigningKeyId: reserved.signingKey,
    rotationKeypair: rotationKey.keypair,
    handle,
    pdsUrl: pds.baseUrl,
  });

  const confirmRes = await fetch(`${pds.baseUrl}/agent/identity/claim/confirm`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${account.accessJwt}`,
    },
    body: JSON.stringify({ user_code: userCode, child: { handle, plcOp: signedOp } }),
  });
  const confirmed: any = await confirmRes.json();
  assert.ok(confirmRes.ok, `child confirm failed: ${JSON.stringify(confirmed)}`);
  assert.equal(confirmed.did, account.did, '`did` still names the confirming account');
  const childDid: string = confirmed.child.did;
  assert.match(childDid, /^did:plc:/);
  assert.equal(confirmed.child.handle, handle);
  assert.notEqual(childDid, account.did, 'the agent got its own DID, not the user\'s');

  // The agent polls exactly as it would have — and collects a child-subject credential.
  const granted: any = await (
    await fetch(`${pds.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:workos:agent-auth:grant-type:claim',
        claim_token: claimToken,
      }),
    })
  ).json();
  assert.ok(granted.access_token, `claim poll did not grant: ${JSON.stringify(granted)}`);
  const sub = (token: string) =>
    JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()).sub;
  assert.equal(sub(granted.access_token), childDid, 'access token is subject to the child');
  assert.equal(sub(granted.identity_assertion), childDid, 'assertion is subject to the child');

  // And a record written with it lands in the child's repo, under the child's handle.
  const writeRes = await fetch(`${pds.baseUrl}/xrpc/com.atproto.repo.createRecord`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${granted.access_token}`,
    },
    body: JSON.stringify({
      repo: childDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'posted as myself', createdAt: new Date().toISOString() },
    }),
  });
  const written: any = await writeRes.json();
  assert.ok(writeRes.ok, `child write failed: ${JSON.stringify(written)}`);
  assert.ok(written.uri.startsWith(`at://${childDid}/app.bsky.feed.post/`), written.uri);

  const rkey = written.uri.split('/').pop();
  const readBack: any = await (
    await fetch(
      `${pds.baseUrl}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(handle)}` +
        `&collection=app.bsky.feed.post&rkey=${rkey}`,
    )
  ).json();
  assert.equal(readBack.value.text, 'posted as myself');
  assert.equal(readBack.uri, written.uri);
});

test('AC3.2: revocation fails closed and never auto-re-registers', async (t) => {
  // Revoke server-side. There is no operator HTTP surface for this yet
  // (that lands with the wallet /v1/agents API), so flip the row the way the
  // server's own tests do.
  const { DatabaseSync } = await import('node:sqlite');
  // The PDS holds its own connections to this file; a busy timeout keeps the
  // UPDATE from failing instantly on a transient lock.
  const db = new DatabaseSync(path.join(pds.dataDir, 'pds.db'), { timeout: 5_000 });
  db.exec(`UPDATE agent_identities SET status = 'revoked'`);
  db.close();

  // Force the next tool call to re-exchange the assertion (drop the cached
  // access token, which may still be inside its 5-minute lifetime).
  const creds = JSON.parse(fs.readFileSync(credsFile(), 'utf8'));
  delete creds.accessToken;
  delete creds.accessTokenExpiresAt;
  fs.writeFileSync(credsFile(), JSON.stringify(creds), { mode: 0o600 });

  const client = await connectClient();
  t.after(() => client.close());

  const result = await client.callTool({
    name: 'create_post',
    arguments: { text: 'should never land' },
  });
  assert.equal(result.isError, true);
  const message = (result.content as { text: string }[])[0]!.text;
  assert.match(message, /revoked in Obsign/);
  assert.match(message, /will not re-register itself/);

  // The revocation is remembered: a fresh server start reports it instead of
  // silently starting a new claim ceremony.
  const restarted = await connectClient();
  t.after(() => restarted.close());
  const status = toolJson(await restarted.callTool({ name: 'whoami', arguments: {} }));
  assert.equal(status.state, 'revoked');
});

test('AC1.3: a PDS with agent auth disabled fails the launch legibly', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-mcp-disabled-'));
  const disabledPds = await spawnPds({ dir, plcUrl: plc.url, agentAuthEnabled: false });
  try {
    const result = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      const proc = spawn(serverBin, [], {
        env: {
          ...serverEnv({ CUSTOS_MCP_STATE_DIR: path.join(dir, 'state') }),
          CUSTOS_PDS_URL: disabledPds.baseUrl,
        },
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      proc.stderr!.on('data', (chunk) => (stderr += String(chunk)));
      // The launch is expected to fail fast; a hang is itself a regression,
      // so kill rather than stall the suite.
      const killer = setTimeout(() => proc.kill(), 15_000);
      proc.on('exit', (code) => {
        clearTimeout(killer);
        resolve({ code, stderr });
      });
    });
    assert.notEqual(result.code, 0, 'exits nonzero');
    assert.match(result.stderr, /service_auth_not_enabled/, 'names the server error');
    assert.match(result.stderr, /disabled/, 'explains it legibly');
  } finally {
    disabledPds.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
