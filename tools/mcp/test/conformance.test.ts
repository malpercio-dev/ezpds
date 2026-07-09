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
  return JSON.parse(content[0]!.text);
}

before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-mcp-test-'));
  mcpStateDir = path.join(tmp, 'mcp-state');
  plc = await startMockPlc();
  pds = await spawnPds({ dir: tmp, plcUrl: plc.url, agentAuthEnabled: true });
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
  ]) {
    assert.ok(tools.includes(expected), `tool list includes ${expected}`);
  }
  assert.ok(!tools.includes('delete_record'), 'delete_record not offered by default');
  assert.ok(!tools.includes('put_record'), 'put_record not offered by default');

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

test('AC2.2: out-of-scope calls relay the 403 as a comprehensible error', async (t) => {
  // Same cached credentials, destructive tools enabled: delete needs the
  // repo delete action, which the default agent profile does not grant.
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
