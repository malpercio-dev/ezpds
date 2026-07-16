// HV-2 live driver: the staging/production half of MM-370's Definition of Done
// (docs/test-plans/2026-07-15-MM-356.md → HV-2). Mirrors test/e2e-fixture.ts but
// against real deployments. Provisions an ephemeral parent, mints a sovereign
// child (genesis published to the REAL plc.directory), exchanges the child
// capability, and drives create_post through the DEPLOYED sidecar as a real MCP
// client. Prints a JSON report; leaves the parent + child up for inspection
// (retire them afterwards with hv2-cleanup.mjs).
//
// Usage (staging):
//   export EZPDS_BASE_URL=https://ezpds-staging.up.railway.app
//   export EZPDS_ADMIN_TOKEN=<staging admin token>          # mints the claim code
//   export MCP_SIDECAR_URL=https://obsign-mcp-staging.up.railway.app
//   export EZPDS_INTEROP_STATE_DIR=/tmp/hv2-state           # parent creds land here
//   node --disable-warning=ExperimentalWarning test/live/hv2-create-post.mjs
//
// Secrets ride env only — nothing sensitive is hardcoded or printed. First run
// on staging: 2026-07-16 (see PR #292); the same driver serves the eventual
// production pass.

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { newKeypair, buildGenesisOp, randomSuffix } from 'ezpds-interop/src/crypto.js';

const BASE = (process.env.EZPDS_BASE_URL ?? '').replace(/\/+$/, '');
const SIDECAR = (process.env.MCP_SIDECAR_URL ?? '').replace(/\/+$/, '');
if (!BASE || !SIDECAR || !process.env.EZPDS_ADMIN_TOKEN) {
  console.error('set EZPDS_BASE_URL, EZPDS_ADMIN_TOKEN, MCP_SIDECAR_URL');
  process.exit(1);
}

const report = { base: BASE, sidecar: SIDECAR };

async function json(res) {
  const body = await res.json();
  if (!res.ok) throw new Error(`${res.url} -> ${res.status}: ${JSON.stringify(body)}`);
  return body;
}

// 1. Ephemeral parent through the full wallet ceremony (interop).
const account = await import('ezpds-interop/src/account.js');
const parent = await account.createAccount({ name: `hv2-parent-${randomSuffix(4)}`, kind: 'ephemeral' });
report.parent = { did: parent.did, handle: parent.handle };

// 2. Mint the sovereign child: reserved repo key + locally-held rotation key.
const described = await json(await fetch(`${BASE}/xrpc/com.atproto.server.describeServer`));
const domain = described.availableUserDomains[0].replace(/^\./, '');
const reserved = await json(
  await fetch(`${BASE}/xrpc/com.atproto.server.reserveSigningKey`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  }),
);
const walletKey = await newKeypair();
const childHandle = `hv2-agent-${randomSuffix(6)}.${domain}`;
const { did: childDid, signedOp } = await buildGenesisOp({
  rotationKeyId: walletKey.keyId,
  repoSigningKeyId: reserved.signingKey,
  rotationKeypair: walletKey.keypair,
  handle: childHandle,
  pdsUrl: BASE,
});
const minted = await json(
  await fetch(`${BASE}/agent/child`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${parent.accessJwt}` },
    body: JSON.stringify({ handle: childHandle, plcOp: signedOp }),
  }),
);
report.child = {
  did: minted.did,
  handle: minted.handle,
  registrationId: minted.registrationId,
  scopes: minted.scopes,
  didMatchesLocalDerivation: minted.did === childDid,
};

// 3. Exchange the child capability for the Bearer a caller forwards.
const token = await json(
  await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: minted.identityAssertion,
      resource: `${BASE}/`,
    }),
  }),
);

// 4. Drive the DEPLOYED sidecar as a real MCP client, forwarding that Bearer.
const client = new Client({ name: 'hv2-live', version: '0.0.0' });
await client.connect(
  new StreamableHTTPClientTransport(new URL(`${SIDECAR}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token.access_token}` } },
  }),
);
const toolJson = (r) => JSON.parse(r.content[0].text);
const who = toolJson(await client.callTool({ name: 'whoami', arguments: {} }));
report.whoami = { did: who.did, state: who.state, handle: who.handle ?? null };

const postText = `Hello from a sovereign child agent — posted through the hosted Custos MCP sidecar (MM-370 HV-2). ${new Date().toISOString()}`;
const createResult = await client.callTool({ name: 'create_post', arguments: { text: postText } });
if (createResult.isError) throw new Error(`create_post failed: ${createResult.content[0].text}`);
const created = toolJson(createResult);
report.post = { uri: created.uri, cid: created.cid };
await client.close();

// 5. Confirm attribution: record in the CHILD repo, parent repo untouched.
const rkey = created.uri.split('/').pop();
const readBack = await json(
  await fetch(
    `${BASE}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(minted.did)}&collection=app.bsky.feed.post&rkey=${rkey}`,
  ),
);
report.readBack = { uri: readBack.uri, text: readBack.value.text };
const parentPosts = await json(
  await fetch(
    `${BASE}/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(parent.did)}&collection=app.bsky.feed.post`,
  ),
);
report.parentRepoPostCount = parentPosts.records.length;

// 6. The child is real on the live network: resolvable in the REAL plc.directory.
const plc = await fetch(`https://plc.directory/${minted.did}`);
report.plcDirectory = plc.ok ? await plc.json() : { status: plc.status };

console.log(JSON.stringify(report, null, 2));
