// AC3.1 + AC3.2: `create_post`, called over the sidecar's Streamable-HTTP
// transport with a forwarded child token, publishes an app.bsky.feed.post to the
// CHILD agent's repo — attributed to the child's own DID, with the parent's repo
// untouched. This is the sovereign-child attribution guarantee (ADR-0023)
// composed with credential forwarding (ADR-0024), end to end.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startE2eFixture, xrpcGet, type E2eFixture } from './e2e-fixture.ts';
import { toolJson } from './support.ts';

const POST_TEXT = 'hello from a sovereign child agent (hermetic e2e, MM-370)';

let fx: E2eFixture;

before(async () => {
  fx = await startE2eFixture();
});

after(async () => {
  await fx.close();
});

test('fixture smoke: PDS + parent + minted child + sidecar all stand up', async () => {
  assert.match(fx.child.did, /^did:plc:[a-z2-7]{24}$/);
  assert.notEqual(fx.child.did, fx.parent.did, 'the child is its own identity, not the parent');
  assert.ok(fx.child.identityAssertion, 'the mint returned the child capability');

  const health = await fetch(`${fx.sidecar.url}/healthz`);
  assert.equal(health.status, 200);

  // The child resolves as a first-class account on the PDS.
  const described = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.describeRepo', {
    repo: fx.child.did,
  });
  assert.equal(described.handle, fx.child.handle);
});

test('AC3.1: create_post over the sidecar creates a readable record', async (t) => {
  const token = await fx.exchangeChildToken();
  const client = await fx.connect(token);
  t.after(() => client.close());

  // The forwarded token IS the child: the session the sidecar minted for this
  // request reports the child DID, not the parent's.
  const who = toolJson(await client.callTool({ name: 'whoami', arguments: {} }));
  assert.equal(who.did, fx.child.did);

  const result = await client.callTool({
    name: 'create_post',
    arguments: { text: POST_TEXT },
  });
  assert.notEqual(result.isError, true, `create_post failed: ${JSON.stringify(result.content)}`);
  const created = toolJson(result);
  assert.ok(created.uri, 'createRecord returned a record uri');
  assert.ok(created.cid, 'createRecord returned a record cid');

  const rkey = created.uri.split('/').pop()!;

  // Read it back over the sidecar (get_record defaults to the session DID)…
  const viaSidecar = toolJson(
    await client.callTool({
      name: 'get_record',
      arguments: { collection: 'app.bsky.feed.post', rkey },
    }),
  );
  assert.equal(viaSidecar.uri, created.uri);
  assert.equal(viaSidecar.value.text, POST_TEXT);

  // …and directly from the PDS, independent of the sidecar.
  const direct = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.getRecord', {
    repo: fx.child.did,
    collection: 'app.bsky.feed.post',
    rkey,
  });
  assert.equal(direct.uri, created.uri);
  assert.equal(direct.value.text, POST_TEXT);
});

test('AC3.2: the post lives in the child repo; the parent repo is unchanged', async () => {
  // The record's at-uri names the CHILD's DID as the repo.
  const childPosts = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.listRecords', {
    repo: fx.child.did,
    collection: 'app.bsky.feed.post',
  });
  assert.equal(childPosts.records.length, 1);
  assert.match(childPosts.records[0].uri, new RegExp(`^at://${fx.child.did}/`));

  const parentPosts = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.listRecords', {
    repo: fx.parent.did,
    collection: 'app.bsky.feed.post',
  });
  assert.equal(parentPosts.records.length, 0, 'nothing was written to the parent repo');

  // The write was authorized by the forwarded child capability, and the audit
  // trail attributes it to the child's registration (visible to the parent).
  const audit = await fetch(
    `${fx.pds.baseUrl}/v1/agents/${fx.child.registrationId}/audit`,
    { headers: { authorization: `Bearer ${fx.parent.accessJwt}` } },
  );
  assert.equal(audit.status, 200);
  const events = ((await audit.json()) as { events: { eventType: string; did?: string }[] })
    .events;
  const write = events.find((event) => event.eventType === 'repo_write');
  assert.ok(write, 'the repo write left an audit event on the child registration');
  assert.equal(write.did, fx.child.did, 'the audit event is attributed to the child DID');
});
