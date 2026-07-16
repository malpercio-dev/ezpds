// AC3.3: a forwarded token whose scopes exclude the write is refused by the PDS
// with 403 InsufficientScope, and the sidecar relays a legible, scope-naming
// error — parity with the stdio server's `relayError` — never a stack trace.
//
// `[agent_auth] granted_scopes` has no env override, so the fixture narrows it
// through a pds.toml in the spawn dir: the child's capability (and therefore the
// exchanged token) carries a repo scope for a different collection, and the PDS
// — the sole authority on scopes (the sidecar never checks them, ADR-0024) —
// refuses the app.bsky.feed.post create.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startE2eFixture, xrpcGet, type E2eFixture } from './e2e-fixture.ts';

// A valid granular grant that deliberately cannot create an app.bsky.feed.post.
const NARROW_SCOPE = 'repo:app.bsky.graph.follow?action=create';

let fx: E2eFixture;

before(async () => {
  fx = await startE2eFixture({ grantedScopes: ['atproto', NARROW_SCOPE] });
});

after(async () => {
  await fx.close();
});

test('AC3.3: an out-of-scope create_post relays 403 InsufficientScope legibly', async (t) => {
  assert.deepEqual(
    fx.child.scopes,
    ['atproto', NARROW_SCOPE],
    'the minted capability is clamped to the narrowed operator scopes',
  );

  const token = await fx.exchangeChildToken();
  const client = await fx.connect(token);
  t.after(() => client.close());

  const result = await client.callTool({
    name: 'create_post',
    arguments: { text: 'this write is outside the granted scopes' },
  });
  assert.equal(result.isError, true, 'the out-of-scope write is refused');

  const message = (result.content as { text: string }[])[0]!.text;
  assert.match(message, /InsufficientScope/, 'names the PDS refusal');
  assert.match(message, /Granted scopes:/, 'reports what the agent actually holds');
  assert.ok(message.includes(NARROW_SCOPE), 'the granted scope list is spelled out');
  assert.doesNotMatch(message, /\n\s+at /, 'no stack trace reaches the caller');

  // The refusal was clean: nothing landed in the child repo.
  const posts = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.listRecords', {
    repo: fx.child.did,
    collection: 'app.bsky.feed.post',
  });
  assert.equal(posts.records.length, 0);
});
