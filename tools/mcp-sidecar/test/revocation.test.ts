// AC3.4: revoking the child mid-session kills the delegated capability at the
// caller-facing surface, legibly, with no partial write.
//
// Revocation is enforced at the token-exchange boundary (AC1.7): flipping the
// registration to `revoked` makes the next jwt-bearer exchange fail with
// `access_denied`, while an already-issued access token remains valid until its
// 5-minute TTL lapses — the documented, deliberate revocation bound (see the
// jwt-bearer notes in crates/pds/AGENTS.md). A real caller's session re-exchanges
// the durable assertion for fresh short-lived tokens (exactly what the stdio
// AgentSession does), so the sequence a revoked caller experiences is: the
// refresh fails legibly naming the revocation, and with no forwardable
// credential the sidecar refuses the call legibly too — nothing is written.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  startE2eFixture,
  xrpcGet,
  TokenExchangeError,
  type E2eFixture,
} from './e2e-fixture.ts';
import { toolJson } from './support.ts';

let fx: E2eFixture;

before(async () => {
  fx = await startE2eFixture();
});

after(async () => {
  await fx.close();
});

test('AC3.4: revocation mid-session fails the next call legibly, with no partial write', async (t) => {
  // One successful write first — the session is live and working.
  const token = await fx.exchangeChildToken();
  const client = await fx.connect(token);
  t.after(() => client.close());

  const first = await client.callTool({
    name: 'create_post',
    arguments: { text: 'posted before revocation' },
  });
  assert.notEqual(first.isError, true, `pre-revocation post failed: ${JSON.stringify(first.content)}`);
  const created = toolJson(first);

  // The parent revokes the child through the real Phase-1 surface.
  const revoked = await fetch(`${fx.pds.baseUrl}/agent/child/revoke`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${fx.parent.accessJwt}`,
    },
    body: JSON.stringify({ did: fx.child.did }),
  });
  assert.equal(revoked.status, 200);
  assert.equal(((await revoked.json()) as { status: string }).status, 'revoked');

  // The delegated capability is dead: the caller's next token refresh — the
  // step every session performs before forwarding — fails with a legible,
  // revocation-naming error, not a stack trace.
  await assert.rejects(
    fx.exchangeChildToken(),
    (err: unknown) => {
      assert.ok(err instanceof TokenExchangeError);
      assert.equal(err.code, 'access_denied');
      assert.match(err.message, /revoked/i, 'the refusal names the revocation');
      return true;
    },
  );

  // With no forwardable credential, the sidecar refuses the second create_post
  // legibly (it holds nothing on the caller's behalf to fall back to, ADR-0024).
  const bare = await fx.connect();
  t.after(() => bare.close());
  const second = await bare.callTool({
    name: 'create_post',
    arguments: { text: 'should never land' },
  });
  assert.equal(second.isError, true);
  const message = (second.content as { text: string }[])[0]!.text;
  assert.match(message, /not authenticated/, 'the refusal is legible');
  assert.match(message, /OAuth/, 'and points at the recovery path');
  assert.doesNotMatch(message, /\n\s+at /, 'no stack trace reaches the caller');

  // No partial write: the child repo holds exactly the pre-revocation post.
  const posts = await xrpcGet(fx.pds.baseUrl, 'com.atproto.repo.listRecords', {
    repo: fx.child.did,
    collection: 'app.bsky.feed.post',
  });
  assert.equal(posts.records.length, 1);
  assert.equal(posts.records[0].uri, created.uri);
});
