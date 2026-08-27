// Atproto Spaces checks: drive the com.atproto.space + com.atproto.simplespace
// alpha surface end-to-end on the target deployment — create a simplespace,
// write/read/list records in it, exercise the sync reads (getLatestCommit,
// listRepoOps, getRepo CAR), and tear the space down again.
//
// Everything runs as the account's own session against its own PDS (the
// authority = self shape); a random skey keeps repeated runs independent, and
// the space is deleted in a finally so a failed step never leaks one. Works
// against any Custos deployment; a PDS without the space surface fails the
// first call with an unknown-method error, which the suite reports as-is.

import { BASE_URL } from './config.js';
import { xrpc } from './http.js';
import { ensureSession } from './account.js';
import { randomSuffix } from './crypto.js';

const SPACE_TYPE = 'dev.malpercio.interop.bucket';
const COLLECTION = 'dev.malpercio.interop.note';

export async function createSpace(name, skey) {
  const account = await ensureSession(name);
  await xrpc(BASE_URL, 'com.atproto.simplespace.createSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: {
      type: SPACE_TYPE,
      skey,
      policy: { $type: 'com.atproto.simplespace.defs#publicPolicy' },
      appAccess: { $type: 'com.atproto.simplespace.defs#open' },
    },
  });
  return `at://${account.did}/space/${SPACE_TYPE}/${skey}`;
}

export async function deleteSpace(name, spaceUri) {
  const account = await ensureSession(name);
  return xrpc(BASE_URL, 'com.atproto.simplespace.deleteSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: { space: spaceUri },
  });
}

/**
 * Create space → write a record → read it back (get/list/listSpaces) → sync
 * reads (getLatestCommit, listRepoOps, getRepo CAR) → delete the record →
 * delete the space. Self-contained; always attempts the space teardown.
 */
export async function spacesRoundTrip(name) {
  const account = await ensureSession(name);
  const token = () => account.accessJwt;
  const skey = `interop-${randomSuffix(6)}`;
  const spaceUri = await createSpace(name, skey);
  try {
    const text = `ezpds interop spaces check ${new Date().toISOString()}`;
    const created = await xrpc(BASE_URL, 'com.atproto.space.createRecord', {
      method: 'POST',
      token: token(),
      body: {
        space: spaceUri,
        repo: account.did,
        collection: COLLECTION,
        record: { $type: COLLECTION, text },
      },
    });
    if (!created.cid) throw new Error('space createRecord returned no cid');
    const rkey = created.uri.split('/').pop();

    const fetched = await xrpc(BASE_URL, 'com.atproto.space.getRecord', {
      token: token(),
      params: { space: spaceUri, repo: account.did, collection: COLLECTION, rkey },
    });
    if (fetched.value.text !== text) throw new Error('space getRecord returned different text than written');

    const listed = await xrpc(BASE_URL, 'com.atproto.space.listRecords', {
      token: token(),
      params: { space: spaceUri, repo: account.did, collection: COLLECTION },
    });
    if (!listed.records.some((r) => r.rkey === rkey)) throw new Error('written record missing from space listRecords');

    const spaces = await xrpc(BASE_URL, 'com.atproto.space.listSpaces', {
      token: token(),
      params: { did: account.did },
    });
    if (!spaces.spaces.some((s) => s.uri === spaceUri)) throw new Error('space missing from listSpaces');

    const latest = await xrpc(BASE_URL, 'com.atproto.space.getLatestCommit', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
    });
    if (!latest.commit?.rev) throw new Error('space getLatestCommit returned no commit rev');

    const ops = await xrpc(BASE_URL, 'com.atproto.space.listRepoOps', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
    });
    if (!ops.ops.some((op) => op.rkey === rkey)) throw new Error('write missing from space listRepoOps');

    const car = await xrpc(BASE_URL, 'com.atproto.space.getRepo', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
      raw: true,
    });
    const carBytes = new Uint8Array(await car.arrayBuffer());
    if (carBytes.length === 0) throw new Error('space getRepo returned an empty CAR');

    await xrpc(BASE_URL, 'com.atproto.space.deleteRecord', {
      method: 'POST',
      token: token(),
      body: { space: spaceUri, repo: account.did, collection: COLLECTION, rkey },
    });

    return { space: spaceUri, uri: created.uri, cid: created.cid, commitRev: latest.commit.rev, carBytes: carBytes.length };
  } finally {
    // Teardown failure must not mask the real result; deleteSpace is idempotent.
    await deleteSpace(name, spaceUri).catch((err) => {
      process.stderr.write(`  (space teardown failed for ${spaceUri}: ${err.message})\n`);
    });
  }
}
