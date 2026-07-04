// Repo record operations (create/get/list/delete) plus a CRUD round-trip check.

import { BASE_URL } from './config.js';
import { xrpc } from './http.js';
import { ensureSession } from './account.js';

export async function createRecord(name, collection, record, rkey) {
  const account = await ensureSession(name);
  const body = { repo: account.did, collection, record };
  if (rkey) body.rkey = rkey;
  return xrpc(BASE_URL, 'com.atproto.repo.createRecord', {
    method: 'POST',
    token: account.accessJwt,
    body,
  });
}

export async function getRecord(did, collection, rkey) {
  // The lexicon names this param `repo`, but ezpds's getRecord currently
  // requires `did` (routes/get_record.rs). Send both — serde ignores the
  // extra — so the CLI works against ezpds today and the spec shape.
  return xrpc(BASE_URL, 'com.atproto.repo.getRecord', { params: { repo: did, did, collection, rkey } });
}

export async function listRecords(did, collection, params = {}) {
  return xrpc(BASE_URL, 'com.atproto.repo.listRecords', { params: { repo: did, collection, ...params } });
}

export async function deleteRecord(name, collection, rkey) {
  const account = await ensureSession(name);
  return xrpc(BASE_URL, 'com.atproto.repo.deleteRecord', {
    method: 'POST',
    token: account.accessJwt,
    body: { repo: account.did, collection, rkey },
  });
}

export async function createPost(name, text, extra = {}) {
  return createRecord(name, 'app.bsky.feed.post', {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: new Date().toISOString(),
    ...extra,
  });
}

export function rkeyFromUri(uri) {
  return uri.split('/').pop();
}

/** Create → read back → list → delete → confirm gone. Self-contained. */
export async function crudRoundTrip(name) {
  const account = await ensureSession(name);
  const text = `ezpds interop CRUD check ${new Date().toISOString()}`;
  const created = await createPost(name, text);
  const rkey = rkeyFromUri(created.uri);

  const fetched = await getRecord(account.did, 'app.bsky.feed.post', rkey);
  if (fetched.value.text !== text) throw new Error('getRecord returned different text than written');
  if (fetched.cid !== created.cid) throw new Error(`CID mismatch: created ${created.cid}, fetched ${fetched.cid}`);

  const listed = await listRecords(account.did, 'app.bsky.feed.post', { limit: 50 });
  if (!listed.records.some((r) => r.uri === created.uri)) throw new Error('created record missing from listRecords');

  await deleteRecord(name, 'app.bsky.feed.post', rkey);

  let goneStatus = null;
  try {
    await getRecord(account.did, 'app.bsky.feed.post', rkey);
  } catch (err) {
    goneStatus = err.status;
  }
  if (goneStatus === null) throw new Error('record still readable after deleteRecord');

  return { uri: created.uri, cid: created.cid, deletedStatus: goneStatus };
}
