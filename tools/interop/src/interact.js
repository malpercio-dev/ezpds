// Scoped cross-account interactions. HARD CONSTRAINT: staging federates with
// the real ATProto network, and the only external identity these tools may
// touch is the operator's own (config.ALLOWED_TARGET). Every write is recorded
// in the state ledger so `interact cleanup` can remove it.

import { ALLOWED_TARGET, PUBLIC_APPVIEW_URL } from './config.js';
import { xrpc } from './http.js';
import { fetchDidWebDocument, pdsEndpointFromDoc, resolveHandleViaPds } from './identity.js';
import { createRecord, deleteRecord, rkeyFromUri } from './records.js';
import { loadState, saveState } from './state.js';

/** Resolve + verify the one allowed target; throws on any mismatch. */
export async function resolveTarget() {
  const did = ALLOWED_TARGET.did;
  const doc = await fetchDidWebDocument(did);
  const aka = doc.alsoKnownAs ?? [];
  if (!aka.includes(`at://${ALLOWED_TARGET.handle}`)) {
    throw new Error(`did:web doc for ${did} does not assert at://${ALLOWED_TARGET.handle} (alsoKnownAs: ${aka.join(', ')})`);
  }
  const pds = pdsEndpointFromDoc(doc);
  if (!pds) throw new Error(`no atproto_pds service in DID document for ${did}`);

  // Cross-check: our PDS's resolveHandle must agree (exercises its DNS/HTTP
  // handle-resolution path against a real external handle).
  const resolved = await resolveHandleViaPds(ALLOWED_TARGET.handle);
  if (resolved !== did) {
    throw new Error(`PDS resolveHandle(${ALLOWED_TARGET.handle}) returned ${resolved}, expected ${did}`);
  }
  return { did, handle: ALLOWED_TARGET.handle, pds, doc };
}

function assertAllowed(subjectDid) {
  if (subjectDid !== ALLOWED_TARGET.did) {
    throw new Error(`interaction target ${subjectDid} is not in the allowlist (${ALLOWED_TARGET.did}) — refusing`);
  }
}

function recordInteraction(accountName, entry) {
  const state = loadState();
  state.interactions.push({ account: accountName, createdAt: new Date().toISOString(), ...entry });
  saveState(state);
}

export async function followTarget(accountName) {
  const target = await resolveTarget();
  assertAllowed(target.did);
  const created = await createRecord(accountName, 'app.bsky.graph.follow', {
    $type: 'app.bsky.graph.follow',
    subject: target.did,
    createdAt: new Date().toISOString(),
  });
  recordInteraction(accountName, { collection: 'app.bsky.graph.follow', rkey: rkeyFromUri(created.uri), uri: created.uri, subject: target.did });
  return created;
}

/** Latest original post by the target, via the public AppView. Pass an
 * already-resolved target to avoid re-running the did:web + resolveHandle
 * round-trips. */
export async function latestTargetPost(target) {
  target = target ?? (await resolveTarget());
  const feed = await xrpc(PUBLIC_APPVIEW_URL, 'app.bsky.feed.getAuthorFeed', {
    params: { actor: target.did, limit: 10, filter: 'posts_no_replies' },
  });
  const own = (feed.feed ?? []).map((item) => item.post).find((p) => p?.author?.did === target.did);
  if (!own) throw new Error(`no posts found for ${target.handle} via AppView`);
  return { uri: own.uri, cid: own.cid, text: own.record?.text };
}

export async function likeTargetPost(accountName) {
  const target = await resolveTarget();
  const post = await latestTargetPost(target);
  if (!post.uri.startsWith(`at://${target.did}/`)) {
    throw new Error(`post ${post.uri} is not authored by the allowed target — refusing`);
  }
  const created = await createRecord(accountName, 'app.bsky.feed.like', {
    $type: 'app.bsky.feed.like',
    subject: { uri: post.uri, cid: post.cid },
    createdAt: new Date().toISOString(),
  });
  recordInteraction(accountName, { collection: 'app.bsky.feed.like', rkey: rkeyFromUri(created.uri), uri: created.uri, subject: post.uri });
  return { like: created, post };
}

export async function mentionTarget(accountName) {
  const target = await resolveTarget();
  assertAllowed(target.did);
  const prefix = 'ezpds staging interop check — hello ';
  const mention = `@${target.handle}`;
  const text = `${prefix}${mention} (automated, will be cleaned up)`;
  const byteStart = Buffer.byteLength(prefix, 'utf8');
  const byteEnd = byteStart + Buffer.byteLength(mention, 'utf8');

  const created = await createRecord(accountName, 'app.bsky.feed.post', {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: new Date().toISOString(),
    facets: [
      {
        index: { byteStart, byteEnd },
        features: [{ $type: 'app.bsky.richtext.facet#mention', did: target.did }],
      },
    ],
  });
  recordInteraction(accountName, { collection: 'app.bsky.feed.post', rkey: rkeyFromUri(created.uri), uri: created.uri, subject: target.did });
  return created;
}

/** Delete every interaction record in the ledger (best-effort, idempotent). */
export async function cleanupInteractions(accountName) {
  const state = loadState();
  const mine = state.interactions.filter((i) => !accountName || i.account === accountName);
  const results = [];
  for (const entry of mine) {
    try {
      await deleteRecord(entry.account, entry.collection, entry.rkey);
      results.push({ ...entry, deleted: true });
    } catch (err) {
      results.push({ ...entry, deleted: false, error: err.message });
    }
  }
  const deletedUris = new Set(results.filter((r) => r.deleted).map((r) => r.uri));
  const next = loadState();
  next.interactions = next.interactions.filter((i) => !deletedUris.has(i.uri));
  saveState(next);
  return results;
}
