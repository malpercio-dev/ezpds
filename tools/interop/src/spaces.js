// Atproto Spaces checks against the pin (atproto `permissioned-data` @ 047d603).
//
//   spacesRoundTrip    authority = self, one host: create a space, write/read/list records,
//                      the account's own sync reads, teardown. Runs against any deployment.
//   allowListRefusal   an `allowedApps` space refuses authorizeSpaceSync without a client
//                      attestation, the authority's own request included.
//   spacesInterop      the cross-host scenario: an authority on one host, a member on the
//                      other, run in each direction between Custos and the reference built from
//                      source (`bin/reference-pds spaces`). Every step a syncer or a migrating
//                      account would take, with each MAC and STAR export checked by the
//                      reference's own `@atproto/space` at the pin.
//   confirmMacVectors  recompute the crypto crate's MAC vectors with that same library.
//
// Hosts come from the accounts: `create-account --host` and `import-session` record the PDS,
// so naming two accounts spans two hosts. A random skey keeps runs independent.

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { xrpc, HttpError, sleep } from './http.js';
import { createAccount, createStandardAccount, ensureSession } from './account.js';
import { randomSuffix, randomPassword } from './crypto.js';
import { accountHost } from './state.js';
import { newSpaceKey } from './space-signature.js';
import { parseStar } from './star.js';
import { fetchPlcDocument } from './identity.js';
import { defaultEmail } from './config.js';

const SPACE_TYPE = 'dev.malpercio.interop.bucket';
const COLLECTION = 'dev.malpercio.interop.note';
const LABEL_COLLECTION = 'com.atproto.label.record';
const STAR = 'application/vnd.dasl.star';

const PUBLIC_POLICY = { $type: 'com.atproto.memberspace.policy', publicRead: true, publicWrite: true };

// ---- the reference library ----

const REFERENCE_SRC = path.join(
  process.env.EZPDS_REFERENCE_CACHE ?? path.join(os.homedir(), '.cache', 'ezpds', 'reference-pds'),
  'atproto',
);

let referenceLib;
/** The pin's `@atproto/space` and `@atproto/crypto`, from the `bin/reference-pds build` checkout. */
export async function reference() {
  if (!referenceLib) {
    const load = (pkg) => import(pathToFileURL(path.join(REFERENCE_SRC, 'packages', pkg, 'dist', 'index.js')).href)
      .catch((cause) => { throw new Error(`reference ${pkg} not built under ${REFERENCE_SRC}: run \`just reference-pds build\``, { cause }); });
    referenceLib = { space: await load('space'), crypto: await load('crypto') };
  }
  return referenceLib;
}

// ---- small helpers ----

const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (b) => Buffer.from(b).toString('hex');

/** A lexicon `commit` from JSON (`data` as `{$bytes}`) as the reference's `SpaceCommit`. */
export function commitFromJson(c) {
  return { ver: c.ver, repo: c.repo, space: c.space, rev: c.rev, data: unb64(c.data.$bytes) };
}

/** The `#atproto_kem` key in a DID document, as a did:key. */
export function kemKeyFromDoc(doc) {
  const vm = (doc.verificationMethod ?? []).find((m) => m.id === '#atproto_kem' || m.id === `${doc.id}#atproto_kem`);
  if (!vm?.publicKeyMultibase) throw new Error(`${doc.id} publishes no #atproto_kem`);
  return `did:key:${vm.publicKeyMultibase}`;
}

async function readBody(res) {
  const text = await res.text();
  return (res.headers.get('content-type') ?? '').includes('json') && text ? JSON.parse(text) : text;
}

/** A raw XRPC call that keeps the response headers. Non-2xx throws HttpError. */
async function call(host, nsid, { params, token, headers = {}, body, contentType, spaceSig, bytes = false, method } = {}) {
  const res = await xrpc(host, nsid, {
    params,
    token,
    method: method ?? (body !== undefined ? 'POST' : 'GET'),
    headers: contentType ? { ...headers, 'Content-Type': contentType } : headers,
    body,
    spaceSig,
    raw: true,
  });
  if (!res.ok) throw new HttpError(res.status, await readBody(res), res.url);
  return { headers: res.headers, body: bytes ? new Uint8Array(await res.arrayBuffer()) : await readBody(res) };
}

export async function createSpace(name, skey, { policy = PUBLIC_POLICY } = {}) {
  const account = await ensureSession(name);
  const out = await xrpc(accountHost(account), 'com.atproto.space.createSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: { spaceType: SPACE_TYPE, skey, policy },
  });
  return out.space ?? `at://${account.did}/space/${SPACE_TYPE}/${skey}`;
}

export async function deleteSpace(name, spaceUri) {
  const account = await ensureSession(name);
  return xrpc(accountHost(account), 'com.atproto.space.deleteSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: { space: spaceUri },
  });
}

function teardown(name, spaceUri) {
  return deleteSpace(name, spaceUri).catch((err) => {
    process.stderr.write(`  (space teardown failed for ${spaceUri}: ${err.message})\n`);
  });
}

// ---- single host ----

/**
 * Create space → write a record → read it back (get/list/listSpaces) → the owner's sync reads
 * (getLatestCommit, listRepoOps, getRepo as a parsed STAR archive) → delete the record → delete
 * the space. An account reading its own repo needs no MAC.
 */
export async function spacesRoundTrip(name) {
  const account = await ensureSession(name);
  const host = accountHost(account);
  const token = () => account.accessJwt;
  const spaceUri = await createSpace(name, `interop-${randomSuffix(6)}`);
  try {
    const text = `ezpds interop spaces check ${new Date().toISOString()}`;
    const created = await xrpc(host, 'com.atproto.space.createRecord', {
      method: 'POST',
      token: token(),
      body: { space: spaceUri, repo: account.did, collection: COLLECTION, record: { $type: COLLECTION, text } },
    });
    if (!created.cid) throw new Error('space createRecord returned no cid');
    const rkey = created.uri.split('/').pop();
    const q = { space: spaceUri, repo: account.did };

    const fetched = await xrpc(host, 'com.atproto.space.getRecord', { token: token(), params: { ...q, collection: COLLECTION, rkey } });
    if (fetched.value.text !== text) throw new Error('space getRecord returned different text than written');

    const listed = await xrpc(host, 'com.atproto.space.listRecords', { token: token(), params: { ...q, collection: COLLECTION } });
    if (!listed.records.some((r) => r.rkey === rkey && r.collection === COLLECTION)) throw new Error('written record missing from space listRecords');

    const spaces = await xrpc(host, 'com.atproto.space.listSpaces', { token: token() });
    if (!spaces.spaces.some((s) => s.space === spaceUri)) throw new Error('space missing from listSpaces');

    const latest = await xrpc(host, 'com.atproto.space.getLatestCommit', { token: token(), params: q });
    if (!latest.commit?.rev) throw new Error('space getLatestCommit returned no commit rev');

    const ops = await xrpc(host, 'com.atproto.space.listRepoOps', { token: token(), params: q });
    if (!ops.ops.some((op) => op.rkey === rkey)) throw new Error('write missing from space listRepoOps');

    const star = await call(host, 'com.atproto.space.getRepo', { token: token(), params: q, bytes: true });
    const { meta, pairs } = parseStar(star.body);
    if (!pairs.some((p) => p.key === `${COLLECTION}/${rkey}`)) throw new Error('space getRepo archive does not carry the record');

    await xrpc(host, 'com.atproto.space.deleteRecord', {
      method: 'POST',
      token: token(),
      body: { ...q, collection: COLLECTION, rkey },
    });
    return { space: spaceUri, uri: created.uri, commitRev: latest.commit.rev, export: { records: pairs.length, rev: meta.rev } };
  } finally {
    await teardown(name, spaceUri);
  }
}

/**
 * A memberspace with `allowedApps` must refuse authorizeSpaceSync without a client attestation,
 * including the authority's own request. The positive half needs a publicly served client_id
 * document and stays manual (see the README).
 */
export async function allowListRefusal(name) {
  const account = await ensureSession(name);
  const host = accountHost(account);
  const spaceUri = await createSpace(name, `interop-${randomSuffix(6)}`, {
    policy: { ...PUBLIC_POLICY, allowedApps: ['https://interop.invalid/client-metadata.json'] },
  });
  try {
    const { token: delegationToken } = await xrpc(host, 'com.atproto.space.getDelegationToken', {
      token: account.accessJwt,
      params: { space: spaceUri },
    });
    const key = await newSpaceKey();
    const err = await xrpc(host, 'com.atproto.space.authorizeSpaceSync', {
      method: 'POST',
      body: { space: spaceUri, credentialKey: key.did(), delegationToken },
    }).then(() => null, (e) => e);
    if (!err) throw new Error('allowedApps space issued a credential to a request naming no client');
    if (!(err instanceof HttpError) || err.status !== 400 || err.errorCode !== 'AppNotAuthorized') {
      throw new Error(`allowedApps refusal was not AppNotAuthorized: ${err.message}`);
    }
    return { space: spaceUri, authority: account.did, refusedWith: err.errorCode, status: err.status };
  } finally {
    await teardown(name, spaceUri);
  }
}

// ---- the syncer's notification endpoint ----

/**
 * A local endpoint playing the syncer: answers `confirmRegistration` for its own token and
 * records every `notifySpaceUpdate`. Listens on localhost (both families), because an
 * IP-literal endpoint is refused by both hosts.
 */
async function startSyncerEndpoint(token) {
  const confirmations = [];
  const updates = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const reply = (status, json) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(json));
      };
      let body;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return reply(400, { error: 'InvalidRequest', message: 'body is not JSON' });
      }
      if (req.url === '/xrpc/com.atproto.space.confirmRegistration') {
        confirmations.push(body);
        if (body.token !== token) return reply(400, { error: 'InvalidToken', message: 'not our token' });
        return reply(200, { challenge: body.challenge });
      }
      if (req.url === '/xrpc/com.atproto.space.notifySpaceUpdate') {
        updates.push(body);
        return reply(200, {});
      }
      return reply(404, { error: 'MethodNotImplemented' });
    });
  });
  await new Promise((resolve) => server.listen(0, resolve));
  return {
    endpoint: `http://localhost:${server.address().port}`,
    confirmations,
    updates,
    close: () => server.close(),
  };
}

async function waitFor(what, predicate, timeoutMs = 20_000) {
  for (const deadline = Date.now() + timeoutMs; ;) {
    const found = predicate();
    if (found) return found;
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs / 1000}s waiting for ${what}`);
    await sleep(250);
  }
}

// ---- the cross-host scenario ----

/**
 * One direction of the cross-host scenario: `authority` hosts a memberspace, `member` (on
 * another host) writes into it, and a syncer reads it with a credential from the authority.
 * Each step is recorded with its outcome; a failed step does not stop the ones that don't
 * depend on it. Returns `{ok, steps}`.
 */
export async function spacesInterop({ authority: authorityName, member: memberName }) {
  const { space: lib } = await reference();
  const steps = [];
  const ctx = {};
  const step = async (name, fn) => {
    try {
      const detail = await fn();
      steps.push({ step: name, ok: true, detail });
    } catch (err) {
      steps.push({ step: name, ok: false, error: err.message, ...(err.body ? { response: err.body } : {}) });
    }
  };
  const need = (...keys) => {
    for (const k of keys) if (ctx[k] === undefined) throw new Error(`skipped: an earlier step did not produce ${k}`);
  };

  const authority = await ensureSession(authorityName);
  const member = await ensureSession(memberName);
  const authorityHost = accountHost(authority);
  const memberHost = accountHost(member);
  if (authorityHost === memberHost) throw new Error('authority and member are on the same host; name accounts on two hosts');
  const notifyToken = `interop-${randomSuffix(12)}`;
  const syncer = await startSyncerEndpoint(notifyToken);
  const skey = `interop-${randomSuffix(6)}`;
  const kem = {};
  const repoQ = () => ({ space: ctx.space, repo: member.did });
  const asMember = () => ({ key: ctx.key, credential: ctx.credential, audience: member.did });
  const asAuthority = () => ({ key: ctx.key, credential: ctx.credential, audience: authority.did });

  try {
    await step('identity: both DID documents publish #atproto_kem', async () => {
      kem.authority = kemKeyFromDoc(await fetchPlcDocument(authority.did));
      kem.member = kemKeyFromDoc(await fetchPlcDocument(member.did));
      return { authorityHost, memberHost, authorityKem: kem.authority, memberKem: kem.member };
    });

    await step('policy: memberspace on the authority, putMembers, published policy record', async () => {
      ctx.space = await createSpace(authorityName, skey, {
        policy: { $type: 'com.atproto.memberspace.policy', publishPolicy: true, publishMembers: true },
      });
      await xrpc(authorityHost, 'com.atproto.memberspace.putMembers', {
        method: 'POST',
        token: authority.accessJwt,
        body: { space: ctx.space, members: [{ did: member.did, read: true, write: true }] },
      });
      const q = { space: ctx.space, repo: authority.did };
      const policy = await xrpc(authorityHost, 'com.atproto.space.getRecord', {
        token: authority.accessJwt,
        params: { ...q, collection: 'com.atproto.space.policy', rkey: 'self' },
      });
      if (policy.value?.policy?.$type !== 'com.atproto.memberspace.policy') {
        throw new Error(`published policy record is ${JSON.stringify(policy.value)}`);
      }
      const listed = await xrpc(authorityHost, 'com.atproto.memberspace.listMembers', {
        token: authority.accessJwt,
        params: { space: ctx.space },
      });
      if (!listed.members?.some((m) => m.did === member.did && m.write)) throw new Error('member missing from listMembers');
      const memberRecord = await xrpc(authorityHost, 'com.atproto.space.getRecord', {
        token: authority.accessJwt,
        params: { ...q, collection: 'com.atproto.memberspace.member', rkey: member.did },
      });
      return { space: ctx.space, policyRecord: policy.uri, memberRecord: memberRecord.uri };
    });

    await step('credential: delegation token from the member host → authorizeSpaceSync with notify', async () => {
      need('space');
      const { token: delegationToken } = await xrpc(memberHost, 'com.atproto.space.getDelegationToken', {
        token: member.accessJwt,
        params: { space: ctx.space },
      });
      ctx.key = await newSpaceKey();
      const out = await xrpc(authorityHost, 'com.atproto.space.authorizeSpaceSync', {
        method: 'POST',
        body: {
          space: ctx.space,
          credentialKey: ctx.key.did(),
          delegationToken,
          notify: { endpoint: syncer.endpoint, token: notifyToken },
        },
      });
      ctx.credential = out.credential;
      const confirmed = syncer.confirmations.find((c) => c.token === notifyToken && c.space === ctx.space);
      if (!confirmed) throw new Error('the authority registered the endpoint without calling confirmRegistration');
      return { spaceRev: out.spaceRev ?? null, confirmRegistration: 'answered' };
    });

    await step('write: member writes a record into the foreign space from its own host', async () => {
      need('space');
      const text = `ezpds interop cross-host ${new Date().toISOString()}`;
      ctx.note = await xrpc(memberHost, 'com.atproto.space.createRecord', {
        method: 'POST',
        token: member.accessJwt,
        body: { ...repoQ(), collection: COLLECTION, record: { $type: COLLECTION, text } },
      });
      return { uri: ctx.note.uri };
    });

    await step('moderation: a com.atproto.label.record written as an ordinary space record', async () => {
      need('space', 'note');
      ctx.label = await xrpc(memberHost, 'com.atproto.space.createRecord', {
        method: 'POST',
        token: member.accessJwt,
        body: {
          ...repoQ(),
          collection: LABEL_COLLECTION,
          record: { $type: LABEL_COLLECTION, uri: ctx.note.uri, cid: ctx.note.cid, val: 'interop-check', cts: new Date().toISOString() },
        },
      });
      return { uri: ctx.label.uri };
    });

    await step('notification: repoWrite for the member arrives at the registered endpoint', async () => {
      need('credential', 'label');
      const got = await waitFor('a repoWrite naming the member', () => syncer.updates.find((u) =>
        u.token === notifyToken && u.update?.$type === 'com.atproto.space.defs#repoWrite' && u.update.repo === member.did));
      return { spaceRev: got.update.spaceRev, prevSpaceRev: got.update.prevSpaceRev ?? null, received: syncer.updates.length };
    });

    await step('credential: refused without its signature', async () => {
      need('credential');
      const err = await xrpc(memberHost, 'com.atproto.space.getLatestCommit', {
        params: repoQ(),
        headers: { Authorization: `Atproto-Space-Credential ${ctx.credential}`, 'Atproto-Space-Audience': member.did },
      }).then(() => null, (e) => e);
      if (!err) throw new Error('the member host accepted an unsigned space credential');
      if (!(err instanceof HttpError)) throw err;
      // The reference's name for a missing signature; Custos answers the same.
      if (err.status !== 401 || err.errorCode !== 'BadSpaceSignature') {
        throw new Error(`expected 401 BadSpaceSignature, got ${err.status} ${err.errorCode}`);
      }
      return { status: err.status, error: err.errorCode, message: err.errorDescription };
    });

    // A fresh key share per request, encapsulated to the author's published #atproto_kem.
    const macRead = async (host, nsid, params, author, profile, sig, opts = {}) => {
      const enc = await lib.encapsulate(kem[author]);
      const res = await call(host, nsid, {
        params,
        headers: { 'Accept-Signature': lib.formatMacRequest(profile, enc.keyShare) },
        spaceSig: sig,
        ...opts,
      });
      return { ...res, enc };
    };

    await step('MAC: getRecord on the member host, verified against the member #atproto_kem', async () => {
      need('credential', 'note');
      const rkey = ctx.note.uri.split('/').pop();
      const { body, headers, enc } = await macRead(memberHost, 'com.atproto.space.getRecord',
        { ...repoQ(), collection: COLLECTION, rkey }, 'member', lib.RECORD_MAC_PROFILE, asMember());
      await lib.verifyRecord(body, { ...enc, headers, uri: ctx.note.uri });
      return { uri: body.uri, cid: body.cid };
    });

    await step('MAC: getLatestCommit on the member host', async () => {
      need('credential', 'label');
      const { body, headers, enc } = await macRead(memberHost, 'com.atproto.space.getLatestCommit',
        repoQ(), 'member', lib.COMMIT_MAC_PROFILE, asMember());
      ctx.memberCommit = commitFromJson(body.commit);
      lib.verifyCommit(ctx.memberCommit, { ...enc, headers, ...repoQ() });
      return { rev: ctx.memberCommit.rev, data: hex(ctx.memberCommit.data) };
    });

    await step('MAC: listRepoOps on the member host', async () => {
      need('credential', 'memberCommit');
      const { body, headers, enc } = await macRead(memberHost, 'com.atproto.space.listRepoOps',
        repoQ(), 'member', lib.COMMIT_MAC_PROFILE, asMember());
      const commit = commitFromJson(body.commit);
      lib.verifyCommit(commit, { ...enc, headers, ...repoQ() });
      const rkeys = body.ops.map((op) => `${op.collection}/${op.rkey}`);
      for (const uri of [ctx.note.uri, ctx.label.uri]) {
        const p = uri.split('/').slice(-2).join('/');
        if (!rkeys.includes(p)) throw new Error(`listRepoOps is missing ${p}`);
      }
      return { ops: body.ops.length, rev: commit.rev };
    });

    await step('STAR: getRepo on the member host, MAC verified and LtHash recomputed against data', async () => {
      need('credential', 'memberCommit');
      const { body, headers, enc } = await macRead(memberHost, 'com.atproto.space.getRepo',
        repoQ(), 'member', lib.COMMIT_MAC_PROFILE, asMember(), { bytes: true });
      const { commit, records } = await lib.verifyRepoStarFull([body], { ...enc, headers, ...repoQ() });
      parseStar(body); // and the strict key order, by this tool's own parser
      if (hex(commit.data) !== hex(ctx.memberCommit.data)) throw new Error('getRepo commit data differs from getLatestCommit');
      const paths = records.map((r) => `${r.collection}/${r.rkey}`);
      if (!paths.includes(`${LABEL_COLLECTION}/${ctx.label.uri.split('/').pop()}`)) throw new Error('getRepo is missing the label record');
      return { bytes: body.length, records: records.length };
    });

    await step('credential: reads on the authority side (policy record MAC, listWriters)', async () => {
      need('credential', 'memberCommit');
      const q = { space: ctx.space, repo: authority.did };
      const policyUri = `${ctx.space}/${authority.did}/com.atproto.space.policy/self`;
      const { body, headers, enc } = await macRead(authorityHost, 'com.atproto.space.getRecord',
        { ...q, collection: 'com.atproto.space.policy', rkey: 'self' }, 'authority', lib.RECORD_MAC_PROFILE, asAuthority());
      await lib.verifyRecord(body, { ...enc, headers, uri: policyUri });
      const writers = await xrpc(authorityHost, 'com.atproto.space.listWriters', { params: { space: ctx.space }, spaceSig: asAuthority() });
      const entry = writers.repos.find((r) => r.repo === member.did);
      if (!entry) throw new Error(`member missing from listWriters: ${JSON.stringify(writers.repos)}`);
      if (hex(unb64(entry.data.$bytes)) !== hex(ctx.memberCommit.data)) {
        throw new Error(`listWriters data ${hex(unb64(entry.data.$bytes))} is not the member commit ${hex(ctx.memberCommit.data)}`);
      }
      return { policyRecord: body.uri, writers: writers.repos.length, memberSpaceRev: entry.spaceRev };
    });

    await step('writer set: removeWriter → listWriters shows repoRemoved', async () => {
      need('credential', 'memberCommit');
      await xrpc(authorityHost, 'com.atproto.space.removeWriter', {
        method: 'POST',
        token: authority.accessJwt,
        body: { space: ctx.space, repo: member.did },
      });
      const writers = await xrpc(authorityHost, 'com.atproto.space.listWriters', { params: { space: ctx.space }, spaceSig: asAuthority() });
      const entry = writers.repos.find((r) => r.repo === member.did);
      if (entry?.$type !== 'com.atproto.space.defs#repoRemoved') throw new Error(`member entry after removeWriter: ${JSON.stringify(entry)}`);
      const notice = await waitFor('a repoRemoved notification', () => syncer.updates.find((u) =>
        u.update?.$type === 'com.atproto.space.defs#repoRemoved' && u.update.repo === member.did), 10_000).then(() => 'received', (e) => e.message);
      return { spaceRev: entry.spaceRev, notification: notice };
    });

    await step('writer set: clearRecords → empty digest', async () => {
      need('space', 'memberCommit');
      await xrpc(memberHost, 'com.atproto.space.clearRecords', { method: 'POST', token: member.accessJwt, body: repoQ() });
      const after = await xrpc(memberHost, 'com.atproto.space.getLatestCommit', { token: member.accessJwt, params: repoQ() });
      const empty = hex(new lib.LtHash().digest());
      const got = hex(unb64(after.commit.data.$bytes));
      if (got !== empty) throw new Error(`commit data after clearRecords is ${got}, not the empty digest ${empty}`);
      return { rev: after.commit.rev, data: got };
    });

    // A throwaway authority, because migrating leaves a copy of its DID on the destination,
    // and a host that holds a copy of an authority answers for it locally from then on.
    await step(`migration: an authority's space, ${label(authorityHost)} → ${label(memberHost)}`, async () => {
      const name = `${authorityName}-mig-${randomSuffix(4)}`;
      if (authority.host) await createStandardAccount({ name, host: authorityHost });
      else await createAccount({ name, kind: 'ephemeral' });
      const migrating = await ensureSession(name);
      const space = await createSpace(name, `interop-${randomSuffix(6)}`, {
        policy: { $type: 'com.atproto.memberspace.policy', publishPolicy: true, publishMembers: true },
      });
      await xrpc(authorityHost, 'com.atproto.memberspace.putMembers', {
        method: 'POST',
        token: migrating.accessJwt,
        body: { space, members: [{ did: member.did, read: true, write: false }] },
      });
      await xrpc(authorityHost, 'com.atproto.space.createRecord', {
        method: 'POST',
        token: migrating.accessJwt,
        body: { space, repo: migrating.did, collection: COLLECTION, record: { $type: COLLECTION, text: 'moves with the space' } },
      });
      return migrateSpace({ authority: migrating, from: authorityHost, to: memberHost, space });
    });
  } finally {
    syncer.close();
    if (ctx.space) await teardown(authorityName, ctx.space);
  }

  const ok = steps.every((s) => s.ok);
  return { ok, authority: `${authority.did} @ ${authorityHost}`, member: `${member.did} @ ${memberHost}`, space: ctx.space, steps };
}

function label(host) {
  return host.startsWith('https://') ? 'Custos' : 'reference';
}

/**
 * Carry the authority's space to another host the way an account migration does: a
 * deactivated account for the same DID on the destination (createAccount under the source's
 * service auth), then exportSpaceMeta → importSpaceMeta and getRepo → importRepo, and the
 * destination must answer the same commit digest. The account stays deactivated there and the
 * DID is not repointed: neither is needed for the space data to move, and both are covered by
 * the account-migration checks.
 */
async function migrateSpace({ authority, from, to, space }) {
  const dest = await xrpc(to, 'com.atproto.server.describeServer');
  const { token: serviceAuth } = await xrpc(from, 'com.atproto.server.getServiceAuth', {
    token: authority.accessJwt,
    params: { aud: dest.did, lxm: 'com.atproto.server.createAccount' },
  });
  const domain = dest.availableUserDomains[0].replace(/^\./, '');
  const password = randomPassword();
  // The standard migration order; Custos refuses createAccount for a DID without a reserved key.
  await xrpc(to, 'com.atproto.server.reserveSigningKey', { method: 'POST', body: { did: authority.did } });
  const migrated = await xrpc(to, 'com.atproto.server.createAccount', {
    method: 'POST',
    token: serviceAuth,
    body: { did: authority.did, handle: `mig-${randomSuffix(6)}.${domain}`, email: defaultEmail(`mig-${randomSuffix(4)}`), password },
  });
  const q = { space, repo: authority.did };

  const meta = await call(from, 'com.atproto.space.exportSpaceMeta', { token: authority.accessJwt, params: { space }, bytes: true });
  await call(to, 'com.atproto.space.importSpaceMeta', { token: migrated.accessJwt, body: meta.body, contentType: STAR });

  const repo = await call(from, 'com.atproto.space.getRepo', { token: authority.accessJwt, params: q, bytes: true });
  await call(to, 'com.atproto.space.importRepo', { token: migrated.accessJwt, body: repo.body, contentType: STAR });

  const before = await xrpc(from, 'com.atproto.space.getLatestCommit', { token: authority.accessJwt, params: q });
  const after = await xrpc(to, 'com.atproto.space.getLatestCommit', { token: migrated.accessJwt, params: q });
  if (hex(unb64(before.commit.data.$bytes)) !== hex(unb64(after.commit.data.$bytes))) {
    throw new Error(`digests differ after import: source ${before.commit.data.$bytes}, destination ${after.commit.data.$bytes}`);
  }
  const back = await call(to, 'com.atproto.space.getRepo', { token: migrated.accessJwt, params: q, bytes: true });
  const { pairs } = parseStar(back.body);
  return { metaBytes: meta.body.length, repoBytes: repo.body.length, records: pairs.length, data: hex(unb64(after.commit.data.$bytes)) };
}

// ---- MAC vectors ----

const VECTORS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../crates/crypto/tests/fixtures/space/mac-vectors.json');

/**
 * Recompute every MAC vector in the crypto crate's fixture with the reference's own code at
 * the pin: the shared secret decapsulated from the fixture's key share, the request parsed by
 * `parseMacRequest`, the response built by `createCommitMacHeaders`/`createRecordMacHeaders`.
 * Each must match the fixture byte for byte.
 */
export async function confirmMacVectors() {
  const { space: lib, crypto } = await reference();
  const fixture = JSON.parse(fs.readFileSync(VECTORS, 'utf8'));
  const kemKey = await crypto.P256Keypair.import(Uint8Array.from(fixture.kem.kemPrivateKeyBytes));
  const secret = lib.decapsulate(kemKey, fixture.kem.keyShare);
  if (hex(secret) !== fixture.kem.sharedSecretHex) throw new Error(`shared secret ${hex(secret)} differs from the fixture`);
  const { CID } = await import('multiformats/cid');
  const results = fixture.vectors.map((v) => {
    const profile = v.profile === 'commit' ? lib.COMMIT_MAC_PROFILE : lib.RECORD_MAC_PROFILE;
    const req = lib.parseMacRequest(v.acceptSignature, profile);
    const params = { ...req, sharedSecret: secret };
    const { headers } = v.profile === 'commit'
      ? lib.createCommitMacHeaders({ ...v.commit, data: Uint8Array.from(Buffer.from(v.commit.dataHex, 'hex')) }, params)
      : lib.createRecordMacHeaders(v.record.uri, CID.parse(v.record.cid), params);
    const got = [headers[lib.MAC_COVERED_HEADER[profile]], headers['signature-input'], headers.signature];
    const want = [v.coveredHeader, v.signatureInput, v.signature];
    if (got.some((g, i) => g !== want[i])) throw new Error(`vector "${v.name}" differs: got ${JSON.stringify(got)}, fixture ${JSON.stringify(want)}`);
    return v.name;
  });
  return { confirmed: results.length, vectors: results };
}

