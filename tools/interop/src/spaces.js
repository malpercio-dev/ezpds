// Atproto Spaces checks: drive the com.atproto.space + com.atproto.simplespace
// alpha surface end-to-end, in the two shapes that matter.
//
//   spacesRoundTrip     authority = self, everything on one host: create a
//                       simplespace, write/read/list records in it, exercise the
//                       sync reads, tear the space down again.
//   crossHostRoundTrip  the shape a foreign implementation judges us on: a repo
//                       host and a space host that need not be the same server.
//                       Delegation token from the member's own PDS → DPoP-bound
//                       credential from the authority → credential-authed reads
//                       on both sides.
//   allowListRefusal    an `allowList` space must refuse a credential request
//                       that names no client — the one app-perimeter assertion
//                       reachable without a publicly hosted client_id document.
//
// Hosts come from the accounts, not a global: an account adopted by
// `import-session` carries the PDS it authenticated against, so one run spans two
// hosts by naming two accounts. A random skey keeps repeated runs independent, and
// every space is deleted in a finally so a failed step never leaks one.

import { xrpc, HttpError } from './http.js';
import { ensureSession } from './account.js';
import { randomSuffix } from './crypto.js';
import { accountHost, loadState, getAccount } from './state.js';
import { newDpopKey } from './dpop.js';
import { parseCar, decodeBlock } from './car.js';
import { resolveDidDoc, spaceEndpointFromDoc } from './identity.js';

const SPACE_TYPE = 'dev.malpercio.interop.bucket';
const COLLECTION = 'dev.malpercio.interop.note';

const OPEN_APP_ACCESS = { $type: 'com.atproto.simplespace.defs#open' };
const PUBLIC_POLICY = { $type: 'com.atproto.simplespace.defs#publicPolicy' };

/** `at://<authority>/space/<type>/<skey>` → its parts. */
export function parseSpaceUri(uri) {
  const match = /^at:\/\/([^/]+)\/space\/([^/]+)\/([^/]+)$/.exec(uri);
  if (!match) throw new Error(`not a space URI: ${uri}`);
  return { authority: match[1], type: match[2], skey: match[3] };
}

export async function createSpace(name, skey, { appAccess = OPEN_APP_ACCESS, policy = PUBLIC_POLICY } = {}) {
  const account = await ensureSession(name);
  await xrpc(accountHost(account), 'com.atproto.simplespace.createSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: { type: SPACE_TYPE, skey, policy, appAccess },
  });
  return `at://${account.did}/space/${SPACE_TYPE}/${skey}`;
}

export async function deleteSpace(name, spaceUri) {
  const account = await ensureSession(name);
  return xrpc(accountHost(account), 'com.atproto.simplespace.deleteSpace', {
    method: 'POST',
    token: account.accessJwt,
    body: { space: spaceUri },
  });
}

/**
 * Assert a space-export CAR is structurally what the lexicon promises, rather than
 * merely non-empty: CARv1, two roots in order (signed commit, then the DRISL record
 * index), every block hashing to the CID that names it, and `path` present in the
 * index pointing at a block the CAR actually carries.
 */
async function assertSpaceCar(bytes, path) {
  const car = await parseCar(bytes);
  if (car.roots.length !== 2) throw new Error(`space getRepo CAR declares ${car.roots.length} roots, expected 2 (commit, index)`);
  const [commitCid, indexCid] = car.roots;

  const commit = decodeBlock(car, commitCid);
  if (!commit.rev || !commit.sig) throw new Error('space getRepo commit root carries no rev/sig');

  const index = decodeBlock(car, indexCid);
  const recordCid = index?.[path];
  if (!recordCid) throw new Error(`space getRepo index does not list ${path} (has: ${Object.keys(index ?? {}).join(', ') || 'nothing'})`);
  if (!car.blocks.has(recordCid.toString())) throw new Error(`space getRepo index points at ${recordCid} but the CAR carries no such block`);

  return { bytes: bytes.length, blocks: car.blocks.size, commitRev: commit.rev, recordCid: recordCid.toString() };
}

/**
 * Create space → write a record → read it back (get/list/listSpaces) → sync
 * reads (getLatestCommit, listRepoOps, getRepo CAR) → delete the record →
 * delete the space. Self-contained; always attempts the space teardown.
 */
export async function spacesRoundTrip(name) {
  const account = await ensureSession(name);
  const host = accountHost(account);
  const token = () => account.accessJwt;
  const skey = `interop-${randomSuffix(6)}`;
  const spaceUri = await createSpace(name, skey);
  try {
    const text = `ezpds interop spaces check ${new Date().toISOString()}`;
    const created = await xrpc(host, 'com.atproto.space.createRecord', {
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

    const fetched = await xrpc(host, 'com.atproto.space.getRecord', {
      token: token(),
      params: { space: spaceUri, repo: account.did, collection: COLLECTION, rkey },
    });
    if (fetched.value.text !== text) throw new Error('space getRecord returned different text than written');

    const listed = await xrpc(host, 'com.atproto.space.listRecords', {
      token: token(),
      params: { space: spaceUri, repo: account.did, collection: COLLECTION },
    });
    if (!listed.records.some((r) => r.rkey === rkey)) throw new Error('written record missing from space listRecords');

    const spaces = await xrpc(host, 'com.atproto.space.listSpaces', {
      token: token(),
      params: { did: account.did },
    });
    if (!spaces.spaces.some((s) => s.uri === spaceUri)) throw new Error('space missing from listSpaces');

    const latest = await xrpc(host, 'com.atproto.space.getLatestCommit', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
    });
    if (!latest.commit?.rev) throw new Error('space getLatestCommit returned no commit rev');

    const ops = await xrpc(host, 'com.atproto.space.listRepoOps', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
    });
    if (!ops.ops.some((op) => op.rkey === rkey)) throw new Error('write missing from space listRepoOps');

    const car = await xrpc(host, 'com.atproto.space.getRepo', {
      token: token(),
      params: { space: spaceUri, repo: account.did },
      raw: true,
    });
    const exported = await assertSpaceCar(new Uint8Array(await car.arrayBuffer()), `${COLLECTION}/${rkey}`);

    await xrpc(host, 'com.atproto.space.deleteRecord', {
      method: 'POST',
      token: token(),
      body: { space: spaceUri, repo: account.did, collection: COLLECTION, rkey },
    });

    return { space: spaceUri, uri: created.uri, cid: created.cid, commitRev: latest.commit.rev, car: exported };
  } finally {
    // Teardown failure must not mask the real result; deleteSpace is idempotent.
    await deleteSpace(name, spaceUri).catch((err) => {
      process.stderr.write(`  (space teardown failed for ${spaceUri}: ${err.message})\n`);
    });
  }
}

/**
 * Where to reach the authority of `spaceUri`: an explicit override, else the host of a
 * local account for that DID, else whatever the authority's own DID document publishes.
 * The last path is what a real foreign client does, so it is the default.
 */
export async function resolveSpaceHost(spaceUri, override) {
  if (override) return override.replace(/\/+$/, '');
  const { authority } = parseSpaceUri(spaceUri);
  const local = Object.values(loadState().accounts).find((a) => a.did === authority);
  if (local) return accountHost(local);
  const endpoint = spaceEndpointFromDoc(await resolveDidDoc(authority));
  if (!endpoint) throw new Error(`${authority} publishes no space or PDS endpoint; pass --space-host`);
  return endpoint.replace(/\/+$/, '');
}

/**
 * Exchange a delegation token for a DPoP-bound space credential.
 *
 * Two hosts, two proof shapes: the member's own PDS mints the delegation token (it need
 * not know the space at all), and the authority spends it for a credential bound to the
 * mint-time proof's key. Every later read presents that credential under the `DPoP`
 * scheme with a per-request proof carrying `ath`.
 */
export async function acquireSpaceCredential({ memberName, spaceUri, spaceHost, clientAttestation }) {
  const member = await ensureSession(memberName);
  const repoHost = accountHost(member);
  const host = spaceHost ?? await resolveSpaceHost(spaceUri);

  const { token: delegation } = await xrpc(repoHost, 'com.atproto.space.getDelegationToken', {
    token: member.accessJwt,
    params: { space: spaceUri },
  });

  const key = await newDpopKey();
  let credential;
  try {
    ({ credential } = await xrpc(host, 'com.atproto.space.getSpaceCredential', {
      method: 'POST',
      token: delegation,
      body: { space: spaceUri, clientAttestation },
      dpop: { key }, // no `bind`: the delegation token is the Bearer grant, not the bound token
    }));
  } catch (err) {
    // `htu` is checked against the authority's *configured* public URL, so calling a host
    // by an address it does not publish fails here and nowhere else. Worth naming: the
    // symptom (InvalidToken on a proof that is otherwise correct) points nowhere useful.
    if (err instanceof HttpError && err.status === 401) {
      throw new Error(`${err.message}\n  hint: the DPoP htu must match the authority's own public URL — check that ${host} is what it publishes`);
    }
    throw err;
  }
  return { key, credential, delegation, repoHost, spaceHost: host, member };
}

/**
 * The cross-host shape: a repo host and a space host that need not be the same server.
 *
 * Runs degenerate (both hosts the same account's PDS) when only `member` is given, which
 * still exercises the whole credential path; name a second account with `--authority`, or
 * an existing foreign space with `--space`, to make the two halves genuinely different.
 */
export async function crossHostRoundTrip({ member: memberName, authority: authorityName, space, spaceHost }) {
  const member = await ensureSession(memberName);
  const repoHost = accountHost(member);

  // Either join an existing (possibly foreign) space, or stand one up on the authority's host.
  const ownedSpace = space ? null : await createSpace(authorityName ?? memberName, `interop-${randomSuffix(6)}`);
  const spaceUri = space ?? ownedSpace;
  const { authority } = parseSpaceUri(spaceUri);

  try {
    // A write into a space this host may never have heard of: the repo host registers the
    // space on first write, which is what lets a member join a foreign authority's space.
    const text = `ezpds interop cross-host check ${new Date().toISOString()}`;
    const created = await xrpc(repoHost, 'com.atproto.space.createRecord', {
      method: 'POST',
      token: member.accessJwt,
      body: { space: spaceUri, repo: member.did, collection: COLLECTION, record: { $type: COLLECTION, text } },
    });
    const rkey = created.uri.split('/').pop();

    const { key, credential, spaceHost: authorityHost } = await acquireSpaceCredential({
      memberName, spaceUri, spaceHost,
    });
    const dpop = { key, bind: credential };

    // The credential must not be usable as a plain Bearer token: that is the whole point of
    // binding it, and a host that accepts it unbound is the interop failure worth catching.
    const unbound = await xrpc(repoHost, 'com.atproto.space.getRecord', {
      token: credential,
      params: { space: spaceUri, repo: member.did, collection: COLLECTION, rkey },
    }).then(() => null, (err) => err);
    if (unbound === null) throw new Error('space credential was accepted without a DPoP proof');
    if (!(unbound instanceof HttpError)) throw unbound;

    // Credential-authed reads on the repo host — the side that holds the records.
    const record = await xrpc(repoHost, 'com.atproto.space.getRecord', {
      params: { space: spaceUri, repo: member.did, collection: COLLECTION, rkey },
      dpop,
    });
    if (record.value.text !== text) throw new Error('credential-authed getRecord returned different text than written');

    const ops = await xrpc(repoHost, 'com.atproto.space.listRepoOps', {
      params: { space: spaceUri, repo: member.did },
      dpop,
    });
    if (!ops.ops.some((op) => op.rkey === rkey)) throw new Error('write missing from credential-authed listRepoOps');

    const car = await xrpc(repoHost, 'com.atproto.space.getRepo', {
      params: { space: spaceUri, repo: member.did },
      raw: true,
      dpop,
    });
    const exported = await assertSpaceCar(new Uint8Array(await car.arrayBuffer()), `${COLLECTION}/${rkey}`);

    // …and on the space host — the side that is the authority. `listRepos` is the writer
    // set the authority tracks, so the member's repo must show up here after the write.
    const config = await xrpc(authorityHost, 'com.atproto.simplespace.getSpace', {
      params: { space: spaceUri },
      dpop,
    });
    if (config.uri !== spaceUri) throw new Error(`getSpace answered for ${config.uri}, not ${spaceUri}`);

    const repos = await xrpc(authorityHost, 'com.atproto.space.listRepos', {
      params: { space: spaceUri },
      dpop,
    });
    const listed = (repos.repos ?? []).some((r) => r.did === member.did);
    // The writer row is durable with the commit only when the authority IS the repo host;
    // a foreign authority learns of the write through a best-effort, non-blocking fan-out,
    // so its absence there is a lag to report, not a failure to assert.
    if (!listed && repoHost === authorityHost) {
      throw new Error(`member ${member.did} missing from the authority's listRepos after writing`);
    }

    await xrpc(repoHost, 'com.atproto.space.deleteRecord', {
      method: 'POST',
      token: member.accessJwt,
      body: { space: spaceUri, repo: member.did, collection: COLLECTION, rkey },
    });

    return {
      space: spaceUri,
      crossHost: repoHost !== authorityHost,
      repoHost,
      spaceHost: authorityHost,
      authority,
      member: member.did,
      credentialUnboundRejected: unbound.status,
      policy: config.policy?.$type ?? null,
      appAccess: config.appAccess?.$type ?? null,
      memberInAuthorityListRepos: listed,
      car: exported,
    };
  } finally {
    if (ownedSpace) {
      await deleteSpace(authorityName ?? memberName, ownedSpace).catch((err) => {
        process.stderr.write(`  (space teardown failed for ${ownedSpace}: ${err.message})\n`);
      });
    }
  }
}

/**
 * An `allowList` space must refuse a credential request that names no client — including
 * the authority's own, which is the part a host is likeliest to get wrong.
 *
 * The positive half (an allow-listed app presenting a matching attestation) needs a
 * publicly served client_id document and so stays out of the CLI; see the README.
 */
export async function allowListRefusal(name) {
  const account = getAccount(loadState(), name);
  const spaceUri = await createSpace(name, `interop-${randomSuffix(6)}`, {
    appAccess: { $type: 'com.atproto.simplespace.defs#allowList', allowed: ['https://interop.invalid/client-metadata.json'] },
  });
  try {
    const err = await acquireSpaceCredential({ memberName: name, spaceUri }).then(() => null, (e) => e);
    if (!err) throw new Error('allowList space minted a credential for a request naming no client');
    if (!(err instanceof HttpError) || err.status !== 403 || err.body?.error !== 'AppNotAuthorized') {
      throw new Error(`allowList refusal was not AppNotAuthorized/403: ${err.message}`);
    }
    return { space: spaceUri, authority: account.did, refusedWith: err.body.error, status: err.status };
  } finally {
    await deleteSpace(name, spaceUri).catch((e) => {
      process.stderr.write(`  (space teardown failed for ${spaceUri}: ${e.message})\n`);
    });
  }
}
