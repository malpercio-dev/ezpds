// Sync-protocol checks: CAR export, latest-commit agreement, repo status, and
// listRepos presence — the surface a relay consumes when crawling this host.

import * as dagCbor from '@ipld/dag-cbor';
import { BASE_URL } from './config.js';
import { request, xrpc } from './http.js';
import { loadState, getAccount } from './state.js';

function readVarint(bytes, offset) {
  let value = 0n;
  let shift = 0n;
  let pos = offset;
  for (;;) {
    const byte = bytes[pos++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return [Number(value), pos];
}

/** Parse a CARv1 header and return { version, roots: [cidString] , size }. */
export function parseCarHeader(bytes) {
  const [headerLen, bodyStart] = readVarint(bytes, 0);
  const header = dagCbor.decode(bytes.subarray(bodyStart, bodyStart + headerLen));
  return {
    version: header.version,
    roots: (header.roots ?? []).map((cid) => cid.toString()),
    size: bytes.length,
  };
}

export async function getRepoCar(did) {
  const res = await request(`${BASE_URL}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(did)}`, { raw: true });
  if (!res.ok) throw new Error(`getRepo failed: HTTP ${res.status} ${await res.text()}`);
  return new Uint8Array(await res.arrayBuffer());
}

export async function syncChecks(name) {
  const account = getAccount(loadState(), name);
  const did = account.did;
  const results = { did, checks: [] };
  const check = (label, ok, detail) => results.checks.push({ label, ok, detail });

  const latest = await xrpc(BASE_URL, 'com.atproto.sync.getLatestCommit', { params: { did } });
  check('getLatestCommit', Boolean(latest.cid && latest.rev), `cid=${latest.cid} rev=${latest.rev}`);

  const car = await getRepoCar(did);
  const header = parseCarHeader(car);
  check('getRepo CAR header', header.version === 1 && header.roots.length === 1, `${header.size} bytes, roots=${header.roots.join(',')}`);
  check('CAR root == latest commit', header.roots[0] === latest.cid, header.roots[0]);

  const status = await xrpc(BASE_URL, 'com.atproto.sync.getRepoStatus', { params: { did } });
  check('getRepoStatus active', status.active === true, JSON.stringify(status));

  const repos = await xrpc(BASE_URL, 'com.atproto.sync.listRepos', { params: { limit: 1000 } });
  check('listRepos contains repo', (repos.repos ?? []).some((r) => r.did === did), `${(repos.repos ?? []).length} repos on host`);

  results.ok = results.checks.every((c) => c.ok);
  return results;
}
