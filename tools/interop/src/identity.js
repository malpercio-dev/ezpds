// Identity interop checks: handle↔DID resolution through every path the live
// network would use — the PDS's resolveHandle, the HTTP well-known fallback,
// and the global plc.directory record — asserting they agree bidirectionally.

import { BASE_URL, PLC_URL } from './config.js';
import { request, xrpc } from './http.js';
import { loadState, getAccount } from './state.js';

export async function resolveHandleViaPds(handle) {
  const data = await xrpc(BASE_URL, 'com.atproto.identity.resolveHandle', { params: { handle } });
  return data.did;
}

/**
 * The well-known handle-verification path a relay/AppView uses when there is no
 * DNS TXT record: GET https://<handle>/.well-known/atproto-did. For subdomain
 * handles of the PDS host, that request lands on the PDS itself (it resolves
 * the Host header against its handles table).
 */
export async function resolveHandleViaWellKnown(handle) {
  const text = await request(`https://${handle}/.well-known/atproto-did`);
  return String(text).trim();
}

export async function fetchPlcDocument(did) {
  if (!did.startsWith('did:plc:')) throw new Error(`not a did:plc: ${did}`);
  return request(`${PLC_URL}/${did}`);
}

export async function fetchDidWebDocument(did) {
  if (!did.startsWith('did:web:')) throw new Error(`not a did:web: ${did}`);
  const host = decodeURIComponent(did.slice('did:web:'.length));
  if (host.includes(':')) throw new Error(`unsupported did:web with path/port: ${did}`);
  return request(`https://${host}/.well-known/did.json`);
}

export function pdsEndpointFromDoc(doc) {
  const service = (doc.service ?? []).find(
    (s) => s.id === '#atproto_pds' || s.id?.endsWith('#atproto_pds') || s.type === 'AtprotoPersonalDataServer',
  );
  return service?.serviceEndpoint ?? null;
}

/**
 * Full identity verification for one of our accounts. Checks:
 *  - PDS resolveHandle(handle) → did
 *  - well-known atproto-did on the handle host → did
 *  - plc.directory DID document: alsoKnownAs includes at://handle, PDS service
 *    endpoint points back at this deployment.
 */
export async function verifyIdentity(name) {
  const account = getAccount(loadState(), name);
  const results = { did: account.did, handle: account.handle, checks: [] };
  const check = (label, ok, detail) => results.checks.push({ label, ok, detail });

  const viaPds = await resolveHandleViaPds(account.handle);
  check('pds resolveHandle', viaPds === account.did, viaPds);

  try {
    const viaWellKnown = await resolveHandleViaWellKnown(account.handle);
    check('well-known atproto-did', viaWellKnown === account.did, viaWellKnown);
  } catch (err) {
    check('well-known atproto-did', false, `unreachable: ${err.message}`);
  }

  const doc = await fetchPlcDocument(account.did);
  const aka = doc.alsoKnownAs ?? [];
  check('plc.directory alsoKnownAs', aka.includes(`at://${account.handle}`), aka.join(', '));
  const endpoint = pdsEndpointFromDoc(doc);
  check('plc.directory PDS endpoint', endpoint === BASE_URL, endpoint);

  results.ok = results.checks.every((c) => c.ok);
  return results;
}
