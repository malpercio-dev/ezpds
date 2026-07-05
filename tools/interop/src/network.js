// Wider-network visibility checks: relay crawl status (bsky.network) and
// AppView visibility (public.api.bsky.app). These are informational — staging
// may legitimately not be crawled — so they report rather than hard-fail.

import { PDS_HOSTNAME, RELAY_URL, PUBLIC_APPVIEW_URL, BASE_URL } from './config.js';
import { xrpc, HttpError } from './http.js';
import { loadState, getAccount } from './state.js';
import { ensureSession } from './account.js';

export async function relayHostStatus() {
  try {
    const status = await xrpc(RELAY_URL, 'com.atproto.sync.getHostStatus', { params: { hostname: PDS_HOSTNAME } });
    return { known: true, ...status };
  } catch (err) {
    if (err instanceof HttpError && (err.status === 404 || err.status === 400)) {
      return { known: false, detail: typeof err.body === 'object' ? err.body?.message ?? err.body?.error : String(err.body) };
    }
    throw err;
  }
}

export async function appviewProfile(actor) {
  try {
    return { found: true, profile: await xrpc(PUBLIC_APPVIEW_URL, 'app.bsky.actor.getProfile', { params: { actor } }) };
  } catch (err) {
    if (err instanceof HttpError && (err.status === 400 || err.status === 404)) {
      return { found: false, detail: typeof err.body === 'object' ? err.body?.message ?? err.body?.error : String(err.body) };
    }
    throw err;
  }
}

/**
 * Exercise the PDS's authenticated service proxy (app.bsky.* → AppView): the
 * same call a real client makes through its own PDS. Verifies inter-service
 * auth (getServiceAuth-signed JWT) works end to end.
 */
export async function appviewViaPdsProxy(name, actor) {
  const account = await ensureSession(name);
  return xrpc(BASE_URL, 'app.bsky.actor.getProfile', { params: { actor }, token: account.accessJwt });
}

export async function networkChecks(name) {
  const account = getAccount(loadState(), name);
  const results = { checks: [] };
  const check = (label, ok, detail, informational = false) =>
    results.checks.push({ label, ok, detail, informational });

  const relay = await relayHostStatus();
  check(
    `relay ${new URL(RELAY_URL).host} knows ${PDS_HOSTNAME}`,
    relay.known,
    relay.known ? `status=${relay.status ?? 'n/a'} accountCount=${relay.accountCount ?? '?'} seq=${relay.seq ?? '?'}` : relay.detail,
    true,
  );

  const profile = await appviewProfile(account.did);
  check(
    'AppView knows our account',
    profile.found,
    profile.found ? `handle=${profile.profile.handle}` : profile.detail,
    true,
  );

  try {
    const viaProxy = await appviewViaPdsProxy(name, account.did);
    check('PDS→AppView service proxy', Boolean(viaProxy.did), `resolved ${viaProxy.did ?? '(none)'}`);
  } catch (err) {
    // If the AppView doesn't know the account yet, the proxy leg still proves
    // auth + forwarding worked when the upstream error is a clean 400.
    const upstreamKnown = err instanceof HttpError && err.status === 400;
    check('PDS→AppView service proxy', upstreamKnown, `${err.message}${upstreamKnown ? ' (proxy leg OK; account unknown upstream)' : ''}`);
  }

  results.ok = results.checks.filter((c) => !c.informational).every((c) => c.ok);
  return results;
}
