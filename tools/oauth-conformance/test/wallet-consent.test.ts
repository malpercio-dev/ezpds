// The wallet (device-key) consent path, end to end.
//
// This is the leg real third-party logins to sovereign accounts actually take: an account with
// no usable password approves from its wallet, by signing a canonical envelope with a key in
// its PLC rotation set. The password form covered by `flow.test.ts` is the other branch of the
// same page.
//
// It is also the only path on which the PAR-time DPoP key binding survives to the issued code.
// The password form's PAR row is consumed by the GET that renders it, and the POST rebuilds the
// request from attacker-controllable hidden fields, so `oauth_authorize.rs` deliberately issues
// an unbound code there. The wallet path keeps its pending request server-side and carries
// `dpop_jkt` through to `store_authorization_code`. Before this file, that enforcement was
// exercised end-to-end nowhere — only by a Rust unit test that wrote the binding straight onto
// the code row, skipping the PAR and consent legs the binding has to survive.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

// Safe as a static import (unlike `account.js`, which the fixture must load only after
// EZPDS_BASE_URL is set): `crypto.js` reads no configuration.
import { newKeypair } from 'ezpds-interop/src/crypto.js';

import { completeWalletConsent, parseWalletPath } from '../src/consent.ts';
import {
  approveWithDeviceKey,
  consentStatus,
  previewConsentRequest,
  signApproval,
  submitApproval,
} from '../src/wallet-consent.ts';
import {
  decodeJwtPayload,
  discover,
  generateDpopKey,
  par,
  pkce,
  tokenRequestWithNonceRetry,
  xrpc,
  type DpopKey,
  type ServerMetadata,
} from '../src/wire-client.ts';
import { startClientHost, startFixture, type ClientHost, type Fixture } from './fixture.ts';

let fixture: Fixture;
let client: ClientHost;
let metadata: ServerMetadata;
let CLIENT_ID: string;
let REDIRECT_URI: string;

const SCOPE = 'atproto transition:generic';

before(async () => {
  fixture = await startFixture();
  client = await startClientHost();
  CLIENT_ID = client.clientId;
  REDIRECT_URI = client.redirectUri;
  const res = await discover(fixture.baseUrl);
  assert.equal(res.status, 200, 'authorization-server metadata must be served');
  metadata = res.json as ServerMetadata;
}, { timeout: 120_000 });

after(() => {
  client?.close();
  fixture?.stop();
});

/**
 * Push a request and load the consent page, returning the wallet block's fields.
 *
 * `dpopKey` proves a key at PAR time; the resulting pending request records its thumbprint,
 * which is what the binding tests then check the issued code against.
 */
async function startWalletRequest(
  opts: { scope?: string; state?: string; dpopKey?: DpopKey } = {},
): Promise<{ requestId: string; userCode: string; matchCode: string | null; verifier: string }> {
  const { verifier, challenge } = pkce();
  const pushed = await par(
    metadata,
    {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      scope: opts.scope ?? SCOPE,
      ...(opts.state ? { state: opts.state } : {}),
    },
    opts.dpopKey ? { dpopKey: opts.dpopKey } : {},
  );
  assert.equal(pushed.status, 201, `PAR must succeed: ${pushed.text}`);

  const pageRes = await fetch(
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
  );
  assert.equal(pageRes.status, 200, 'the consent page must render');
  return { ...parseWalletPath(await pageRes.text()), verifier };
}

/** The signer/audience fields every approval in this file shares. */
function signerFor(requestId: string) {
  return {
    serverDid: fixture.serverDid,
    accountDid: fixture.account.did,
    signer: fixture.account.rotationKey,
    clientId: CLIENT_ID,
    requestId,
  };
}

test('the consent page offers a wallet path alongside the password form', async () => {
  const { requestId, userCode } = await startWalletRequest();
  assert.match(
    requestId,
    /^poauth_/,
    'the pending request id is what the QR, the handoff link, the status poll and the ' +
      'completion form are all keyed on',
  );
  assert.ok(userCode.length > 0, 'the typed code is the guaranteed no-camera channel');
});

test('the wallet previews a pending request by user_code and by request_id', async () => {
  const { requestId, userCode } = await startWalletRequest({ scope: SCOPE });

  const typed = await previewConsentRequest(fixture.baseUrl, { userCode });
  assert.equal(typed.status, 200, `preview by user_code must succeed: ${typed.text}`);
  assert.equal(typed.json.requestId, requestId, 'both channels must name one request');
  assert.equal(typed.json.clientId, CLIENT_ID);
  assert.equal(typed.json.redirectUri, REDIRECT_URI);
  assert.deepEqual(
    typed.json.requestedScope,
    SCOPE.split(' '),
    'the wallet shows the requested permissions, so they must arrive as a list',
  );

  const handoff = await previewConsentRequest(fixture.baseUrl, { requestId });
  assert.equal(handoff.status, 200, `preview by request_id must succeed: ${handoff.text}`);
  assert.equal(handoff.json.requestId, requestId);
});

test('a guessed or resolved code reveals nothing about request state', async () => {
  // Every non-pending outcome is one uniform 404, so a caller cannot probe beyond
  // "pending or not" — including with a well-formed code for a request it does not own.
  const missing = await previewConsentRequest(fixture.baseUrl, { userCode: 'ZZZZ-ZZZZ' });
  assert.equal(missing.status, 404);

  const { requestId, userCode } = await startWalletRequest();
  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 200);
  const resolved = await previewConsentRequest(fixture.baseUrl, { userCode });
  assert.equal(resolved.status, 404, 'a resolved request is no longer previewable');

  const both = await previewConsentRequest(fixture.baseUrl, { userCode, requestId });
  assert.equal(both.status, 400, 'exactly one selector, stated explicitly rather than guessed');
});

test('a device-key approval completes the full flow and issues a working session', async () => {
  const { requestId, verifier } = await startWalletRequest({ state: 'wallet-state' });

  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 200, `the signed approval must be accepted: ${response.text}`);
  assert.equal(response.json.status, 'approved');
  assert.equal(response.json.did, fixture.account.did);

  const status = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(status.status, 200);
  assert.equal(status.json.status, 'approved', 'the browser learns of the approval by polling');

  // The browser's completion form — the same one the page's poller submits on approval.
  const completed = await completeWalletConsent(fixture.baseUrl, requestId);
  assert.equal(completed.status, 303, `completion must redirect: ${completed.body.slice(0, 300)}`);
  assert.ok(completed.location?.startsWith(REDIRECT_URI), completed.location ?? '');
  const code = completed.params.get('code');
  assert.ok(code, `completion must yield an authorization code: ${completed.location}`);
  assert.equal(completed.params.get('state'), 'wallet-state', 'state must round-trip');
  assert.equal(
    completed.params.get('iss'),
    metadata.issuer,
    'RFC 9207: the authorization response must identify the issuer on this path too',
  );

  const key = await generateDpopKey();
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });
  assert.equal(exchange.final.status, 200, `token exchange must succeed: ${exchange.final.text}`);
  assert.equal(
    exchange.final.json.sub,
    fixture.account.did,
    'a wallet-approved code must name the approving account, exactly as the password path does',
  );
  assert.equal(exchange.final.json.scope, SCOPE, 'the scope the wallet granted must be issued');

  const session = await xrpc(
    fixture.baseUrl,
    'com.atproto.server.getSession',
    key,
    exchange.final.json.access_token,
  );
  assert.equal(session.status, 200, `an authenticated call must succeed: ${session.text}`);
  assert.equal(session.json.did, fixture.account.did);
});

test('a code issued through the wallet path is bound to the PAR-time DPoP key', async () => {
  // The property this whole file exists for. PAR proves a key; the pending request keeps it
  // server-side; the issued code carries it; the token endpoint refuses any other presenter.
  // Nothing else in the suite reaches this — see the password-path gap test in flow.test.ts.
  const flowKey = await generateDpopKey();
  const otherKey = await generateDpopKey();
  const { requestId, verifier } = await startWalletRequest({ dpopKey: flowKey });

  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 200, response.text);
  const completed = await completeWalletConsent(fixture.baseUrl, requestId);
  const code = completed.params.get('code');
  assert.ok(code, `completion must yield a code: ${completed.location}`);

  const params = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  };

  const stolen = await tokenRequestWithNonceRetry(metadata, otherKey, params);
  assert.equal(
    stolen.final.status,
    400,
    'a code bound at PAR time must not redeem under a different DPoP key — an intercepted ' +
      `code would otherwise be usable by whoever intercepted it. Got: ${stolen.final.text}`,
  );
  assert.equal(stolen.final.json.error, 'invalid_grant');

  // The rejection must not have consumed the code: the legitimate client still redeems it.
  const rightful = await tokenRequestWithNonceRetry(metadata, flowKey, params);
  assert.equal(
    rightful.final.status,
    200,
    `the key that pushed the request must still redeem: ${rightful.final.text}`,
  );
  const claims = decodeJwtPayload(rightful.final.json.access_token);
  assert.equal(claims.cnf?.jkt, flowKey.thumbprint);
});

test('an approval envelope cannot be replayed onto its own request', async () => {
  // The `request_id` binding plus the single-use guarded status transition together subsume a
  // nonce store: a captured envelope lands on an already-terminal row and wins nothing.
  const { requestId } = await startWalletRequest();
  const body = await signApproval({ ...signerFor(requestId), grantedScope: SCOPE });

  const first = await submitApproval(fixture.baseUrl, body);
  assert.equal(first.status, 200, first.text);

  const replay = await submitApproval(fixture.baseUrl, body);
  assert.notEqual(replay.status, 200, `a replayed envelope must win nothing: ${replay.text}`);

  // And the replay must not have disturbed the request it was replayed onto.
  const status = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(status.json.status, 'approved');
});

test('an approval envelope cannot be replayed onto a different request', async () => {
  const first = await startWalletRequest();
  const second = await startWalletRequest();
  const body = await signApproval({ ...signerFor(first.requestId), grantedScope: SCOPE });

  // Re-point the signed envelope at the other pending request. `request_id` is inside the
  // signature, so the reconstructed envelope no longer matches.
  const moved = await submitApproval(fixture.baseUrl, {
    ...body,
    requestId: second.requestId,
  });
  assert.equal(moved.status, 401, `a re-pointed envelope must be refused: ${moved.text}`);
  const status = await consentStatus(fixture.baseUrl, second.requestId);
  assert.equal(status.json.status, 'pending', 'the targeted request must stay pending');
});

test('an approval cannot be widened beyond the scope that was signed', async () => {
  const { requestId } = await startWalletRequest({ scope: SCOPE });
  const body = await signApproval({ ...signerFor(requestId), grantedScope: 'atproto' });

  const widened = await submitApproval(fixture.baseUrl, { ...body, grantedScope: SCOPE });
  assert.equal(widened.status, 401, `a widened grant must be refused: ${widened.text}`);
});

test('a narrowed grant is honoured all the way to the issued token', async () => {
  // The user unchecking a permission in the wallet. The granted set is signed verbatim, and
  // the server reduces it against what was requested — it can only narrow, never add.
  const { requestId, verifier } = await startWalletRequest({ scope: SCOPE });
  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: 'atproto',
  });
  assert.equal(response.status, 200, response.text);

  const completed = await completeWalletConsent(fixture.baseUrl, requestId);
  const code = completed.params.get('code');
  assert.ok(code, `completion must yield a code: ${completed.location}`);
  const key = await generateDpopKey();
  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });
  assert.equal(exchange.final.status, 200, exchange.final.text);
  assert.equal(
    exchange.final.json.scope,
    'atproto',
    'the client must be told it got less than it asked for, not silently handed the full set',
  );
});

test('a key outside the account rotation set cannot approve', async () => {
  // Authority is the account's *current* `rotationKeys`, read live from the directory. A
  // well-formed envelope signed by any other key is refused, however valid its signature.
  const { requestId } = await startWalletRequest();
  const stranger = await newKeypair();

  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    signer: stranger.keypair,
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 401, `a foreign key must not approve: ${response.text}`);
  const status = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(status.json.status, 'pending');
});

test('a stale envelope is refused', async () => {
  // The timestamp is inside the signature, so an old proof cannot be re-dated — it can only be
  // replayed as-is, and the window is what stops that.
  const { requestId } = await startWalletRequest();
  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
    timestamp: Math.floor(Date.now() / 1000) - 3600,
  });
  assert.equal(response.status, 401, `an hour-old proof must be refused: ${response.text}`);
});

test('a denial terminates the request and issues no code', async () => {
  const { requestId } = await startWalletRequest();
  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    decision: 'deny',
  });
  assert.equal(response.status, 200, response.text);
  assert.equal(response.json.status, 'denied');

  const status = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(status.json.status, 'denied');

  const completed = await completeWalletConsent(fixture.baseUrl, requestId);
  assert.equal(completed.location, null, 'a denied request must never redirect with a code');
  assert.equal(completed.status, 400, 'the browser gets an explanatory page, not a redirect');
});

test('completion is single-use: an approved request mints at most one code', async () => {
  const { requestId } = await startWalletRequest();
  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 200, response.text);

  // The page's poller and the no-JS button can both fire; only one may win.
  const first = await completeWalletConsent(fixture.baseUrl, requestId);
  assert.equal(first.status, 303);
  assert.ok(first.params.get('code'));

  const second = await completeWalletConsent(fixture.baseUrl, requestId);
  assert.equal(second.location, null, 'a second completion must not mint a second code');
});

test('a request cannot be completed before it is approved', async () => {
  const { requestId } = await startWalletRequest();
  const completed = await completeWalletConsent(fixture.baseUrl, requestId);
  assert.equal(completed.location, null, 'a pending request must not yield a code');
  const status = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(status.json.status, 'pending', 'and it must stay approvable');
});

test('with no push dispatched, no number is required or disclosed', async () => {
  // The observable half of the V060 number-match contract. Matching becomes mandatory only
  // once a `login-approval` push actually went out, which needs a configured notification
  // relay and an iroh endpoint — network this hermetic suite deliberately does not have. The
  // enforcement itself (wrong number → 403, request stays pending; denial skips the check) is
  // covered by the Rust test `push_delivered_request_requires_the_matching_number`; see the
  // gap list in the README.
  //
  // What is reachable here is the other side of the same rule, and it is the side an
  // over-eager mitigation would break: a wallet-initiated sign-in must not be made to ask for
  // a number nobody was ever shown.
  const { requestId, userCode, matchCode } = await startWalletRequest();
  assert.equal(matchCode, null, 'the page must show no number when no push went out');

  const preview = await previewConsentRequest(fixture.baseUrl, { userCode });
  assert.equal(preview.status, 200);
  assert.equal(preview.json.matchRequired, false);
  assert.equal(
    preview.json.matchCode,
    undefined,
    'the number is the proof the approver can see the login surface, so it must never be in ' +
      'the wallet preview under any condition',
  );

  const { response } = await approveWithDeviceKey(fixture.baseUrl, {
    ...signerFor(requestId),
    grantedScope: SCOPE,
  });
  assert.equal(response.status, 200, `approval must not demand a number: ${response.text}`);
});

test('the status poll is throttled with slow_down', async () => {
  // The page's poller backs off on this; a client that hammered the endpoint instead would be
  // told to slow down rather than served.
  const { requestId } = await startWalletRequest();
  const first = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(first.status, 200);
  const second = await consentStatus(fixture.baseUrl, requestId);
  assert.equal(second.status, 429);
  assert.equal(second.json.status, 'slow_down');
});
