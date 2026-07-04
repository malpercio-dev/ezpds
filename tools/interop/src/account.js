// Account provisioning + session management against the ezpds provisioning API
// and standard XRPC session endpoints.
//
// Flow (mirrors the identity-wallet mobile ceremony):
//   1. admin claim code            POST /v1/accounts/claim-codes   (admin token)
//   2. pending mobile account      POST /v1/accounts/mobile
//   3. PDS-issued repo signing key GET  /v1/repo-signing-key       (session token)
//   4. client-signed did:plc genesis op → POST /v1/dids
//   5. handle registration         POST /v1/handles
//   6. standard session            POST /xrpc/com.atproto.server.createSession

import { BASE_URL, ADMIN_TOKEN, defaultEmail } from './config.js';
import { request, xrpc } from './http.js';
import { newKeypair, keypairFromHex, buildGenesisOp, randomPassword, randomSuffix } from './crypto.js';
import { loadState, saveState, getAccount } from './state.js';

export async function describeServer() {
  return xrpc(BASE_URL, 'com.atproto.server.describeServer');
}

export async function health() {
  return xrpc(BASE_URL, '_health');
}

export async function mintClaimCode() {
  if (!ADMIN_TOKEN) {
    throw new Error('EZPDS_ADMIN_TOKEN is not set — cannot mint a claim code. Either export it or pass --claim-code.');
  }
  const data = await request(`${BASE_URL}/v1/accounts/claim-codes`, {
    method: 'POST',
    token: ADMIN_TOKEN,
    body: { count: 1, expiresInHours: 1 },
  });
  return data.codes[0];
}

/**
 * Create a fully provisioned account and persist its credentials in state.
 *
 * @param {{name: string, kind: 'persistent'|'ephemeral', handle?: string, claimCode?: string}} opts
 */
export async function createAccount({ name, kind, handle, claimCode }) {
  const state = loadState();
  if (state.accounts[name]) {
    throw new Error(`account "${name}" already exists in state (did: ${state.accounts[name].did}). Pick another --name or delete it first.`);
  }

  if (!handle) {
    const server = await describeServer();
    const domains = server.availableUserDomains ?? [];
    if (!domains.length) throw new Error('describeServer returned no availableUserDomains; pass --handle explicitly');
    const domain = domains[0].replace(/^\./, '');
    handle = `${name.replace(/[^a-z0-9-]/gi, '-').toLowerCase()}-${randomSuffix(4)}.${domain}`;
  }

  const email = defaultEmail(name);
  const password = randomPassword();
  const code = claimCode ?? await mintClaimCode();

  console.log(`creating ${kind} account "${name}" — handle ${handle}`);

  // Device key: identifies this CLI as the account's "device".
  const deviceKey = await newKeypair();
  const mobile = await request(`${BASE_URL}/v1/accounts/mobile`, {
    method: 'POST',
    body: {
      email,
      handle,
      devicePublicKey: deviceKey.publicKeyBase64,
      platform: 'ios',
      claimCode: code,
    },
  });

  // PDS-issued per-account repo signing key: rotationKeys[1] + verificationMethods.atproto.
  const repoKey = await request(`${BASE_URL}/v1/repo-signing-key`, { token: mobile.sessionToken });

  // Rotation key: held locally, signs the genesis op — the root of control.
  const rotationKey = await newKeypair();
  const { did, signedOp } = await buildGenesisOp({
    rotationKeyId: rotationKey.keyId,
    repoSigningKeyId: repoKey.keyId,
    rotationKeypair: rotationKey.keypair,
    handle,
    pdsUrl: BASE_URL,
  });

  const didResult = await request(`${BASE_URL}/v1/dids`, {
    method: 'POST',
    token: mobile.sessionToken,
    body: {
      rotationKeyPublic: rotationKey.keyId,
      signedCreationOp: signedOp,
      password,
    },
  });
  if (didResult.did !== did) {
    throw new Error(`DID mismatch: locally derived ${did}, server registered ${didResult.did}`);
  }

  await request(`${BASE_URL}/v1/handles`, {
    method: 'POST',
    token: didResult.session_token,
    body: { accountId: did, handle },
  });

  const session = await xrpc(BASE_URL, 'com.atproto.server.createSession', {
    method: 'POST',
    body: { identifier: did, password },
  });

  state.accounts[name] = {
    kind,
    name,
    did,
    handle,
    email,
    password,
    rotationKeyId: rotationKey.keyId,
    rotationKeyPrivateHex: rotationKey.privateKeyHex,
    deviceKeyId: deviceKey.keyId,
    deviceKeyPrivateHex: deviceKey.privateKeyHex,
    repoSigningKeyId: repoKey.keyId,
    provisioningSessionToken: didResult.session_token,
    deviceToken: mobile.deviceToken,
    accessJwt: session.accessJwt,
    refreshJwt: session.refreshJwt,
    createdAt: new Date().toISOString(),
  };
  saveState(state);

  console.log(`account created: ${did} (${handle})`);
  return state.accounts[name];
}

function jwtExpiresSoon(jwt, marginSeconds = 60) {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
    return payload.exp * 1000 < Date.now() + marginSeconds * 1000;
  } catch {
    return true;
  }
}

/**
 * Return a valid accessJwt for the named account, refreshing (or as a last
 * resort re-authenticating) only when needed — createSession is rate-limited
 * to 30/5min per IP, so sessions are reused aggressively.
 */
export async function ensureSession(name) {
  const state = loadState();
  const account = getAccount(state, name);

  if (account.accessJwt && !jwtExpiresSoon(account.accessJwt)) return account;

  if (account.refreshJwt && !jwtExpiresSoon(account.refreshJwt)) {
    try {
      const refreshed = await xrpc(BASE_URL, 'com.atproto.server.refreshSession', {
        method: 'POST',
        token: account.refreshJwt,
      });
      account.accessJwt = refreshed.accessJwt;
      account.refreshJwt = refreshed.refreshJwt;
      saveState(state);
      return account;
    } catch {
      // fall through to createSession
    }
  }

  const session = await xrpc(BASE_URL, 'com.atproto.server.createSession', {
    method: 'POST',
    body: { identifier: account.did, password: account.password },
  });
  account.accessJwt = session.accessJwt;
  account.refreshJwt = session.refreshJwt;
  saveState(state);
  return account;
}

/**
 * Tear down an ephemeral account: deactivate it with a deleteAfter a few
 * minutes out; the server-side reaper then permanently purges it (repo, blobs,
 * sessions, handle) and broadcasts #account status=deleted so relays drop it.
 * The did:plc entry remains on plc.directory per ezpds's wallet-native model.
 */
export async function scheduleEphemeralDeletion(name, { afterMinutes = 5 } = {}) {
  const state = loadState();
  const account = getAccount(state, name);
  if (account.kind !== 'ephemeral') {
    throw new Error(`account "${name}" is ${account.kind}, not ephemeral — refusing to schedule deletion`);
  }
  const live = await ensureSession(name);
  const deleteAfter = new Date(Date.now() + afterMinutes * 60_000).toISOString();
  await xrpc(BASE_URL, 'com.atproto.server.deactivateAccount', {
    method: 'POST',
    token: live.accessJwt,
    body: { deleteAfter },
  });
  account.scheduledDeletion = deleteAfter;
  saveState(state);
  console.log(`ephemeral account "${name}" deactivated; server reaper will purge it after ${deleteAfter}`);
  return deleteAfter;
}

export async function getSession(name) {
  const account = await ensureSession(name);
  return xrpc(BASE_URL, 'com.atproto.server.getSession', { token: account.accessJwt });
}

export { keypairFromHex };
