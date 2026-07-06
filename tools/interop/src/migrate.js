// Outbound migration flow: self-signed PLC op + account repointing to a destination PDS.
// Reuses account session helpers, identity/sync resolvers, and crypto primitives.

import * as dagCbor from '@ipld/dag-cbor';
import { BASE_URL, PLC_URL } from './config.js';
import { request, xrpc, sleep } from './http.js';
import { ensureSession } from './account.js';
import { keypairFromHex } from './crypto.js';
import { resolveHandleViaPds, fetchPlcDocument, pdsEndpointFromDoc } from './identity.js';
import { getRepoCar } from './sync.js';
import { loadState, saveState, getAccount } from './state.js';

/**
 * Sign a PLC operation (genesis or migration) with a rotation keypair.
 * Returns the signed op with sig appended.
 */
async function signPlcOp(unsignedOp, rotationKeypair) {
  const unsignedBytes = dagCbor.encode(unsignedOp);
  const signature = await rotationKeypair.sign(unsignedBytes);
  const signedOp = { ...unsignedOp, sig: Buffer.from(signature).toString('base64url') };
  return signedOp;
}

/**
 * Build a migration PLC operation that repoints the DID from source to target PDS.
 * Requires: prev CID, target PDS endpoint, new signing key, and existing rotation/aka config.
 */
async function buildMigrationOp({
  prev,
  services,
  alsoKnownAs,
  rotationKeys,
  verificationMethods,
  rotationKeypair,
}) {
  const unsignedOp = {
    prev,
    type: 'plc_operation',
    services,
    alsoKnownAs,
    rotationKeys,
    verificationMethods,
  };

  return signPlcOp(unsignedOp, rotationKeypair);
}

/**
 * Perform a complete outbound migration: source PDS → destination PDS.
 * Self-signs the PLC migration op with the stored rotation key.
 */
export async function performMigration({ name, targetPds, inviteCode }) {
  const state = loadState();
  const sourceAccount = getAccount(state, name);

  console.error(`\n=== Migration perform: ${sourceAccount.did} → ${targetPds} ===\n`);

  // 1. Ensure source session is active
  const source = await ensureSession(name);
  console.error(`✓ Source session valid (${source.handle})`);

  // 2. Describe target server → get destination server DID
  const destServer = await xrpc(targetPds, 'com.atproto.server.describeServer');
  const destDid = destServer.did;
  console.error(`✓ Target server described (did: ${destDid})`);

  // 3. Reserve a signing key on the destination
  const reserveResp = await request(`${targetPds}/xrpc/com.atproto.server.reserveSigningKey`, {
    method: 'POST',
    body: { did: source.did },
  });
  const signingKey = reserveResp.signingKey;
  console.error(`✓ Signing key reserved: ${signingKey}`);

  // 4. Get service auth token from source (authorizes account creation on dest)
  const serviceAuthResp = await xrpc(BASE_URL, 'com.atproto.server.getServiceAuth', {
    token: source.accessJwt,
    params: {
      aud: destDid,
      lxm: 'com.atproto.server.createAccount',
    },
  });
  const serviceAuthToken = serviceAuthResp.token;
  console.error(`✓ Service auth token obtained`);

  // 5. Create account on destination with service auth (migration mode)
  let destSession;
  try {
    const createResp = await request(`${targetPds}/xrpc/com.atproto.server.createAccount`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${serviceAuthToken}` },
      body: {
        handle: source.handle,
        email: source.email,
        did: source.did,
        ...(inviteCode ? { inviteCode } : {}),
      },
    });
    destSession = createResp;
    console.error(`✓ Account created on destination`);
  } catch (err) {
    // 409 DidAlreadyExists — account exists, try to resume
    if (err.status === 409) {
      console.error(`⚠ Account already exists on destination (409), resuming from stored session`);
      // Check if we have a stored dest session; if not, reauth
      if (state.accounts[name]?.destAccessJwt) {
        destSession = {
          accessJwt: state.accounts[name].destAccessJwt,
          refreshJwt: state.accounts[name].destRefreshJwt,
        };
        console.error(`  Using stored destination session`);
      } else {
        throw new Error('Account exists but no destination session stored; cannot resume');
      }
    } else {
      throw err;
    }
  }

  // 6. Export repo from source and import to destination
  console.error(`Exporting repo from source...`);
  const sourceCar = await getRepoCar(source.did);
  console.error(`✓ Repo exported (${sourceCar.length} bytes)`);

  console.error(`Importing repo to destination...`);
  await request(`${targetPds}/xrpc/com.atproto.repo.importRepo`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${destSession.accessJwt}`,
      'Content-Type': 'application/vnd.ipld.car',
    },
    body: sourceCar,
  });
  console.error(`✓ Repo imported`);

  // 7. Blob drain loop: list missing blobs on dest, fetch from source, upload to dest
  console.error(`Draining blobs...`);
  let cursor = undefined;
  let blobCount = 0;
  for (;;) {
    const listResp = await xrpc(targetPds, 'com.atproto.repo.listMissingBlobs', {
      token: destSession.accessJwt,
      params: { cursor },
    });

    const missingBlobs = listResp.blobs ?? [];
    if (missingBlobs.length === 0) break;

    for (const blobMissing of missingBlobs) {
      const blobCid = blobMissing.cid;
      const mimeType = blobMissing.mimeType;

      // Fetch from source (no auth). Must go through xrpc(), which serializes params into the
      // query string — request() ignores `params`, so the did/cid would be dropped.
      const blobBytes = await xrpc(BASE_URL, 'com.atproto.sync.getBlob', {
        raw: true,
        params: { did: source.did, cid: blobCid },
      });
      if (!blobBytes.ok) throw new Error(`Failed to fetch blob ${blobCid}: HTTP ${blobBytes.status}`);

      // Upload to dest (with Bearer token)
      const blobBody = await blobBytes.arrayBuffer();
      await request(`${targetPds}/xrpc/com.atproto.repo.uploadBlob`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${destSession.accessJwt}`,
          'Content-Type': mimeType,
        },
        body: new Uint8Array(blobBody),
      });
      blobCount++;
    }

    cursor = listResp.cursor;
    if (!cursor) break;
  }
  console.error(`✓ Blobs drained (${blobCount} uploaded)`);

  // 8. Copy preferences from source to dest
  console.error(`Copying preferences...`);
  const sourcePrefs = await xrpc(BASE_URL, 'app.bsky.actor.getPreferences', {
    token: source.accessJwt,
  });
  const preferences = sourcePrefs.preferences ?? [];
  if (preferences.length > 0) {
    await xrpc(targetPds, 'app.bsky.actor.putPreferences', {
      token: destSession.accessJwt,
      method: 'POST',
      body: { preferences },
    });
    console.error(`✓ Preferences copied (${preferences.length})`);
  } else {
    console.error(`✓ No source preferences to copy`);
  }

  // 9. Verify the import completed on the destination (NSID is checkAccountStatus, not
  //    getAccountStatus). Blobs must all be imported and the repo must be committed.
  const destStatus = await xrpc(targetPds, 'com.atproto.server.checkAccountStatus', {
    token: destSession.accessJwt,
  });
  if (destStatus.importedBlobs !== destStatus.expectedBlobs || !destStatus.repoCommit) {
    throw new Error(
      `import incomplete on destination: importedBlobs=${destStatus.importedBlobs} ` +
        `expectedBlobs=${destStatus.expectedBlobs} repoCommit=${destStatus.repoCommit}`,
    );
  }
  console.error(
    `✓ Import verified (blobs ${destStatus.importedBlobs}/${destStatus.expectedBlobs}, repoCommit ${destStatus.repoCommit})`,
  );

  // 10. Identity migration: build and sign the PLC operation
  console.error(`\nBuilding and signing migration PLC operation...`);

  // Fetch the account's PLC op audit log to get the previous op's CID (the `prev` of the new op).
  const auditLog = await request(`${PLC_URL}/${source.did}/log/audit`);
  if (!Array.isArray(auditLog) || auditLog.length === 0) {
    throw new Error(`unexpected PLC audit log shape for ${source.did} (expected a non-empty array)`);
  }
  const previousEntry = auditLog.at(-1);
  const prevCid = previousEntry?.cid;
  if (typeof prevCid !== 'string') {
    throw new Error('latest PLC audit entry has no string `cid` to use as prev');
  }

  // Get the recommended DID credentials from the destination
  // (which includes the new signing key and preserved rotation/aka fields)
  const recommended = await xrpc(targetPds, 'com.atproto.identity.getRecommendedDidCredentials', {
    token: destSession.accessJwt,
  });

  // Build the migration op. CRITICAL: the wallet rotation key MUST stay at rotationKeys[0] — this
  // is the "credible exit" guarantee (the key that just signed this op must remain authorized).
  // getRecommendedDidCredentials returns ONLY the destination PDS signing key, so we prepend the
  // wallet key and dedup rather than trusting the recommendation to preserve it.
  const walletRotationKey = sourceAccount.rotationKeyId;
  const recommendedRotationKeys = recommended.rotationKeys ?? [];
  const rotationKeys = [
    walletRotationKey,
    ...recommendedRotationKeys.filter((k) => k !== walletRotationKey),
  ];
  const migrationOp = await buildMigrationOp({
    prev: prevCid,
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: targetPds,
      },
    },
    alsoKnownAs: recommended.alsoKnownAs ?? [`at://${source.handle}`],
    rotationKeys,
    verificationMethods: {
      atproto: signingKey,
    },
    rotationKeypair: await keypairFromHex(sourceAccount.rotationKeyPrivateHex),
  });

  console.error(`✓ Migration op signed with rotation key`);

  // 11. Post the signed migration op to PLC
  console.error(`Posting migration op to PLC...`);
  await request(`${PLC_URL}/${source.did}`, {
    method: 'POST',
    body: migrationOp,
  });
  console.error(`✓ Migration op posted to PLC`);

  // 12. Activate the destination once its DID doc has propagated. checkAccountStatus.validDid
  //     reflects whether plc.directory now serves the repointed doc; activateAccount itself returns
  //     an empty body, so its response can't confirm anything — we gate on validDid instead.
  console.error(`Activating account on destination...`);
  let activated = false;
  for (let attempt = 0; attempt < 10; attempt++) {
    const status = await xrpc(targetPds, 'com.atproto.server.checkAccountStatus', {
      token: destSession.accessJwt,
    });
    if (status.validDid) {
      await xrpc(targetPds, 'com.atproto.server.activateAccount', {
        token: destSession.accessJwt,
        method: 'POST',
      });
      activated = true;
      console.error(`✓ Account activated on destination`);
      break;
    }
    console.error(`  (attempt ${attempt + 1}/10) DID doc not yet propagated, waiting...`);
    await sleep(1000);
  }
  if (!activated) {
    // Do NOT deactivate the source — that would leave the identity homeless.
    throw new Error('destination DID doc did not propagate; account not activated (source left active)');
  }

  // Deactivate the source LAST, only after the destination is live.
  console.error(`Deactivating source account...`);
  await xrpc(BASE_URL, 'com.atproto.server.deactivateAccount', {
    token: source.accessJwt,
    method: 'POST',
  });
  console.error(`✓ Source account deactivated`);

  // 13. Persist the migration results
  state.accounts[name] = {
    ...state.accounts[name],
    pds: targetPds,
    destAccessJwt: destSession.accessJwt,
    destRefreshJwt: destSession.refreshJwt,
    migrationStatus: 'complete',
  };
  saveState(state);
  console.error(`✓ Migration state persisted\n`);

  return {
    did: source.did,
    handle: source.handle,
    sourcePds: BASE_URL,
    targetPds,
    status: 'complete',
  };
}

/**
 * Verify that a migration succeeded: handle/DID/repo resolve to the new PDS.
 */
export async function verifyMigration({ name, targetPds }) {
  const state = loadState();
  const account = getAccount(state, name);

  console.error(`\n=== Migration verify: ${account.did} ===\n`);

  const results = {
    did: account.did,
    handle: account.handle,
    pds: targetPds,
    checks: [],
  };

  const check = (label, ok, detail) => {
    results.checks.push({ label, ok, detail });
    console.error(`  ${ok ? '✓' : '✗'} ${label}: ${detail}`);
  };

  // Resolve handle → DID (should be unchanged)
  const resolvedDid = await resolveHandleViaPds(account.handle);
  check('handle resolves to DID', resolvedDid === account.did, resolvedDid);

  // Fetch PLC doc and verify PDS endpoint
  const plcDoc = await fetchPlcDocument(account.did);
  const pdsEndpoint = pdsEndpointFromDoc(plcDoc);
  check('PLC endpoint points to target PDS', pdsEndpoint === targetPds, pdsEndpoint);

  // Fetch repo from target PDS to verify it's serveable
  try {
    const carBytes = await request(`${targetPds}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(account.did)}`, {
      raw: true,
    });
    if (!carBytes.ok) throw new Error(`HTTP ${carBytes.status}`);
    const car = await carBytes.arrayBuffer();
    check('repo is serveable on target PDS', car.byteLength > 0, `${car.byteLength} bytes`);
  } catch (err) {
    check('repo is serveable on target PDS', false, err.message);
  }

  results.ok = results.checks.every(c => c.ok);
  console.error(`\nVerification: ${results.ok ? '✓ PASS' : '✗ FAIL'}\n`);

  return results;
}
