// Retire the artifacts an hv2-create-post.mjs run leaves up for inspection:
// revoke each parent's children (kills the delegated capability; the child
// account and its DID remain, inert), then schedule the ephemeral parent for
// reaper deletion. Reads one interop state dir (EZPDS_INTEROP_STATE_DIR — the
// same one the driver ran with) and acts on every account in it. Needs the same
// EZPDS_BASE_URL; secrets ride env only.

const BASE = (process.env.EZPDS_BASE_URL ?? '').replace(/\/+$/, '');
const account = await import('ezpds-interop/src/account.js');
const { loadState } = await import('ezpds-interop/src/state.js');

const state = loadState();
for (const name of Object.keys(state.accounts ?? {})) {
  const live = await account.ensureSession(name);
  const children = await fetch(`${BASE}/agent/child`, {
    headers: { authorization: `Bearer ${live.accessJwt}` },
  }).then((r) => r.json());
  for (const child of children.children ?? []) {
    if (child.status !== 'revoked') {
      const res = await fetch(`${BASE}/agent/child/revoke`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${live.accessJwt}`,
        },
        body: JSON.stringify({ did: child.did }),
      });
      console.log(`revoked child ${child.did}: ${res.status}`);
    }
  }
  await account.scheduleEphemeralDeletion(name);
}
