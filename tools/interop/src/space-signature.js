// RFC 9421 HTTP Message Signatures as Atproto Spaces profiles them — the client half
// of the space credential flow, mirroring the reference's `createSpaceSigHeaders`
// (packages/space/src/http-signature.ts on atproto's `permissioned-data` branch).
//
// Two shapes, matching the two server seams:
//   * credential exchange (`getSpaceCredential`): covers `("authorization")` and
//     names the key in `keyid`. The authority copies that keyid into the minted
//     credential's `cnf.kid`.
//   * credential use (every credential-authed read): `Authorization: Atproto-Space
//     <credential>` plus `Atproto-Space-Audience: <did>`, both covered, in that
//     order, signed by the `cnf.kid` key. The audience is the DID the request is
//     for — the repo owner on a repo read, the space authority on a space-level one.
//
// No timestamp, nonce, or jti: the signature is deterministic per (credential,
// audience), and the spec allows replay against the same audience until expiry.

import { P256Keypair } from '@atproto/crypto';

const LABEL = 'atproto-space';

/** A fresh P-256 key a credential will be bound to. Ephemeral per run. */
export function newSpaceKey() {
  return P256Keypair.create();
}

/**
 * The headers that carry one signed space request.
 *
 * @param {P256Keypair} key
 * @param {{authorization: string, audience?: string}} req
 *   `audience` present ⇒ the credential-use shape; absent ⇒ the exchange shape.
 * @returns {Promise<Record<string, string>>}
 */
export async function spaceSigHeaders(key, { authorization, audience }) {
  const input = audience === undefined
    ? `("authorization");keyid="${key.did()}"`
    : '("authorization" "atproto-space-audience")';
  const base = [`"authorization": ${authorization}`];
  if (audience !== undefined) base.push(`"atproto-space-audience": ${audience}`);
  base.push(`"@signature-params": ${input}`);
  const signature = await key.sign(new TextEncoder().encode(base.join('\n')));
  return {
    Authorization: authorization,
    ...(audience !== undefined ? { 'Atproto-Space-Audience': audience } : {}),
    'Signature-Input': `${LABEL}=${input}`,
    Signature: `${LABEL}=:${Buffer.from(signature).toString('base64')}:`,
  };
}
