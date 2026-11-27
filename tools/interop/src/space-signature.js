// The RFC 9421 signature on a space-credential request, as the pin profiles it — the client
// half of `createSpaceSigHeaders` (packages/space/src/http-signature.ts, atproto
// `permissioned-data` @ 355b733).
//
// A request authorized by a space credential carries `Authorization: Atproto-Space-Credential
// <credential>` and `Atproto-Space-Audience: <did>`, both covered, in that order, signed by the
// key the credential is bound to (`cnf.kid`, the `credentialKey` handed to
// `authorizeSpaceSync`). The audience is the DID the request is for: the repo owner on a repo
// read, the space authority on a space-level one. No timestamp, nonce or jti: the signature is
// deterministic per (credential, audience).

import { P256Keypair } from '@atproto/crypto';

const LABEL = 'sig';
const TAG = 'atproto-space-credential';
const PARAMS = `("authorization" "atproto-space-audience");tag="${TAG}"`;

/** A fresh P-256 key a credential will be bound to. Ephemeral per run. */
export function newSpaceKey() {
  return P256Keypair.create();
}

/**
 * The headers that carry one credential-authorized request.
 *
 * @param {P256Keypair} key the credential's bound key
 * @param {{credential: string, audience: string}} req
 * @returns {Promise<Record<string, string>>}
 */
export async function spaceSigHeaders(key, { credential, audience }) {
  const authorization = `Atproto-Space-Credential ${credential}`;
  const base = [
    `"authorization": ${authorization}`,
    `"atproto-space-audience": ${audience}`,
    `"@signature-params": ${PARAMS}`,
  ].join('\n');
  const signature = await key.sign(new TextEncoder().encode(base));
  return {
    Authorization: authorization,
    'Atproto-Space-Audience': audience,
    'Signature-Input': `${LABEL}=${PARAMS}`,
    Signature: `${LABEL}=:${Buffer.from(signature).toString('base64')}:`,
  };
}
