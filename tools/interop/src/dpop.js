// RFC 9449 DPoP proof construction — the client half of the Atproto Spaces
// credential flow.
//
// Two proof shapes ride this one builder, matching the two server seams:
//   * mint-time (`getSpaceCredential`): no `ath`, because the token in
//     `Authorization` is the delegation grant being spent, not a DPoP-bound
//     token. The proof's key is what the minted credential gets bound to.
//   * resource (every credential-authed read): `ath` = SHA-256 of the
//     credential, which rides `Authorization: DPoP <credential>`.
//
// WebCrypto rather than node:crypto's sign(): ECDSA there returns raw R||S,
// which is exactly the JWS ES256 encoding (node's returns DER).

import { webcrypto, createHash, randomUUID } from 'node:crypto';

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

/** A fresh P-256 proof key. Ephemeral per run: nothing binds to it but live credentials. */
export async function newDpopKey() {
  const { privateKey, publicKey } = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const { x, y } = await webcrypto.subtle.exportKey('jwk', publicKey);
  // Only the RFC 7638 required members, in lexicographic order: the server thumbprints
  // this JWK verbatim and compares against the credential's `cnf.jkt`.
  return { privateKey, jwk: { crv: 'P-256', kty: 'EC', x, y } };
}

/**
 * Build a DPoP proof JWT for one request.
 *
 * @param {{privateKey: CryptoKey, jwk: object}} key
 * @param {{method: string, url: string, boundToken?: string}} req
 *   `boundToken` present ⇒ an `ath` claim (resource proof); absent ⇒ mint-time proof.
 */
export async function dpopProof(key, { method, url, boundToken }) {
  // `htu` is scheme + host + path only (RFC 9449 §4.3) — query strings are stripped,
  // which matters because every XRPC query carries its params there.
  const htu = new URL(url);
  htu.search = '';
  htu.hash = '';

  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk };
  const claims = {
    jti: randomUUID(),
    htm: method.toUpperCase(),
    htu: htu.toString(),
    iat: Math.floor(Date.now() / 1000),
  };
  if (boundToken) claims.ath = b64u(createHash('sha256').update(boundToken).digest());

  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  const signature = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    Buffer.from(signingInput),
  );
  return `${signingInput}.${b64u(signature)}`;
}
