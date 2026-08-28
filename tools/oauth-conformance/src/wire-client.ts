// A hand-rolled AT Protocol OAuth client that owns every byte it sends.
//
// The point of writing this by hand rather than importing an SDK is that an SDK hides the
// wire: it retries the DPoP nonce dance for you, tolerates a missing `state`, and normalizes
// error bodies before you ever see them. Every OAuth bug this repo shipped lived in exactly
// those details, so the conformance suite needs a client that reports them literally.
//
// This is deliberately NOT a good general-purpose client. It does the minimum a spec-reading
// implementer would do, and it exposes the raw response of every leg so tests can assert on
// status codes, headers, and error strings directly.

import * as crypto from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from 'jose';

/** A DPoP keypair plus the RFC 7638 thumbprint the server binds tokens to. */
export interface DpopKey {
  privateKey: KeyLike;
  publicJwk: JWK;
  thumbprint: string;
}

export async function generateDpopKey(): Promise<DpopKey> {
  // `extractable` matters: exportJWK needs the public half in JWK form for the proof header.
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  // RFC 7638: SHA-256 over the canonical JSON of the required members, in lexicographic
  // order. For an EC key that is exactly crv, kty, x, y — any other order or any extra
  // member yields a different thumbprint and every binding check fails.
  const canonical = JSON.stringify({
    crv: publicJwk.crv,
    kty: publicJwk.kty,
    x: publicJwk.x,
    y: publicJwk.y,
  });
  const thumbprint = crypto.createHash('sha256').update(canonical).digest('base64url');
  return { privateKey, publicJwk, thumbprint };
}

/**
 * Mint a DPoP proof (RFC 9449 §4).
 *
 * `htu` must be scheme + host + path with the query string stripped (§4.3) — a proof whose
 * htu carries `?limit=10` is rejected, which is a classic hand-rolled-client bug worth
 * being able to reproduce deliberately.
 */
export async function dpopProof(
  key: DpopKey,
  htm: string,
  url: string,
  opts: { nonce?: string; accessToken?: string; iat?: number } = {},
): Promise<string> {
  const parsed = new URL(url);
  const htu = `${parsed.origin}${parsed.pathname}`;
  const payload: Record<string, unknown> = {
    htm,
    htu,
    jti: crypto.randomUUID(),
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.accessToken) {
    // `ath` binds the proof to one access token (§4.3): base64url of SHA-256 over the token
    // string. Required at resource endpoints, absent at the token endpoint.
    payload.ath = crypto.createHash('sha256').update(opts.accessToken).digest('base64url');
  }
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk })
    .setIssuedAt(opts.iat)
    .sign(key.privateKey);
}

/** A confidential client's signing keypair, published as a JWK set in its metadata. */
export interface ClientKey {
  privateKey: KeyLike;
  /** The public half, with `kid`, ready to embed as `jwks: { keys: [...] }`. */
  publicJwk: JWK & { kid: string };
}

export async function generateClientKey(kid = 'conformance-1'): Promise<ClientKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid };
  return { privateKey, publicJwk };
}

/**
 * Mint an RFC 7523 `private_key_jwt` client assertion.
 *
 * `iss` and `sub` are both the client_id, and `aud` identifies the authorization server —
 * the claims that stop an assertion minted for one server being replayed against another.
 * Overrides exist so tests can produce deliberately wrong assertions.
 */
export async function clientAssertion(
  key: ClientKey,
  clientId: string,
  audience: string,
  overrides: { iss?: string; sub?: string; exp?: number | null; jti?: string | null } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: overrides.iss ?? clientId,
    sub: overrides.sub ?? clientId,
    aud: audience,
    iat: now,
  };
  if (overrides.exp !== null) payload.exp = overrides.exp ?? now + 60;
  if (overrides.jti !== null) payload.jti = overrides.jti ?? crypto.randomUUID();
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', kid: key.publicJwk.kid })
    .sign(key.privateKey);
}

export const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** PKCE (RFC 7636 §4.1): 43–128 unreserved characters, and its S256 challenge. */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/** A response with its body already read, so tests can assert status, headers, and body. */
export interface WireResponse {
  status: number;
  headers: Headers;
  /** Parsed JSON when the body was JSON, else `undefined`. */
  json: any;
  text: string;
}

async function readResponse(res: Response): Promise<WireResponse> {
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: res.headers, json, text };
}

export interface ServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint: string;
  [key: string]: unknown;
}

export async function discover(baseUrl: string): Promise<WireResponse> {
  return readResponse(await fetch(`${baseUrl}/.well-known/oauth-authorization-server`));
}

/** POST a pushed authorization request, returning the raw response. */
export async function par(
  metadata: ServerMetadata,
  params: Record<string, string>,
  opts: { dpopKey?: DpopKey } = {},
): Promise<WireResponse> {
  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
  };
  if (opts.dpopKey) {
    headers.DPoP = await dpopProof(
      opts.dpopKey,
      'POST',
      metadata.pushed_authorization_request_endpoint,
    );
  }
  return readResponse(
    await fetch(metadata.pushed_authorization_request_endpoint, {
      method: 'POST',
      headers,
      body: new URLSearchParams(params).toString(),
    }),
  );
}

/**
 * POST to the token endpoint exactly once, with no nonce retry.
 *
 * The absence of a retry is the feature: a test drives the `use_dpop_nonce` challenge
 * explicitly so it can assert the challenge happened and carried a `DPoP-Nonce` header,
 * rather than having a helpful client paper over a server that never issued one.
 */
export async function tokenRequest(
  metadata: ServerMetadata,
  key: DpopKey,
  params: Record<string, string>,
  opts: { nonce?: string } = {},
): Promise<WireResponse> {
  const proof = await dpopProof(key, 'POST', metadata.token_endpoint, { nonce: opts.nonce });
  return readResponse(
    await fetch(metadata.token_endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        DPoP: proof,
      },
      body: new URLSearchParams(params).toString(),
    }),
  );
}

/**
 * The nonce dance as a spec-following client performs it: try, and if the server answers
 * `use_dpop_nonce`, retry once with the nonce it handed back. Returns both legs so a test can
 * assert the challenge occurred.
 */
export async function tokenRequestWithNonceRetry(
  metadata: ServerMetadata,
  key: DpopKey,
  params: Record<string, string>,
): Promise<{ challenge?: WireResponse; final: WireResponse }> {
  const first = await tokenRequest(metadata, key, params);
  if (first.status === 400 && first.json?.error === 'use_dpop_nonce') {
    const nonce = first.headers.get('dpop-nonce');
    if (!nonce) {
      // Returning rather than throwing keeps this a *finding* the test reports, not a crash.
      return { challenge: first, final: first };
    }
    return { challenge: first, final: await tokenRequest(metadata, key, params, { nonce }) };
  }
  return { final: first };
}

/** An authenticated XRPC call with a DPoP-bound access token. */
export async function xrpc(
  baseUrl: string,
  nsid: string,
  key: DpopKey,
  accessToken: string,
  opts: { nonce?: string; scheme?: string } = {},
): Promise<WireResponse> {
  const url = `${baseUrl}/xrpc/${nsid}`;
  const proof = await dpopProof(key, 'GET', url, {
    nonce: opts.nonce,
    accessToken,
  });
  return readResponse(
    await fetch(url, {
      headers: {
        // `scheme` is overridable so a test can present a DPoP-bound token as `Bearer`
        // and assert the server refuses it.
        authorization: `${opts.scheme ?? 'DPoP'} ${accessToken}`,
        DPoP: proof,
      },
    }),
  );
}

/** Decode a JWT payload without verifying — tests assert on claims, they don't trust them. */
export function decodeJwtPayload(jwt: string): any {
  const part = jwt.split('.')[1];
  if (!part) throw new Error(`not a JWT: ${jwt.slice(0, 32)}…`);
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}
