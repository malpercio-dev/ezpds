// The wallet's side of OAuth consent: a hand-rolled client for the four device-key endpoints
// in `crates/pds/src/routes/oauth_consent.rs`.
//
// Written by hand for the same reason as `wire-client.ts`: this is a protocol surface a real
// wallet speaks, and the interesting failures are in what exactly goes on the wire. It signs a
// canonical envelope with a key from the account's PLC rotation set, so a test can vary any
// single field — the request id, the client, the decision, the granted scope, the signing key —
// and watch the server refuse.
//
// Nothing here is a shortcut around the server. There is no test-only approve endpoint; these
// are the same requests the identity wallet issues, and the account's authority is resolved
// live from the mock directory's audit log on every call.

import {
  OAUTH_CONSENT_DECISION_APPROVE,
  consentNonce,
  encodeOAuthConsentEnvelope,
} from './consent-envelope.ts';

/** The signer a wallet holds: any keypair whose `did:key` is in the account's rotation set. */
export interface ConsentSigner {
  /** The `did:key:` URI the envelope names as `key`, and the server looks up in `rotationKeys`. */
  did(): string;
  /** Raw 64-byte r‖s P-256 signature, low-S canonical, over SHA-256 of the message. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** A response with its body already read, so tests can assert on status and error strings. */
export interface WalletResponse {
  status: number;
  json: any;
  text: string;
}

async function readResponse(res: Response): Promise<WalletResponse> {
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, json, text };
}

/**
 * `GET /oauth/authorize/consent-request` — what the wallet shows the user before approving.
 *
 * Exactly one of `userCode` (typed) or `requestId` (QR / handoff) is sent; supplying both is a
 * 400 the server states explicitly, which is itself worth being able to reproduce.
 */
export async function previewConsentRequest(
  baseUrl: string,
  by: { userCode?: string; requestId?: string },
): Promise<WalletResponse> {
  const query = new URLSearchParams();
  if (by.userCode !== undefined) query.set('user_code', by.userCode);
  if (by.requestId !== undefined) query.set('request_id', by.requestId);
  return readResponse(await fetch(`${baseUrl}/oauth/authorize/consent-request?${query}`));
}

/** `GET /oauth/authorize/status` — the browser's poll, exposed so tests can read the state. */
export async function consentStatus(
  baseUrl: string,
  requestId: string,
): Promise<WalletResponse> {
  return readResponse(
    await fetch(
      `${baseUrl}/oauth/authorize/status?request_id=${encodeURIComponent(requestId)}`,
    ),
  );
}

export interface ApprovalEnvelope {
  did: string;
  signingKey: string;
  requestId: string;
  decision: string;
  grantedScope: string;
  matchCode?: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export interface SignApprovalOptions {
  serverDid: string;
  accountDid: string;
  signer: ConsentSigner;
  requestId: string;
  /** The client_id the pending request was created for — bound into the signature. */
  clientId: string;
  decision?: string;
  /** Space-joined granted scope; the empty string for a denial. */
  grantedScope?: string;
  /** The number read off the sign-in page. Sent outside the envelope, as the wallet does. */
  matchCode?: string;
  /** Overridden by tests that need a stale or future proof. */
  timestamp?: number;
  nonce?: string;
}

/**
 * Build a signed approve/deny envelope — the request body, not yet sent.
 *
 * Separated from `submitApproval` so a test can tamper with the body *after* signing (raising
 * the granted scope, re-pointing the request id) and prove the signature refuses to cover it.
 */
export async function signApproval(opts: SignApprovalOptions): Promise<ApprovalEnvelope> {
  const decision = opts.decision ?? OAUTH_CONSENT_DECISION_APPROVE;
  // A denial signs over the empty scope string; the server substitutes it regardless of what
  // the body carries, so signing anything else would fail verification.
  const grantedScope =
    decision === OAUTH_CONSENT_DECISION_APPROVE ? (opts.grantedScope ?? 'atproto') : '';
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? consentNonce();
  const signingKey = opts.signer.did();

  const envelope = encodeOAuthConsentEnvelope({
    serverDid: opts.serverDid,
    accountDid: opts.accountDid,
    signingKeyDid: signingKey,
    requestId: opts.requestId,
    clientId: opts.clientId,
    decision,
    grantedScope,
    timestamp,
    nonce,
  });
  const signature = Buffer.from(await opts.signer.sign(envelope)).toString('base64url');

  const body: ApprovalEnvelope = {
    did: opts.accountDid,
    signingKey,
    requestId: opts.requestId,
    decision,
    grantedScope,
    timestamp,
    nonce,
    signature,
  };
  if (opts.matchCode !== undefined) body.matchCode = opts.matchCode;
  return body;
}

/** `POST /oauth/authorize/approve` — submit an envelope verbatim. */
export async function submitApproval(
  baseUrl: string,
  body: ApprovalEnvelope | Record<string, unknown>,
): Promise<WalletResponse> {
  return readResponse(
    await fetch(`${baseUrl}/oauth/authorize/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

/** Sign and submit in one step — the ordinary path most tests want. */
export async function approveWithDeviceKey(
  baseUrl: string,
  opts: SignApprovalOptions,
): Promise<{ body: ApprovalEnvelope; response: WalletResponse }> {
  const body = await signApproval(opts);
  return { body, response: await submitApproval(baseUrl, body) };
}
