// A JavaScript port of the canonical OAuth-consent envelope the wallet signs.
//
// The encoding is defined in Rust (`crates/crypto/src/oauth_consent.rs`) and nowhere else, so
// this file is a second implementation of a wire format rather than a wrapper around one. That
// is only safe because both sides are pinned to the same golden vector
// (`test-vectors/oauth-consent-envelope-v1.json`, asserted by `consent-envelope.test.ts` here
// and by `canonical_envelope_has_a_stable_golden_vector` there): a divergence in either
// direction fails one of the two suites rather than silently producing envelopes the server
// rejects for reasons a test would report as "approval rejected".
//
// Every value is prefixed with its UTF-8 **byte** length, not its character count — a handle or
// client_id carrying multi-byte characters would otherwise encode a length the server disagrees
// with, and the signature check would fail with no indication why.

import * as crypto from 'node:crypto';

/** Protocol domain and version. Changing the wire encoding requires a new domain. */
export const OAUTH_CONSENT_DOMAIN = 'org.obsign.custos.oauth-consent.v1';
export const OAUTH_CONSENT_METHOD = 'POST';
export const OAUTH_CONSENT_APPROVE_PATH = '/oauth/authorize/approve';

/** The two decisions a wallet can sign over a pending request. */
export const OAUTH_CONSENT_DECISION_APPROVE = 'approve';
export const OAUTH_CONSENT_DECISION_DENY = 'deny';

/**
 * Lowercase-hex SHA-256 of the canonical granted-scope string (space-joined tokens).
 *
 * Both sides hash the identical verbatim string, so the scope binding is agreed without a
 * shared normalizer — which also means the caller must pass exactly what it puts on the wire.
 */
export function grantedScopeHash(grantedScope: string): string {
  return crypto.createHash('sha256').update(grantedScope, 'utf8').digest('hex');
}

export interface ConsentEnvelopeFields {
  serverDid: string;
  accountDid: string;
  signingKeyDid: string;
  requestId: string;
  clientId: string;
  decision: string;
  /** The canonical space-joined granted-scope string; empty for a denial. */
  grantedScope: string;
  timestamp: number;
  nonce: string;
}

/**
 * Encode the exact bytes an approval/denial is signed over.
 *
 * Field order is part of version 1: domain, audience, method, path, account DID, signing-key
 * DID, request id, client id, decision, granted-scope hash, timestamp, then nonce.
 */
export function encodeOAuthConsentEnvelope(fields: ConsentEnvelopeFields): Buffer {
  const entries: Array<[string, string]> = [
    ['domain', OAUTH_CONSENT_DOMAIN],
    ['aud', fields.serverDid],
    ['method', OAUTH_CONSENT_METHOD],
    ['path', OAUTH_CONSENT_APPROVE_PATH],
    ['did', fields.accountDid],
    ['key', fields.signingKeyDid],
    ['request', fields.requestId],
    ['client', fields.clientId],
    ['decision', fields.decision],
    ['scopeHash', grantedScopeHash(fields.grantedScope)],
    ['timestamp', String(fields.timestamp)],
    ['nonce', fields.nonce],
  ];

  return Buffer.concat(
    entries.map(([name, value]) =>
      Buffer.from(`${name}:${Buffer.byteLength(value, 'utf8')}:${value}\n`, 'utf8'),
    ),
  );
}

/**
 * A fresh 32-byte anti-replay nonce in canonical unpadded base64url.
 *
 * The server re-encodes what it receives and requires the result to reproduce the input
 * (`auth/signed_proof.rs`), so a non-canonical spelling is rejected before any signature work.
 */
export function consentNonce(): string {
  return crypto.randomBytes(32).toString('base64url');
}
