// Central configuration for the interop CLI. Everything is env-overridable, but the
// defaults target the ezpds staging deployment on the live ATProto network.

export const BASE_URL = (process.env.EZPDS_BASE_URL ?? 'https://ezpds-staging.up.railway.app').replace(/\/+$/, '');
export const PDS_HOSTNAME = new URL(BASE_URL).hostname;

export const ADMIN_TOKEN = process.env.EZPDS_ADMIN_TOKEN ?? null;

export const PLC_URL = (process.env.EZPDS_PLC_URL ?? 'https://plc.directory').replace(/\/+$/, '');
export const PUBLIC_APPVIEW_URL = (process.env.EZPDS_PUBLIC_APPVIEW_URL ?? 'https://public.api.bsky.app').replace(/\/+$/, '');
export const RELAY_URL = (process.env.EZPDS_RELAY_URL ?? 'https://bsky.network').replace(/\/+$/, '');

// The ONLY external network identity these tools are permitted to interact with
// (follow/like/mention). Hard-coded on purpose: staging federates with the real
// network, and we must not touch other users. Do not widen this list without the
// operator's explicit sign-off.
export const ALLOWED_TARGET = Object.freeze({
  handle: 'malpercio.dev',
  did: 'did:web:malpercio.dev',
});

export { MIN_REQUEST_INTERVAL_MS, MAX_RATE_LIMIT_RETRIES } from './pacing.js';

// Default email pattern for test accounts (outbound email is stubbed server-side).
export function defaultEmail(name) {
  const local = process.env.EZPDS_INTEROP_EMAIL_LOCAL ?? 'root';
  const domain = process.env.EZPDS_INTEROP_EMAIL_DOMAIN ?? 'malpercio.dev';
  return `${local}+ezpds-interop-${name}@${domain}`;
}
