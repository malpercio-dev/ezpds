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

// Pacing: minimum gap between HTTP requests, so scripted runs stay far below the
// PDS per-IP limits (global 3000/5min; createSession 30/5min) and are polite to
// public infrastructure (plc.directory, the relay, the AppView).
export const MIN_REQUEST_INTERVAL_MS = Number(process.env.EZPDS_INTEROP_PACE_MS ?? 350);

// How many times to retry a 429 (honoring Retry-After) before giving up.
export const MAX_RATE_LIMIT_RETRIES = 4;

// Default email pattern for test accounts (outbound email is stubbed server-side).
export function defaultEmail(name) {
  const local = process.env.EZPDS_INTEROP_EMAIL_LOCAL ?? 'root';
  const domain = process.env.EZPDS_INTEROP_EMAIL_DOMAIN ?? 'malpercio.dev';
  return `${local}+ezpds-interop-${name}@${domain}`;
}
