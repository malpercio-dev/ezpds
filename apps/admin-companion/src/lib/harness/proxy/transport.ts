/**
 * Proxy-mode transport for the admin harness: same-origin `/__pds/*` fetches the vite
 * dev server forwards to the hermetic local PDS (browser-harness.AC3.5), plus the
 * admin-token helpers used to mint the device pairing code.
 */

/** Fetch a bare relay path on the proxied PDS (e.g. `/v1/accounts/claim-codes`). */
export function pdsFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`/__pds${path}`, init);
}

/** The throwaway admin token (`VITE_HARNESS_ADMIN_TOKEN`, printed by `just harness-pds`). */
export function adminToken(): string | null {
  return (import.meta.env.VITE_HARNESS_ADMIN_TOKEN as string | undefined) ?? null;
}

/**
 * Mint a single-use admin **device pairing code** via the master-token-only endpoint, so
 * a browser session can pair for real without an out-of-band code. Throws (as a typed
 * relay error) if no admin token is configured.
 */
export async function mintPairingCode(): Promise<string> {
  const token = adminToken();
  if (!token) {
    throw {
      code: 'KEYCHAIN',
      message:
        'proxy mode needs VITE_HARNESS_ADMIN_TOKEN (printed by `just harness-pds`) to mint a pairing code',
    };
  }
  const res = await pdsFetch('/v1/admin/pairing-codes', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ expiresInMinutes: 10 }),
  });
  if (!res.ok) {
    throw { code: 'RELAY_REJECTED', status: res.status, message: 'pairing-code mint failed' };
  }
  const body = (await res.json()) as { pairingCode?: string };
  if (!body.pairingCode) throw { code: 'BAD_RESPONSE', message: 'no pairingCode returned' };
  return body.pairingCode;
}

/** A fresh random nonce for the per-request replay guard. */
export function freshNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Current unix time in seconds (the timestamp field of both envelopes). */
export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}
