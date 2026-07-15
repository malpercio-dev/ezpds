/**
 * Proxy-mode transport for the wallet harness.
 *
 * Every request is same-origin to `/__pds/*`; the vite dev server proxies it server-side
 * to the hermetic local PDS (`VITE_HARNESS_PDS_URL`), so the browser never makes a
 * cross-origin request and no CORS changes land in the PDS (browser-harness.AC3.5).
 */

/** Fetch a path on the proxied PDS (e.g. `/xrpc/com.atproto.server.describeServer`). */
export function pdsFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`/__pds${path}`, init);
}

/**
 * The throwaway admin token (`just harness-pds` prints it), exposed to the harness dev
 * server via `VITE_HARNESS_ADMIN_TOKEN`. Only ever present in a dev build against a local
 * hermetic PDS; used to mint claim codes so the create-account flow is turnkey.
 */
export function adminToken(): string | null {
  return (import.meta.env.VITE_HARNESS_ADMIN_TOKEN as string | undefined) ?? null;
}

/** Mint one claim code via the admin API. Throws if no admin token is configured. */
export async function mintClaimCode(): Promise<string> {
  const token = adminToken();
  if (!token) {
    throw {
      code: 'NETWORK_ERROR',
      message:
        'proxy mode needs VITE_HARNESS_ADMIN_TOKEN (printed by `just harness-pds`) to mint a claim code',
    };
  }
  const res = await pdsFetch('/v1/accounts/claim-codes', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ count: 1 }),
  });
  if (!res.ok) {
    throw { code: 'NETWORK_ERROR', message: `claim-code mint failed (${res.status})` };
  }
  const body = (await res.json()) as { codes?: string[] };
  const code = body.codes?.[0];
  if (!code) throw { code: 'UNKNOWN', message: 'claim-code mint returned no code' };
  return code;
}
