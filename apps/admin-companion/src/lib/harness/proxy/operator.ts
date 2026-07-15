/**
 * Proxy-mode operator handlers for the admin harness (browser-harness Phase 6).
 *
 * These are the admin app's genuinely signed-request commands: they run for real against
 * the hermetic local PDS through the `/__pds/*` dev-server proxy, using the real WebCrypto
 * admin key to sign the canonical envelopes the relay's `require_admin` verifies —
 *  - `pair_device`: mints a pairing code (admin API), self-signs the registration, and
 *    registers the device (`POST /v1/admin/devices`), so the pairing is real;
 *  - `generate_claim_code`: a signed `POST /v1/accounts/claim-codes`;
 *  - `list_admin_devices`: a signed `GET /v1/admin/devices`.
 *
 * Everything else falls through to the fake. The signed path signs the BARE relay path
 * (no `/__pds` prefix): the vite proxy strips `/__pds` before the request reaches the
 * relay, which verifies `uri.path()`, so the signed path must match what the relay sees.
 */
import type { Handler } from '../registry';
import type { AdminDevice } from '$lib/ipc';
import { activeRelay, findRelay, seedRelay, type AdminState } from '../state';
import { deviceDidKey } from './device-key';
import { signRegistration, signedHeaders } from './signing';
import { mintPairingCode, pdsFetch, freshNonce, unixNow } from './transport';

async function relayReject(res: Response, fallback: string): Promise<never> {
  let message = fallback;
  try {
    const body = (await res.json()) as { message?: string; error?: string };
    message = body.message ?? body.error ?? fallback;
  } catch {
    // non-JSON body
  }
  throw { code: 'RELAY_REJECTED', status: res.status, message };
}

export async function buildOperatorProxyHandlers(
  state: AdminState
): Promise<Partial<Record<string, Handler>>> {
  return {
    // Real pairing: mint a code, self-sign the registration, register the device.
    pair_device: async (args): Promise<string> => {
      const pairingCode = await mintPairingCode();
      const publicKey = await deviceDidKey();
      const label = String(args.label ?? 'Harness console');
      const nickname = String(args.nickname ?? 'proxy');
      const timestamp = unixNow();
      const signature = await signRegistration(pairingCode, publicKey, timestamp);
      const res = await pdsFetch('/v1/admin/devices', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pairingCode, label, publicKey, platform: 'ios', timestamp, signature }),
      });
      if (!res.ok) return relayReject(res, 'device registration failed');
      const body = (await res.json()) as { deviceId?: string };
      if (!body.deviceId) throw { code: 'BAD_RESPONSE', message: 'no deviceId returned' };

      // Record the real pairing in state so list_pairings/set_active reflect it. Reuse the
      // fake relay shape but pin the relay-assigned device id from the real registration.
      const relay = seedRelay({ nickname, relayUrl: String(args.relayUrl ?? '/__pds') });
      relay.deviceId = body.deviceId;
      relay.deviceLabel = label;
      relay.devices = [];
      state.relays.push(relay);
      state.active = relay.pairingId;
      return body.deviceId;
    },

    // Real signed claim-code mint against the active pairing's relay.
    generate_claim_code: async (): Promise<string> => {
      const relay = activeRelay(state);
      if (!relay) throw { code: 'NOT_PAIRED' };
      const path = '/v1/accounts/claim-codes';
      const body = new TextEncoder().encode(JSON.stringify({ count: 1 }));
      const headers = {
        'content-type': 'application/json',
        ...(await signedHeaders(relay.deviceId, 'POST', path, body, unixNow(), freshNonce())),
      };
      const res = await pdsFetch(path, { method: 'POST', headers, body });
      if (!res.ok) return relayReject(res, 'claim-code mint failed');
      const parsed = (await res.json()) as { codes?: string[] };
      const code = parsed.codes?.[0];
      if (!code) throw { code: 'BAD_RESPONSE', message: 'relay returned no claim codes' };
      return code;
    },

    // Real signed device list for the pinned pairing.
    list_admin_devices: async (args): Promise<AdminDevice[]> => {
      const relay = findRelay(state, String(args.pairingId ?? ''));
      if (!relay) throw { code: 'NO_SUCH_PAIRING' };
      const path = '/v1/admin/devices';
      const empty = new Uint8Array(0);
      const headers = await signedHeaders(relay.deviceId, 'GET', path, empty, unixNow(), freshNonce());
      const res = await pdsFetch(path, { method: 'GET', headers });
      if (!res.ok) return relayReject(res, 'device list failed');
      const parsed = (await res.json()) as { devices?: AdminDevice[] };
      return parsed.devices ?? [];
    },
  };
}
