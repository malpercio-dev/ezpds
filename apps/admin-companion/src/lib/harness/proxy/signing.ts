/**
 * The admin-companion signing envelopes, in TypeScript — byte-for-byte identical to the
 * Rust `signing.rs` (which itself mirrors the relay's `auth.rs`). Reproduced here so the
 * harness's proxy mode signs real requests the relay's `require_admin` accepts.
 *
 * Registration: `pairingCode\npublicKey\ntimestamp`.
 * Per-request:  `method\npath\ntimestamp\nnonce\nsha256_hex(body)`.
 * Signatures are base64url-no-pad of the low-S r‖s P-256 signature (see device-key.ts).
 */
import { signWithDeviceKey, base64urlNoPad } from './device-key';

export const ADMIN_DEVICE_HEADER = 'X-Admin-Device';
export const ADMIN_TIMESTAMP_HEADER = 'X-Admin-Timestamp';
export const ADMIN_NONCE_HEADER = 'X-Admin-Nonce';
export const ADMIN_SIGNATURE_HEADER = 'X-Admin-Signature';

/** Lowercase hex SHA-256 of `data` — the body-hash field of the request envelope. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', data as unknown as BufferSource)
  );
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** The canonical registration message a device self-signs. */
export function registrationSignString(pairingCode: string, publicKey: string, timestamp: number): string {
  return `${pairingCode}\n${publicKey}\n${timestamp}`;
}

/** The canonical per-request envelope. */
export async function requestSignString(
  method: string,
  path: string,
  timestamp: number,
  nonce: string,
  body: Uint8Array
): Promise<string> {
  const bodyHash = await sha256Hex(body);
  return `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

/** Sign the registration message and return the base64url-no-pad signature. */
export async function signRegistration(
  pairingCode: string,
  publicKey: string,
  timestamp: number
): Promise<string> {
  const message = registrationSignString(pairingCode, publicKey, timestamp);
  const sig = await signWithDeviceKey(new TextEncoder().encode(message));
  return base64urlNoPad(sig);
}

/** The four `X-Admin-*` headers authenticating one signed request. */
export async function signedHeaders(
  deviceId: string,
  method: string,
  path: string,
  body: Uint8Array,
  timestamp: number,
  nonce: string
): Promise<Record<string, string>> {
  const sign = await requestSignString(method, path, timestamp, nonce, body);
  const signature = base64urlNoPad(await signWithDeviceKey(new TextEncoder().encode(sign)));
  return {
    [ADMIN_DEVICE_HEADER]: deviceId,
    [ADMIN_TIMESTAMP_HEADER]: String(timestamp),
    [ADMIN_NONCE_HEADER]: nonce,
    [ADMIN_SIGNATURE_HEADER]: signature,
  };
}
