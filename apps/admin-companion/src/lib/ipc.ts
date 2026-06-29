/**
 * Typed wrappers for all Tauri IPC commands.
 *
 * This is the ONLY file that calls `invoke()` directly; page components import
 * these functions instead. Mirrors the identity-wallet `ipc.ts` convention.
 *
 * Phase 7 adds the pairing + signed-request surface on top of the Phase 6 device-key
 * primitives.
 */
import { invoke } from '@tauri-apps/api/core';

/** The device's admin public key, as returned by the Rust backend. */
export interface DevicePublicKey {
  /** Multibase base58btc-encoded compressed P-256 point ('z'…). */
  multibase: string;
  /** Full did:key URI ('did:key:z…'). */
  keyId: string;
}

/** Tagged error from device-key operations: `{ code: "SCREAMING_SNAKE_CASE" }`. */
export interface DeviceKeyError {
  code:
    | 'KEY_GENERATION_FAILED'
    | 'KEY_NOT_FOUND'
    | 'SIGNING_FAILED'
    | 'INVALID_SIGNATURE'
    | 'KEYCHAIN_ERROR';
  message?: string;
}

/**
 * Tagged error from the relay client: `{ code, … }`. The distinct codes let the UI
 * render honest, specific states rather than one generic failure.
 */
export type RelayClientError =
  | { code: 'NOT_PAIRED' }
  | { code: 'DEVICE_KEY'; message: string }
  | { code: 'KEYCHAIN'; message: string }
  | { code: 'INVALID_RELAY_URL' }
  | { code: 'UNREACHABLE'; message: string }
  | { code: 'RELAY_REJECTED'; status: number; message: string }
  | { code: 'BAD_RESPONSE'; message: string };

/** The device's current pairing, as persisted after a successful registration. */
export interface Pairing {
  /** Relay-assigned id this device sends as `X-Admin-Device`. */
  deviceId: string;
  /** Base URL of the paired relay. */
  relayUrl: string;
}

/**
 * Get-or-create this device's admin key (Secure Enclave on a real device,
 * software key on the simulator/macOS). Idempotent.
 */
export function getOrCreateDeviceKey(): Promise<DevicePublicKey> {
  return invoke<DevicePublicKey>('get_or_create_device_key');
}

/**
 * Sign arbitrary bytes with the device's admin key. Returns a raw 64-byte
 * (r‖s, low-S) P-256 signature. The canonical request envelope is built in Rust.
 */
export function signWithDeviceKey(data: Uint8Array): Promise<Uint8Array> {
  return invoke<number[]>('sign_with_device_key', { data: Array.from(data) }).then(
    (bytes) => Uint8Array.from(bytes),
  );
}

/**
 * Pair this device with `relayUrl` by claiming `pairingCode`. Persists the
 * relay-assigned device id and returns it. Throws a {@link RelayClientError}.
 */
export function pairDevice(
  relayUrl: string,
  pairingCode: string,
  label: string,
): Promise<string> {
  return invoke<string>('pair_device', { relayUrl, pairingCode, label });
}

/** The current pairing, or `null` if this device has not paired yet. */
export function pairingState(): Promise<Pairing | null> {
  return invoke<Pairing | null>('pairing_state');
}

/** Mint a single account claim code via a signed request to the paired relay. */
export function generateClaimCode(): Promise<string> {
  return invoke<string>('generate_claim_code');
}

/** Forget the current pairing locally (unpair). */
export function unpair(): Promise<void> {
  return invoke('unpair');
}

/**
 * A pairing payload decoded from a scanned QR (or pasted text). The operator's
 * code-minting tool encodes `{ relayUrl, pairingCode }` as JSON in the QR.
 */
export interface PairingPayload {
  relayUrl: string;
  pairingCode: string;
}

/**
 * Parse a scanned/pasted pairing payload. Accepts the canonical JSON
 * `{"relayUrl":"…","pairingCode":"…"}`; returns `null` if the text is not a
 * well-formed payload (the caller then keeps the manual-entry fields).
 */
export function parsePairingPayload(text: string): PairingPayload | null {
  try {
    const parsed: unknown = JSON.parse(text);
    if (
      parsed &&
      typeof parsed === 'object' &&
      typeof (parsed as Record<string, unknown>).relayUrl === 'string' &&
      typeof (parsed as Record<string, unknown>).pairingCode === 'string'
    ) {
      const { relayUrl, pairingCode } = parsed as PairingPayload;
      if (relayUrl.trim() && pairingCode.trim()) {
        return { relayUrl: relayUrl.trim(), pairingCode: pairingCode.trim() };
      }
    }
  } catch {
    // Not JSON — not a structured payload.
  }
  return null;
}

/**
 * Scan a QR code with the device camera (real iOS device only; unavailable on the
 * simulator/desktop, where the manual-entry fields are used instead). Returns the
 * raw decoded string. Dynamically imports the mobile-only plugin so the web/host
 * build never resolves it.
 */
export async function scanQrCode(): Promise<string> {
  const { scan, Format } = await import('@tauri-apps/plugin-barcode-scanner');
  const result = await scan({ windowed: true, formats: [Format.QRCode] });
  return result.content;
}
