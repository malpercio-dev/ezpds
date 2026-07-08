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
  | { code: 'BAD_RESPONSE'; message: string }
  | { code: 'NO_SUCH_PAIRING' }
  | { code: 'SELF_REVOKE_NOT_ALLOWED' };

/** One stored relay pairing. `id` is the stable local handle (a UUID minted at pair
 * time); `deviceId` is relay-assigned and changes on re-pair. `nickname` is the
 * operator's local display name and never leaves the device. */
export interface Pairing {
  id: string;
  nickname: string;
  relayUrl: string;
  deviceId: string;
  deviceLabel: string;
}

/** Every stored pairing plus the active selection (`null` when nothing is selected —
 * fresh install, or the active entry was removed with two or more remaining). */
export interface PairingsState {
  active: string | null;
  pairings: Pairing[];
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
export async function pairDevice(
  relayUrl: string,
  pairingCode: string,
  label: string,
  nickname: string,
): Promise<string> {
  return invoke<string>('pair_device', { relayUrl, pairingCode, label, nickname });
}

/** All stored pairings and the active selection. */
export async function listPairings(): Promise<PairingsState> {
  return invoke<PairingsState>('list_pairings');
}

/** Set the active pairing by id. */
export async function setActivePairing(id: string): Promise<void> {
  return invoke('set_active_pairing', { id });
}

/** Rename a pairing locally by id. */
export async function renamePairing(id: string, nickname: string): Promise<void> {
  return invoke('rename_pairing', { id, nickname });
}

/** Mint a single account claim code via a signed request to the paired relay. */
export function generateClaimCode(): Promise<string> {
  return invoke<string>('generate_claim_code');
}

/**
 * Revoke this device on the relay (a signed self-revoke), then forget the pairing
 * locally. Throws a {@link RelayClientError} if the relay can't be reached or rejects the
 * request — in which case the pairing is left intact so the caller can retry or fall back
 * to {@link unpair}.
 */
export async function revokeSelf(id: string): Promise<void> {
  return invoke('revoke_self', { id });
}

/**
 * Forget a pairing locally **without** contacting the relay — the fallback when
 * {@link revokeSelf} can't reach the relay. The credential stays valid server-side.
 */
export async function unpair(id: string): Promise<void> {
  return invoke('unpair', { id });
}

/**
 * One registered companion device on a relay, as the relay reports it. `id` is the
 * relay-assigned registration id — the row where it equals a pairing's `deviceId` is
 * the device in your hand. Timestamps are the relay's SQLite UTC datetime strings.
 */
export interface AdminDevice {
  id: string;
  label: string;
  /** The device's P-256 public key as a did:key URI. */
  publicKey: string;
  platform: string;
  scopes: string;
  /** Derived server-side: 'active' while revokedAt is null, 'revoked' once stamped. */
  status: 'active' | 'revoked';
  createdAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
}

/**
 * List every device registered on the given pairing's relay — active and revoked,
 * newest first — via a signed request. Throws a {@link RelayClientError}.
 */
export function listAdminDevices(pairingId: string): Promise<AdminDevice[]> {
  return invoke<AdminDevice[]>('list_admin_devices', { pairingId });
}

/**
 * Revoke another device's registration on the given pairing's relay — the loss
 * response. Refused for the pairing's own registration (`SELF_REVOKE_NOT_ALLOWED`);
 * self-revoke is {@link revokeSelf}, which also forgets the pairing locally. Returns
 * the device's post-revoke state.
 */
export function revokeAdminDevice(pairingId: string, deviceId: string): Promise<AdminDevice> {
  return invoke<AdminDevice>('revoke_admin_device', { pairingId, deviceId });
}

/** Whether the biometric (user-presence) gate on signing actions is enabled (default on). */
export function biometricEnabled(): Promise<boolean> {
  return invoke<boolean>('biometric_enabled');
}

/** Persist the biometric-gate preference (the Settings toggle). */
export function setBiometricEnabled(enabled: boolean): Promise<void> {
  return invoke('set_biometric_enabled', { enabled });
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
    if (parsed === null || typeof parsed !== 'object') return null;
    const record = parsed as Record<string, unknown>;
    const { relayUrl, pairingCode } = record;
    // The contract is exactly two fields — an object carrying extras (e.g. a stray
    // "debug" key) is not a valid pairing payload and must be rejected. Requiring both
    // fields to be present strings under a 2-key cap means the two keys can only be
    // relayUrl and pairingCode.
    if (
      Object.keys(record).length === 2 &&
      typeof relayUrl === 'string' &&
      typeof pairingCode === 'string'
    ) {
      const url = relayUrl.trim();
      const code = pairingCode.trim();
      if (url && code) {
        return { relayUrl: url, pairingCode: code };
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

/**
 * Stop an in-progress {@link scanQrCode}. The pending `scan()` settles, so its
 * caller's `finally` runs and scan mode tears down. Mobile-only and best-effort:
 * off-device the plugin isn't present, so callers should ignore a rejection.
 */
export async function cancelQrScan(): Promise<void> {
  const { cancel } = await import('@tauri-apps/plugin-barcode-scanner');
  await cancel();
}
