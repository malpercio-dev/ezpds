/**
 * Map a {@link RelayClientError} to an honest, specific operator-facing message.
 *
 * The relay deliberately returns generic messages (it never reveals which check
 * failed), so the *client* is where a failure becomes a specific, actionable state —
 * "check device time", "access revoked", "relay unreachable" — per the design plan's
 * error-handling note. Keeps copy in one place so Phase 8's screens reuse it.
 */
import type { RelayClientError } from './ipc';

export function describeRelayError(error: unknown): string {
  const e = error as RelayClientError | undefined;
  switch (e?.code) {
    case 'NOT_PAIRED':
      return 'This device is not paired yet. Pair it first.';
    case 'INVALID_RELAY_URL':
      return "That relay URL isn't a valid address.";
    case 'UNREACHABLE':
      return "Couldn't reach the relay. Check the URL and your connection.";
    case 'RELAY_REJECTED':
      // 403 is the one non-generic relay status: this device was revoked server-side.
      if (e.status === 403) {
        return 'This device has been revoked. Pair again to restore access.';
      }
      // 401 covers an expired/used pairing code, a bad signature, or — for a signed
      // request — a clock outside the relay's ±60s window. Surface the time hint too.
      if (e.status === 401) {
        return 'The relay rejected the request. The pairing code may be expired or used, or this device’s clock may be off — check the device time.';
      }
      return `The relay rejected the request (HTTP ${e.status}).`;
    case 'DEVICE_KEY':
      return "Couldn't use this device's admin key.";
    case 'KEYCHAIN':
      return 'A secure-storage error occurred on this device.';
    case 'BAD_RESPONSE':
      return 'The relay returned an unexpected response.';
    default:
      return 'Something went wrong. Please try again.';
  }
}
