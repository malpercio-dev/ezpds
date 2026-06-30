/**
 * Map a {@link RelayClientError} to an honest, specific operator-facing message.
 *
 * The relay deliberately returns generic messages (it never reveals which check
 * failed), so the *client* is where a failure becomes a specific, actionable state —
 * "check device time", "access revoked", "relay unreachable" — per the design plan's
 * error-handling note. Keeps copy in one place so Phase 8's screens reuse it.
 */
import type { RelayClientError } from './ipc';
import type { Status } from './components/ui/StatusChip.svelte';

/** How the operator recovers from a given failure. */
export type Recovery = 'pair' | 'retry' | 'none';

/**
 * A failure rendered as a recovery state: the status chip to show, a short chip label, the
 * full message, and which recovery affordance the screen should offer. This is the
 * error matrix in one place — `describeRelayError` supplies the prose, this adds the chip
 * + CTA so every screen renders failures the same way.
 */
export interface ErrorView {
  status: Status;
  chipLabel: string;
  message: string;
  recovery: Recovery;
}

export function classifyRelayError(error: unknown): ErrorView {
  const e = error as RelayClientError | undefined;
  const message = describeRelayError(error);
  switch (e?.code) {
    case 'NOT_PAIRED':
      // Not paired — route the operator to pairing.
      return { status: 'pending', chipLabel: 'not paired', message, recovery: 'pair' };
    case 'UNREACHABLE':
      // A transient/network failure — retry, with the relay URL visible (the screen
      // renders it). Calm-slate "info", not an alarm: nothing is wrong with the credential.
      return { status: 'info', chipLabel: 'unreachable', message, recovery: 'retry' };
    case 'INVALID_RELAY_URL':
      return { status: 'error', chipLabel: 'bad relay url', message, recovery: 'none' };
    case 'RELAY_REJECTED':
      // A revoked device (the relay's one non-generic status) — access is gone; re-pair to
      // restore it.
      if (e.status === 403) {
        return { status: 'revoked', chipLabel: 'access revoked', message, recovery: 'pair' };
      }
      // A 401 is most often a clock outside the relay's ±60s window — surface the
      // "check device time" hint (in `message`) and let the operator retry after fixing it.
      if (e.status === 401) {
        return { status: 'error', chipLabel: 'check device time', message, recovery: 'retry' };
      }
      return { status: 'error', chipLabel: 'rejected', message, recovery: 'retry' };
    case 'DEVICE_KEY':
    case 'KEYCHAIN':
    case 'BAD_RESPONSE':
    default:
      return { status: 'error', chipLabel: 'failed', message, recovery: 'retry' };
  }
}

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
