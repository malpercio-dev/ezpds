/**
 * Pure helpers for the in-flight transfer screen (Functional Core — no IPC).
 *
 * The relay reports every planned device swap that can still advance; these helpers
 * map each stored state-machine status to its chip and to the one timeline line a
 * collapsed row shows. Unlike the claim-code inventory there is no history split —
 * the relay's list is *only* in-flight states, and a cancelled/completed transfer
 * simply leaves it.
 */
import type { TransferEntry } from '$lib/ipc';

/**
 * The chip rendering for each relay-reported status — tone + label, never color
 * alone (the StatusChip adds the glyph). `pending` is a live code waiting to be
 * typed in; `accepted`/`completing` mean the target device already holds a working
 * credential — the state the operator most needs to notice, so it gets the alarm
 * tone rather than the neutral one.
 */
export function chipFor(status: TransferEntry['status']): {
  chip: 'pending' | 'ready' | 'info' | 'revoked';
  label: string;
} {
  switch (status) {
    case 'pending':
      return { chip: 'pending', label: 'code out' };
    case 'accepted':
      return { chip: 'revoked', label: 'device holds credential' };
    case 'completing':
      return { chip: 'revoked', label: 'completing' };
    default: {
      // The wire carries status as a plain string, and this app pairs with relays of
      // potentially different versions — an unfamiliar status must render as a visible
      // unknown, never a blank chip. `never` keeps the compile-time exhaustiveness check.
      const unknown: never = status;
      return { chip: 'info', label: `unknown (${String(unknown)})` };
    }
  }
}

/**
 * The one timeline line a collapsed row shows: what the transfer is waiting on.
 * Relay timestamps verbatim — literal truth, no relative-time gloss. An accepted
 * transfer reports the acceptance fact (its expiry no longer stops completion);
 * a pending one reports the code's deadline.
 */
export function timelineLine(entry: TransferEntry): string {
  switch (entry.status) {
    case 'pending':
      return `code expires ${entry.expiresAt}`;
    case 'accepted':
      return `accepted ${entry.acceptedAt ?? 'at an unknown time'}`;
    case 'completing':
      return `accepted ${entry.acceptedAt ?? 'at an unknown time'}`;
    default: {
      // Version-skew guard (see chipFor): an unknown status still gets a factual line.
      const unknown: never = entry.status;
      void unknown;
      return `opened ${entry.createdAt}`;
    }
  }
}

/**
 * The row's leading identity: the account under transfer, preferring its
 * human-readable handle, falling back to the DID (always known).
 */
export function accountLabel(entry: TransferEntry): string {
  return entry.handle ?? entry.did;
}
