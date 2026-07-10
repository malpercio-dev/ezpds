/**
 * Pure helpers for the claim-code inventory screen (Functional Core — no IPC).
 *
 * The relay reports every minted code with a derived status; the screen splits them
 * into the actionable set (outstanding live credentials) and the historical record.
 */
import type { ClaimCodeEntry } from '$lib/ipc';

export interface PartitionedCodes {
  /** Live credentials — `pending` codes the operator can still share or revoke. */
  outstanding: ClaimCodeEntry[];
  /** The historical record — redeemed, expired, and revoked codes. */
  history: ClaimCodeEntry[];
}

/**
 * Split an inventory page (or accumulated pages) into outstanding vs history,
 * preserving the relay's newest-first order within each group. Only `pending` is
 * outstanding: every other status is terminal or dead and belongs to history.
 */
export function partitionCodes(codes: ClaimCodeEntry[]): PartitionedCodes {
  const outstanding: ClaimCodeEntry[] = [];
  const history: ClaimCodeEntry[] = [];
  for (const entry of codes) {
    (entry.status === 'pending' ? outstanding : history).push(entry);
  }
  return { outstanding, history };
}

/**
 * The chip rendering for each relay-reported status — tone + label, never color
 * alone (the StatusChip adds the glyph). `redeemed` is the success story (the code
 * did its job); `revoked` is the operator's kill; `expired` is neutral clock death.
 */
export function chipFor(status: ClaimCodeEntry['status']): {
  chip: 'pending' | 'ready' | 'info' | 'revoked';
  label: string;
} {
  switch (status) {
    case 'pending':
      return { chip: 'pending', label: 'pending' };
    case 'redeemed':
      return { chip: 'ready', label: 'redeemed' };
    case 'expired':
      return { chip: 'info', label: 'expired' };
    case 'revoked':
      return { chip: 'revoked', label: 'revoked' };
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
 * The one timeline line a collapsed row shows: the fact that ended the code's life,
 * or its expiry deadline while it is still pending. Relay timestamps verbatim —
 * literal truth, no relative-time gloss.
 */
export function timelineLine(entry: ClaimCodeEntry): string {
  switch (entry.status) {
    case 'redeemed':
      return `redeemed ${entry.redeemedAt ?? 'at an unknown time'}`;
    case 'revoked':
      return `revoked ${entry.revokedAt ?? 'at an unknown time'}`;
    case 'expired':
      return `expired ${entry.expiresAt}`;
    case 'pending':
      return `expires ${entry.expiresAt}`;
    default: {
      // Version-skew guard (see chipFor): an unknown status still gets a factual line.
      const unknown: never = entry.status;
      void unknown;
      return `minted ${entry.createdAt}`;
    }
  }
}
