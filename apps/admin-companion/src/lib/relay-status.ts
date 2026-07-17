// Pure presentation policy for the Home relay-status block (Functional Core).
//
// `GET /v1/admin/relay-status` reports literal facts only — no ok/warn/behind verdict. This
// module is where the operator's thresholds live: the gap bands and the relay-status mapping the
// issue (MM-281) specifies. Keeping the policy here — not in the Rust handler and not scattered
// through Svelte markup — means an operator can tune it without a redeploy, and the genuinely
// non-obvious bit (folding the two severity axes together) is unit-testable in one place.

import type { RelayStatus } from '$lib/ipc';
import { formatDuration } from '$lib/health';

/** The chip statuses this block uses (a subset of StatusChip's `Status` union). */
export type RelayChipStatus = 'ready' | 'pending' | 'error' | 'info';

/** Ordered worst-last so severities compare by index. */
type Severity = 'ok' | 'warn' | 'error';
const SEVERITY_RANK: Record<Severity, number> = { ok: 0, warn: 1, error: 2 };

/** Gap thresholds (events the relay is behind us). MM-281: `< 500` ok, `< 5000` warn, else error. */
export const GAP_OK_BELOW = 500;
export const GAP_WARN_BELOW = 5_000;

/** Each severity's chip status (color + glyph + text; never color alone — see StatusChip). */
const CHIP_FOR: Record<Severity, RelayChipStatus> = {
  ok: 'ready', // ● safe/green
  warn: 'pending', // ◌ warning/amber
  error: 'error', // ! critical/red
};

/** One label/value row in the block's fact sheet. */
export interface RelayFact {
  label: string;
  value: string;
}

/** The rendered view of a relay-status readout: an overall chip, a headline, and detail facts. */
export interface RelayStatusView {
  chip: { status: RelayChipStatus; label: string };
  /** A one-line human summary of the verdict. */
  headline: string;
  /** Literal detail rows, in display order. */
  facts: RelayFact[];
}

/** Severity of the gap (how far the relay's cursor trails our head). A relay *ahead* of our
 *  in-memory frontier (negative gap, possible right after a restart) is caught up, not behind. */
function gapSeverity(behind: number): Severity {
  if (behind < GAP_OK_BELOW) return 'ok';
  if (behind < GAP_WARN_BELOW) return 'warn';
  return 'error';
}

/** Severity of the relay's lifecycle status. MM-281: `active`/`idle` ok, `throttled` warn,
 *  `offline`/`banned` error. An unknown value from a newer relay is surfaced cautiously as warn. */
function relayStatusSeverity(status: string): Severity {
  switch (status) {
    case 'active':
    case 'idle':
      return 'ok';
    case 'throttled':
      return 'warn';
    case 'offline':
    case 'banned':
      return 'error';
    default:
      return 'warn';
  }
}

function worst(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/** Group a non-negative integer with thousands separators (`8204` → `8,204`). Deterministic
 *  (no locale dependency), so the output is stable across devices and in tests. */
export function groupDigits(n: number): string {
  return Math.trunc(n)
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** "N ago" for the relay's cursor timestamp (RFC 3339). Falls back to the raw string if it can't
 *  be parsed — better to show the literal value than to hide a fact behind a formatter. */
export function formatRelayCursor(iso: string, nowSeconds: number): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  const age = Math.max(0, nowSeconds - Math.floor(ms / 1000));
  return `${formatDuration(age)} ago`;
}

/**
 * Fold a raw {@link RelayStatus} readout into a renderable {@link RelayStatusView}.
 *
 * `nowSeconds` is the current unix time, passed in so the function stays pure. The overall chip
 * takes the **worst** of the two severity axes (relay lifecycle status and gap), so the more
 * alarming signal is never hidden behind a calmer one; the chip label names whichever axis
 * dominates.
 */
export function relayStatusView(status: RelayStatus, nowSeconds: number): RelayStatusView {
  // No relay configured — federation notifications are disabled; there is nothing to poll.
  if (status.relayHost === null) {
    return {
      chip: { status: 'info', label: 'no relay' },
      headline: 'Federation is disabled — no relay is configured for this server.',
      facts: [{ label: 'pds head', value: groupDigits(status.pdsHeadSeq) }],
    };
  }

  const facts: RelayFact[] = [{ label: 'relay', value: status.relayHost }];

  // Could not reach the relay at all (transport failure/timeout).
  if (!status.reachable) {
    return {
      chip: { status: 'error', label: 'unreachable' },
      headline: status.detail ?? 'Could not reach the relay.',
      facts: [...facts, { label: 'pds head', value: groupDigits(status.pdsHeadSeq) }],
    };
  }

  // Reachable but the relay has no cursor for us — it has never crawled this server.
  if (status.relaySeq === null) {
    if (status.relayStatus !== null) facts.push({ label: 'relay status', value: status.relayStatus });
    facts.push({ label: 'pds head', value: groupDigits(status.pdsHeadSeq) });
    return {
      chip: { status: 'pending', label: 'not seen' },
      headline: status.detail ?? 'The relay has not crawled this server yet.',
      facts,
    };
  }

  // Reachable and crawling — combine the relay-status and gap severities.
  const behind = Math.max(0, status.gap ?? 0);
  const statusSev = status.relayStatus ? relayStatusSeverity(status.relayStatus) : 'ok';
  const gapSev = gapSeverity(behind);
  const overall = worst(statusSev, gapSev);

  // Label the axis that dominates: the relay-status word when it is the (co-)dominant problem,
  // otherwise the gap. When both are fine, distinguish fully-caught-up from a healthy minor lag.
  const statusDominates =
    (statusSev === 'warn' || statusSev === 'error') && SEVERITY_RANK[statusSev] >= SEVERITY_RANK[gapSev];
  let label: string;
  if (statusDominates) {
    label = status.relayStatus as string;
  } else if (gapSev !== 'ok') {
    label = `behind ${groupDigits(behind)}`;
  } else {
    label = behind === 0 ? 'caught up' : 'crawling';
  }

  let headline: string;
  if (statusDominates) {
    headline = `The relay reports this server ${status.relayStatus}.`;
  } else if (behind === 0) {
    headline = 'The relay is caught up with this server.';
  } else {
    headline = `The relay is ${groupDigits(behind)} event${behind === 1 ? '' : 's'} behind.`;
  }

  facts.push({ label: 'relay status', value: status.relayStatus ?? 'unknown' });
  facts.push({
    label: 'behind by',
    value: behind === 0 ? 'caught up' : `${groupDigits(behind)} event${behind === 1 ? '' : 's'}`,
  });
  if (status.relayCursorAt !== null) {
    facts.push({ label: 'last seen', value: formatRelayCursor(status.relayCursorAt, nowSeconds) });
  }
  facts.push({ label: 'relay seq', value: groupDigits(status.relaySeq) });
  facts.push({ label: 'pds head', value: groupDigits(status.pdsHeadSeq) });
  if (status.accountCount !== null) {
    facts.push({ label: 'accounts indexed', value: groupDigits(status.accountCount) });
  }

  return { chip: { status: CHIP_FOR[overall], label }, headline, facts };
}
