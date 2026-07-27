import type { Urgency } from './deadline';
import { deriveIdentityPanelState, formatCheckedAgo, isVerified } from './identity-status';
import { isDidWeb } from './did-doc-utils';
import type { MonitorHistory, SweepRecord, UnauthorizedChange } from './ipc';

/**
 * The app-level Defend surface's derivations — what every identity's protection adds up
 * to, and how the monitor's own log reads.
 *
 * This is pure and shared on purpose. The home strip and the Protection surface are the
 * same statement at two sizes, exactly as `UrgencyBadge` and `StatusPanel` are for one
 * identity; deriving each separately is how they drift into contradicting each other,
 * which on a security surface is worse than either being wrong alone.
 */

/** What the surface knows about one identity before its state is derived. */
export type ProtectionInput = {
  did: string;
  handle: string | null;
  /** Unauthorized changes standing against this identity. */
  changes: UnauthorizedChange[];
  /** The Secure Enclave no longer holds this identity's device key. */
  deviceKeyUnusable: boolean;
  /** Whether the monitor's last sweep reached plc.directory for this identity. */
  plcCheckSucceeded: boolean;
  /** ISO 8601 of the last successful verification, from the monitor's own log. */
  lastVerifiedAt: string | null;
};

/** One row of the Protection surface: an identity and its derived state. */
export type ProtectionRow = ProtectionInput & {
  urgency: Urgency;
  /** Whether the state rests on a reading the wallet could actually take. */
  verified: boolean;
  isWeb: boolean;
  alertCount: number;
  deadline: Date | null;
};

export function toRow(input: ProtectionInput, now: number = Date.now()): ProtectionRow {
  const panel = deriveIdentityPanelState(input.changes, input.deviceKeyUnusable, now);
  return {
    ...input,
    urgency: panel.urgency,
    deadline: panel.deadline,
    alertCount: panel.alertCount,
    verified: isVerified(input.did, input.plcCheckSucceeded),
    isWeb: isDidWeb(input.did),
  };
}

/**
 * How urgently each state wants to be at the top of the list. Higher sorts first.
 *
 * Two orderings already coexist in the wallet, for good reasons, and this surface picks
 * one deliberately:
 *
 *  - The identity panel (`identity-status.ts`) ranks by **what is true**, so an active
 *    unauthorized change outranks a dead device key however the remedies sequence.
 *  - The home card strips (`IdentityListHome.activeStrip`) rank by **what to do next**, so
 *    a dead device key outranks an alarm — the override the alarm leads to is signed with
 *    the very key that is missing, so offering that first sends the user into a flow that
 *    cannot complete.
 *
 * Protection follows the panel: it is the app's report of what is happening to the
 * identities, and "someone is rewriting this identity right now" is the graver fact
 * whichever remedy runs first. The sequencing is not lost — it moves into copy, where the
 * summary of an alarm that is also missing a key says to recover first (see `summarize`).
 * Ordering states the severity; the sentence states the order of operations.
 */
const URGENCY_RANK: Record<Urgency, number> = {
  critical: 3,
  expired: 2,
  warning: 1,
  safe: 0,
};

/**
 * Order for the Protection list: most urgent first, then the soonest deadline (the window
 * closing first is the one that needs the user first), then by handle so the list is
 * stable across renders rather than reshuffling on every sweep.
 */
export function compareRows(a: ProtectionRow, b: ProtectionRow): number {
  const byUrgency = URGENCY_RANK[b.urgency] - URGENCY_RANK[a.urgency];
  if (byUrgency !== 0) return byUrgency;

  if (a.deadline && b.deadline) {
    const byDeadline = a.deadline.getTime() - b.deadline.getTime();
    if (byDeadline !== 0) return byDeadline;
  } else if (a.deadline || b.deadline) {
    return a.deadline ? -1 : 1;
  }

  return (a.handle ?? a.did).localeCompare(b.handle ?? b.did);
}

export function orderRows(rows: ProtectionRow[]): ProtectionRow[] {
  return [...rows].sort(compareRows);
}

/** The one statement the home strip and the Protection panel both render. */
export type ProtectionSummary = {
  urgency: Urgency;
  /**
   * False only in the `safe` state, where the directory could not be reached: there is no
   * fresh evidence, so the surface drops the green rather than assert an all-clear it did
   * not verify. Mirrors `StatusPanel`'s rule for a single identity.
   */
  verified: boolean;
  headline: string;
  detail: string;
};

/**
 * Fold every identity's state into the app-level statement.
 *
 * The worst state wins, by the same rank the list is ordered by — a surface that averaged
 * would be able to say "secure" over a row that says otherwise, which is the one thing a
 * summary of a security state must never do.
 */
export function summarize(
  rows: ProtectionRow[],
  history: MonitorHistory | null,
  now: number = Date.now()
): ProtectionSummary {
  if (rows.length === 0) {
    return {
      urgency: 'safe',
      verified: false,
      headline: 'Nothing to watch yet',
      detail: 'Add an identity and the wallet starts watching the public record for it.',
    };
  }

  const worst = rows.reduce((a, b) => (URGENCY_RANK[b.urgency] > URGENCY_RANK[a.urgency] ? b : a));
  const alerts = rows.reduce((n, r) => n + r.alertCount, 0);
  const unusable = rows.filter((r) => r.deviceKeyUnusable).length;

  if (worst.urgency === 'critical') {
    return {
      urgency: 'critical',
      verified: true,
      headline: `${count(alerts, 'unauthorized change', 'unauthorized changes')} ${alerts === 1 ? 'needs' : 'need'} your attention`,
      // The alarm leads because it is the graver fact, but the order of operations still
      // has to be stated: a recovery override is signed with this device's key, so an
      // identity whose key is gone must be recovered before its override can be built.
      // Dropping this line would leave the user to discover that inside a dead-end flow.
      detail:
        unusable > 0
          ? `${count(unusable, 'identity', 'identities')} also can't be signed for — recover ${unusable === 1 ? 'it' : 'them'} first, so the override can be signed`
          : 'Review the flagged identities — the window to reverse a change is limited',
    };
  }

  if (worst.urgency === 'expired') {
    return {
      urgency: 'expired',
      verified: true,
      headline: 'A recovery window has closed',
      detail: 'The moment to reverse the change has passed. Review what happened',
    };
  }

  if (worst.urgency === 'warning') {
    return {
      urgency: 'warning',
      verified: true,
      headline: `This device can't sign for ${count(unusable, 'identity', 'identities')}`,
      detail: `${unusable === 1 ? 'Its key is' : 'Their keys are'} gone from this device; the ${unusable === 1 ? 'identity itself is' : 'identities themselves are'} unaffected`,
    };
  }

  // Every identity is a did:web: there is no public record to watch, and claiming to watch
  // one would be the inverse of the honesty the unverified state exists to provide.
  if (rows.every((r) => r.isWeb)) {
    return {
      urgency: 'safe',
      verified: true,
      headline: 'Held on your own domains',
      detail: "did:web identities aren't watched on the public record — control of the domain is the safeguard",
    };
  }

  const checked = lastSweepAt(history);
  if (rows.some((r) => !r.verified)) {
    return {
      urgency: 'safe',
      verified: false,
      headline: 'Not fully checked',
      detail: checked
        ? `Couldn't reach the public record for every identity. Last full check ${formatCheckedAgo(checked, now)}`
        : "Couldn't reach the public record to check just now",
    };
  }

  return {
    urgency: 'safe',
    verified: true,
    headline: 'All identities secure',
    detail: checked
      ? `Public record checked ${formatCheckedAgo(checked, now)}`
      : 'Watching the public record',
  };
}

/** When the monitor last completed a pass, in epoch ms; null if it never has. */
export function lastSweepAt(history: MonitorHistory | null): number | null {
  const at = history?.sweeps[0]?.at;
  if (!at) return null;
  const ms = Date.parse(at);
  return Number.isNaN(ms) ? null : ms;
}

/** "checked 4 min ago" for one identity's row, from the monitor's own log. */
export function formatLastVerified(iso: string | null, now: number = Date.now()): string {
  if (iso === null) return 'Never checked';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return 'Never checked';
  return `Checked ${formatCheckedAgo(ms, now)}`;
}

/**
 * One line of the sweep log: what the pass did, in the register of a receipt rather than
 * a status. It reports the pass, never the identity — an identity's state is its own row,
 * and a log entry that editorialised would let a five-hour-old record contradict it.
 */
export function describeSweep(sweep: SweepRecord): string {
  const scope =
    sweep.identitiesChecked === 0
      ? 'No identities to check'
      : `Checked ${count(sweep.identitiesChecked, 'identity', 'identities')}`;

  const parts = [scope];
  if (sweep.identitiesFailed > 0) {
    parts.push(
      `${sweep.identitiesFailed} unreachable`
    );
  }
  if (sweep.unauthorizedFound > 0) {
    parts.push(`${count(sweep.unauthorizedFound, 'change', 'changes')} flagged`);
  } else if (sweep.identitiesChecked > sweep.identitiesFailed) {
    parts.push('nothing out of place');
  }
  return parts.join(' · ');
}

/**
 * A sweep's clock time for the log, in the device's own locale and zone — the log is read
 * against "when was I using my phone", never against UTC. An unparseable stamp renders
 * nothing rather than "Invalid Date".
 */
export function formatClockTime(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return '';
  return new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

/** How the unattended cadence reads, from the interval the backend actually keeps. */
export function describeInterval(intervalSecs: number): string {
  if (intervalSecs <= 0) return 'The wallet checks in the background';
  const minutes = Math.round(intervalSecs / 60);
  if (minutes < 60) return `The wallet checks every ${minutes} minutes while it's running`;
  const hours = Math.round(minutes / 60);
  return `The wallet checks every ${hours === 1 ? 'hour' : `${hours} hours`} while it's running`;
}

function count(n: number, singular: string, plural: string): string {
  return `${n} ${n === 1 ? singular : plural}`;
}
