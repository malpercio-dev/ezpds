import { getDeadline, getUrgency, type Urgency } from './deadline';
import { isDidWeb } from './did-doc-utils';
import type { UnauthorizedChange } from './ipc';

/**
 * The identity screen's status panel state — the large-format sibling of `UrgencyBadge`,
 * sharing its four-state vocabulary so one identity reads the same at both sizes.
 *
 * The panel's `safe` and the badge's `safe` mean different things on purpose. The badge
 * only ever renders *inside* an alarm, where `safe` means "more than 24h of recovery
 * window left" — never "all clear". The panel is the identity's whole answer to "am I
 * okay?", so its `safe` is the all-clear and an active unauthorized change can never
 * produce it, however much window remains. That is why this derivation exists instead
 * of calling `getUrgency()` on an alert deadline directly.
 */
export type IdentityPanelState = {
  urgency: Urgency;
  /**
   * The recovery deadline the panel counts down to: the soonest still-open window while
   * the alarm is live, the last one to close once they all have. `null` outside the alarm
   * states, and also when an alarm's timestamps were unreadable (see below).
   */
  deadline: Date | null;
  /** Unauthorized changes behind the alarm; 0 in every non-alarm state. */
  alertCount: number;
};

/**
 * Fold what the wallet knows about one identity into a single panel state.
 *
 * Precedence — an unauthorized change outranks a dead device key, the inverse of the home
 * list's card strips. The strips order by *what the user should do next*, where recovery
 * has to come first because the override needs the key that is missing. The panel reports
 * *what is true*, and "someone is rewriting your identity right now" is the more severe
 * fact regardless of which remedy runs first. The warning state's copy is what routes the
 * user to recovery; it does not need to outrank the alarm to do that.
 */
export function deriveIdentityPanelState(
  changes: UnauthorizedChange[],
  deviceKeyUnusable: boolean,
  now: number = Date.now()
): IdentityPanelState {
  if (changes.length > 0) {
    const deadlines: Date[] = [];
    for (const change of changes) {
      try {
        deadlines.push(getDeadline(change.createdAt));
      } catch {
        // An unreadable timestamp costs us the countdown, never the alarm: the change is
        // still an unauthorized rewrite of this identity. Falling through to `safe` here
        // would hide an attack behind a parsing bug, so the alarm is raised without one.
      }
    }

    const open = deadlines.filter((d) => getUrgency(d, now) !== 'expired');
    if (open.length > 0) {
      return {
        urgency: 'critical',
        deadline: open.reduce((a, b) => (a.getTime() <= b.getTime() ? a : b)),
        alertCount: changes.length,
      };
    }

    // Every window has closed. Ashen, not alarm — the distinction the design brief draws
    // between "act now" and "the moment to act has passed".
    return {
      urgency: 'expired',
      deadline:
        deadlines.length > 0
          ? deadlines.reduce((a, b) => (a.getTime() >= b.getTime() ? a : b))
          : null,
      alertCount: changes.length,
    };
  }

  if (deviceKeyUnusable) {
    return { urgency: 'warning', deadline: null, alertCount: 0 };
  }

  return { urgency: 'safe', deadline: null, alertCount: 0 };
}

/**
 * Whether a panel state for `did` rests on a reading the wallet could actually take.
 *
 * `plcCheckSucceeded` is `!IdentityStatus.checkFailed` — the monitor's report of whether
 * plc.directory answered. It is the right input for a did:plc and a meaningless one for a
 * did:web, which has no PLC audit log at all.
 *
 * `PlcMonitor::check_all` omits a did:web from the sweep entirely (it has nothing to
 * report, so it reports nothing), which means the caller's `plcCheckSucceeded` for one is
 * never a reading — it is whatever the screen initialized before the first check, and
 * `IdentityScreen` initializes `false` on purpose so a did:plc cannot open green unearned.
 * Read literally, that would tell a did:web user their public record could not be reached
 * when they have no public record: the exact opposite of the honesty the unverified state
 * exists to provide. This short-circuit is what stops it, so it is load-bearing rather
 * than belt-and-braces even now that the backend no longer claims a failed check.
 *
 * So a did:web is verified by construction. Its protection is control of its domain, which
 * no directory sweep observes in either direction.
 */
export function isVerified(did: string, plcCheckSucceeded: boolean): boolean {
  return isDidWeb(did) || plcCheckSucceeded;
}

/**
 * The one label vocabulary the badge and the panel share, so an identity reads the same
 * whichever size it is rendered at.
 *
 * `verified` is a qualifier on the *evidence*, not a fifth state: when the directory could
 * not be reached (`IdentityStatus.checkFailed`), the wallet has no fresh reading, and a
 * panel saying "Secure" would be asserting something it did not check. The identity is not
 * in danger — only our knowledge of it is stale — so it stays in the `safe` state and says
 * so plainly instead.
 */
export function panelLabel(urgency: Urgency, verified: boolean = true): string {
  switch (urgency) {
    case 'safe':
      return verified ? 'Secure' : 'Not checked';
    case 'warning':
      return 'Action needed';
    case 'critical':
      return 'Under attack';
    case 'expired':
      return 'Recovery window closed';
  }
}

/**
 * "Directory checked N ago" for the secure panel.
 *
 * The wallet has no stored sweep timestamp to read (exposing the background monitor's
 * history is its own piece of work), so the only honest source is the check this screen
 * ran itself. Sub-minute reads as "just now" rather than "0 minutes ago", and anything
 * past a day stops counting — a figure that stale is better stated vaguely than precisely.
 */
export function formatCheckedAgo(checkedAt: number, now: number = Date.now()): string {
  const elapsed = now - checkedAt;
  if (elapsed < 60_000) return 'just now';
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return 'over a day ago';
}
