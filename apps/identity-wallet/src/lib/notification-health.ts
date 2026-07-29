// Turning the Notification Service Extension's breadcrumbs into a sentence.
//
// iOS cannot let an extension suppress an alert push, so a payload this device cannot verify
// still produces a banner — the honest "Couldn't verify a notification from your Custos
// instance". That notice is correct and completely uninformative: a key desync and a relay
// sending junk read identically on the lock screen, and they call for opposite responses.
//
// This is where the difference gets stated. Pure over its inputs, so every branch of the
// wording is testable without a push, an extension, or a device.

import type { NotificationFailure } from '$lib/ipc';

/**
 * How far back a failure still says something about the present.
 *
 * A week: long enough that a problem which fires once a day is visibly a pattern rather than a
 * one-off, short enough that a fixed problem stops being reported without the user having to
 * acknowledge it. (They still can — see `clearNotificationFailures` — but the surface must not
 * depend on their doing so.)
 */
export const FAILURE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * How loudly to say it.
 *
 * Two levels, not four. The wallet's urgency ladder (safe/warning/critical/expired) belongs to
 * identity state, where the stakes are a key and a recovery window; nothing here can cost the
 * user an identity. Borrowing that vocabulary would inflate a missed banner into something it
 * shares a visual language with.
 *
 * `attention` never means "you are in danger" — it means "this will keep happening until
 * something changes".
 */
export type NotificationHealthLevel = 'quiet' | 'info' | 'attention';

export type NotificationHealth = {
  level: NotificationHealthLevel;
  /** Failures inside the window. */
  count: number;
  /** The most recent failure's timestamp, or null when there is none. */
  latest: string | null;
  /** One line naming what happened. Never a colour, never an icon alone. */
  headline: string;
  /** What it means, in the user's terms. */
  detail: string;
  /** What to do, or null when there is genuinely nothing to do. */
  advice: string | null;
};

const QUIET: NotificationHealth = {
  level: 'quiet',
  count: 0,
  latest: null,
  headline: 'No notification problems',
  detail: 'Every recent notification from your server arrived and could be verified.',
  advice: null,
};

/**
 * The per-reason wording.
 *
 * Each entry answers the same two questions — what happened, and is it on the user to act —
 * because those are what the lock-screen notice cannot say. Note that `KEYS_UNAVAILABLE` is
 * deliberately `info` and carries no advice: it is the push that arrived before the first
 * unlock after a restart, it is already fixed by the time anyone reads this, and telling
 * someone to act on it would spend their attention on nothing.
 */
const REASONS: Record<string, { level: NotificationHealthLevel; detail: string; advice: string | null }> = {
  UNKNOWN_KID: {
    level: 'attention',
    detail:
      'Your server signed these with a key this device has not seen. That usually means its notification keys changed after the last time this device checked in.',
    advice: 'Open one of your identities. Obsign refreshes the keys on every contact with your server.',
  },
  OPEN_FAILED: {
    level: 'attention',
    detail:
      'These arrived signed by a key this device knows, but did not unlock with it — so they were not really from your server, or the copy of its key here is out of date.',
    advice: 'Open one of your identities to refresh the keys. If it keeps happening, your relay may be sending notifications your server did not.',
  },
  MALFORMED_PAYLOAD: {
    level: 'attention',
    detail:
      'These were not notifications your server sent. Whatever delivers your notifications can always send something — it just cannot make it look genuine, which is why they showed as unverified.',
    advice: 'Nothing is at risk. If it keeps happening, consider pointing your server at a different notification relay.',
  },
  MALFORMED_PLAINTEXT: {
    level: 'attention',
    detail:
      'These genuinely came from your server, but this version of Obsign could not read what was inside them.',
    advice: 'Updating Obsign should fix this.',
  },
  KEYS_UNAVAILABLE: {
    level: 'info',
    detail:
      'These arrived before this iPhone had been unlocked since it last restarted, so the keys needed to read them were not available yet.',
    advice: null,
  },
};

function headlineFor(count: number): string {
  return count === 1
    ? '1 notification could not be verified'
    : `${count} notifications could not be verified`;
}

/**
 * Fold the extension's log into what Settings shows.
 *
 * The **worst** level in the window wins, and the wording comes from the reason that occurs
 * most among the failures at that level — so a week containing one genuinely benign
 * post-restart failure alongside four key-desync ones reports the desync, and a week of only
 * post-restart failures does not manufacture an alarm.
 *
 * An unrecognized reason (a newer extension than this app) counts toward the total and is
 * described generically rather than dropped: the entry the user is asking about is exactly the
 * one a stricter reader would have discarded.
 */
export function summarizeNotificationFailures(
  failures: NotificationFailure[],
  now: number = Date.now()
): NotificationHealth {
  const recent = failures.filter((failure) => {
    const at = Date.parse(failure.at);
    // An unparseable timestamp is kept, not dropped. It is still a failure that happened, and
    // silently discarding it would make a clock problem look like a clean bill of health.
    return Number.isNaN(at) || now - at <= FAILURE_WINDOW_MS;
  });
  if (recent.length === 0) return QUIET;

  const level: NotificationHealthLevel = recent.some(
    (failure) => (REASONS[failure.reason]?.level ?? 'attention') === 'attention'
  )
    ? 'attention'
    : 'info';

  const atLevel = recent.filter(
    (failure) => (REASONS[failure.reason]?.level ?? 'attention') === level
  );
  const counts = new Map<string, number>();
  for (const failure of atLevel) {
    counts.set(failure.reason, (counts.get(failure.reason) ?? 0) + 1);
  }
  const dominant = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
  const wording = REASONS[dominant] ?? {
    level: 'attention' as const,
    detail:
      'These could not be verified, for a reason this version of Obsign does not recognise.',
    advice: 'Updating Obsign may explain them.',
  };

  return {
    level,
    count: recent.length,
    latest: recent[0]?.at ?? null,
    headline: headlineFor(recent.length),
    detail: wording.detail,
    advice: wording.advice,
  };
}
