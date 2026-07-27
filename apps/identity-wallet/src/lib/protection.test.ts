import { describe, it, expect } from 'vitest';
import {
  toRow,
  orderRows,
  summarize,
  lastSweepAt,
  formatLastVerified,
  describeSweep,
  describeInterval,
  formatClockTime,
  type ProtectionInput,
} from './protection';
import type { MonitorHistory, SweepRecord, UnauthorizedChange } from './ipc';

const NOW = Date.parse('2026-07-26T12:00:00Z');

/** An unauthorized change whose 72h recovery window opened `hoursAgo` ago. */
function change(hoursAgo: number): UnauthorizedChange {
  return {
    cid: `bafy${hoursAgo}`,
    createdAt: new Date(NOW - hoursAgo * 3_600_000).toISOString(),
    signingKey: null,
    operation: {},
  };
}

function input(over: Partial<ProtectionInput> & { did: string }): ProtectionInput {
  return {
    handle: null,
    changes: [],
    deviceKeyUnusable: false,
    plcCheckSucceeded: true,
    lastVerifiedAt: null,
    ...over,
  };
}

function history(over: Partial<MonitorHistory> = {}): MonitorHistory {
  return { sweeps: [], identities: [], intervalSecs: 900, ...over };
}

function sweep(over: Partial<SweepRecord> = {}): SweepRecord {
  return {
    at: '2026-07-26T11:55:00Z',
    trigger: 'background',
    identitiesChecked: 3,
    identitiesFailed: 0,
    unauthorizedFound: 0,
    ...over,
  };
}

describe('toRow', () => {
  it('derives the same four states the identity panel uses', () => {
    expect(toRow(input({ did: 'did:plc:a' }), NOW).urgency).toBe('safe');
    expect(toRow(input({ did: 'did:plc:a', deviceKeyUnusable: true }), NOW).urgency).toBe('warning');
    expect(toRow(input({ did: 'did:plc:a', changes: [change(1)] }), NOW).urgency).toBe('critical');
    expect(toRow(input({ did: 'did:plc:a', changes: [change(100)] }), NOW).urgency).toBe('expired');
  });

  it('treats a did:web as verified without a directory reading', () => {
    // A did:web has no PLC audit log, so the sweep fails for it on every pass. Reporting
    // that as "not checked" would state a fact about a record it does not have.
    const row = toRow(input({ did: 'did:web:example.com', plcCheckSucceeded: false }), NOW);
    expect(row.verified).toBe(true);
    expect(row.isWeb).toBe(true);
  });

  it('carries a failed directory read through as unverified for a did:plc', () => {
    expect(toRow(input({ did: 'did:plc:a', plcCheckSucceeded: false }), NOW).verified).toBe(false);
  });
});

describe('orderRows', () => {
  it('leads with the graver fact: an active attack outranks a dead device key', () => {
    const rows = [
      toRow(input({ did: 'did:plc:calm', handle: 'calm.test' }), NOW),
      toRow(input({ did: 'did:plc:nokey', handle: 'nokey.test', deviceKeyUnusable: true }), NOW),
      toRow(input({ did: 'did:plc:attacked', handle: 'attacked.test', changes: [change(1)] }), NOW),
      toRow(input({ did: 'did:plc:closed', handle: 'closed.test', changes: [change(100)] }), NOW),
    ];

    expect(orderRows(rows).map((r) => r.handle)).toEqual([
      'attacked.test',
      'closed.test',
      'nokey.test',
      'calm.test',
    ]);
  });

  it('puts the soonest-closing window first among identities under attack', () => {
    const rows = [
      toRow(input({ did: 'did:plc:later', handle: 'later.test', changes: [change(1)] }), NOW),
      toRow(input({ did: 'did:plc:sooner', handle: 'sooner.test', changes: [change(60)] }), NOW),
    ];

    expect(orderRows(rows).map((r) => r.handle)).toEqual(['sooner.test', 'later.test']);
  });

  it('is stable for equal states, so a sweep never reshuffles the list', () => {
    const rows = [
      toRow(input({ did: 'did:plc:b', handle: 'zeta.test' }), NOW),
      toRow(input({ did: 'did:plc:a', handle: 'alpha.test' }), NOW),
    ];

    expect(orderRows(rows).map((r) => r.handle)).toEqual(['alpha.test', 'zeta.test']);
    // Ordering must not mutate the caller's array.
    expect(rows.map((r) => r.handle)).toEqual(['zeta.test', 'alpha.test']);
  });
});

describe('summarize', () => {
  it('never reports secure over an identity that is not', () => {
    const rows = [
      toRow(input({ did: 'did:plc:a' }), NOW),
      toRow(input({ did: 'did:plc:b', changes: [change(1)] }), NOW),
    ];

    const summary = summarize(rows, history({ sweeps: [sweep()] }), NOW);
    expect(summary.urgency).toBe('critical');
    expect(summary.headline).toBe('1 unauthorized change needs your attention');
  });

  /**
   * The ordering states severity; the copy has to state the order of operations, because a
   * recovery override is signed with the key that is missing.
   */
  it('tells the user to recover first when an alarmed wallet also has a dead key', () => {
    const rows = [
      toRow(input({ did: 'did:plc:a', changes: [change(1)] }), NOW),
      toRow(input({ did: 'did:plc:b', deviceKeyUnusable: true }), NOW),
    ];

    const summary = summarize(rows, history({ sweeps: [sweep()] }), NOW);
    expect(summary.urgency).toBe('critical');
    expect(summary.detail).toContain('recover it first');
  });

  it('reports the dead key alone when nothing is under attack', () => {
    const rows = [toRow(input({ did: 'did:plc:a', deviceKeyUnusable: true }), NOW)];
    const summary = summarize(rows, history({ sweeps: [sweep()] }), NOW);

    expect(summary.urgency).toBe('warning');
    expect(summary.headline).toBe("This device can't sign for 1 identity");
    expect(summary.detail).toContain('unaffected');
  });

  it('states the all-clear with when it was checked', () => {
    const rows = [toRow(input({ did: 'did:plc:a' }), NOW)];
    const summary = summarize(rows, history({ sweeps: [sweep({ at: '2026-07-26T11:56:00Z' })] }), NOW);

    expect(summary).toMatchObject({ urgency: 'safe', verified: true, headline: 'All identities secure' });
    expect(summary.detail).toBe('Public record checked 4 min ago');
  });

  it('drops the all-clear when the directory could not be reached', () => {
    const rows = [
      toRow(input({ did: 'did:plc:a' }), NOW),
      toRow(input({ did: 'did:plc:b', plcCheckSucceeded: false }), NOW),
    ];

    const summary = summarize(rows, history({ sweeps: [sweep()] }), NOW);
    expect(summary.urgency).toBe('safe');
    expect(summary.verified).toBe(false);
    expect(summary.headline).toBe('Not fully checked');
  });

  /**
   * "Not asked yet" and "asked and got no answer" are different facts. Conflating them
   * would report a directory outage on every app open — and inferring verification from
   * the absence of a failure would show the all-clear before the first sweep answered,
   * which is the unearned claim the unverified state exists to prevent.
   */
  it('says a check is in flight rather than failed before the first sweep answers', () => {
    const rows = [toRow(input({ did: 'did:plc:a', plcCheckSucceeded: false }), NOW)];

    const pending = summarize(rows, history(), NOW, true);
    expect(pending.verified).toBe(false);
    expect(pending.headline).toBe('Checking the public record');
    expect(pending.detail).toBe('Asking plc.directory about each identity now');

    // Same rows, but a sweep has answered: now it is a failure, and says so.
    expect(summarize(rows, history(), NOW, false).headline).toBe('Not fully checked');
  });

  it('keeps the previous check time visible while a check is in flight', () => {
    const rows = [toRow(input({ did: 'did:plc:a', plcCheckSucceeded: false }), NOW)];
    const summary = summarize(rows, history({ sweeps: [sweep({ at: '2026-07-26T11:50:00Z' })] }), NOW, true);

    expect(summary.detail).toBe('Last checked 10 min ago');
  });

  /**
   * `check_all` omits a did:web (`is_monitorable`), so it is never in `sweptOk` — but it is
   * verified by construction and must not drag the wallet into the unverified state.
   */
  it('does not let an omitted did:web make the wallet read as unchecked', () => {
    const rows = [
      toRow(input({ did: 'did:plc:a', plcCheckSucceeded: true }), NOW),
      toRow(input({ did: 'did:web:example.com', plcCheckSucceeded: false }), NOW),
    ];

    const summary = summarize(rows, history({ sweeps: [sweep()] }), NOW, false);
    expect(summary).toMatchObject({ verified: true, headline: 'All identities secure' });
  });

  it('claims no watch over an all-did:web wallet', () => {
    const rows = [toRow(input({ did: 'did:web:example.com', plcCheckSucceeded: false }), NOW)];
    const summary = summarize(rows, history(), NOW);

    expect(summary.headline).toBe('Held on your own domains');
    expect(summary.detail).toContain("aren't watched on the public record");
  });

  it('says nothing is being watched when the wallet is empty', () => {
    expect(summarize([], history(), NOW).headline).toBe('Nothing to watch yet');
  });

  it('does not claim a check time before the first sweep is recorded', () => {
    const rows = [toRow(input({ did: 'did:plc:a' }), NOW)];
    expect(summarize(rows, history(), NOW).detail).toBe('Watching the public record');
  });
});

describe('lastSweepAt', () => {
  it('reads the newest sweep', () => {
    expect(lastSweepAt(history({ sweeps: [sweep({ at: '2026-07-26T11:55:00Z' })] }))).toBe(
      Date.parse('2026-07-26T11:55:00Z')
    );
  });

  it('is null with no history and with an unparseable timestamp', () => {
    expect(lastSweepAt(null)).toBeNull();
    expect(lastSweepAt(history())).toBeNull();
    expect(lastSweepAt(history({ sweeps: [sweep({ at: 'not a date' })] }))).toBeNull();
  });
});

describe('formatLastVerified', () => {
  it('reports elapsed time since the last successful check', () => {
    expect(formatLastVerified('2026-07-26T11:58:00Z', NOW)).toBe('Checked 2 min ago');
    expect(formatLastVerified('2026-07-26T11:59:50Z', NOW)).toBe('Checked just now');
  });

  it('says never rather than guessing when there is no reading', () => {
    expect(formatLastVerified(null, NOW)).toBe('Never checked');
    expect(formatLastVerified('nonsense', NOW)).toBe('Never checked');
  });
});

describe('describeSweep', () => {
  it('reports a clean pass', () => {
    expect(describeSweep(sweep())).toBe('Checked 3 identities · nothing out of place');
  });

  it('names unreachable identities and findings', () => {
    expect(describeSweep(sweep({ identitiesFailed: 1 }))).toBe(
      'Checked 3 identities · 1 unreachable · nothing out of place'
    );
    expect(describeSweep(sweep({ unauthorizedFound: 2 }))).toBe(
      'Checked 3 identities · 2 changes flagged'
    );
  });

  /** A pass where nothing answered has not verified anything, and must not imply it did. */
  it('withholds the all-clear when every identity was unreachable', () => {
    expect(describeSweep(sweep({ identitiesChecked: 2, identitiesFailed: 2 }))).toBe(
      'Checked 2 identities · 2 unreachable'
    );
  });

  it('handles a sweep with no identities', () => {
    expect(describeSweep(sweep({ identitiesChecked: 0 }))).toBe('No identities to check');
  });
});

describe('formatClockTime', () => {
  it('renders a wall-clock time', () => {
    expect(formatClockTime('2026-07-26T11:55:00Z')).toMatch(/\d/);
  });

  it('renders nothing rather than "Invalid Date"', () => {
    expect(formatClockTime('not a timestamp')).toBe('');
  });
});

describe('describeInterval', () => {
  it('reads the cadence from the backend rather than restating a constant', () => {
    expect(describeInterval(900)).toBe("The wallet checks every 15 minutes while it's running");
    expect(describeInterval(3600)).toBe("The wallet checks every hour while it's running");
  });

  it('degrades honestly when the cadence is unknown', () => {
    expect(describeInterval(0)).toBe('The wallet checks in the background');
  });
});
