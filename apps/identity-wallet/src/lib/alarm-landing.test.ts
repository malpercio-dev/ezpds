import { describe, it, expect } from 'vitest';
import { alarmKey, decideAlarmLanding } from './alarm-landing';
import type { IdentityStatus, UnauthorizedChange } from './ipc';

const NOW = Date.parse('2026-07-26T12:00:00Z');

function change(cid: string, hoursAgo: number): UnauthorizedChange {
  return {
    cid,
    createdAt: new Date(NOW - hoursAgo * 3_600_000).toISOString(),
    signingKey: null,
    operation: {},
  };
}

function status(did: string, changes: UnauthorizedChange[] = []): IdentityStatus {
  return { did, checkFailed: false, unauthorizedChanges: changes };
}

describe('alarmKey', () => {
  it('is stable across the order plc.directory returned the entries in', () => {
    const a = status('did:plc:a', [change('bafy1', 1), change('bafy2', 2)]);
    const b = status('did:plc:a', [change('bafy2', 2), change('bafy1', 1)]);
    expect(alarmKey(a)).toBe(alarmKey(b));
  });

  it('changes when a new unauthorized operation appears', () => {
    const before = status('did:plc:a', [change('bafy1', 1)]);
    const after = status('did:plc:a', [change('bafy1', 1), change('bafy2', 0)]);
    expect(alarmKey(after)).not.toBe(alarmKey(before));
  });

  it('distinguishes identities carrying the same change count', () => {
    expect(alarmKey(status('did:plc:a', [change('bafy1', 1)]))).not.toBe(
      alarmKey(status('did:plc:b', [change('bafy1', 1)]))
    );
  });
});

describe('decideAlarmLanding', () => {
  it('does not interrupt when nothing is in alarm', () => {
    const { landing } = decideAlarmLanding([status('did:plc:a'), status('did:plc:b')]);
    expect(landing).toEqual({ kind: 'none' });
  });

  it('lands on the identity alarm surface when exactly one identity is alarmed', () => {
    const changes = [change('bafy1', 1)];
    const { landing } = decideAlarmLanding([status('did:plc:a', changes), status('did:plc:b')]);
    expect(landing).toEqual({ kind: 'identity', did: 'did:plc:a', changes });
  });

  it('lands on Protection when more than one identity is alarmed', () => {
    const { landing } = decideAlarmLanding([
      status('did:plc:a', [change('bafy1', 1)]),
      status('did:plc:b', [change('bafy2', 2)]),
    ]);
    expect(landing).toEqual({ kind: 'protection' });
  });

  it('still interrupts for an alarm whose recovery window has closed', () => {
    // The remedy is gone; the fact is not. The most serious state the app can report must
    // not be the only one it never volunteers.
    const changes = [change('bafy1', 100)];
    const { landing } = decideAlarmLanding([status('did:plc:a', changes)]);
    expect(landing).toEqual({ kind: 'identity', did: 'did:plc:a', changes });
  });

  it('does not re-take the app for an alarm already shown and dismissed', () => {
    const alarmed = status('did:plc:a', [change('bafy1', 1)]);
    const first = decideAlarmLanding([alarmed]);
    expect(first.landing.kind).toBe('identity');

    const dismissed = new Set(first.keys);
    expect(decideAlarmLanding([alarmed], dismissed).landing).toEqual({ kind: 'none' });
  });

  it('interrupts again when a dismissed identity is attacked a second time', () => {
    const seen = status('did:plc:a', [change('bafy1', 4)]);
    const dismissed = new Set(decideAlarmLanding([seen]).keys);

    const escalated = status('did:plc:a', [change('bafy1', 4), change('bafy2', 0)]);
    expect(decideAlarmLanding([escalated], dismissed).landing).toEqual({
      kind: 'identity',
      did: 'did:plc:a',
      changes: escalated.unauthorizedChanges,
    });
  });

  it('sends a new second alarm to Protection rather than hiding the dismissed one', () => {
    const a = status('did:plc:a', [change('bafy1', 4)]);
    const dismissed = new Set(decideAlarmLanding([a]).keys);

    const b = status('did:plc:b', [change('bafy2', 1)]);
    const { landing, keys } = decideAlarmLanding([a, b], dismissed);
    expect(landing).toEqual({ kind: 'protection' });
    // Only the unseen alarm is newly consumed; the dismissed one stays dismissed.
    expect(keys).toEqual([alarmKey(b)]);
  });

  it('reports every alarm it presented so the caller can mark them shown', () => {
    const a = status('did:plc:a', [change('bafy1', 1)]);
    const b = status('did:plc:b', [change('bafy2', 2)]);
    const { keys } = decideAlarmLanding([a, b]);
    expect(new Set(keys)).toEqual(new Set([alarmKey(a), alarmKey(b)]));
  });
});
