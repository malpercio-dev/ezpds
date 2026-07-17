import { describe, expect, it } from 'vitest';
import { flagDate, flagLine, sortFlaggedFirst } from './flags';
import type { AccountFlag, AccountListEntry } from './ipc';

function flag(overrides?: Partial<AccountFlag>): AccountFlag {
  return {
    val: 'spam',
    labelerDid: 'did:plc:ar7c4by46qjdydhdevvrndac',
    cts: '2026-07-01T09:30:00Z',
    ...overrides,
  };
}

function account(did: string, flags: AccountFlag[] = []): AccountListEntry {
  return {
    did,
    handle: null,
    createdAt: '2026-07-01 00:00:00',
    status: 'active',
    totalBytes: 0,
    quotaUsedPct: 0,
    flags,
  };
}

describe('flagLine', () => {
  it('renders value, shortened labeler, and date', () => {
    expect(flagLine(flag())).toBe('spam · did:plc:ar7c4b…ndac · 2026-07-01');
  });

  it('keeps a short labeler DID whole', () => {
    expect(flagLine(flag({ labelerDid: 'did:plc:short' }))).toBe(
      'spam · did:plc:short · 2026-07-01'
    );
  });
});

describe('flagDate', () => {
  it('takes the calendar date from an ISO timestamp', () => {
    expect(flagDate('2026-07-01T09:30:00Z')).toBe('2026-07-01');
  });

  it('shows a non-ISO timestamp verbatim rather than hiding it', () => {
    expect(flagDate('yesterday-ish')).toBe('yesterday-ish');
  });
});

describe('sortFlaggedFirst', () => {
  it('floats flagged accounts above unflagged ones, DID order within each group', () => {
    const rows = [
      account('did:plc:aaa'),
      account('did:plc:zzz', [flag()]),
      account('did:plc:bbb'),
      account('did:plc:mmm', [flag({ val: '!hide' })]),
    ];
    const sorted = sortFlaggedFirst(rows).map((r) => r.did);
    expect(sorted).toEqual(['did:plc:mmm', 'did:plc:zzz', 'did:plc:aaa', 'did:plc:bbb']);
  });

  it('does not mutate its input', () => {
    const rows = [account('did:plc:b'), account('did:plc:a', [flag()])];
    sortFlaggedFirst(rows);
    expect(rows[0].did).toBe('did:plc:b');
  });
});
