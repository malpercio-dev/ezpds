import { describe, expect, it } from 'vitest';
import { chipFor, partitionCodes, timelineLine } from './claim-codes';
import type { ClaimCodeEntry } from './ipc';

function entry(overrides: Partial<ClaimCodeEntry> & Pick<ClaimCodeEntry, 'code' | 'status'>): ClaimCodeEntry {
  return {
    createdAt: '2026-07-10 12:00:00',
    expiresAt: '2026-07-11 12:00:00',
    ...overrides,
  };
}

describe('partitionCodes', () => {
  it('splits pending from every terminal state, preserving order within each group', () => {
    const codes = [
      entry({ code: 'NEW001', status: 'pending' }),
      entry({ code: 'SPENT1', status: 'redeemed', redeemedAt: '2026-07-10 13:00:00' }),
      entry({ code: 'NEW002', status: 'pending' }),
      entry({ code: 'KILLED', status: 'revoked', revokedAt: '2026-07-10 14:00:00' }),
      entry({ code: 'LAPSED', status: 'expired' }),
    ];

    const { outstanding, history } = partitionCodes(codes);

    expect(outstanding.map((c) => c.code)).toEqual(['NEW001', 'NEW002']);
    expect(history.map((c) => c.code)).toEqual(['SPENT1', 'KILLED', 'LAPSED']);
  });

  it('handles an empty inventory', () => {
    expect(partitionCodes([])).toEqual({ outstanding: [], history: [] });
  });
});

describe('chipFor', () => {
  it('maps every status to a tone + label pair', () => {
    expect(chipFor('pending')).toEqual({ chip: 'pending', label: 'pending' });
    expect(chipFor('redeemed')).toEqual({ chip: 'ready', label: 'redeemed' });
    expect(chipFor('expired')).toEqual({ chip: 'info', label: 'expired' });
    expect(chipFor('revoked')).toEqual({ chip: 'revoked', label: 'revoked' });
  });
});

describe('version-skew fallbacks', () => {
  it('renders an unknown wire status visibly instead of a blank chip', () => {
    // The wire carries status as a plain string; a newer relay may emit values this
    // build has never heard of. The cast simulates that skew past the TS union.
    const skewed = 'suspended' as ClaimCodeEntry['status'];
    expect(chipFor(skewed)).toEqual({ chip: 'info', label: 'unknown (suspended)' });
    expect(timelineLine(entry({ code: 'E', status: skewed }))).toBe(
      'minted 2026-07-10 12:00:00',
    );
    // And an unknown status is never treated as a live credential.
    expect(partitionCodes([entry({ code: 'E', status: skewed })]).outstanding).toEqual([]);
  });
});

describe('timelineLine', () => {
  it('reports the fact that ended the code, or the deadline while pending', () => {
    expect(timelineLine(entry({ code: 'A', status: 'pending' }))).toBe(
      'expires 2026-07-11 12:00:00',
    );
    expect(
      timelineLine(entry({ code: 'B', status: 'redeemed', redeemedAt: '2026-07-10 13:00:00' })),
    ).toBe('redeemed 2026-07-10 13:00:00');
    expect(
      timelineLine(entry({ code: 'C', status: 'revoked', revokedAt: '2026-07-10 14:00:00' })),
    ).toBe('revoked 2026-07-10 14:00:00');
    expect(timelineLine(entry({ code: 'D', status: 'expired' }))).toBe(
      'expired 2026-07-11 12:00:00',
    );
  });
});
