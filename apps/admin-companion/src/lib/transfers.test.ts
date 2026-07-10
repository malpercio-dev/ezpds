import { describe, expect, it } from 'vitest';
import { accountLabel, chipFor, timelineLine } from './transfers';
import type { TransferEntry } from './ipc';

function entry(
  overrides: Partial<TransferEntry> & Pick<TransferEntry, 'id' | 'status'>,
): TransferEntry {
  return {
    did: 'did:plc:abc123',
    createdAt: '2026-07-10 12:00:00',
    expiresAt: '2026-07-10 12:15:00',
    ...overrides,
  };
}

describe('chipFor', () => {
  it('maps every in-flight status to a tone + label pair', () => {
    expect(chipFor('pending')).toEqual({ chip: 'pending', label: 'code out' });
    expect(chipFor('accepted')).toEqual({ chip: 'revoked', label: 'device holds credential' });
    expect(chipFor('completing')).toEqual({ chip: 'revoked', label: 'completing' });
  });

  it('renders an unfamiliar relay status as a visible unknown, never a blank chip', () => {
    // Version skew: a newer relay may report a status this app has never heard of.
    const skewed = chipFor('paused' as TransferEntry['status']);
    expect(skewed.chip).toBe('info');
    expect(skewed.label).toContain('paused');
  });
});

describe('timelineLine', () => {
  it("reports a pending transfer's code deadline", () => {
    expect(timelineLine(entry({ id: 't-1', status: 'pending' }))).toBe(
      'code expires 2026-07-10 12:15:00',
    );
  });

  it('reports the acceptance fact once a device holds the credential', () => {
    const accepted = entry({
      id: 't-2',
      status: 'accepted',
      acceptedAt: '2026-07-10 12:05:00',
    });
    expect(timelineLine(accepted)).toBe('accepted 2026-07-10 12:05:00');
    // Expiry deliberately absent: it no longer stops completion for an accepted swap.
    expect(timelineLine(accepted)).not.toContain('expires');
  });

  it('stays factual when the relay omits acceptedAt', () => {
    expect(timelineLine(entry({ id: 't-3', status: 'completing' }))).toBe(
      'accepted at an unknown time',
    );
  });

  it('falls back to the opened timestamp for an unfamiliar status', () => {
    const skewed = entry({ id: 't-4', status: 'paused' as TransferEntry['status'] });
    expect(timelineLine(skewed)).toBe('opened 2026-07-10 12:00:00');
  });
});

describe('accountLabel', () => {
  it('prefers the handle and falls back to the DID', () => {
    expect(accountLabel(entry({ id: 't-5', status: 'pending', handle: 'swap.example.com' }))).toBe(
      'swap.example.com',
    );
    expect(accountLabel(entry({ id: 't-6', status: 'pending' }))).toBe('did:plc:abc123');
  });
});
