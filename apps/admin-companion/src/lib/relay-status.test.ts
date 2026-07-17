import { describe, expect, it } from 'vitest';

import type { RelayStatus } from './ipc';
import { formatRelayCursor, groupDigits, relayStatusView } from './relay-status';

/** A fully-caught-up, healthy readout; override fields per test. */
function status(overrides: Partial<RelayStatus> = {}): RelayStatus {
  return {
    relayHost: 'bsky.network',
    reachable: true,
    relayStatus: 'active',
    relaySeq: 1000,
    accountCount: 3,
    pdsHeadSeq: 1000,
    gap: 0,
    relayCursorAt: '2026-07-17T00:00:00.000Z',
    detail: null,
    checkedAt: '2026-07-17T00:00:10.000Z',
    ...overrides,
  };
}

describe('groupDigits', () => {
  it('inserts thousands separators deterministically', () => {
    expect(groupDigits(0)).toBe('0');
    expect(groupDigits(999)).toBe('999');
    expect(groupDigits(1000)).toBe('1,000');
    expect(groupDigits(8204)).toBe('8,204');
    expect(groupDigits(1234567)).toBe('1,234,567');
  });
});

describe('formatRelayCursor', () => {
  it('renders the age since the cursor timestamp', () => {
    const now = Math.floor(Date.parse('2026-07-17T00:05:00.000Z') / 1000);
    expect(formatRelayCursor('2026-07-17T00:00:00.000Z', now)).toBe('5m 0s ago');
  });

  it('clamps a future timestamp to zero rather than a negative age', () => {
    const now = Math.floor(Date.parse('2026-07-17T00:00:00.000Z') / 1000);
    expect(formatRelayCursor('2026-07-17T01:00:00.000Z', now)).toBe('0s ago');
  });

  it('falls back to the raw value when the timestamp is unparseable', () => {
    expect(formatRelayCursor('not-a-date', 0)).toBe('not-a-date');
  });
});

describe('relayStatusView — configuration & reachability', () => {
  it('reports "no relay" (info) when none is configured', () => {
    const view = relayStatusView(status({ relayHost: null }), 0);
    expect(view.chip).toEqual({ status: 'info', label: 'no relay' });
    expect(view.headline).toContain('disabled');
  });

  it('reports "unreachable" (error) with the relay detail when transport fails', () => {
    const view = relayStatusView(
      status({ reachable: false, relaySeq: null, relayStatus: null, gap: null, detail: 'relay did not respond in time' }),
      0,
    );
    expect(view.chip).toEqual({ status: 'error', label: 'unreachable' });
    expect(view.headline).toBe('relay did not respond in time');
  });

  it('reports "not seen" (warning) when the relay has never crawled us', () => {
    const view = relayStatusView(
      status({ relaySeq: null, relayStatus: null, gap: null, accountCount: null, relayCursorAt: null, detail: 'relay has not crawled this host' }),
      0,
    );
    expect(view.chip).toEqual({ status: 'pending', label: 'not seen' });
    expect(view.headline).toBe('relay has not crawled this host');
  });
});

describe('relayStatusView — gap thresholds (MM-281 bands)', () => {
  it('caught up: gap 0 → ready/caught up', () => {
    const view = relayStatusView(status({ gap: 0 }), 0);
    expect(view.chip).toEqual({ status: 'ready', label: 'caught up' });
    expect(view.headline).toBe('The relay is caught up with this server.');
  });

  it('healthy minor lag: gap below 500 → ready/crawling', () => {
    const view = relayStatusView(status({ pdsHeadSeq: 1499, gap: 499 }), 0);
    expect(view.chip).toEqual({ status: 'ready', label: 'crawling' });
  });

  it('warn band: 500 ≤ gap < 5000 → pending/behind N', () => {
    const view = relayStatusView(status({ pdsHeadSeq: 3204, gap: 2204 }), 0);
    expect(view.chip).toEqual({ status: 'pending', label: 'behind 2,204' });
    expect(view.headline).toBe('The relay is 2,204 events behind.');
  });

  it('error band: gap ≥ 5000 → error/behind N', () => {
    const view = relayStatusView(status({ pdsHeadSeq: 9204, gap: 8204 }), 0);
    expect(view.chip).toEqual({ status: 'error', label: 'behind 8,204' });
  });

  it('a relay cursor ahead of our frontier (negative gap) reads as caught up, not a huge gap', () => {
    const view = relayStatusView(status({ pdsHeadSeq: 1000, relaySeq: 1002, gap: -2 }), 0);
    expect(view.chip.status).toBe('ready');
    expect(view.chip.label).toBe('caught up');
  });
});

describe('relayStatusView — relay lifecycle status', () => {
  it('throttled with a small gap → pending/throttled (status word)', () => {
    const view = relayStatusView(status({ relayStatus: 'throttled', gap: 10 }), 0);
    expect(view.chip).toEqual({ status: 'pending', label: 'throttled' });
    expect(view.headline).toBe('The relay reports this server throttled.');
  });

  it('offline overrides a small gap → error/offline', () => {
    const view = relayStatusView(status({ relayStatus: 'offline', gap: 3 }), 0);
    expect(view.chip).toEqual({ status: 'error', label: 'offline' });
  });

  it('an unknown status is surfaced cautiously as a warning', () => {
    const view = relayStatusView(status({ relayStatus: 'quarantined', gap: 0 }), 0);
    expect(view.chip.status).toBe('pending');
    expect(view.chip.label).toBe('quarantined');
  });

  it('takes the worst axis: throttled but a huge gap → error, labelled by the gap', () => {
    // The gap (error) is worse than throttled (warn), so the dominant problem is being far behind.
    const view = relayStatusView(status({ relayStatus: 'throttled', pdsHeadSeq: 9000, gap: 8000 }), 0);
    expect(view.chip.status).toBe('error');
    expect(view.chip.label).toBe('behind 8,000');
  });
});

describe('relayStatusView — facts', () => {
  it('surfaces the literal numbers and the cursor age', () => {
    const now = Math.floor(Date.parse('2026-07-17T00:05:00.000Z') / 1000);
    const view = relayStatusView(
      status({ pdsHeadSeq: 3204, relaySeq: 1000, gap: 2204, accountCount: 12, relayCursorAt: '2026-07-17T00:00:00.000Z' }),
      now,
    );
    const facts = Object.fromEntries(view.facts.map((f) => [f.label, f.value]));
    expect(facts['relay']).toBe('bsky.network');
    expect(facts['behind by']).toBe('2,204 events');
    expect(facts['last seen']).toBe('5m 0s ago');
    expect(facts['relay seq']).toBe('1,000');
    expect(facts['pds head']).toBe('3,204');
    expect(facts['accounts indexed']).toBe('12');
  });

  it('uses the singular "event" for a gap of one', () => {
    const view = relayStatusView(status({ pdsHeadSeq: 1001, gap: 1 }), 0);
    const facts = Object.fromEntries(view.facts.map((f) => [f.label, f.value]));
    expect(facts['behind by']).toBe('1 event');
    expect(view.headline).toBe('The relay is 1 event behind.');
  });
});
