import { describe, expect, it } from 'vitest';

import { formatBackfillWindow, formatDuration, sweepLine, unownedBlobLine } from './health';

describe('formatDuration', () => {
  it('renders sub-minute durations as bare seconds', () => {
    expect(formatDuration(0)).toBe('0s');
    expect(formatDuration(47)).toBe('47s');
    expect(formatDuration(59)).toBe('59s');
  });

  it('renders the two largest units, uptime-style', () => {
    expect(formatDuration(60)).toBe('1m 0s');
    expect(formatDuration(12 * 60 + 3)).toBe('12m 3s');
    expect(formatDuration(4 * 3600 + 12 * 60)).toBe('4h 12m');
    expect(formatDuration(3 * 86_400 + 4 * 3600 + 59 * 60)).toBe('3d 4h');
  });

  it('clamps negative input to zero rather than rendering nonsense', () => {
    expect(formatDuration(-5)).toBe('0s');
  });
});

describe('formatBackfillWindow', () => {
  it('says "empty log" for null instead of a misleading zero', () => {
    expect(formatBackfillWindow(null)).toBe('empty log');
  });

  it('renders a present window as a duration', () => {
    expect(formatBackfillWindow(3600)).toBe('1h 0m');
  });
});

describe('sweepLine', () => {
  const NOW = 1_750_000_000;

  it('distinguishes "never ran" from a completed pass', () => {
    expect(sweepLine(null, NOW)).toBe('not yet run');
  });

  it('renders age and swept count for a completed pass', () => {
    expect(sweepLine({ completedAt: NOW - 4 * 60, swept: 7, errors: 0 }, NOW)).toBe(
      '4m 0s ago · swept 7',
    );
  });

  it('keeps a healthy quiet pass visible as swept 0', () => {
    expect(sweepLine({ completedAt: NOW - 30, swept: 0, errors: 0 }, NOW)).toBe(
      '30s ago · swept 0',
    );
  });

  it('marks a pass older than 24h stale, naming the fault', () => {
    expect(sweepLine({ completedAt: NOW - 86_400, swept: 2, errors: 0 }, NOW)).toBe(
      '1d 0h ago · swept 2 · stale !',
    );
    // Just under the threshold: no marker.
    expect(sweepLine({ completedAt: NOW - 86_399, swept: 2, errors: 0 }, NOW)).toBe(
      '23h 59m ago · swept 2',
    );
  });

  it('clamps a completedAt slightly in the future (clock skew) to 0s, unmarked', () => {
    expect(sweepLine({ completedAt: NOW + 10, swept: 1, errors: 0 }, NOW)).toBe(
      '0s ago · swept 1',
    );
  });

  // The sweep is alive and collecting, but one account's reconcile failed, so that
  // account is excluded and leaks disk. A fresh timestamp must not read as "all clear"
  // just because staleness is the older, more familiar signal.
  it('reports a fresh pass that skipped work as failed, not stale', () => {
    const line = sweepLine({ completedAt: NOW - 4 * 60, swept: 7, errors: 1 }, NOW);
    expect(line).toBe('4m 0s ago · swept 7 · failed 1 !');
    expect(line).not.toContain('stale');
  });

  it('reports errors with no staleness threshold — one skipped subject is worth saying', () => {
    expect(sweepLine({ completedAt: NOW - 30, swept: 0, errors: 3 }, NOW)).toBe(
      '30s ago · swept 0 · failed 3 !',
    );
  });

  // Both faults at once must stay separable: an unlabelled marker could not say which
  // one it meant, which is the whole reason each fault carries its own name.
  it('names both faults independently when a stale pass also skipped work', () => {
    const line = sweepLine({ completedAt: NOW - 86_400, swept: 2, errors: 1 }, NOW);
    expect(line).toBe('1d 0h ago · swept 2 · failed 1 · stale !');
    expect(line).toContain('failed 1');
    expect(line).toContain('stale');
  });

  it('carries every fault as text, never color, and marks the line just once', () => {
    const both = sweepLine({ completedAt: NOW - 86_400, swept: 2, errors: 1 }, NOW);
    // One attention glyph per line, regardless of how many faults are named.
    expect(both.match(/!/g)).toHaveLength(1);
    // A healthy line stays unmarked, so the glyph means something.
    expect(sweepLine({ completedAt: NOW - 30, swept: 0, errors: 0 }, NOW)).not.toContain('!');
  });
});

describe('unownedBlobLine', () => {
  // ~0 is the real baseline, not a tuned threshold: GC drops a physical row together
  // with its last owner, so a row is unowned only between two statements.
  it('reports a real zero as the all-clear, unmarked', () => {
    expect(unownedBlobLine(0, 0)).toEqual({ line: 'none', alarm: false });
  });

  it('names the condition in words and marks a standing population', () => {
    expect(unownedBlobLine(2, 4096)).toEqual({
      line: '2 · 4.0 KiB (4096 B) · ownership lost !',
      alarm: true,
    });
  });

  // The distinction this whole readout turns on. Unlike the sweep `errors` field — where
  // a missing value could safely default to 0, "no failures" — 0 HERE is the all-clear,
  // so defaulting an absent field to it would fabricate an all-clear an old relay never
  // gave. "not reported" is the only honest reading.
  it('never collapses an unreported pair into the reported all-clear', () => {
    const unreported = unownedBlobLine(null, null);
    expect(unreported).toEqual({ line: 'not reported', alarm: false });
    expect(unreported.line).not.toBe(unownedBlobLine(0, 0).line);
  });

  it('treats a half-reported pair as unanswered — a half-answer is no answer', () => {
    expect(unownedBlobLine(2, null).line).toBe('not reported');
    expect(unownedBlobLine(null, 4096).line).toBe('not reported');
  });

  // An unanswerable question is not an alarm: raising one on every older relay would
  // train the operator to dismiss the row that actually matters.
  it('raises the alarm only for a reported, standing population', () => {
    expect(unownedBlobLine(null, null).alarm).toBe(false);
    expect(unownedBlobLine(0, 0).alarm).toBe(false);
    expect(unownedBlobLine(1, 10).alarm).toBe(true);
  });

  // Status is text + glyph + position, never color (AAA) — and the glyph means something
  // only if the quiet states stay unmarked.
  it('carries the state as text and marks the line exactly once', () => {
    const alarming = unownedBlobLine(7, 900_000).line;
    expect(alarming).toContain('ownership lost');
    expect(alarming.match(/!/g)).toHaveLength(1);
    expect(unownedBlobLine(0, 0).line).not.toContain('!');
    expect(unownedBlobLine(null, null).line).not.toContain('!');
  });
});
