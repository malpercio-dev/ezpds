import { describe, it, expect } from 'vitest';
import { formatTimestamp } from './datetime';

describe('formatTimestamp', () => {
  it('formats an ISO string and an equivalent Date identically', () => {
    const iso = '2026-07-14T15:45:00Z';
    expect(formatTimestamp(new Date(iso))).toBe(formatTimestamp(iso));
  });

  it('renders to the minute — seconds do not change the output', () => {
    expect(formatTimestamp('2026-07-14T15:45:12Z')).toBe(formatTimestamp('2026-07-14T15:45:00Z'));
  });

  it('omits the year — differing only by year yields the same string', () => {
    // Both are mid-July (DST-stable), so the local month/day/hour/minute match.
    expect(formatTimestamp('2026-07-14T15:45:00Z')).toBe(formatTimestamp('2027-07-14T15:45:00Z'));
  });

  it('returns a non-empty string for a valid timestamp', () => {
    expect(formatTimestamp('2026-07-14T15:45:00Z').length).toBeGreaterThan(0);
  });
});
