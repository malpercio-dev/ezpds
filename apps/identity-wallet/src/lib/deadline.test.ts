import { describe, it, expect } from 'vitest';
import { getDeadline, getUrgency, formatCountdown, RECOVERY_WINDOW_MS } from './deadline';

describe('deadline utils', () => {
  describe('getDeadline', () => {
    it('returns a date exactly 72 hours after createdAt', () => {
      const deadline = getDeadline('2026-03-29T12:00:00.000Z');
      expect(deadline.getTime()).toBe(new Date('2026-04-01T12:00:00.000Z').getTime());
    });

    it('RECOVERY_WINDOW_MS equals 72 hours in milliseconds', () => {
      expect(RECOVERY_WINDOW_MS).toBe(72 * 60 * 60 * 1000);
    });

    it('throws on invalid timestamp', () => {
      expect(() => getDeadline('not-a-date')).toThrow('Invalid createdAt timestamp');
    });
  });

  describe('getUrgency', () => {
    const deadline = new Date('2026-04-01T12:00:00.000Z');

    it('returns safe when >24 hours remaining', () => {
      const now = deadline.getTime() - 48 * 3600_000; // 48h before
      expect(getUrgency(deadline, now)).toBe('safe');
    });

    it('returns safe at exactly 24 hours remaining', () => {
      const now = deadline.getTime() - 24 * 3600_000; // exactly 24h before
      expect(getUrgency(deadline, now)).toBe('safe');
    });

    it('returns warning when 4-24 hours remaining', () => {
      const now = deadline.getTime() - 12 * 3600_000; // 12h before
      expect(getUrgency(deadline, now)).toBe('warning');
    });

    it('returns critical when <4 hours remaining', () => {
      const now = deadline.getTime() - 2 * 3600_000; // 2h before
      expect(getUrgency(deadline, now)).toBe('critical');
    });

    it('returns warning at exactly 4 hours remaining', () => {
      const now = deadline.getTime() - 4 * 3600_000; // exactly 4h before
      expect(getUrgency(deadline, now)).toBe('warning');
    });

    it('returns expired at exactly the deadline', () => {
      expect(getUrgency(deadline, deadline.getTime())).toBe('expired');
    });

    it('returns expired when past deadline', () => {
      const now = deadline.getTime() + 3600_000; // 1h after
      expect(getUrgency(deadline, now)).toBe('expired');
    });
  });

  describe('formatCountdown', () => {
    const deadline = new Date('2026-04-01T12:00:00.000Z');

    it('formats 72 hours remaining', () => {
      const now = deadline.getTime() - 72 * 3600_000;
      expect(formatCountdown(deadline, now)).toBe('72h 0m remaining');
    });

    it('formats 23h 59m remaining', () => {
      const now = deadline.getTime() - (23 * 3600_000 + 59 * 60_000);
      expect(formatCountdown(deadline, now)).toBe('23h 59m remaining');
    });

    it('formats 0h 1m remaining', () => {
      const now = deadline.getTime() - 60_000;
      expect(formatCountdown(deadline, now)).toBe('0h 1m remaining');
    });

    it('returns Expired at exactly the deadline', () => {
      expect(formatCountdown(deadline, deadline.getTime())).toBe('Expired');
    });

    it('returns Expired when past deadline', () => {
      const now = deadline.getTime() + 3600_000;
      expect(formatCountdown(deadline, now)).toBe('Expired');
    });
  });
});
