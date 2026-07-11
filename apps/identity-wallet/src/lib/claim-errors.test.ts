import { describe, it, expect } from 'vitest';
import { formatRateLimitMessage, formatServerErrorMessage } from './claim-errors';

describe('formatRateLimitMessage', () => {
  it('phrases a sub-minute Retry-After in seconds', () => {
    expect(formatRateLimitMessage('30')).toBe(
      'Your PDS is rate limiting requests. Try again in about 30 seconds.',
    );
  });

  it('singularizes one second', () => {
    expect(formatRateLimitMessage('1')).toContain('about 1 second.');
  });

  it('rounds a minute-or-more Retry-After up to whole minutes', () => {
    expect(formatRateLimitMessage('120')).toBe(
      'Your PDS is rate limiting requests. Try again in about 2 minutes.',
    );
    // 90s → ceil to 2 minutes
    expect(formatRateLimitMessage('90')).toContain('about 2 minutes.');
    // 60s → 1 minute (singular)
    expect(formatRateLimitMessage('60')).toContain('about 1 minute.');
  });

  it('falls back to a generic wait when Retry-After is absent', () => {
    expect(formatRateLimitMessage(null)).toBe(
      'Your PDS is rate limiting requests. Please wait a moment and try again.',
    );
    expect(formatRateLimitMessage('')).toContain('Please wait a moment');
  });

  it('does not over-parse a non-numeric (HTTP-date) Retry-After', () => {
    expect(formatRateLimitMessage('Wed, 21 Oct 2026 07:28:00 GMT')).toBe(
      'Your PDS is rate limiting requests. Please try again later.',
    );
  });

  it('never presents a rate limit as a connectivity problem', () => {
    for (const input of ['30', '600', null, '', 'garbage']) {
      expect(formatRateLimitMessage(input).toLowerCase()).not.toContain('connection');
    }
  });
});

describe('formatServerErrorMessage', () => {
  it('shows the server message verbatim behind a short lead', () => {
    expect(formatServerErrorMessage('Handle is required')).toBe(
      'Your PDS reported: Handle is required',
    );
  });

  it('falls back when the server sent no message', () => {
    expect(formatServerErrorMessage('   ')).toBe('Your PDS rejected the request.');
    expect(formatServerErrorMessage('')).toBe('Your PDS rejected the request.');
  });
});
