import { describe, expect, it } from 'vitest';
import {
  FAILURE_WINDOW_MS,
  summarizeNotificationFailures,
} from './notification-health';
import type { NotificationFailure } from '$lib/ipc';

const NOW = Date.parse('2026-07-27T12:00:00Z');

function failure(reason: string, agoMs = 0, kid: number | null = 1): NotificationFailure {
  return { at: new Date(NOW - agoMs).toISOString(), reason, kid };
}

describe('summarizeNotificationFailures', () => {
  it('reports nothing when nothing failed', () => {
    const health = summarizeNotificationFailures([], NOW);
    expect(health.level).toBe('quiet');
    expect(health.count).toBe(0);
    expect(health.advice).toBeNull();
  });

  it('drops failures older than the window, so a fixed problem stops being reported', () => {
    const health = summarizeNotificationFailures(
      [failure('UNKNOWN_KID', FAILURE_WINDOW_MS + 1000)],
      NOW
    );
    expect(health.level).toBe('quiet');
  });

  it('names a key desync and points at the thing that fixes it', () => {
    const health = summarizeNotificationFailures(
      [failure('UNKNOWN_KID'), failure('UNKNOWN_KID', 3600_000)],
      NOW
    );
    expect(health.level).toBe('attention');
    expect(health.count).toBe(2);
    expect(health.headline).toContain('2 notifications');
    expect(health.advice).toContain('Open one of your identities');
  });

  it('counts one failure in the singular', () => {
    expect(summarizeNotificationFailures([failure('OPEN_FAILED')], NOW).headline).toBe(
      '1 notification could not be verified'
    );
  });

  // The post-restart window is real but self-healing. Presenting it at the same weight as a
  // key desync would spend the user's attention on something already fixed.
  it('treats a locked-Keychain failure as informational, with nothing to do', () => {
    const health = summarizeNotificationFailures([failure('KEYS_UNAVAILABLE')], NOW);
    expect(health.level).toBe('info');
    expect(health.advice).toBeNull();
    expect(health.detail).toContain('restarted');
  });

  // The whole point of levelling before choosing wording: a benign failure must never be the
  // sentence shown for a week that also contains a real one.
  it('lets the real problem win the wording over a benign one', () => {
    const health = summarizeNotificationFailures(
      [
        failure('KEYS_UNAVAILABLE'),
        failure('KEYS_UNAVAILABLE', 1000),
        failure('KEYS_UNAVAILABLE', 2000),
        failure('UNKNOWN_KID', 3000),
      ],
      NOW
    );
    expect(health.level).toBe('attention');
    expect(health.count).toBe(4);
    expect(health.advice).toContain('Open one of your identities');
  });

  it('describes junk pushes as detectable spam, not as a risk', () => {
    const health = summarizeNotificationFailures([failure('MALFORMED_PAYLOAD', 0, null)], NOW);
    expect(health.level).toBe('attention');
    expect(health.detail).toContain('not notifications your server sent');
    expect(health.advice).toContain('Nothing is at risk');
  });

  // The extension is a separate bundle on its own release schedule, so this is a state the
  // shipped app can genuinely be in.
  it('keeps a reason it does not recognise rather than hiding the failure', () => {
    const health = summarizeNotificationFailures([failure('SOMETHING_NEW')], NOW);
    expect(health.count).toBe(1);
    expect(health.level).toBe('attention');
    expect(health.detail).toContain('does not recognise');
  });

  // An unparseable timestamp is a clock or encoding problem, not an absence of failures.
  it('keeps a failure whose timestamp cannot be read', () => {
    const health = summarizeNotificationFailures(
      [{ at: 'not a date', reason: 'OPEN_FAILED', kid: 2 }],
      NOW
    );
    expect(health.count).toBe(1);
    expect(health.level).toBe('attention');
  });

  it('reports the newest failure as the latest', () => {
    const newest = failure('OPEN_FAILED');
    const health = summarizeNotificationFailures([newest, failure('OPEN_FAILED', 60_000)], NOW);
    expect(health.latest).toBe(newest.at);
  });
});
