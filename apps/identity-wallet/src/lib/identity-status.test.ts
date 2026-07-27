import { describe, it, expect } from 'vitest';
import {
  deriveIdentityPanelState,
  formatCheckedAgo,
  isVerified,
  panelLabel,
} from './identity-status';
import type { UnauthorizedChange } from './ipc';

const NOW = Date.parse('2026-07-26T12:00:00Z');
const HOUR = 60 * 60 * 1000;

function change(createdAt: string, cid = 'bafy-1'): UnauthorizedChange {
  return { cid, createdAt, signingKey: 'did:key:zabc', operation: {} };
}

/** An operation detected `hoursAgo` before NOW; its 72h window closes 72 - hoursAgo from now. */
function detectedHoursAgo(hoursAgo: number, cid?: string): UnauthorizedChange {
  return change(new Date(NOW - hoursAgo * HOUR).toISOString(), cid);
}

describe('deriveIdentityPanelState', () => {
  it('is secure with no changes and a usable device key', () => {
    expect(deriveIdentityPanelState([], false, NOW)).toEqual({
      urgency: 'safe',
      deadline: null,
      alertCount: 0,
    });
  });

  it('warns when this device can no longer sign', () => {
    expect(deriveIdentityPanelState([], true, NOW)).toEqual({
      urgency: 'warning',
      deadline: null,
      alertCount: 0,
    });
  });

  it('raises the alarm for an open recovery window, however much time remains', () => {
    // One hour in, 71 hours of window left — `getUrgency` would call that deadline
    // 'safe'. The panel must not: an active unauthorized change is never all-clear.
    const state = deriveIdentityPanelState([detectedHoursAgo(1)], false, NOW);
    expect(state.urgency).toBe('critical');
    expect(state.alertCount).toBe(1);
    expect(state.deadline?.getTime()).toBe(NOW + 71 * HOUR);
  });

  it('counts down to the soonest still-open window when several are live', () => {
    const state = deriveIdentityPanelState(
      [detectedHoursAgo(2, 'bafy-a'), detectedHoursAgo(70, 'bafy-b')],
      false,
      NOW
    );
    expect(state.urgency).toBe('critical');
    expect(state.alertCount).toBe(2);
    expect(state.deadline?.getTime()).toBe(NOW + 2 * HOUR);
  });

  it('ignores already-closed windows while any window is still open', () => {
    const state = deriveIdentityPanelState(
      [detectedHoursAgo(100, 'bafy-old'), detectedHoursAgo(50, 'bafy-live')],
      false,
      NOW
    );
    expect(state.urgency).toBe('critical');
    expect(state.deadline?.getTime()).toBe(NOW + 22 * HOUR);
  });

  it('closes to the expired state, reporting the last window to shut', () => {
    const state = deriveIdentityPanelState(
      [detectedHoursAgo(100, 'bafy-a'), detectedHoursAgo(80, 'bafy-b')],
      false,
      NOW
    );
    expect(state.urgency).toBe('expired');
    expect(state.alertCount).toBe(2);
    expect(state.deadline?.getTime()).toBe(NOW - 8 * HOUR);
  });

  it('still raises the alarm when every timestamp is unreadable', () => {
    // A parsing failure costs the countdown, never the alarm.
    const state = deriveIdentityPanelState([change('not-a-timestamp')], false, NOW);
    expect(state.urgency).toBe('expired');
    expect(state.alertCount).toBe(1);
    expect(state.deadline).toBeNull();
  });

  it('lets an open window survive a sibling change with an unreadable timestamp', () => {
    const state = deriveIdentityPanelState(
      [change('not-a-timestamp', 'bafy-bad'), detectedHoursAgo(10, 'bafy-ok')],
      false,
      NOW
    );
    expect(state.urgency).toBe('critical');
    expect(state.deadline?.getTime()).toBe(NOW + 62 * HOUR);
  });

  it('reports the alarm over a dead device key', () => {
    // Both are true; the panel names the more severe fact. The home list's card strips
    // order the other way round because they answer "what do I do first", not "what is true".
    expect(deriveIdentityPanelState([detectedHoursAgo(1)], true, NOW).urgency).toBe('critical');
  });
});

describe('isVerified', () => {
  const PLC = 'did:plc:harness106zzd8';
  const WEB = 'did:web:example.com';

  it('follows the directory for a did:plc', () => {
    expect(isVerified(PLC, true)).toBe(true);
    expect(isVerified(PLC, false)).toBe(false);
  });

  it('holds a did:web verified even when the sweep reports a failed check', () => {
    // `PlcMonitor::check_all` does not filter by DID method, so it asks plc.directory
    // about a did:web too — and that fetch fails on EVERY sweep, since a did:web has no
    // PLC audit log. Honouring that verdict would put "Not checked / couldn't reach the
    // public record" on an identity that has no public record.
    expect(isVerified(WEB, false)).toBe(true);
    expect(isVerified(WEB, true)).toBe(true);
  });

  it('reads the method from the DID, not from a prefix that merely contains it', () => {
    expect(isVerified('did:plc:notdid:web:decoy', false)).toBe(false);
  });
});

describe('panelLabel', () => {
  it('uses the shared four-state vocabulary', () => {
    expect(panelLabel('safe')).toBe('Secure');
    expect(panelLabel('warning')).toBe('Action needed');
    expect(panelLabel('critical')).toBe('Under attack');
    expect(panelLabel('expired')).toBe('Recovery window closed');
  });

  it('never claims "Secure" on a reading the wallet could not take', () => {
    expect(panelLabel('safe', false)).toBe('Not checked');
  });

  it('leaves the non-safe states alone — they rest on evidence already in hand', () => {
    // An unreachable directory does not un-detect a change already found, nor revive a
    // device key already known to be gone.
    expect(panelLabel('warning', false)).toBe('Action needed');
    expect(panelLabel('critical', false)).toBe('Under attack');
    expect(panelLabel('expired', false)).toBe('Recovery window closed');
  });
});

describe('formatCheckedAgo', () => {
  it('reads a sub-minute check as "just now"', () => {
    expect(formatCheckedAgo(NOW - 30_000, NOW)).toBe('just now');
  });

  it('counts whole minutes within the hour', () => {
    expect(formatCheckedAgo(NOW - 60_000, NOW)).toBe('1 min ago');
    expect(formatCheckedAgo(NOW - 59 * 60_000, NOW)).toBe('59 min ago');
  });

  it('switches to whole hours within the day', () => {
    expect(formatCheckedAgo(NOW - HOUR, NOW)).toBe('1h ago');
    expect(formatCheckedAgo(NOW - 23 * HOUR, NOW)).toBe('23h ago');
  });

  it('stops counting past a day rather than quoting a stale figure precisely', () => {
    expect(formatCheckedAgo(NOW - 25 * HOUR, NOW)).toBe('over a day ago');
    expect(formatCheckedAgo(NOW - 400 * HOUR, NOW)).toBe('over a day ago');
  });
});
