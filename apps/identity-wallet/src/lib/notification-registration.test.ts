import { get } from 'svelte/store';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  describeRegistration,
  recordRegistrationFailure,
  recordRegistrationOutcome,
  registrationRecords,
} from './notification-registration';

const DID = 'did:web:tester.example.com';

beforeEach(() => {
  registrationRecords.set({});
});

describe('the registration ledger', () => {
  it('records a completed attempt by its status', () => {
    recordRegistrationOutcome(DID, {
      status: 'REGISTERED',
      deviceUuid: 'device-1',
      notificationKeyId: 'did:key:zExample',
    });
    expect(get(registrationRecords)[DID]).toEqual({ kind: 'outcome', status: 'REGISTERED' });
  });

  it('records a rejection by its wire code', () => {
    recordRegistrationFailure(DID, { code: 'SESSION_LOCKED', reason: 'NO_REFRESH_CHAIN' });
    expect(get(registrationRecords)[DID]).toEqual({ kind: 'error', code: 'SESSION_LOCKED' });
  });

  it('an unclassifiable rejection is still a recorded failure, not a dropped one', () => {
    // A thrown string or transport fault carries no code; the attempt still failed and the
    // surface must say so rather than keep reporting the previous state.
    recordRegistrationFailure(DID, 'something broke');
    expect(get(registrationRecords)[DID]).toEqual({ kind: 'error', code: 'UNKNOWN' });
  });

  it('the newest record wins, so a recovery replaces the failure that preceded it', () => {
    recordRegistrationFailure(DID, { code: 'SESSION_LOCKED' });
    recordRegistrationOutcome(DID, {
      status: 'REGISTERED',
      deviceUuid: 'device-1',
      notificationKeyId: 'did:key:zExample',
    });
    expect(get(registrationRecords)[DID]).toEqual({ kind: 'outcome', status: 'REGISTERED' });
  });

  it('one identity’s record never touches another’s', () => {
    const other = 'did:plc:someoneelse';
    recordRegistrationOutcome(DID, {
      status: 'REGISTERED',
      deviceUuid: 'device-1',
      notificationKeyId: null,
    });
    recordRegistrationFailure(other, { code: 'NETWORK_ERROR', message: 'timeout' });
    const records = get(registrationRecords);
    expect(records[DID]).toEqual({ kind: 'outcome', status: 'REGISTERED' });
    expect(records[other]).toEqual({ kind: 'error', code: 'NETWORK_ERROR' });
  });
});

describe('describeRegistration', () => {
  it('does not invent a result before an attempt has reported', () => {
    const health = describeRegistration(undefined);
    expect(health.level).toBe('info');
    expect(health.headline).toBe('Not checked yet');
  });

  it('a registered identity reads quiet with nothing to do', () => {
    const health = describeRegistration({ kind: 'outcome', status: 'REGISTERED' });
    expect(health.level).toBe('quiet');
    expect(health.advice).toBeNull();
  });

  it('a locked identity is the loud case, and the advice names the fix', () => {
    // The state this surface exists for: SESSION_LOCKED fails registration on every app
    // open, silently, forever — the identity can never receive a sign-in request push and
    // nothing else anywhere says so.
    const health = describeRegistration({ kind: 'error', code: 'SESSION_LOCKED' });
    expect(health.level).toBe('attention');
    expect(health.headline).toContain('Locked');
    expect(health.advice).toContain('unlock');
  });

  it('the two ordinary "no" outcomes stay informational, not alarming', () => {
    for (const status of ['AWAITING_APNS_TOKEN', 'UNSUPPORTED'] as const) {
      expect(describeRegistration({ kind: 'outcome', status }).level).toBe('info');
    }
  });

  it('transient failures say they retry on their own', () => {
    for (const code of ['NETWORK_ERROR', 'RATE_LIMITED']) {
      const health = describeRegistration({ kind: 'error', code });
      expect(health.level).toBe('info');
      expect(health.detail).toContain('retries');
    }
  });

  it('an unrecognized code reaches the screen generically, carrying the code as diagnostic', () => {
    const health = describeRegistration({ kind: 'error', code: 'SOMETHING_NEW' });
    expect(health.level).toBe('attention');
    expect(health.advice).toContain('SOMETHING_NEW');
  });
});
