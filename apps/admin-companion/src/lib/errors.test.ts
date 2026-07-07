import { describe, it, expect } from 'vitest';
import { classifyRelayError, describeRelayError } from './errors';
import type { RelayClientError } from './ipc';

/** Every distinct `RelayClientError` shape the client can produce. */
const NOT_PAIRED: RelayClientError = { code: 'NOT_PAIRED' };
const UNREACHABLE: RelayClientError = { code: 'UNREACHABLE', message: 'timed out' };
const INVALID_RELAY_URL: RelayClientError = { code: 'INVALID_RELAY_URL' };
const REJECTED_403: RelayClientError = { code: 'RELAY_REJECTED', status: 403, message: 'forbidden' };
const REJECTED_401: RelayClientError = { code: 'RELAY_REJECTED', status: 401, message: 'unauthorized' };
const REJECTED_500: RelayClientError = { code: 'RELAY_REJECTED', status: 500, message: 'server error' };
const NO_SUCH_PAIRING: RelayClientError = { code: 'NO_SUCH_PAIRING' };
const DEVICE_KEY: RelayClientError = { code: 'DEVICE_KEY', message: 'no key' };
const KEYCHAIN: RelayClientError = { code: 'KEYCHAIN', message: 'locked' };
const BAD_RESPONSE: RelayClientError = { code: 'BAD_RESPONSE', message: 'not json' };

describe('classifyRelayError', () => {
  it('classifies NOT_PAIRED as pending, routing to pair', () => {
    expect(classifyRelayError(NOT_PAIRED)).toEqual({
      status: 'pending',
      chipLabel: 'not paired',
      message: describeRelayError(NOT_PAIRED),
      recovery: 'pair',
    });
  });

  it('classifies UNREACHABLE as info, routing to retry', () => {
    expect(classifyRelayError(UNREACHABLE)).toEqual({
      status: 'info',
      chipLabel: 'unreachable',
      message: describeRelayError(UNREACHABLE),
      recovery: 'retry',
    });
  });

  it('classifies INVALID_RELAY_URL as error, with no recovery affordance', () => {
    expect(classifyRelayError(INVALID_RELAY_URL)).toEqual({
      status: 'error',
      chipLabel: 'bad relay url',
      message: describeRelayError(INVALID_RELAY_URL),
      recovery: 'none',
    });
  });

  it('classifies NO_SUCH_PAIRING as error, with no recovery affordance', () => {
    expect(classifyRelayError(NO_SUCH_PAIRING)).toEqual({
      status: 'error',
      chipLabel: 'no such server',
      message: describeRelayError(NO_SUCH_PAIRING),
      recovery: 'none',
    });
  });

  it('classifies RELAY_REJECTED with status 403 as revoked, offering forget or switch', () => {
    expect(classifyRelayError(REJECTED_403)).toEqual({
      status: 'revoked',
      chipLabel: 'access revoked',
      message: describeRelayError(REJECTED_403),
      recovery: 'forget-or-switch',
    });
  });

  it('classifies RELAY_REJECTED with status 401 as a clock-skew error, routing to retry', () => {
    expect(classifyRelayError(REJECTED_401)).toEqual({
      status: 'error',
      chipLabel: 'check device time',
      message: describeRelayError(REJECTED_401),
      recovery: 'retry',
    });
  });

  it('classifies RELAY_REJECTED with any other status as a generic rejection', () => {
    expect(classifyRelayError(REJECTED_500)).toEqual({
      status: 'error',
      chipLabel: 'rejected',
      message: describeRelayError(REJECTED_500),
      recovery: 'retry',
    });
  });

  it('classifies DEVICE_KEY as a generic failure, routing to retry', () => {
    expect(classifyRelayError(DEVICE_KEY)).toEqual({
      status: 'error',
      chipLabel: 'failed',
      message: describeRelayError(DEVICE_KEY),
      recovery: 'retry',
    });
  });

  it('classifies KEYCHAIN as a generic failure, routing to retry', () => {
    expect(classifyRelayError(KEYCHAIN)).toEqual({
      status: 'error',
      chipLabel: 'failed',
      message: describeRelayError(KEYCHAIN),
      recovery: 'retry',
    });
  });

  it('classifies BAD_RESPONSE as a generic failure, routing to retry', () => {
    expect(classifyRelayError(BAD_RESPONSE)).toEqual({
      status: 'error',
      chipLabel: 'failed',
      message: describeRelayError(BAD_RESPONSE),
      recovery: 'retry',
    });
  });

  it('classifies an unrecognized/undefined error as the generic failure fallback', () => {
    expect(classifyRelayError(undefined)).toEqual({
      status: 'error',
      chipLabel: 'failed',
      message: describeRelayError(undefined),
      recovery: 'retry',
    });
    expect(classifyRelayError(new Error('boom'))).toEqual({
      status: 'error',
      chipLabel: 'failed',
      message: describeRelayError(new Error('boom')),
      recovery: 'retry',
    });
  });
});

describe('describeRelayError', () => {
  it.each([
    ['NOT_PAIRED', NOT_PAIRED],
    ['INVALID_RELAY_URL', INVALID_RELAY_URL],
    ['UNREACHABLE', UNREACHABLE],
    ['RELAY_REJECTED (403)', REJECTED_403],
    ['RELAY_REJECTED (401)', REJECTED_401],
    ['RELAY_REJECTED (other)', REJECTED_500],
    ['NO_SUCH_PAIRING', NO_SUCH_PAIRING],
    ['DEVICE_KEY', DEVICE_KEY],
    ['KEYCHAIN', KEYCHAIN],
    ['BAD_RESPONSE', BAD_RESPONSE],
    ['unrecognized', undefined],
  ])('returns a non-empty message for %s', (_label, error) => {
    const message = describeRelayError(error);
    expect(typeof message).toBe('string');
    expect(message.length).toBeGreaterThan(0);
  });

  it('never reveals which check failed on a 403 — states revocation, not a cause', () => {
    expect(describeRelayError(REJECTED_403)).toMatch(/revoked/i);
    expect(describeRelayError(REJECTED_403)).toMatch(/forget.*switch/i);
  });

  it('surfaces the "check device time" hint on a 401', () => {
    expect(describeRelayError(REJECTED_401)).toMatch(/device time/i);
  });

  it('includes the raw HTTP status for an unrecognized rejection status', () => {
    expect(describeRelayError(REJECTED_500)).toBe('The relay rejected the request (HTTP 500).');
  });

  it('produces a distinct message per error code', () => {
    const messages = [
      NOT_PAIRED,
      INVALID_RELAY_URL,
      UNREACHABLE,
      REJECTED_403,
      REJECTED_401,
      REJECTED_500,
      NO_SUCH_PAIRING,
      DEVICE_KEY,
      KEYCHAIN,
      BAD_RESPONSE,
      undefined,
    ].map((e) => describeRelayError(e));
    expect(new Set(messages).size).toBe(messages.length);
  });
});
