import { describe, it, expect } from 'vitest';
import { resolvePinnedPairing, pinnedHref } from './pinned-pairing';
import type { Pairing, PairingsState } from './ipc';

function pairing(id: string): Pairing {
  return { id, nickname: id, relayUrl: `https://${id}.example`, deviceId: `dev-${id}`, deviceLabel: id };
}

describe('resolvePinnedPairing', () => {
  const state: PairingsState = { active: 'b', pairings: [pairing('a'), pairing('b'), pairing('c')] };

  it('prefers the ?server= pin over the active pairing', () => {
    const params = new URLSearchParams('server=a');
    expect(resolvePinnedPairing(state, params)?.id).toBe('a');
  });

  it('falls back to the active pairing when no pin is given', () => {
    expect(resolvePinnedPairing(state, new URLSearchParams())?.id).toBe('b');
  });

  it('returns null when the pinned id matches no pairing', () => {
    const params = new URLSearchParams('server=zzz');
    expect(resolvePinnedPairing(state, params)).toBeNull();
  });

  it('returns null when there is no pin and no active pairing', () => {
    const noActive: PairingsState = { active: null, pairings: [pairing('a')] };
    expect(resolvePinnedPairing(noActive, new URLSearchParams())).toBeNull();
  });

  it('resolves the active pairing to its full object', () => {
    const resolved = resolvePinnedPairing(state, new URLSearchParams());
    expect(resolved).toEqual(pairing('b'));
  });
});

describe('pinnedHref', () => {
  it('builds a server-pinned link', () => {
    expect(pinnedHref('/devices', 'abc')).toBe('/devices?server=abc');
  });

  it('appends extra query params after the server pin', () => {
    expect(pinnedHref('/account', 'abc', { did: 'did:plc:xyz' })).toBe(
      '/account?server=abc&did=did%3Aplc%3Axyz',
    );
  });

  it('percent-encodes the pairing id consistently', () => {
    expect(pinnedHref('/status', 'a b')).toBe('/status?server=a+b');
  });
});
