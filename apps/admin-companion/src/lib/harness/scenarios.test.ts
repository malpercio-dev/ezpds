import { describe, it, expect } from 'vitest';
import { scenarios, buildScenario, isScenarioName, DEFAULT_SCENARIO } from './scenarios';
import { buildRegistry } from './registry';
import type { PairingsState } from '$lib/ipc';

describe('admin harness scenarios', () => {
  it('unpaired has no relays and no active selection', () => {
    const state = scenarios.unpaired();
    expect(state.relays).toHaveLength(0);
    expect(state.active).toBeNull();
  });

  it('single-relay pairs one active relay', () => {
    const state = scenarios['single-relay']();
    expect(state.relays).toHaveLength(1);
    expect(state.active).toBe(state.relays[0].pairingId);
  });

  it('multi-relay pairs two relays with one active', () => {
    const state = scenarios['multi-relay']();
    expect(state.relays).toHaveLength(2);
    expect(state.relays.map((r) => r.pairingId)).toContain(state.active);
  });

  it('degraded-health surfaces a stale sweep', () => {
    const state = scenarios['degraded-health']();
    expect(state.relays[0].health.sweeps.accountReaper).toBeNull();
  });

  it('isScenarioName narrows known names', () => {
    expect(isScenarioName('single-relay')).toBe(true);
    expect(isScenarioName('nope')).toBe(false);
  });

  it('buildScenario falls back to the default for an unknown name', () => {
    const fallback = buildScenario('does-not-exist');
    const expected = scenarios[DEFAULT_SCENARIO]();
    expect(fallback.relays.length).toBe(expected.relays.length);
  });

  it('pair then unpair round-trips through the fake (AC2.1)', () => {
    const state = scenarios.unpaired();
    const registry = buildRegistry(state);
    const deviceId = registry.pair_device({
      relayUrl: 'https://new.relay',
      pairingCode: 'CODE',
      label: 'Test device',
      nickname: 'newrelay',
    }) as string;
    let pairings = registry.list_pairings({}) as PairingsState;
    expect(pairings.pairings).toHaveLength(1);
    expect(deviceId).toBeTruthy();

    registry.unpair({ id: pairings.pairings[0].id });
    pairings = registry.list_pairings({}) as PairingsState;
    expect(pairings.pairings).toHaveLength(0);
  });

  it('generate_claim_code appears in the inventory (AC2.1)', () => {
    const state = scenarios['single-relay']();
    const registry = buildRegistry(state);
    const pairingId = state.active!;
    const code = registry.generate_claim_code({}) as string;
    const inventory = registry.list_claim_codes({ pairingId }) as { codes: { code: string }[] };
    expect(inventory.codes.some((c) => c.code === code)).toBe(true);
  });

  it('self-revoke of the device row is refused (AC2.3)', () => {
    const state = scenarios['single-relay']();
    const registry = buildRegistry(state);
    const relay = state.relays[0];
    expect(() =>
      registry.revoke_admin_device({ pairingId: relay.pairingId, deviceId: relay.deviceId })
    ).toThrow();
  });
});
