/**
 * Named scenario presets for the admin-companion fake harness.
 *
 * Each preset builds a fresh {@link AdminState} in a known starting condition so any
 * operator-console state — including a degraded relay — can be reproduced on demand via
 * `window.__harness.scenario(name)`. Pure functions over `state.ts`.
 */
import { emptyAdminState, seedRelay, type AdminState } from './state';

/** The canonical admin scenario names. */
export type ScenarioName =
  | 'unpaired'
  | 'single-relay'
  | 'multi-relay'
  | 'degraded-health'
  | 'flagged-accounts';

/** The default scenario when `VITE_HARNESS` is set with no explicit choice. */
export const DEFAULT_SCENARIO: ScenarioName = 'single-relay';

export const scenarios: Record<ScenarioName, () => AdminState> = {
  unpaired: () => emptyAdminState(),

  'single-relay': () => {
    const state = emptyAdminState();
    const relay = seedRelay({
      nickname: 'staging',
      relayUrl: 'https://staging.harness.relay',
      accounts: 4,
    });
    state.relays = [relay];
    state.active = relay.pairingId;
    return state;
  },

  'multi-relay': () => {
    const state = emptyAdminState();
    const staging = seedRelay({
      nickname: 'staging',
      relayUrl: 'https://staging.harness.relay',
      accounts: 4,
    });
    const production = seedRelay({
      nickname: 'production',
      relayUrl: 'https://production.harness.relay',
      accounts: 12,
    });
    state.relays = [staging, production];
    state.active = staging.pairingId;
    return state;
  },

  'degraded-health': () => {
    const state = emptyAdminState();
    const relay = seedRelay({
      nickname: 'production',
      relayUrl: 'https://production.harness.relay',
      accounts: 9,
      degraded: true,
    });
    state.relays = [relay];
    state.active = relay.pairingId;
    return state;
  },

  // Labeler-watching triage view: two accounts flagged by the watched labeler, so the
  // Accounts screen shows the flagged-first sort + per-row flag lines and Home shows
  // the flagged notice.
  'flagged-accounts': () => {
    const state = emptyAdminState();
    const relay = seedRelay({
      nickname: 'production',
      relayUrl: 'https://production.harness.relay',
      accounts: 6,
      flagged: 2,
    });
    state.relays = [relay];
    state.active = relay.pairingId;
    return state;
  },
};

export function isScenarioName(name: string): name is ScenarioName {
  return name in scenarios;
}

export function buildScenario(name: string): AdminState {
  return isScenarioName(name) ? scenarios[name]() : scenarios[DEFAULT_SCENARIO]();
}
