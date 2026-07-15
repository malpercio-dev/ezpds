/**
 * Named scenario presets for the identity-wallet fake harness.
 *
 * Each preset builds a fresh {@link WalletState} that puts the app in a known
 * starting condition, so an agent (or a human) can reproduce any UI state — including
 * rare ones — on demand via `window.__harness.scenario(name)`. Pure functions over
 * `state.ts`, unit-testable in the Node environment.
 */
import {
  DEFAULT_PDS_URL,
  emptyWalletState,
  seedAgent,
  seedAlert,
  seedIdentity,
  upsertIdentity,
  type WalletState,
} from './state';

/** The canonical wallet scenario names. */
export type ScenarioName =
  | 'fresh-install'
  | 'one-identity'
  | 'multi-identity'
  | 'alert-active'
  | 'migration-in-flight'
  | 'agent-connected';

/** The default scenario when `VITE_HARNESS` is set with no explicit choice. */
export const DEFAULT_SCENARIO: ScenarioName = 'one-identity';

/** Every scenario builder, keyed by name. */
export const scenarios: Record<ScenarioName, () => WalletState> = {
  'fresh-install': () => emptyWalletState(),

  'one-identity': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'alice.harness.pds.local' }));
    return state;
  },

  'multi-identity': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'alice.harness.pds.local' }));
    upsertIdentity(
      state,
      seedIdentity({ handle: 'bob.harness.pds.local', deviceKeyIsRoot: false })
    );
    return state;
  },

  'alert-active': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    // A recent unauthorized change so the recovery-window countdown is live.
    identity.alerts = [seedAlert(identity.did, isoHoursAgo(2))];
    upsertIdentity(state, identity);
    return state;
  },

  'migration-in-flight': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    upsertIdentity(state, identity);
    // A prepared migration whose source is already authenticated and the destination
    // account created, so the migration screens land mid-flow.
    state.migration = {
      did: identity.did,
      destPdsUrl: 'https://destination.harness.pds.local',
      sourceAuthenticated: true,
      destinationCreated: true,
      repoTransferred: false,
      blobsTransferred: false,
      preferencesTransferred: false,
      verified: false,
      armed: false,
    };
    return state;
  },

  'agent-connected': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    identity.agents = [seedAgent(identity.did, identity.did)];
    upsertIdentity(state, identity);
    return state;
  },
};

/** Whether a string names a known scenario. */
export function isScenarioName(name: string): name is ScenarioName {
  return name in scenarios;
}

/** Build a state for `name`, falling back to the default for an unknown name. */
export function buildScenario(name: string): WalletState {
  return isScenarioName(name) ? scenarios[name]() : scenarios[DEFAULT_SCENARIO]();
}

function isoHoursAgo(hours: number): string {
  // Fixed reference clock keeps scenarios deterministic in tests; the exact instant
  // is irrelevant — only the relative age matters to the recovery-window UI.
  const base = Date.parse('2026-07-15T12:00:00.000Z');
  return new Date(base - hours * 3600_000).toISOString();
}
