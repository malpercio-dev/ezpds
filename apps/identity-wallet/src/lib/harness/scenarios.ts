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
  seedAppPassword,
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
  | 'agent-connected'
  | 'app-password-minted'
  | 'rekey-eligible'
  | 'rekey-mixed';

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

  'app-password-minted': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    // One plain credential and one privileged (chat-capable) one, so the list
    // screen's privilege badge and per-entry revoke are both reachable.
    identity.appPasswords = [
      seedAppPassword('Bluesky app'),
      seedAppPassword('Chat client', true),
    ];
    upsertIdentity(state, identity);
    return state;
  },

  // A single old-model did:plc identity (2-key rotationKeys) — the "Add a recovery key" strip
  // shows and the full re-key upgrade runs (MM-411).
  'rekey-eligible': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'alice.harness.pds.local' }));
    return state;
  },

  // Old-model + new-model + did:web side by side — only the old-model identity is offered the
  // upgrade, proving the prompt skips new-model and did:web identities.
  'rekey-mixed': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'oldmodel.harness.pds.local' }));
    upsertIdentity(
      state,
      seedIdentity({ handle: 'newmodel.harness.pds.local', recoveryKey: true })
    );
    upsertIdentity(
      state,
      seedIdentity({ handle: 'web.example.com', did: 'did:web:web.example.com' })
    );
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
