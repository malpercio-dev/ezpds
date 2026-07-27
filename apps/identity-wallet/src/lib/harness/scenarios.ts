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
  | 'foreign-pds'
  | 'unreachable-pds'
  | 'one-identity'
  | 'multi-identity'
  | 'alert-active'
  | 'migration-in-flight'
  | 'agent-connected'
  | 'app-password-minted'
  | 'device-key-unusable'
  | 'rekey-eligible'
  | 'rekey-mixed'
  | 'self-held-kit'
  | 'self-held-kit-escrow-host'
  | 'recover-escrow'
  | 'recover-sovereign'
  | 'recover-wrong-set'
  | 'recover-corrupt-share'
  | 'recover-mismatch'
  | 'recover-pending-delay'
  | 'recover-cancelled'
  | 'recover-epilogue-resume';

/** The default scenario when `VITE_HARNESS` is set with no explicit choice. */
export const DEFAULT_SCENARIO: ScenarioName = 'one-identity';

/** Every scenario builder, keyed by name. */
export const scenarios: Record<ScenarioName, () => WalletState> = {
  'fresh-install': () => emptyWalletState(),

  /**
   * A first launch pointed at a spec-compliant, non-Custos PDS: it advertises no Custos
   * capabilities, so the create flow's gate closes at the config step and steers to import.
   * This is the majority of the ecosystem (the reference PDS, bsky.social, rsky-pds), and
   * the only scenario that reaches `CreateUnavailableScreen`.
   */
  'foreign-pds': () => {
    const state = emptyWalletState();
    // Reached, and it genuinely advertises nothing — the answer that closes the gate.
    state.pdsCapabilities = { version: null, reached: true, capabilities: [] };
    state.availableUserDomains = ['.foreign.pds.local'];
    return state;
  },

  /**
   * A host the capability probe could not reach. Indistinguishable from `foreign-pds`
   * through the capability list alone — which is the point: the create-flow gate must
   * show a retryable error here rather than telling the user their server cannot create
   * identities, a claim it has no evidence for.
   */
  'unreachable-pds': () => {
    const state = emptyWalletState();
    state.pdsCapabilities = { version: null, reached: false, capabilities: [] };
    return state;
  },

  'one-identity': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'alice.harness.pds.local' }));
    return state;
  },

  /**
   * A device restored from an encrypted backup: the device-key metadata restored, the
   * Secure Enclave key could not. The wallet must not claim custody of rotationKeys[0]
   * it cannot sign with — the card shows "Can't sign" and offers the recovery ceremony.
   */
  'device-key-unusable': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(
      state,
      seedIdentity({ handle: 'alice.harness.pds.local', deviceKeyUnusable: true })
    );
    // The same loss on a did:web, where the ceremony does not apply: a did:web has no
    // rotation keys to rotate into, so the card must state the domain-side remedy rather
    // than offer a flow `start_share_recovery` refuses outright.
    upsertIdentity(
      state,
      seedIdentity({
        handle: 'web.example.com',
        did: 'did:web:web.example.com',
        deviceKeyUnusable: true,
      })
    );
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

  // Happy path A (escrow-assisted): Share 1 in iCloud, escrow releases the moment
  // the emailed code is entered (zero-delay server config).
  'recover-escrow': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    state.recovery.escrow.delaySecs = 0;
    return state;
  },

  // Happy path B (fully sovereign): Share 1 in iCloud + Share 3 entered manually.
  // Paste `state().recovery.fixtures.share3Words` (or `.share3`) into the entry box.
  'recover-sovereign': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    return state;
  },

  // Entering `fixtures.wrongSet` reports a cross-generation SHARE_SET_MISMATCH.
  'recover-wrong-set': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    return state;
  },

  // Entering `fixtures.corrupt` reports SHARE_CHECKSUM (damaged/mistyped share).
  'recover-corrupt-share': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    return state;
  },

  // Valid shares that don't belong to this identity: verification fails with
  // SHARES_DO_NOT_MATCH_IDENTITY before anything signs.
  'recover-mismatch': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    state.recovery.verifyOutcome = 'mismatch';
    return state;
  },

  // The escrow release opens a 24h pending window; the second poll releases, so
  // both the wait state and the arrival are reachable.
  'recover-pending-delay': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    state.recovery.escrow.delaySecs = 86400;
    state.recovery.escrow.releaseAfterPolls = 2;
    return state;
  },

  // The pending release was cancelled from a signed-in device: polls answer the
  // uniform 401 and the wait screen shows the cancelled state.
  'recover-cancelled': () => {
    const state = emptyWalletState();
    state.recovery.share1Present = true;
    state.recovery.escrow.delaySecs = 86400;
    state.recovery.escrow.cancelled = true;
    return state;
  },

  // An app restart interrupted the rotation epilogue mid-way: launch resumes
  // straight to the epilogue screen, which re-runs only the incomplete steps.
  'recover-epilogue-resume': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    upsertIdentity(state, identity);
    state.recovery.did = identity.did;
    state.recovery.handle = identity.handle;
    state.recovery.epilogue = {
      opSubmitted: true,
      escrowDeposited: false,
      escrowSkipped: false,
      share1Written: false,
    };
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
    upsertIdentity(
      state,
      seedIdentity({ handle: 'alice.harness.pds.local', recoveryKey: false })
    );
    return state;
  },

  // Old-model + new-model + did:web side by side — only the old-model identity is offered the
  // upgrade, proving the prompt skips new-model and did:web identities.
  'rekey-mixed': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(
      state,
      seedIdentity({ handle: 'oldmodel.harness.pds.local', recoveryKey: false })
    );
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

  /**
   * A claimed identity on a spec-compliant non-Custos host: device key at rotationKeys[0], a
   * longer tail than the Custos re-key's `[device, PDS]`, no recovery key, and a host that
   * answered describeServer advertising nothing. This is the escrow-less self-held kit's whole
   * population — the identity detail screen offers "Add a recovery key", and the backup step
   * hands the user Shares 2 AND 3 rather than escrowing one (MM-456).
   */
  'self-held-kit': () => {
    const state = emptyWalletState();
    state.pdsUrl = 'https://bsky.social';
    state.pdsCapabilities = { version: null, reached: true, capabilities: [] };
    const identity = seedIdentity({
      handle: 'alice.bsky.social',
      pdsUrl: 'https://bsky.social',
      recoveryKey: false,
    });
    // The tail a claim leaves behind: the old host's own keys, which the kit must shift down
    // intact rather than replace. Two of them, so the array is the length `guard_rekey_op`
    // rejects — the shape only this flow can serve.
    identity.rotationKeys = [
      identity.deviceKeyId,
      'did:key:zharnessForeignPdsKey',
      'did:key:zharnessForeignLegacyKey',
    ];
    upsertIdentity(state, identity);
    return state;
  },

  /**
   * The same identity after the kit, now hosted somewhere that DOES advertise escrow — the
   * upsell seam's only true state. `self_held_kit_escrow_offer_cmd` answers true here and
   * false everywhere else, and "Add a recovery key" is withheld (there is nothing to add).
   */
  'self-held-kit-escrow-host': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    state.pdsCapabilities = {
      version: '0.8.5',
      reached: true,
      capabilities: ['createCeremony', 'escrow', 'sovereignSessions'],
    };
    const identity = seedIdentity({ handle: 'alice.harness.pds.local', recoveryKey: true });
    identity.selfHeldKitInstalled = true;
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

/**
 * An ISO timestamp `hours` before now — measured against the *live* clock, deliberately.
 *
 * The recovery-window UI reads these fixtures against `Date.now()` (`$lib/deadline`'s
 * `getUrgency`/`formatCountdown`, via `$lib/identity-status`), so a fixed base instant is
 * not a fixed *age*: it ages out. Pinned to a literal date, `isoHoursAgo(2)` stops being a
 * two-hour-old alert the moment real time passes it, and once 72 hours have elapsed the
 * `alert-active` scenario renders "Recovery window closed" — the one preset that exists to
 * demonstrate a live alarm no longer demonstrating one.
 *
 * Determinism for the docs screenshots is owned by the capture driver, not by a constant
 * here: `tools/screenshots/capture.mjs` freezes the page clock to `FIXED_CLOCK` before the
 * harness installs, so `Date.now()` there is that instant and every seeded age resolves
 * identically on every run.
 */
function isoHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}
