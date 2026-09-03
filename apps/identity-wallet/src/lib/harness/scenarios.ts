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
  fakePlcDid,
  seedAgent,
  seedAlert,
  seedAppPassword,
  seedIdentity,
  upsertIdentity,
  HARNESS_AGENT_SCOPES,
  type WalletState,
} from './state';

/** The canonical wallet scenario names. */
export type ScenarioName =
  | 'fresh-install'
  | 'passwordless-signup'
  | 'foreign-pds'
  | 'unreachable-pds'
  | 'one-identity'
  | 'multi-identity'
  | 'alert-active'
  | 'alert-warning'
  | 'alert-critical'
  | 'alert-expired'
  | 'alert-multi'
  | 'migration-in-flight'
  | 'agent-connected'
  | 'agent-accounts-unprovisioned'
  | 'agent-child-mint'
  | 'agent-children'
  | 'agent-children-recovered'
  | 'app-password-minted'
  | 'device-key-unusable'
  | 'notifications-unverified'
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
   * A first launch pointed at a Custos running with `accounts.password_optional` on, so it
   * advertises `optionalPassword` and the create flow never asks for a password: the handle
   * step submits directly, and `PasswordScreen` is not part of the flow at all.
   *
   * Deliberately a separate scenario rather than a capability added to `emptyWalletState`.
   * The flag is off by default on the server, so the default fixture keeps matching a stock
   * deployment — and every other scenario (and the docs screenshots built from them) keeps
   * exercising the with-password path, which is still what most hosts do.
   */
  'passwordless-signup': () => {
    const state = emptyWalletState();
    state.pdsCapabilities = {
      ...state.pdsCapabilities,
      capabilities: [...state.pdsCapabilities.capabilities, 'optionalPassword'],
    };
    return state;
  },

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
  // The Settings notification diagnostic with something to report. Unreachable any other
  // way in a browser: the breadcrumbs are written by the Notification Service Extension,
  // which only exists on a device and only runs when a real sealed push arrives — and
  // `window.__harness.state()` returns a deep clone, never the live store, so seeding a
  // scenario is the only way in.
  //
  // The mix is deliberate — two key-desync failures alongside one benign post-restart one,
  // so the surface has to level correctly rather than describe whichever it saw first.
  // Timestamps are relative to load, since the readout windows on the last seven days.
  'notifications-unverified': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    upsertIdentity(state, seedIdentity({ handle: 'alice.harness.pds.local' }));
    state.notifications.notificationKeyMinted = true;
    state.notifications.apnsToken = 'harnessapnstoken';
    const now = Date.now();
    state.notifications.recentFailures = [
      { at: new Date(now - 60 * 60 * 1000).toISOString(), reason: 'UNKNOWN_KID', kid: 4 },
      { at: new Date(now - 5 * 60 * 60 * 1000).toISOString(), reason: 'UNKNOWN_KID', kid: 4 },
      { at: new Date(now - 30 * 60 * 60 * 1000).toISOString(), reason: 'KEYS_UNAVAILABLE', kid: 3 },
    ];
    return state;
  },
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

  // The four alert presets below are one per `deadline.ts` urgency band, and they are the
  // ONLY way to reach three of them: `UrgencyBadge`'s state comes from how much of the
  // 72-hour PLC recovery window is left, so the state is chosen entirely by how old the
  // seeded change is. `alert-active` alone left `warning`, `critical`, and `expired`
  // unreachable — including the expired branch where `AlertDetailScreen` disables the
  // override button, which no amount of clicking could otherwise produce.
  //
  // Separate scenarios rather than one multi-age identity list: reaching a given state by
  // hand is then one `window.__harness.scenario(name)` call, and each docs screenshot
  // frames a single state rather than four competing for one viewport.

  // ~70h remaining — `safe`, the calm end of the alarm register.
  'alert-active': () => alertScenario(2),

  // ~12h remaining — `warning`, the first escalation.
  'alert-warning': () => alertScenario(60),

  // ~3h remaining — `critical`, the red "act now" peak of the alarm design.
  'alert-critical': () => alertScenario(69),

  // Past the window — `expired`, the ashen "the moment to act has passed" state, and the
  // only one that reaches `AlertDetailScreen`'s disabled "Recovery window expired" button.
  'alert-expired': () => alertScenario(73),

  // Two identities in alarm at once — the only preset that reaches the *multi*-identity
  // half of the launch takeover, where the app lands on Protection rather than on one
  // identity's alarm surface, and the only way to see Protection's "Not now" exit. Their
  // ages differ so the surface's most-urgent-first ordering is visible rather than assumed.
  'alert-multi': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const alice = seedIdentity({ handle: 'alice.harness.pds.local' });
    alice.alerts = [seedAlert(alice.did, isoHoursAgo(2))];
    const bob = seedIdentity({ handle: 'bob.harness.pds.local', deviceKeyIsRoot: false });
    bob.alerts = [seedAlert(bob.did, isoHoursAgo(69))];
    upsertIdentity(state, alice);
    upsertIdentity(state, bob);
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

  // The cooperative mint, ready to drive: a provisioned identity, plus one child already
  // holding `scribe.harness.pds.local`. Approve an agent with a code starting with "CHILD"
  // (e.g. CHILD1) — the preview comes back anonymous with that same handle proposed, so
  // accepting the agent's proposal reproduces the taken-handle rejection and any other handle
  // mints. Deliberately the agent's *own* proposal that collides: the wallet must never treat
  // the hint as settled.
  'agent-child-mint': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    identity.children = [
      {
        registrationId: 'reg-CHILD0',
        did: fakePlcDid(`${identity.did}:child:0`),
        handle: 'scribe.harness.pds.local',
        status: 'claimed',
        createdAt: '2026-07-15T12:00:00.000Z',
        scopes: [...HARNESS_AGENT_SCOPES],
        audit: [],
      },
    ];
    identity.childIndex = identity.children.length;
    upsertIdentity(state, identity);
    return state;
  },

  // The parent console with every child state on screen at once: one live (renew / revoke /
  // delete all reachable), one already revoked (renewal must refuse — revocation is one-way),
  // and one counting down to permanent removal. The live child carries an audit trail read
  // through the /v1/agents parent arm, so the detail screen's activity record is populated.
  'agent-children': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    const now = '2026-07-15T12:00:00.000Z';
    const childDid = (i: number) => fakePlcDid(`${identity.did}:child:${i}`);
    identity.children = [
      {
        registrationId: 'reg-CHILD0',
        did: childDid(0),
        handle: 'scribe.harness.pds.local',
        status: 'claimed',
        createdAt: now,
        scopes: [...HARNESS_AGENT_SCOPES],
        audit: [
          { id: 'ev-child0-1', eventType: 'claim_confirmed', did: childDid(0), createdAt: now },
          { id: 'ev-child0-2', eventType: 'token_exchanged', createdAt: now, detail: { grant: 'claim' } },
          {
            id: 'ev-child0-3',
            eventType: 'repo_write',
            did: childDid(0),
            createdAt: now,
            detail: { creates: 2, collections: ['app.bsky.feed.post'] },
          },
        ],
      },
      {
        registrationId: 'reg-CHILD1',
        did: childDid(1),
        handle: 'archivist.harness.pds.local',
        status: 'revoked',
        createdAt: now,
        scopes: ['atproto', 'repo:*?action=create&action=update'],
        audit: [
          { id: 'ev-child1-1', eventType: 'claim_confirmed', did: childDid(1), createdAt: now },
          { id: 'ev-child1-2', eventType: 'revoked', did: identity.did, createdAt: now },
        ],
      },
      {
        registrationId: 'reg-CHILD2',
        did: childDid(2),
        handle: 'retired.harness.pds.local',
        status: 'revoked',
        createdAt: now,
        scopes: [],
        deleteAfter: isoInDays(7),
        audit: [{ id: 'ev-child2-1', eventType: 'revoked', did: identity.did, createdAt: now }],
      },
    ];
    // This is the device that minted them, so its counter already clears the list and the
    // recovery epilogue has nothing to report.
    identity.childIndex = identity.children.length;
    upsertIdentity(state, identity);
    return state;
  },

  // A restored device meeting its children again: the delegation seed came back with the
  // recovery seed, but the child counter did not, so the recovery epilogue runs against the
  // server's list. One child re-derives, one names a rotation key this seed cannot reproduce
  // (unrecoverable, the finding that must never be silent), and one cannot be checked at all
  // because plc.directory refused — a different sentence, not a softer one.
  'agent-children-recovered': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
    const now = '2026-07-15T12:00:00.000Z';
    const childDid = (i: number) => fakePlcDid(`${identity.did}:child:${i}`);
    identity.children = [
      {
        registrationId: 'reg-CHILD0',
        did: childDid(0),
        handle: 'scribe.harness.pds.local',
        status: 'claimed',
        createdAt: now,
        scopes: [...HARNESS_AGENT_SCOPES],
        audit: [{ id: 'ev-r0', eventType: 'claim_confirmed', did: childDid(0), createdAt: now }],
      },
      {
        registrationId: 'reg-CHILD1',
        did: childDid(1),
        handle: 'archivist.harness.pds.local',
        status: 'claimed',
        createdAt: now,
        scopes: [...HARNESS_AGENT_SCOPES],
        recoveryKey: 'lost',
        audit: [{ id: 'ev-r1', eventType: 'claim_confirmed', did: childDid(1), createdAt: now }],
      },
      {
        registrationId: 'reg-CHILD2',
        did: childDid(2),
        handle: 'courier.harness.pds.local',
        status: 'claimed',
        createdAt: now,
        scopes: [...HARNESS_AGENT_SCOPES],
        recoveryKey: 'unreachable',
        audit: [{ id: 'ev-r2', eventType: 'claim_confirmed', did: childDid(2), createdAt: now }],
      },
    ];
    // The counter a restore does not bring back: behind the list, which is what puts the
    // epilogue in play.
    identity.childIndex = 0;
    upsertIdentity(state, identity);
    return state;
  },

  // An identity created before agent accounts existed: no delegation seed, so My Agents
  // offers "Enable agent accounts" and the child-mint path must refuse to start. Share 1
  // is in iCloud and escrow releases instantly, so the provisioning ceremony is drivable
  // end to end (enter the code, verify, provisioned).
  'agent-accounts-unprovisioned': () => {
    const state = emptyWalletState();
    state.pdsUrl = DEFAULT_PDS_URL;
    state.recovery.share1Present = true;
    state.recovery.escrow.delaySecs = 0;
    upsertIdentity(
      state,
      seedIdentity({ handle: 'alice.harness.pds.local', agentAccountsProvisioned: false })
    );
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
    // One plain credential, one privileged (chat-capable), and one carrying the
    // personal-details grant, so the list screen's badges and per-entry revoke are
    // all reachable.
    identity.appPasswords = [
      seedAppPassword('Bluesky app'),
      seedAppPassword('Chat client', true),
      seedAppPassword('Bluesky with age checks', false, true),
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
/**
 * One identity carrying one unauthorized change seeded `hoursAgo` in the past.
 *
 * The age is the whole fixture: `getUrgency` reads `createdAt + 72h` against the live
 * clock, so the caller picks the urgency band by picking the age and nothing else varies
 * between the four alert presets.
 */
function alertScenario(hoursAgo: number): WalletState {
  const state = emptyWalletState();
  state.pdsUrl = DEFAULT_PDS_URL;
  const identity = seedIdentity({ handle: 'alice.harness.pds.local' });
  identity.alerts = [seedAlert(identity.did, isoHoursAgo(hoursAgo))];
  upsertIdentity(state, identity);
  return state;
}

function isoHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

/**
 * A future ISO timestamp, off the live clock. Pinning a purge deadline to a literal would land
 * it in the past and render the child as already-removed rather than counting down.
 */
function isoInDays(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString();
}
