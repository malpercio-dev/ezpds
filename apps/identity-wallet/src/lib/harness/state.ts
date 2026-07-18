/**
 * Stateful in-memory fake for the identity-wallet harness (browser test mode).
 *
 * Pure TypeScript: no Tauri, no DOM, no network — so it is unit-testable in the
 * Node vitest environment (see `state.test.ts`). The registry (`registry.ts`) owns
 * the command→handler mapping and mutates a {@link WalletState} instance through the
 * helpers here; scenarios (`scenarios.ts`) seed fresh states from presets.
 *
 * The domain modeled mirrors what the wallet's screens actually read: managed
 * identities (each with a PLC-format DID document, a device key, PLC-monitor alerts,
 * and bound agents), plus the transient state the multi-step create / claim /
 * migration flows thread across commands.
 */
import type { UnauthorizedChange } from '$lib/ipc';
import type {
  AgentSummary,
  AgentAuditEvent,
  AppPasswordEntry,
} from '$lib/ipc';

/** A `did:key` multibase string that is stable for a given seed (not a real key). */
export function fakeDeviceKeyId(seed: string): string {
  return `did:key:zHarnessDev${hashToken(seed)}`;
}

/** A plausible-looking `did:plc` for a given seed. */
export function fakePlcDid(seed: string): string {
  return `did:plc:harness${hashToken(seed)}`;
}

/** Deterministic base36-ish token from a string — keeps fakes readable and stable. */
function hashToken(seed: string): string {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h = (h ^ seed.charCodeAt(i)) >>> 0;
    h = (h * 16777619) >>> 0;
  }
  return h.toString(36).padStart(7, '0').slice(0, 12);
}

/** One agent bound to an identity, plus its append-only audit trail. */
export interface FakeAgent {
  summary: AgentSummary;
  audit: AgentAuditEvent[];
}

/** One managed identity as the fake models it. */
export interface FakeIdentity {
  did: string;
  handle: string;
  pdsUrl: string;
  /** `did:key` of this identity's device key. */
  deviceKeyId: string;
  /** PLC rotation keys, `rotationKeys[0]` === deviceKeyId when the device is root. */
  rotationKeys: string[];
  /** PLC-monitor alerts surfaced on the home screen. */
  alerts: UnauthorizedChange[];
  /** Agents bound to this identity ("My agents"). */
  agents: FakeAgent[];
  /** App passwords minted for this identity (metadata only, like the real list route). */
  appPasswords: AppPasswordEntry[];
  /**
   * The staged recovery key of an in-flight old-model re-key (MM-411), or null when none is
   * staged. Mirrors the per-DID `rekey-staging:{did}` Keychain slot: set by `build_rekey`,
   * survives `submit_rekey`, and is cleared by `confirm_rekey`. Drives `rekey_in_progress`.
   */
  rekeyStagedRecoveryKey: string | null;
}

/** Transient state for the multi-step import (claim) flow. */
export interface ClaimFlow {
  did: string;
  handle: string;
  pdsUrl: string;
  authenticated: boolean;
  verificationRequested: boolean;
}

/** Transient state for the wallet-authorized outbound migration flow. */
export interface MigrationFlow {
  did: string;
  destPdsUrl: string;
  sourceAuthenticated: boolean;
  destinationCreated: boolean;
  repoTransferred: boolean;
  blobsTransferred: boolean;
  preferencesTransferred: boolean;
  verified: boolean;
  armed: boolean;
}

/** Transient state for the create flow (account → DID ceremony → handle). */
export interface CreateFlow {
  claimCode?: string;
  email?: string;
  handle?: string;
  did?: string;
}

/**
 * Share fixtures for the recovery flow fake. The fake never does real share
 * crypto — these strings are recognized by `add_recovery_share` to produce each
 * validation outcome deterministically. Grab them via
 * `window.__harness.state().recovery.fixtures` when driving the screens.
 */
export interface RecoveryFixtures {
  /** Accepted as a valid Share 3 of the current set (base32-style form). */
  share3: string;
  /** Accepted as the same valid Share 3 (word-phrase form). */
  share3Words: string;
  /** Rejected as SHARE_SET_MISMATCH — a share from a different generation. */
  wrongSet: string;
  /** Rejected as SHARE_CHECKSUM — a corrupted/mistyped share. */
  corrupt: string;
}

/** The set_id the fake reports for the current (valid) share generation. */
export const RECOVERY_SET_ID = 0x12345678;
/** The set_id the fake reports for the wrong-generation share fixture. */
export const RECOVERY_WRONG_SET_ID = 0x0dead123;

export function defaultRecoveryFixtures(): RecoveryFixtures {
  return {
    share3: 'HARNESSRECOVERSHARE3B2C3D4E5F6G7A2B3C4D5E6F7RECOVERQ2R3S4T5U6V7W2X3Y',
    share3Words:
      'anchor baker canyon delta ember falcon garnet harbor island jasper kettle lantern ' +
      'meadow nickel orchard pebble quarry ribbon saddle timber umbrella velvet walnut ' +
      'yonder zephyr atlas bramble cedar drift echo fable glacier hollow ivory juniper ' +
      'kindle ledger marble north opal prairie quill',
    wrongSet: 'HARNESSWRONGSETSHARE3B2C3D4E5F6G7A2B3C4D5E6F7WRONGSETQ2R3S4T5U6V7W2',
    corrupt: 'HARNESSCORRUPTSHARE3B2C3D4E5F6G7A2B3C4D5E6F7CORRUPTQ2R3S4T5U6V7W2X3',
  };
}

/** The escrow-release sub-state of the recovery flow fake. */
export interface RecoveryEscrow {
  /** 0 → the OTP call releases immediately; >0 → a pending window opens. */
  delaySecs: number;
  initiated: boolean;
  /** The OTP was consumed and a pending window is open. */
  pendingOpened: boolean;
  /**
   * Polls remaining until the window reads as elapsed. `null` → the window never
   * elapses within the scenario (the pure wait-state screen).
   */
  releaseAfterPolls: number | null;
  /** A signed-in device cancelled the pending release: polls answer 401. */
  cancelled: boolean;
  released: boolean;
}

/** The durable rotation-epilogue record as the fake models it. */
export interface RecoveryEpilogue {
  opSubmitted: boolean;
  escrowDeposited: boolean;
  escrowSkipped: boolean;
  share1Written: boolean;
}

/** Transient + scenario state for the "Recover existing identity" flow. */
export interface RecoveryFlow {
  did: string | null;
  handle: string | null;
  /** Scenario knob: Share 1 auto-loads from the (fake) iCloud Keychain. */
  share1Present: boolean;
  collected: { setId: number; index: number }[];
  escrow: RecoveryEscrow;
  /** Scenario knob: whether verification matches the identity's rotationKeys. */
  verifyOutcome: 'ok' | 'mismatch';
  /** One-shot knob: fail the epilogue's escrow deposit on the next run. */
  failEpilogueEscrowOnce: boolean;
  /** Non-null while a rotation epilogue is pending (drives launch resume). */
  epilogue: RecoveryEpilogue | null;
  fixtures: RecoveryFixtures;
}

export function defaultRecoveryFlow(): RecoveryFlow {
  return {
    did: null,
    handle: null,
    share1Present: true,
    collected: [],
    escrow: {
      delaySecs: 0,
      initiated: false,
      pendingOpened: false,
      releaseAfterPolls: null,
      cancelled: false,
      released: false,
    },
    verifyOutcome: 'ok',
    failEpilogueEscrowOnce: false,
    epilogue: null,
    fixtures: defaultRecoveryFixtures(),
  };
}

/** The full wallet fake store. */
export interface WalletState {
  /** Configured PDS base URL, or null on first launch (drives the config screen). */
  pdsUrl: string | null;
  /** Available handle domains the configured PDS offers. */
  availableUserDomains: string[];
  appearance: 'system' | 'light' | 'dark' | null;
  biometricEnabled: boolean;
  identities: FakeIdentity[];
  create: CreateFlow | null;
  claim: ClaimFlow | null;
  migration: MigrationFlow | null;
  recovery: RecoveryFlow;
}

/** The default PDS the fake reports once configured. */
export const DEFAULT_PDS_URL = 'https://harness.pds.local';

/** A fresh, empty wallet state (fresh-install baseline). */
export function emptyWalletState(): WalletState {
  return {
    pdsUrl: null,
    availableUserDomains: ['.harness.pds.local'],
    appearance: null,
    biometricEnabled: true,
    identities: [],
    create: null,
    claim: null,
    migration: null,
    recovery: defaultRecoveryFlow(),
  };
}

/** Build a PLC-format DID document for an identity (the shape the home screen reads). */
export function makeDidDoc(identity: FakeIdentity): Record<string, unknown> {
  return {
    did: identity.did,
    alsoKnownAs: [`at://${identity.handle}`],
    rotationKeys: identity.rotationKeys,
    verificationMethods: {
      atproto: identity.rotationKeys[0] ?? identity.deviceKeyId,
    },
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: identity.pdsUrl,
      },
    },
  };
}

/** The deterministic recovery `did:key` a re-key derives for a DID, in the fake. */
export function fakeRecoveryKeyId(did: string): string {
  return fakeDeviceKeyId(`${did}:recovery`);
}

/**
 * Seed a fresh identity. `deviceKeyIsRoot` controls whether the device key sits at
 * `rotationKeys[0]` — the "Root key" badge on the home card depends on this. `recoveryKey`
 * (default true) seeds the current (client-generated) recovery model — a 3-key
 * `[device, recovery, PDS]` array, so the identity is NOT offered the old-model re-key
 * upgrade (MM-411). Pass `recoveryKey: false` for a pre-ceremony-inversion old-model
 * identity, whose 2-key doc drives the "Add a recovery key" prompt.
 */
export function seedIdentity(
  opts: {
    handle: string;
    pdsUrl?: string;
    did?: string;
    deviceKeyIsRoot?: boolean;
    recoveryKey?: boolean;
  }
): FakeIdentity {
  const pdsUrl = opts.pdsUrl ?? DEFAULT_PDS_URL;
  const did = opts.did ?? fakePlcDid(opts.handle);
  const deviceKeyId = fakeDeviceKeyId(did);
  const deviceKeyIsRoot = opts.deviceKeyIsRoot ?? true;
  const pdsKey = fakeDeviceKeyId(`${did}:pds`);
  const baseKeys = deviceKeyIsRoot ? [deviceKeyId, pdsKey] : [pdsKey, deviceKeyId];
  // The recovery model inserts the recovery key at rotationKeys[1] whichever key is root
  // (device root: [device, recovery, PDS]; interop-style: [PDS, recovery, device]).
  const rotationKeys =
    (opts.recoveryKey ?? true)
      ? [baseKeys[0], fakeRecoveryKeyId(did), ...baseKeys.slice(1)]
      : baseKeys;
  return {
    did,
    handle: opts.handle,
    pdsUrl,
    deviceKeyId,
    rotationKeys,
    alerts: [],
    agents: [],
    appPasswords: [],
    rekeyStagedRecoveryKey: null,
  };
}

/** Build a fake unauthorized-change alert for the migration/recovery surfaces. */
export function seedAlert(seed: string, createdAt: string): UnauthorizedChange {
  return {
    cid: `bafyharness${hashToken(seed)}`,
    createdAt,
    signingKey: fakeDeviceKeyId(`${seed}:attacker`),
    operation: { type: 'plc_operation', note: 'harness-injected unauthorized change' },
  };
}

/** Build a fake claimed agent with a minimal audit trail. */
export function seedAgent(seed: string, did: string): FakeAgent {
  const registrationId = `reg-${hashToken(seed)}`;
  const now = '2026-07-15T12:00:00.000Z';
  return {
    summary: {
      registrationId,
      registrationType: 'service_auth',
      issuer: `did:web:agent-${hashToken(seed)}.example`,
      subject: did,
      scopes: ['repo:write', 'blob:upload'],
      status: 'claimed',
      createdAt: now,
      updatedAt: now,
      lastUsedAt: now,
    },
    audit: [
      { id: `ev-${hashToken(seed)}-1`, eventType: 'registered', createdAt: now },
      { id: `ev-${hashToken(seed)}-2`, eventType: 'claim_confirmed', did, createdAt: now },
      { id: `ev-${hashToken(seed)}-3`, eventType: 'token_exchanged', createdAt: now },
    ],
  };
}

/** Build a fake app-password entry (metadata only, mirroring the real list route). */
export function seedAppPassword(name: string, privileged = false): AppPasswordEntry {
  return {
    name,
    createdAt: '2026-07-15T12:00:00.000Z',
    privileged,
  };
}

/** The deterministic one-time secret the fake `create_app_password` returns for a name. */
export function fakeAppPasswordSecret(name: string): string {
  // hashToken yields 7 chars, so three rounds guarantee the full 16-char secret shape.
  const token = `${hashToken(name)}${hashToken(`${name}:pad`)}${hashToken(`${name}:pad2`)}`.slice(
    0,
    16
  );
  return `${token.slice(0, 4)}-${token.slice(4, 8)}-${token.slice(8, 12)}-${token.slice(12, 16)}`;
}

/** Find a managed identity by DID, or undefined. */
export function findIdentity(state: WalletState, did: string): FakeIdentity | undefined {
  return state.identities.find((i) => i.did === did);
}

/** Register (or replace) an identity in the store. Idempotent by DID. */
export function upsertIdentity(state: WalletState, identity: FakeIdentity): void {
  const idx = state.identities.findIndex((i) => i.did === identity.did);
  if (idx === -1) state.identities.push(identity);
  else state.identities[idx] = identity;
}
