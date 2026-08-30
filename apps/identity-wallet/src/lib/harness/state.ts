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
import type { SweepRecord, UnauthorizedChange } from '$lib/ipc';
import type {
  AgentSummary,
  AgentAuditEvent,
  AppPasswordEntry,
  BackupLocation,
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

/**
 * A child account this identity has minted for an agent — its own DID and handle, under this
 * identity's rotation authority. Enough to drive the mint: the handle set is what a taken-handle
 * rejection is checked against, and the length is the next derivation index.
 */
export interface FakeChild {
  registrationId: string;
  did: string;
  handle: string;
  /** `claimed` = live, `active` = mid-provisioning, `revoked` = credential turned off. */
  status: 'active' | 'claimed' | 'revoked';
  createdAt: string;
  scopes: string[];
  /**
   * Set once deletion is scheduled. Deleting revokes as a side effect, so this is the only thing
   * separating a retired child from a merely revoked one — the same asymmetry the real list route
   * resolves by joining the deletion tombstone.
   */
  deleteAfter?: string;
  /**
   * The child's own append-only trail. Kept here rather than on the parent's `agents` list
   * because that is what the server does: the child's registration is bound to the child's DID,
   * and the parent reads it through the `/v1/agents` parent arm, not by owning it.
   */
  audit: AgentAuditEvent[];
}

/**
 * The agent grant a default-configured Custos issues (`[agent_auth] granted_scopes`). Real scope
 * tokens, not placeholders: `describeScopes` parses the atproto scope grammar, so an invented
 * token like `blob:upload` renders as literal nonsense ("Upload upload files") and the harness
 * stops being a faithful preview of the permissions screen.
 */
export const HARNESS_AGENT_SCOPES = [
  'atproto',
  'repo:*?action=create&action=update',
  'repo:*?action=delete',
  'blob:*/*',
];

/** One agent bound to an identity, plus its append-only audit trail. */
export interface FakeAgent {
  summary: AgentSummary;
  audit: AgentAuditEvent[];
}

/** One blob as the backup fake models it (a "remote" blob on the PDS, or a mirrored copy). */
export interface FakeBlob {
  cid: string;
  mimeType: string;
  size: number;
}

/**
 * The fake's model of the user-held blob-backup mirror (Media Backup screen).
 * The real thing lives in the iCloud Drive ubiquity container; here `remote` is
 * what the PDS would `listBlobs` and `mirrored` is what a backup pass has copied.
 */
export interface FakeBlobBackup {
  /** The user's opt-in flag. */
  enabled: boolean;
  /** Mirror location; `null` models iOS with iCloud Drive off (the unavailable state). */
  location: BackupLocation | null;
  /** Blobs the account's PDS lists (the backup pass's source set). */
  remote: FakeBlob[];
  /** CIDs a backup pass has mirrored so far (subset of `remote` cids). */
  mirroredCids: string[];
  /**
   * Mirrored CIDs iOS has evicted to placeholders (subset of `mirroredCids`). A restore
   * downloads these before uploading; the fake clears them and reports the count as
   * `downloadedFromIcloud`, modeling the on-demand materialization off-device.
   */
  evictedCids: string[];
  /** When the last backup pass completed, or null if never run. */
  lastBackupAt: string | null;
}

/**
 * The fake's model of the user-held repo-backup snapshot ("Back up your posts").
 * The real thing is a full-CAR snapshot in the iCloud Drive ubiquity container; here
 * `rootCid`/`rev` are what the PDS's `getRepo` would serve, and `mirroredRev` is the rev
 * a backup pass has captured (null = never backed up).
 */
export interface FakeRepoBackup {
  /** The user's opt-in flag. */
  enabled: boolean;
  /** Mirror location; `null` models iOS with iCloud Drive off (the unavailable state). */
  location: BackupLocation | null;
  /** The account's current repo root CID (what a fresh `getRepo` would carry). */
  rootCid: string;
  /** The account's current repo revision (TID). */
  rev: string;
  /** The snapshot size a backup pass would write. */
  sizeBytes: number;
  /** The rev a backup pass has mirrored, or `null` if none — drives the "backed up" state. */
  mirroredRev: string | null;
  /** When the last backup pass completed, or null if never run. */
  lastBackupAt: string | null;
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
  /** The user-held blob-backup mirror (Media Backup screen). */
  blobBackup: FakeBlobBackup;
  /** The user-held repo-backup snapshot ("Back up your posts", same screen). */
  repoBackup: FakeRepoBackup;
  /**
   * The staged recovery key of an in-flight old-model re-key (MM-411), or null when none is
   * staged. Mirrors the per-DID `rekey-staging:{did}` Keychain slot: set by `build_rekey`,
   * survives `submit_rekey`, and is cleared by `confirm_rekey`. Drives `rekey_in_progress`.
   */
  rekeyStagedRecoveryKey: string | null;
  /**
   * The staged recovery key of an in-flight escrow-less self-held kit (MM-456), or null when
   * none is staged. Mirrors the per-DID `self-held-kit-staging:{did}` Keychain slot — a slot
   * distinct from the re-key's, because the two flows disagree about who keeps Share 2. Set by
   * `build_self_held_kit`, survives `submit`, cleared by `confirm`.
   */
  selfHeldKitStagedRecoveryKey: string | null;
  /**
   * Whether this identity carries a completed self-held kit — the durable
   * `{did}:self-held-kit` marker. Drives `self_held_kit_escrow_offer_cmd`, the upsell seam
   * that lights up only if the identity later lands on an escrow-capable host.
   */
  selfHeldKitInstalled: boolean;
  /**
   * Models a device restored from an encrypted backup: the device-key metadata came back,
   * the Secure Enclave key did not. `get_device_key_id` answers DEVICE_KEY_UNUSABLE, which
   * is the only way to reach the home screen's degraded "can no longer sign" state in a
   * browser that has no enclave to empty.
   */
  deviceKeyUnusable: boolean;
  /**
   * Whether this identity holds a delegation seed — the `{did}:delegation-seed` Keychain slot
   * the create ceremony writes and "Enable agent accounts" backfills. Drives
   * `agent_accounts_provisioned`, so an unprovisioned identity can be driven through the
   * provisioning gate in the browser. Identities created before the seed existed are the
   * unprovisioned case; seed one with `agentAccountsProvisioned: false`.
   */
  agentAccountsProvisioned: boolean;
  /**
   * The child accounts this identity has minted for agents. Each mint appends one, so
   * `children.length` is the next child-key derivation index — the browser stand-in for the
   * `{did}:child-index` Keychain slot.
   */
  children: FakeChild[];
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
  /** True for a sovereign disaster-recovery session (no source PDS). */
  recovery?: boolean;
  /** Disaster recovery: the self-controlled signing key has been enrolled. */
  recoveryKeyEnrolled?: boolean;
  /** Disaster recovery: polls before the enrolled key reads as visible. */
  recoveryVisibilityPollsRemaining?: number;
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
  /**
   * What the configured PDS advertises under `describeServer`'s `custos` extension.
   * Defaults to a fully-featured Custos, since that is what the fake host stands in for;
   * set `capabilities: []` (and `version: null`) from the console to drive the screens the
   * way a reference PDS or bsky.social would — a host with no Custos capabilities at all,
   * which is what closes the create flow's gate. Set `reached: false` instead to model a
   * host that could not be asked, which must NOT read as "advertises nothing".
   */
  pdsCapabilities: { version: string | null; reached: boolean; capabilities: string[] };
  appearance: 'system' | 'light' | 'dark' | null;
  biometricEnabled: boolean;
  /**
   * App-global background media-backup settings (the iOS BGProcessingTask policy). Global,
   * not per-identity: the sweep is one task covering every opted-in DID. Off-device this is
   * just stored/echoed — the real scheduling is a device concern the harness never runs.
   */
  backgroundBackupSettings: {
    backgroundEnabled: boolean;
    requireExternalPower: boolean;
    wifiOnly: boolean;
  };
  /**
   * The device's push-notification state. App-global, like the real thing: one notification
   * keypair and one `deviceUuid` per install, because a push carries no DID and the extension
   * would have no way to choose among per-identity keys.
   *
   * `apnsToken` is null by default — a browser has no APNs, which is exactly the
   * `AWAITING_APNS_TOKEN` state the real registration path reports off-device. Set it via
   * `window.__harness.state()` to drive the registered path.
   */
  notifications: {
    deviceUuid: string;
    notificationKeyId: string;
    /**
     * Whether the device has minted its notification keypair. Tracked rather than inferred from
     * `apnsToken`, because the real `get_notification_diagnostics` reads the key straight off the
     * Keychain scalar and never consults the token — a device that registered and later lost its
     * token still reports its key.
     */
    notificationKeyMinted: boolean;
    apnsToken: string | null;
    /**
     * Whether this identity's host runs a notification relay — what the real routes answer 501
     * on when it is false.
     *
     * Its own flag, not a capability: the server's 501 comes from `[notifications] relay` being
     * unset in its config, and Custos advertises no notifications capability at all. Reusing
     * `sovereignSessions` as a proxy would both misdescribe the wire and make "a Custos with
     * sovereign sessions but no relay" unreachable, since that flag also drives the create gate,
     * unlock routing, and removal.
     */
    relaySupported: boolean;
    /** Pinned sender keys per hosting server — `kid` is instance-scoped, so the host is part
     *  of the key's identity. */
    pinnedHosts: Record<string, { kid: number; publicKey: string }[]>;
    /**
     * What the Notification Service Extension could not verify, newest first.
     *
     * Empty by default, and populated only by the `notifications-unverified` scenario — a
     * browser has no extension and no push, so nothing can produce one naturally, and
     * `window.__harness.state()` is a deep clone rather than the live store, so it cannot be
     * seeded from the console either.
     */
    recentFailures: { at: string; reason: string; kid: number | null }[];
    /** DIDs whose host has been told about this device (what the register call recorded). */
    registeredDids: string[];
  };
  identities: FakeIdentity[];
  /**
   * The PLC monitor's sweep log, newest first — what the Protection surface reads back.
   * Appended to by `check_identity_status` (the fake's only real sweep) and seeded with
   * the unattended passes a browser has no timer to run; see `recordFakeSweep`.
   */
  monitorSweeps: SweepRecord[];
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
    pdsCapabilities: {
      version: '0.0.0-harness',
      reached: true,
      capabilities: [
        'createCeremony',
        'escrow',
        'sovereignSessions',
        'agents',
        'walletConsent',
        'walletAccountDelete',
        'didWebHosting',
        'appPasswordPersonalDetails',
      ],
    },
    appearance: null,
    biometricEnabled: true,
    backgroundBackupSettings: {
      backgroundEnabled: true,
      requireExternalPower: false,
      wifiOnly: false,
    },
    notifications: {
      deviceUuid: 'harness-device-0001',
      notificationKeyId: 'did:key:zDnaeharnessnotificationkey000000000000000000',
      notificationKeyMinted: false,
      // No APNs in a browser. Leaving it null is the honest default and puts the registration
      // path in the same `AWAITING_APNS_TOKEN` state a simulator produces.
      apnsToken: null,
      // The default host in the harness is a Custos with notifications configured; set this
      // false to model a relay-less one without disturbing any other capability.
      relaySupported: true,
      pinnedHosts: {},
      recentFailures: [],
      registeredDids: [],
    },
    identities: [],
    monitorSweeps: [],
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
    deviceKeyUnusable?: boolean;
    agentAccountsProvisioned?: boolean;
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
    blobBackup: seedBlobBackup(did),
    repoBackup: seedRepoBackup(did),
    rekeyStagedRecoveryKey: null,
    selfHeldKitStagedRecoveryKey: null,
    selfHeldKitInstalled: false,
    deviceKeyUnusable: opts.deviceKeyUnusable ?? false,
    agentAccountsProvisioned: opts.agentAccountsProvisioned ?? true,
    children: [],
  };
}

/**
 * Default blob-backup model for a seeded identity: backup available (fake "iCloud")
 * but not yet opted in, with a small deterministic remote blob set so the Media
 * Backup screen has something to mirror. Script other states via
 * `window.__harness.state()` inspection + `failNext`, or mutate before reseeding.
 */
export function seedBlobBackup(did: string): FakeBlobBackup {
  return {
    enabled: false,
    location: 'icloud',
    remote: [
      { cid: `bafkharness${hashToken(`${did}:avatar`)}`, mimeType: 'image/jpeg', size: 184_320 },
      { cid: `bafkharness${hashToken(`${did}:banner`)}`, mimeType: 'image/png', size: 512_000 },
      { cid: `bafkharness${hashToken(`${did}:clip`)}`, mimeType: 'video/mp4', size: 8_388_608 },
    ],
    mirroredCids: [],
    evictedCids: [],
    lastBackupAt: null,
  };
}

/**
 * Default repo-backup model for a seeded identity: backup available (fake "iCloud") but
 * not yet opted in, with a deterministic current root/rev so the "Back up your posts"
 * section has a snapshot to capture. Script other states via `window.__harness.state()`
 * inspection + `failNext`, or mutate before reseeding.
 */
export function seedRepoBackup(did: string): FakeRepoBackup {
  return {
    enabled: false,
    location: 'icloud',
    rootCid: `bafyharness${hashToken(`${did}:repo-root`)}`,
    rev: `3lharness${hashToken(`${did}:repo-rev`).slice(0, 6)}`,
    sizeBytes: 2_400_000,
    mirroredRev: null,
    lastBackupAt: null,
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
      scopes: [...HARNESS_AGENT_SCOPES],
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
export function seedAppPassword(
  name: string,
  privileged = false,
  personalDetails = false
): AppPasswordEntry {
  return {
    name,
    createdAt: '2026-07-15T12:00:00.000Z',
    privileged,
    personalDetails,
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
