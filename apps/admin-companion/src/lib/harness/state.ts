/**
 * Stateful in-memory fake for the admin-companion (Brass Console) harness.
 *
 * Pure TypeScript — no Tauri, no DOM, no network — so it is unit-testable in the Node
 * vitest environment (see `state.test.ts`). Mirrors the identity-wallet harness layout
 * deliberately; the two apps share no frontend code, so the structure is duplicated with
 * an identical shape rather than extracted into a shared package.
 *
 * The domain modeled is one operator device paired with zero or more relays, each relay
 * carrying its own server-side world: registered admin devices, accounts, claim-code
 * inventory, in-flight transfers, and a server-health readout.
 */
import type {
  DevicePublicKey,
  Pairing,
  AdminDevice,
  AccountFlag,
  AccountListEntry,
  AuditEventEntry,
  ClaimCodeEntry,
  TransferEntry,
  HostedSpaceEntry,
  ServerHealth,
} from '$lib/ipc';

/** Deterministic base36 token from a string — keeps fakes readable and stable. */
export function hashToken(seed: string): string {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h = (h ^ seed.charCodeAt(i)) >>> 0;
    h = (h * 16777619) >>> 0;
  }
  return h.toString(36).padStart(7, '0').slice(0, 12);
}

/** A stable fake `did:key` for this operator device. */
export function fakeDeviceKey(seed = 'admin-device'): DevicePublicKey {
  const multibase = `zAdminHarness${hashToken(seed)}`;
  return { multibase, keyId: `did:key:${multibase}` };
}

/** A plausible `did:plc` for an account. */
export function fakeAccountDid(seed: string): string {
  return `did:plc:acct${hashToken(seed)}`;
}

/** One paired relay plus everything the operator screens read from it. */
export interface FakeRelay {
  /** Stable local pairing id (UUID-ish); the handle every screen addresses. */
  pairingId: string;
  nickname: string;
  relayUrl: string;
  /** This device's relay-assigned registration id (equals one `devices[].id`). */
  deviceId: string;
  deviceLabel: string;
  devices: AdminDevice[];
  accounts: AccountListEntry[];
  claimCodes: ClaimCodeEntry[];
  transfers: TransferEntry[];
  /** Server-wide admin audit log, newest first (matching the relay's ordering). */
  auditEvents: AuditEventEntry[];
  health: ServerHealth;
  /** Per-account takedown state, keyed by DID. */
  takedowns: Record<string, boolean>;
  /**
   * The Atproto Spaces this relay stores something about. Seeded with both kinds, because
   * the difference is what the Spaces screen exists to show: one the relay governs, and one
   * governed by a foreign server where takedown is the only lever.
   */
  spaces: HostedSpaceEntry[];
}

/** The full admin fake store. */
export interface AdminState {
  deviceKey: DevicePublicKey;
  biometricEnabled: boolean;
  /** Active pairing id, or null (fresh install / ambiguous removal). */
  active: string | null;
  relays: FakeRelay[];
}

const FIXED_NOW = '2026-07-15 12:00:00';
const FIXED_NOW_UNIX = Math.floor(Date.parse('2026-07-15T12:00:00Z') / 1000);

/** A fresh, unpaired admin state. */
export function emptyAdminState(): AdminState {
  return {
    deviceKey: fakeDeviceKey(),
    biometricEnabled: true,
    active: null,
    relays: [],
  };
}

/** Convert a relay to the `Pairing` wire shape `list_pairings` returns. */
export function toPairing(relay: FakeRelay): Pairing {
  return {
    id: relay.pairingId,
    nickname: relay.nickname,
    relayUrl: relay.relayUrl,
    deviceId: relay.deviceId,
    deviceLabel: relay.deviceLabel,
  };
}

/** Find a relay by pairing id. */
export function findRelay(state: AdminState, pairingId: string): FakeRelay | undefined {
  return state.relays.find((r) => r.pairingId === pairingId);
}

/** The active relay, or undefined when nothing is selected. */
export function activeRelay(state: AdminState): FakeRelay | undefined {
  return state.active ? findRelay(state, state.active) : undefined;
}

/** Build a healthy server-health readout, adjusted by account count. */
export function healthyServer(
  accounts: number,
  opts?: { degraded?: boolean; flagged?: number }
): ServerHealth {
  const degraded = opts?.degraded ?? false;
  // A completed sweep: recent when healthy, >24h stale when degraded (the staleness glyph).
  const sweep = (offsetSecs: number, swept: number, errors = 0) => ({
    completedAt: FIXED_NOW_UNIX - (degraded ? 60 * 60 * 30 : offsetSecs),
    swept,
    errors,
  });
  // A sweep that is alive but skipping work — the OTHER fault, which staleness cannot
  // express. Deliberately keeps its fresh timestamp even when degraded, so the degraded
  // scenario shows both faults side by side rather than collapsing them into one look.
  const sweepWithErrors = (offsetSecs: number, swept: number, errors: number) => ({
    completedAt: FIXED_NOW_UNIX - offsetSecs,
    swept,
    errors,
  });
  return {
    version: '0.5.0',
    uptimeSeconds: degraded ? 90 : 60 * 60 * 24 * 3,
    accounts: {
      total: accounts,
      active: accounts,
      deactivated: 0,
      suspended: 0,
      takendown: 0,
      flagged: opts?.flagged ?? 0,
    },
    storage: {
      blobCount: accounts * 12,
      blobBytes: accounts * 4_500_000,
      blockCount: accounts * 340,
      // Healthy is a REPORTED zero (the all-clear), not an absent field. Degraded shows
      // the standing population that means bytes intact, ownership gone — the alarm the
      // sweep rows cannot raise, since blob GC keeps completing on schedule beside it.
      blobUnownedCount: degraded ? 534 : 0,
      blobUnownedBytes: degraded ? 1_207_959_552 : 0,
    },
    firehose: {
      currentSeq: accounts * 1000,
      subscribers: degraded ? 0 : 2,
      retainedEvents: accounts * 50,
      backfillWindowSeconds: accounts > 0 ? 3600 : null,
    },
    // Degraded shows all four sweep states at once: blob GC alive but leaking one
    // account's blobs, two sweeps gone stale, and one that has never run.
    sweeps: {
      blobGc: degraded ? sweepWithErrors(300, 3, 1) : sweep(300, 3),
      firehoseGc: sweep(600, 12),
      accountReaper: degraded ? null : sweep(900, 0),
      agentClaimSweep: sweep(1200, 1),
    },
  };
}

/** Build a fake admin device row. `isThisDevice` marks the operator's own registration. */
export function makeAdminDevice(
  seed: string,
  opts?: { revoked?: boolean; label?: string }
): AdminDevice {
  const id = `dev-${hashToken(seed)}`;
  return {
    id,
    label: opts?.label ?? `iPhone ${hashToken(seed).slice(0, 4)}`,
    publicKey: `did:key:zDev${hashToken(seed)}`,
    platform: 'ios',
    scopes: 'admin',
    status: opts?.revoked ? 'revoked' : 'active',
    createdAt: FIXED_NOW,
    lastSeenAt: opts?.revoked ? null : FIXED_NOW,
    revokedAt: opts?.revoked ? FIXED_NOW : null,
  };
}

/** Build a fake account row. */
export function makeAccount(
  seed: string,
  opts?: {
    status?: AccountListEntry['status'];
    handle?: string | null;
    flags?: AccountFlag[];
    /** Override the generated did:plc — used to seed a did:web account. */
    did?: string;
    /** `null` stands in for a relay predating the flag. */
    didWebHosting?: boolean | null;
  }
): AccountListEntry {
  return {
    did: opts?.did ?? fakeAccountDid(seed),
    handle: opts?.handle ?? `${seed}.harness.relay`,
    createdAt: FIXED_NOW,
    status: opts?.status ?? 'active',
    totalBytes: 4_500_000 + hashInt(seed) % 40_000_000,
    quotaUsedPct: hashInt(seed) % 100,
    flags: opts?.flags ?? [],
    // did:plc accounts are never Custos-hosted — their document lives on plc.directory.
    didWebHosting: opts?.didWebHosting ?? false,
  };
}

/** The harness's stand-in watched labeler. */
export const FAKE_LABELER_DID = 'did:plc:harnesslabelermoderation';

/** Build one in-force labeler flag. */
export function makeFlag(val = 'spam', cts = '2026-07-14T08:00:00Z'): AccountFlag {
  return { val, labelerDid: FAKE_LABELER_DID, cts };
}

/** Build a fake claim-code entry. */
export function makeClaimCode(
  seed: string,
  status: ClaimCodeEntry['status'] = 'pending'
): ClaimCodeEntry {
  const base: ClaimCodeEntry = {
    code: `CLAIM-${hashToken(seed).toUpperCase().slice(0, 8)}`,
    status,
    createdAt: FIXED_NOW,
    expiresAt: '2026-07-22 12:00:00',
  };
  if (status === 'redeemed') base.redeemedAt = FIXED_NOW;
  if (status === 'revoked') base.revokedAt = FIXED_NOW;
  return base;
}

/** Build a fake in-flight transfer. */
export function makeTransfer(
  seed: string,
  status: TransferEntry['status'] = 'pending'
): TransferEntry {
  const base: TransferEntry = {
    id: `xfer-${hashToken(seed)}`,
    did: fakeAccountDid(`${seed}:xfer`),
    handle: `${seed}.harness.relay`,
    status,
    createdAt: FIXED_NOW,
    expiresAt: '2026-07-16 12:00:00',
  };
  if (status !== 'pending') {
    base.acceptedAt = FIXED_NOW;
    base.acceptedDevicePlatform = 'ios';
  }
  return base;
}

/** Build a fake server-wide admin audit event. */
export function makeAuditEvent(
  seed: string,
  opts: {
    actor: string;
    action: string;
    subject?: string | null;
    outcome?: string;
    detail?: Record<string, unknown> | null;
    createdAt?: string;
  }
): AuditEventEntry {
  return {
    id: `audit-${hashToken(seed)}`,
    actor: opts.actor,
    action: opts.action,
    subject: opts.subject ?? null,
    outcome: opts.outcome ?? 'ok',
    detail: opts.detail ?? null,
    createdAt: opts.createdAt ?? FIXED_NOW,
  };
}

function hashInt(seed: string): number {
  return parseInt(hashToken(seed).replace(/[^0-9]/g, '0').slice(0, 6), 10) || 0;
}

/**
 * Seed one fully-populated relay. `deviceId` is set to the first device's id so the
 * "this device" row resolves and self-revoke is refused correctly.
 */
export function seedRelay(opts: {
  nickname: string;
  relayUrl: string;
  accounts?: number;
  degraded?: boolean;
  /** How many accounts carry watched-labeler flags (from the end of the DID-seed list,
   *  so flagged rows visibly jump the default order). */
  flagged?: number;
}): FakeRelay {
  const seed = opts.nickname;
  const pairingId = `pair-${hashToken(seed)}`;
  const thisDevice = makeAdminDevice(`${seed}:self`, { label: `${opts.nickname} console` });
  const otherDevice = makeAdminDevice(`${seed}:other`, { label: 'Spare iPad' });
  const accountCount = opts.accounts ?? 3;
  const flaggedCount = Math.min(opts.flagged ?? 0, accountCount);
  const accounts = Array.from({ length: accountCount }, (_, i) => {
    const flagged = i >= accountCount - flaggedCount;
    // One did:web account per relay, so the hosting line has somewhere to appear — it is
    // suppressed on did:plc rows, where the question doesn't arise. Degraded seeds it as
    // NOT served, the reading the flag exists to tell apart from a broken serve path.
    const didWeb = i === 1;
    return makeAccount(`${seed}:acct${i}`, {
      did: didWeb ? `did:web:acct${i}.${seed}.example` : undefined,
      handle: didWeb ? `acct${i}.${seed}.example` : undefined,
      didWebHosting: didWeb ? !opts.degraded : false,
      status: i === 0 && opts.degraded ? 'suspended' : 'active',
      // The first flagged account carries two labels so the row shows a stack.
      flags: flagged
        ? i === accountCount - flaggedCount
          ? [makeFlag('spam'), makeFlag('!hide', '2026-07-15T10:30:00Z')]
          : [makeFlag('platform-manipulation')]
        : [],
    });
  });
  return {
    pairingId,
    nickname: opts.nickname,
    relayUrl: opts.relayUrl,
    deviceId: thisDevice.id,
    deviceLabel: thisDevice.label,
    devices: [thisDevice, otherDevice],
    accounts,
    claimCodes: [
      makeClaimCode(`${seed}:c1`, 'pending'),
      makeClaimCode(`${seed}:c2`, 'redeemed'),
      makeClaimCode(`${seed}:c3`, 'expired'),
    ],
    transfers: opts.degraded
      ? [makeTransfer(`${seed}:t1`, 'accepted')]
      : [makeTransfer(`${seed}:t1`, 'pending')],
    spaces: [
      {
        uri: `at://${accounts[0]?.did ?? fakeAccountDid(`${seed}:acct0`)}/space/org.example.bucket/main`,
        authorityDid: accounts[0]?.did ?? fakeAccountDid(`${seed}:acct0`),
        localAuthority: true,
        createdAt: '2026-07-10 08:00:00',
        repoCount: 3,
        recordCount: 128,
        // A degraded relay has already been acted on, so the screen's restore path and
        // the "refused" chip both have a scenario without an operator tap first.
        takendownAt: opts.degraded ? '2026-07-14 22:10:00' : undefined,
      },
      {
        uri: 'at://did:plc:foreignauthorityaaaaaaaa/space/com.atmoboards.forum/general',
        authorityDid: 'did:plc:foreignauthorityaaaaaaaa',
        localAuthority: false,
        createdAt: '2026-07-12 16:40:00',
        repoCount: 1,
        recordCount: 42,
      },
    ],
    // Newest first, matching the relay: a mixed trail exercising every column the
    // screen renders — device attribution, subjects, detail facts, and a no-subject
    // server-wide action.
    auditEvents: [
      makeAuditEvent(`${seed}:a1`, {
        actor: `device:${thisDevice.id}`,
        action: 'claim_codes_minted',
        detail: { count: 3, expiresInHours: 24 },
        createdAt: '2026-07-15 11:45:00',
      }),
      makeAuditEvent(`${seed}:a2`, {
        actor: 'master-token',
        action: 'request_crawl',
        detail: { requested: 1, accepted: 1 },
        createdAt: '2026-07-15 10:30:00',
      }),
      makeAuditEvent(`${seed}:a3`, {
        actor: `device:${thisDevice.id}`,
        action: 'account_takedown',
        subject: accounts[0]?.did ?? fakeAccountDid(`${seed}:acct0`),
        detail: { resultingStatus: 'takendown' },
        createdAt: '2026-07-15 09:20:00',
      }),
      makeAuditEvent(`${seed}:a4`, {
        actor: 'master-token',
        action: 'device_revoked',
        subject: otherDevice.id,
        outcome: 'revoked',
        createdAt: '2026-07-14 18:05:00',
      }),
      makeAuditEvent(`${seed}:a5`, {
        actor: 'pairing-code',
        action: 'device_registered',
        subject: thisDevice.id,
        detail: { label: thisDevice.label, platform: 'ios' },
        createdAt: '2026-07-14 09:00:00',
      }),
    ],
    health: healthyServer(accountCount, { degraded: opts.degraded, flagged: flaggedCount }),
    takedowns: {},
  };
}

export { FIXED_NOW, FIXED_NOW_UNIX };
