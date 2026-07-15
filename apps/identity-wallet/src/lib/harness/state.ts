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

/**
 * Seed a fresh identity. `deviceKeyIsRoot` controls whether the device key sits at
 * `rotationKeys[0]` — the "Root key" badge on the home card depends on this.
 */
export function seedIdentity(
  opts: {
    handle: string;
    pdsUrl?: string;
    did?: string;
    deviceKeyIsRoot?: boolean;
  }
): FakeIdentity {
  const pdsUrl = opts.pdsUrl ?? DEFAULT_PDS_URL;
  const did = opts.did ?? fakePlcDid(opts.handle);
  const deviceKeyId = fakeDeviceKeyId(did);
  const deviceKeyIsRoot = opts.deviceKeyIsRoot ?? true;
  const pdsKey = fakeDeviceKeyId(`${did}:pds`);
  const rotationKeys = deviceKeyIsRoot ? [deviceKeyId, pdsKey] : [pdsKey, deviceKeyId];
  return {
    did,
    handle: opts.handle,
    pdsUrl,
    deviceKeyId,
    rotationKeys,
    alerts: [],
    agents: [],
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
