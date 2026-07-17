/**
 * The command registry for the admin-companion fake harness.
 *
 * Maps every Tauri command the frontend can `invoke()` to an in-memory handler that
 * reads/writes {@link AdminState} and returns the exact typed shape (and typed
 * {@link RelayClientError} rejections) the real Rust command would.
 *
 * Coverage is enforced (browser-harness.AC1.3): `Registry` is
 * `Record<CommandName, Handler>` (compile-time completeness) and `registry.test.ts`
 * greps the live `$lib/ipc` source for `invoke('…')` names and asserts each is a key —
 * so a command added to `ipc.ts` without a handler fails `pnpm test`.
 */
import type {
  DevicePublicKey,
  PairingsState,
  AdminDevice,
  SubjectStatus,
  AccountUsage,
  AccountStorage,
  ServerHealth,
  RelayStatus,
  RequestCrawlResult,
  AccountList,
  ClaimCodeInventory,
  RevokedClaimCode,
  TransferList,
  CancelledTransfer,
  RevokedCredentials,
  RepairedEmail,
  IssuedResetToken,
} from '$lib/ipc';
import {
  activeRelay,
  findRelay,
  hashToken,
  makeClaimCode,
  toPairing,
  seedRelay,
  type AdminState,
  type FakeRelay,
} from './state';

export type Handler = (args: Record<string, unknown>) => unknown | Promise<unknown>;

/** Every command the admin frontend can invoke. Cross-checked by `registry.test.ts`. */
export type CommandName =
  | 'get_or_create_device_key'
  | 'pair_device'
  | 'list_pairings'
  | 'set_active_pairing'
  | 'rename_pairing'
  | 'generate_claim_code'
  | 'revoke_self'
  | 'unpair'
  | 'list_admin_devices'
  | 'revoke_admin_device'
  | 'get_subject_status'
  | 'update_subject_status'
  | 'get_account_usage'
  | 'get_account_storage'
  | 'get_server_health'
  | 'get_relay_status'
  | 'request_crawl'
  | 'list_accounts'
  | 'list_claim_codes'
  | 'revoke_claim_code'
  | 'list_transfers'
  | 'cancel_transfer'
  | 'revoke_account_credentials'
  | 'set_account_email'
  | 'issue_reset_token'
  | 'biometric_enabled'
  | 'set_biometric_enabled'
  // biometric plugin gate (driven by $lib/biometric — resolves = allow)
  | 'plugin:biometric|authenticate'
  | 'plugin:biometric|status';

export type Registry = Record<CommandName, Handler>;

/** A typed relay-client rejection, matching `RelayClientError` at the `$lib/ipc` seam. */
function relayError(error: unknown): never {
  throw error;
}

/** Resolve the relay a command addresses by pairing id, or throw NO_SUCH_PAIRING. */
function requireRelay(state: AdminState, pairingId: string): FakeRelay {
  const relay = findRelay(state, pairingId);
  if (!relay) relayError({ code: 'NO_SUCH_PAIRING' });
  return relay!;
}

export function buildRegistry(state: AdminState): Registry {
  return {
    get_or_create_device_key: (): DevicePublicKey => state.deviceKey,

    pair_device: (args): string => {
      const relay = seedRelay({
        nickname: String(args.nickname ?? 'relay'),
        relayUrl: String(args.relayUrl ?? 'https://harness.relay'),
      });
      // The freshly-paired device carries the operator-supplied label.
      relay.deviceLabel = String(args.label ?? relay.deviceLabel);
      relay.devices[0].label = relay.deviceLabel;
      state.relays.push(relay);
      state.active = relay.pairingId;
      return relay.deviceId;
    },

    list_pairings: (): PairingsState => ({
      active: state.active,
      pairings: state.relays.map(toPairing),
    }),

    set_active_pairing: (args) => {
      const id = String(args.id ?? '');
      requireRelay(state, id);
      state.active = id;
      return null;
    },

    rename_pairing: (args) => {
      const relay = requireRelay(state, String(args.id ?? ''));
      relay.nickname = String(args.nickname ?? relay.nickname);
      return null;
    },

    generate_claim_code: (): string => {
      const relay = activeRelay(state);
      if (!relay) relayError({ code: 'NOT_PAIRED' });
      const code = makeClaimCode(`${relay!.pairingId}:${relay!.claimCodes.length}`, 'pending');
      relay!.claimCodes.unshift(code);
      return code.code;
    },

    revoke_self: (args) => {
      const id = String(args.id ?? '');
      requireRelay(state, id);
      removePairing(state, id);
      return null;
    },

    unpair: (args) => {
      const id = String(args.id ?? '');
      requireRelay(state, id);
      removePairing(state, id);
      return null;
    },

    list_admin_devices: (args): AdminDevice[] =>
      requireRelay(state, String(args.pairingId ?? '')).devices,

    revoke_admin_device: (args): AdminDevice => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const deviceId = String(args.deviceId ?? '');
      if (deviceId === relay.deviceId) relayError({ code: 'SELF_REVOKE_NOT_ALLOWED' });
      const device = relay.devices.find((d) => d.id === deviceId);
      if (!device) relayError({ code: 'RELAY_REJECTED', status: 404, message: 'device not found' });
      device!.status = 'revoked';
      device!.revokedAt = '2026-07-15 12:00:00';
      device!.lastSeenAt = null;
      return device!;
    },

    get_subject_status: (args): SubjectStatus =>
      subjectStatus(requireRelay(state, String(args.pairingId ?? '')), String(args.did ?? '')),

    update_subject_status: (args): SubjectStatus => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const did = String(args.did ?? '');
      relay.takedowns[did] = Boolean(args.applied);
      return subjectStatus(relay, did);
    },

    get_account_usage: (args): AccountUsage => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const did = String(args.did ?? '');
      const account = relay.accounts.find((a) => a.did === did);
      const n = hashInt(did);
      return {
        recordsCount: 40 + (n % 400),
        commitsCount: 20 + (n % 200),
        blobsCount: 3 + (n % 30),
        storageBytes: account?.totalBytes ?? 4_500_000,
        lastActive: '2026-07-15 09:00:00',
      };
    },

    get_account_storage: (args): AccountStorage => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const did = String(args.did ?? '');
      const account = relay.accounts.find((a) => a.did === did);
      const totalBytes = account?.totalBytes ?? 4_500_000;
      const quotaBytes = 2_000_000_000;
      return {
        blobCount: 3 + (hashInt(did) % 30),
        totalBytes,
        quotaBytes,
        quotaUsedPct: Math.round((totalBytes / quotaBytes) * 100),
        largestBlob: { cid: `bafyharness${hashToken(did)}`, size: Math.floor(totalBytes / 3) },
      };
    },

    get_server_health: (args): ServerHealth =>
      requireRelay(state, String(args.pairingId ?? '')).health,

    get_relay_status: (args): RelayStatus => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      // A healthy, actively-crawling relay a few events behind our head — exercises the
      // "crawling / behind-by-N" state of the block.
      const head = relay.health.firehose.currentSeq;
      const relaySeq = Math.max(0, head - 3);
      return {
        relayHost: 'bsky.network',
        reachable: true,
        relayStatus: 'active',
        relaySeq,
        accountCount: relay.accounts.length,
        pdsHeadSeq: head,
        gap: head - relaySeq,
        relayCursorAt: '2026-07-15T09:00:00.000Z',
        detail: null,
        checkedAt: '2026-07-15T12:00:00.000Z',
      };
    },

    request_crawl: (args): RequestCrawlResult => {
      // Validate the pairing (a signed action against a specific relay), then report the
      // relay accepting the crawl.
      requireRelay(state, String(args.pairingId ?? ''));
      return {
        requested: 1,
        accepted: 1,
        relays: [{ host: 'bsky.network', accepted: true, detail: null }],
      };
    },

    list_accounts: (args): AccountList => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const status = args.status ? String(args.status) : null;
      const q = args.q ? String(args.q).toLowerCase() : null;
      let rows = relay.accounts;
      if (status) rows = rows.filter((a) => a.status === status);
      if (q) rows = rows.filter((a) => a.did.toLowerCase().includes(q) || (a.handle ?? '').toLowerCase().includes(q));
      return { accounts: rows, quotaBytes: 2_000_000_000, cursor: null };
    },

    list_claim_codes: (args): ClaimCodeInventory => ({
      codes: requireRelay(state, String(args.pairingId ?? '')).claimCodes,
    }),

    revoke_claim_code: (args): RevokedClaimCode => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const code = String(args.code ?? '');
      const entry = relay.claimCodes.find((c) => c.code === code);
      if (!entry) relayError({ code: 'RELAY_REJECTED', status: 404, message: 'code not found' });
      if (entry!.status === 'redeemed') relayError({ code: 'RELAY_REJECTED', status: 409, message: 'already redeemed' });
      entry!.status = 'revoked';
      entry!.revokedAt = '2026-07-15 12:00:00';
      return { code, status: 'revoked' };
    },

    list_transfers: (args): TransferList => ({
      transfers: requireRelay(state, String(args.pairingId ?? '')).transfers,
    }),

    cancel_transfer: (args): CancelledTransfer => {
      const relay = requireRelay(state, String(args.pairingId ?? ''));
      const transferId = String(args.transferId ?? '');
      const transfer = relay.transfers.find((t) => t.id === transferId);
      if (!transfer) relayError({ code: 'RELAY_REJECTED', status: 404, message: 'transfer not found' });
      const revokedDeviceCredential = transfer!.status !== 'pending';
      relay.transfers = relay.transfers.filter((t) => t.id !== transferId);
      return { id: transferId, status: 'cancelled', revokedDeviceCredential };
    },

    revoke_account_credentials: (args): RevokedCredentials => {
      requireRelay(state, String(args.pairingId ?? ''));
      return {
        sessionsRevoked: 2,
        appPasswordsRevoked: 1,
        oauthTokensRevoked: 3,
        oauthCodesRevoked: 0,
        transferDeviceTokensRevoked: 0,
      };
    },

    set_account_email: (args): RepairedEmail => {
      requireRelay(state, String(args.pairingId ?? ''));
      return {
        did: String(args.did ?? ''),
        email: String(args.email ?? ''),
        emailConfirmed: false,
      };
    },

    issue_reset_token: (args): IssuedResetToken => {
      requireRelay(state, String(args.pairingId ?? ''));
      return {
        did: String(args.did ?? ''),
        token: `RESET-${hashToken(String(args.did ?? '')).toUpperCase().slice(0, 10)}`,
        expiresIn: 3600,
      };
    },

    biometric_enabled: (): boolean => state.biometricEnabled,
    set_biometric_enabled: (args) => {
      state.biometricEnabled = Boolean(args.enabled);
      return null;
    },

    'plugin:biometric|authenticate': () => null,
    'plugin:biometric|status': () => ({
      isAvailable: true,
      biometryType: 1,
      error: null,
      errorCode: null,
    }),
  };
}

function subjectStatus(relay: FakeRelay, did: string): SubjectStatus {
  return {
    subject: { $type: 'com.atproto.admin.defs#repoRef', did },
    takedown: { applied: relay.takedowns[did] ?? false },
  };
}

/** Remove a pairing, applying the same active-pointer rules the Rust side uses. */
function removePairing(state: AdminState, pairingId: string): void {
  const wasActive = state.active === pairingId;
  state.relays = state.relays.filter((r) => r.pairingId !== pairingId);
  if (state.relays.length === 1) {
    // A sole remaining pairing is always auto-promoted to active.
    state.active = state.relays[0].pairingId;
  } else if (wasActive) {
    // Removing the active pairing with two-or-more remaining clears the selection.
    state.active = null;
  }
}

function hashInt(seed: string): number {
  return parseInt(hashToken(seed).replace(/[^0-9]/g, '0').slice(0, 6), 10) || 0;
}
