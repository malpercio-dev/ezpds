/**
 * The command registry for the identity-wallet fake harness.
 *
 * Maps every Tauri command name the frontend can `invoke()` to an in-memory handler
 * that reads/writes {@link WalletState} and returns the exact typed shape the real Rust
 * command would (the error shapes documented at the `$lib/ipc` seam included).
 *
 * Coverage is enforced two ways (browser-harness.AC1.3):
 *  - `Registry` is `Record<CommandName, Handler>`, so the object literal below must
 *    provide a handler for every name in the {@link CommandName} union (compile error
 *    otherwise);
 *  - `registry.test.ts` greps the real `$lib/ipc` source for `invoke('…')` names and
 *    asserts each is a key here — so a command added to `ipc.ts` without a handler fails
 *    `pnpm test` even if the union was not updated.
 */
import type {
  IdentityInfo,
  VerifiedClaimOp,
  ClaimResult,
  SessionReady,
  SovereignLoginResult,
  IdentityStatus,
  SignedRecoveryOp,
  RemovalOutcome,
  SignedMigrationOp,
  MigrationPathDecision,
  PreparedMigration,
  AccountStatus,
  DidWebMigrationDocument,
  AgentSummary,
  AgentAuditPage,
  AgentClaimPreview,
  AgentClaimConfirmation,
  RegisterHandleResult,
  CreateAccountResult,
  DIDCeremonyResult,
  DidWebPreparation,
} from '$lib/ipc';
import {
  DEFAULT_PDS_URL,
  fakeDeviceKeyId,
  fakePlcDid,
  findIdentity,
  makeDidDoc,
  seedIdentity,
  upsertIdentity,
  type WalletState,
  type FakeIdentity,
} from './state';

/** A fake command handler. `args` is the object the frontend passed to `invoke`. */
export type Handler = (args: Record<string, unknown>) => unknown | Promise<unknown>;

/**
 * Every command the wallet frontend can invoke. Hand-maintained; `registry.test.ts`
 * cross-checks it against the live `$lib/ipc` source so drift fails a test.
 */
export type CommandName =
  // account.ts
  | 'create_account'
  | 'perform_did_ceremony'
  | 'prepare_did_web_ceremony'
  | 'complete_did_web_ceremony'
  | 'plugin:sharesheet|share_text'
  | 'register_handle'
  | 'get_available_user_domains'
  | 'register_created_identity'
  | 'check_handle_resolution'
  | 'get_pds_url'
  | 'save_pds_url'
  // oauth.ts
  | 'prepare_oauth_flow'
  | 'plugin:auth-session|start'
  | 'complete_oauth_flow'
  // appearance.ts
  | 'get_appearance_preference'
  | 'set_appearance_preference'
  // claim.ts
  | 'resolve_identity'
  | 'authenticate_source_pds'
  | 'request_claim_verification'
  | 'sign_and_verify_claim'
  | 'submit_claim'
  // identity.ts
  | 'list_identities'
  | 'get_stored_did_doc'
  | 'refresh_did_doc'
  | 'get_device_key_id'
  | 'sovereign_login'
  | 'ensure_identity_session'
  // monitor.ts
  | 'check_identity_status'
  // recovery.ts
  | 'build_recovery_override_cmd'
  | 'submit_recovery_override_cmd'
  // removal.ts
  | 'request_identity_removal'
  | 'confirm_identity_removal'
  | 'tombstone_identity'
  | 'list_pending_removals'
  // migration.ts
  | 'build_did_web_migration_document_cmd'
  | 'submit_did_web_migration_document_cmd'
  | 'detect_migration_path_cmd'
  | 'build_migration_op_cmd'
  | 'submit_migration_op_cmd'
  | 'prepare_migration'
  | 'authenticate_migration_source'
  | 'create_destination_account'
  | 'transfer_repo'
  | 'transfer_blobs'
  | 'transfer_preferences'
  | 'verify_import'
  | 'arm_identity_leg'
  | 'finalize_migration'
  // handle-change.ts
  | 'get_identity_handle_domains'
  | 'change_handle_cmd'
  // agents.ts
  | 'list_agents'
  | 'revoke_agent'
  | 'get_agent_audit'
  | 'preview_agent_claim'
  | 'confirm_agent_claim'
  // biometric plugin (driven by $lib/biometric — resolves = allow the gate)
  | 'plugin:biometric|authenticate'
  | 'plugin:biometric|status';

export type Registry = Record<CommandName, Handler>;

/** Read `did` from an args object (the common single-arg case). */
function didArg(args: Record<string, unknown>): string {
  return String(args.did ?? '');
}

/** Whether the device key sits at rotationKeys[0]. */
function deviceKeyIsRoot(identity: FakeIdentity): boolean {
  return identity.rotationKeys[0] === identity.deviceKeyId;
}

function identityInfo(identity: FakeIdentity): IdentityInfo {
  return {
    did: identity.did,
    handle: identity.handle,
    pdsUrl: identity.pdsUrl,
    currentRotationKeys: identity.rotationKeys,
    deviceKeyIsRoot: deviceKeyIsRoot(identity),
  };
}

function claimResult(identity: FakeIdentity): ClaimResult {
  return { updatedDidDoc: makeDidDoc(identity) };
}

/**
 * Build the full command registry over a live {@link WalletState}. Handlers close over
 * `state` so mutations persist across commands within a session (browser-harness.AC2.1).
 */
export function buildRegistry(state: WalletState): Registry {
  return {
    // ── account / create flow ────────────────────────────────────────────────
    create_account: (args): CreateAccountResult => {
      state.create = {
        claimCode: String(args.claimCode ?? ''),
        email: String(args.email ?? ''),
        handle: String(args.handle ?? ''),
      };
      return { nextStep: 'did_creation' };
    },
    perform_did_ceremony: (args): DIDCeremonyResult => {
      const handle = String(args.handle ?? state.create?.handle ?? 'newuser.harness.pds.local');
      const did = fakePlcDid(`${handle}:${state.create?.email ?? ''}`);
      state.create = { ...(state.create ?? {}), handle, did };
      return { did, share3: 'HARNESSSHARETHREEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    },
    prepare_did_web_ceremony: (): DidWebPreparation => ({
      deviceKeyMultibase: `z${fakeDeviceKeyId('did:web')}`,
      repoKeyMultibase: `z${fakeDeviceKeyId('did:web:repo')}`,
      pdsUrl: state.pdsUrl ?? DEFAULT_PDS_URL,
    }),
    complete_did_web_ceremony: (args): DIDCeremonyResult => {
      const handle = state.create?.handle ?? 'newuser.example.com';
      const did = `did:web:${handle}`;
      state.create = { ...(state.create ?? {}), handle, did };
      void args;
      return { did, share3: 'HARNESSSHARETHREEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    },
    'plugin:sharesheet|share_text': () => null,
    register_handle: (args): RegisterHandleResult => {
      const handle = String(args.handle ?? state.create?.handle ?? '');
      if (state.create) state.create.handle = handle;
      return { handle, dnsStatus: 'not_configured' };
    },
    get_available_user_domains: (): string[] => state.availableUserDomains,
    register_created_identity: (args) => {
      const did = String(args.did ?? state.create?.did ?? '');
      const handle = String(args.handle ?? state.create?.handle ?? '');
      if (!did) return null;
      const isWeb = did.startsWith('did:web:');
      const identity = seedIdentity({
        handle,
        did,
        pdsUrl: state.pdsUrl ?? DEFAULT_PDS_URL,
        deviceKeyIsRoot: !isWeb,
      });
      upsertIdentity(state, identity);
      state.create = null;
      return null;
    },
    check_handle_resolution: (): boolean => true,
    get_pds_url: (): string | null => state.pdsUrl,
    save_pds_url: (args) => {
      state.pdsUrl = String(args.url ?? '');
      return null;
    },

    // ── oauth (create-flow login; faked in every mode) ───────────────────────
    prepare_oauth_flow: () => ({
      authUrl: 'https://harness.pds.local/oauth/authorize?request_uri=harness',
      callbackScheme: 'org.obsign.identitywallet',
    }),
    'plugin:auth-session|start': () =>
      'org.obsign.identitywallet:/oauth/callback?code=harness-code&state=harness-state',
    complete_oauth_flow: () => null,

    // ── appearance ───────────────────────────────────────────────────────────
    get_appearance_preference: () => state.appearance,
    set_appearance_preference: (args) => {
      state.appearance = args.preference as WalletState['appearance'];
      return null;
    },

    // ── claim (import) flow ──────────────────────────────────────────────────
    resolve_identity: (args): IdentityInfo => {
      const handleOrDid = String(args.handleOrDid ?? '');
      const existing =
        findIdentity(state, handleOrDid) ??
        state.identities.find((i) => i.handle === handleOrDid);
      const identity =
        existing ??
        seedIdentity({
          handle: handleOrDid.startsWith('did:') ? 'imported.harness.pds.local' : handleOrDid,
          did: handleOrDid.startsWith('did:') ? handleOrDid : undefined,
          // An externally-hosted identity being claimed: device key is not yet root.
          deviceKeyIsRoot: false,
        });
      state.claim = {
        did: identity.did,
        handle: identity.handle,
        pdsUrl: identity.pdsUrl,
        authenticated: false,
        verificationRequested: false,
      };
      return identityInfo(identity);
    },
    authenticate_source_pds: (args) => {
      if (state.claim && state.claim.did === didArg(args)) state.claim.authenticated = true;
      return null;
    },
    request_claim_verification: (args) => {
      if (state.claim && state.claim.did === didArg(args)) state.claim.verificationRequested = true;
      return null;
    },
    sign_and_verify_claim: (args): VerifiedClaimOp => {
      const did = didArg(args);
      const deviceKey = fakeDeviceKeyId(did);
      return {
        diff: {
          addedKeys: [deviceKey],
          removedKeys: [],
          changedServices: [],
          prevCid: `bafyharnessprev${did.slice(-6)}`,
        },
        signedOp: { type: 'plc_operation', harness: true },
        warnings: [],
      };
    },
    submit_claim: (args): ClaimResult => {
      const did = didArg(args) || state.claim?.did || '';
      const claim = state.claim;
      const identity =
        findIdentity(state, did) ??
        seedIdentity({
          handle: claim?.handle ?? 'imported.harness.pds.local',
          did,
          pdsUrl: claim?.pdsUrl ?? DEFAULT_PDS_URL,
          // After claiming, the device key becomes the primary rotation key.
          deviceKeyIsRoot: true,
        });
      identity.rotationKeys = [identity.deviceKeyId, ...identity.rotationKeys.filter((k) => k !== identity.deviceKeyId)];
      upsertIdentity(state, identity);
      state.claim = null;
      return claimResult(identity);
    },

    // ── identity store ───────────────────────────────────────────────────────
    list_identities: (): string[] => state.identities.map((i) => i.did),
    get_stored_did_doc: (args): Record<string, unknown> | null => {
      const identity = findIdentity(state, didArg(args));
      return identity ? makeDidDoc(identity) : null;
    },
    refresh_did_doc: (args): Record<string, unknown> => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND' };
      return makeDidDoc(identity);
    },
    get_device_key_id: (args): string => {
      const identity = findIdentity(state, didArg(args));
      return identity ? identity.deviceKeyId : fakeDeviceKeyId(didArg(args));
    },
    sovereign_login: (args): SovereignLoginResult => ({
      did: didArg(args),
      pdsUrl: findIdentity(state, didArg(args))?.pdsUrl ?? DEFAULT_PDS_URL,
      accessExpiresAt: farFuture(),
      refreshExpiresAt: farFuture(),
    }),
    ensure_identity_session: (args): SessionReady => ({
      did: didArg(args),
      pdsUrl: findIdentity(state, didArg(args))?.pdsUrl ?? DEFAULT_PDS_URL,
      accessExpiresAt: farFuture(),
      refreshExpiresAt: farFuture(),
      rotated: false,
    }),

    // ── PLC monitor ──────────────────────────────────────────────────────────
    check_identity_status: (): IdentityStatus[] =>
      state.identities.map((i) => ({
        did: i.did,
        checkFailed: false,
        unauthorizedChanges: i.alerts,
      })),

    // ── recovery override ────────────────────────────────────────────────────
    build_recovery_override_cmd: (args): SignedRecoveryOp => {
      const identity = findIdentity(state, didArg(args));
      return {
        diff: {
          addedKeys: [],
          removedKeys: [fakeDeviceKeyId(`${didArg(args)}:attacker`)],
          changedServices: [],
          prevCid: `bafyharnessprev${didArg(args).slice(-6)}`,
        },
        signedOp: { type: 'plc_operation', recovery: true, did: identity?.did },
      };
    },
    submit_recovery_override_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      if (identity) identity.alerts = [];
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },

    // ── identity removal ─────────────────────────────────────────────────────
    request_identity_removal: () => null,
    confirm_identity_removal: (args): RemovalOutcome => removeIdentity(state, didArg(args)),
    tombstone_identity: (args): RemovalOutcome => removeIdentity(state, didArg(args)),
    // The fake removes an identity synchronously, so it never strands one mid-flow —
    // there is nothing to reconcile on launch. Real backend markers are covered by Rust.
    list_pending_removals: (): string[] => [],

    // ── migration ────────────────────────────────────────────────────────────
    build_did_web_migration_document_cmd: (args): DidWebMigrationDocument => {
      const did = didArg(args);
      return {
        documentText: JSON.stringify({ id: did, harness: true }, null, 2),
        deviceKey: fakeDeviceKeyId(did),
        repoKey: fakeDeviceKeyId(`${did}:repo`),
        pdsEndpoint: 'https://destination.harness.pds.local',
      };
    },
    submit_did_web_migration_document_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },
    detect_migration_path_cmd: (args): MigrationPathDecision => {
      const identity = findIdentity(state, didArg(args));
      const isRoot = identity ? deviceKeyIsRoot(identity) : false;
      return {
        path: isRoot ? 'self_signed' : 'interop',
        deviceKeyId: identity?.deviceKeyId ?? null,
        rotationKeyIndex: identity ? identity.rotationKeys.indexOf(identity.deviceKeyId) : null,
        reason: isRoot ? 'device key is a rotation key' : 'device key not authorized',
      };
    },
    build_migration_op_cmd: (args): SignedMigrationOp => {
      const did = didArg(args);
      return {
        diff: {
          addedKeys: [],
          removedKeys: [],
          changedServices: [
            {
              id: 'atproto_pds',
              changeType: 'modified',
              oldEndpoint: findIdentity(state, did)?.pdsUrl ?? DEFAULT_PDS_URL,
              newEndpoint: state.migration?.destPdsUrl ?? 'https://destination.harness.pds.local',
            },
          ],
          prevCid: `bafyharnessprev${did.slice(-6)}`,
        },
        signedOp: { type: 'plc_operation', migration: true },
      };
    },
    submit_migration_op_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      if (identity && state.migration?.destPdsUrl) {
        identity.pdsUrl = state.migration.destPdsUrl;
      }
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },
    prepare_migration: (args): PreparedMigration => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      state.migration = {
        did,
        destPdsUrl: String(args.destPdsUrl ?? 'https://destination.harness.pds.local'),
        sourceAuthenticated: false,
        destinationCreated: false,
        repoTransferred: false,
        blobsTransferred: false,
        preferencesTransferred: false,
        verified: false,
        armed: false,
      };
      return {
        handle: identity?.handle ?? 'alice.harness.pds.local',
        sourcePdsUrl: identity?.pdsUrl ?? DEFAULT_PDS_URL,
      };
    },
    authenticate_migration_source: () => {
      if (state.migration) state.migration.sourceAuthenticated = true;
      return null;
    },
    create_destination_account: () => {
      if (state.migration) state.migration.destinationCreated = true;
      return null;
    },
    transfer_repo: () => {
      if (state.migration) state.migration.repoTransferred = true;
      return null;
    },
    transfer_blobs: () => {
      if (state.migration) state.migration.blobsTransferred = true;
      return null;
    },
    transfer_preferences: () => {
      if (state.migration) state.migration.preferencesTransferred = true;
      return null;
    },
    verify_import: (): AccountStatus => {
      if (state.migration) state.migration.verified = true;
      return {
        activated: false,
        validDid: true,
        repoCommit: 'bafyharnesscommit',
        repoRev: '3lharnessrev',
        storedBlocks: 128,
        indexedRecords: 42,
        privateStateValues: 3,
        expectedBlobs: 5,
        importedBlobs: 5,
      };
    },
    arm_identity_leg: () => {
      if (state.migration) state.migration.armed = true;
      return null;
    },
    finalize_migration: (args) => {
      const identity = findIdentity(state, didArg(args));
      if (identity && state.migration?.destPdsUrl) identity.pdsUrl = state.migration.destPdsUrl;
      state.migration = null;
      return null;
    },

    // ── change handle ────────────────────────────────────────────────────────
    get_identity_handle_domains: (): string[] => state.availableUserDomains,
    change_handle_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      if (identity) identity.handle = String(args.handle ?? identity.handle);
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },

    // ── agents ───────────────────────────────────────────────────────────────
    list_agents: (): AgentSummary[] => state.identities.flatMap((i) => i.agents.map((a) => a.summary)),
    revoke_agent: (args) => {
      const registrationId = String(args.registrationId ?? '');
      for (const identity of state.identities) {
        const agent = identity.agents.find((a) => a.summary.registrationId === registrationId);
        if (agent) agent.summary.status = 'revoked';
      }
      return null;
    },
    get_agent_audit: (args): AgentAuditPage => {
      const registrationId = String(args.registrationId ?? '');
      for (const identity of state.identities) {
        const agent = identity.agents.find((a) => a.summary.registrationId === registrationId);
        if (agent) return { events: agent.audit };
      }
      return { events: [] };
    },
    preview_agent_claim: (args): AgentClaimPreview => ({
      registrationId: `reg-${String(args.userCode ?? 'HARNESS')}`,
      registrationType: 'service_auth',
      issuer: 'did:web:agent.example',
      subject: state.identities[0]?.did,
      scopes: ['repo:write', 'blob:upload'],
      userCodeExpiresAt: isoInHours(1),
    }),
    confirm_agent_claim: (args): AgentClaimConfirmation => {
      const registrationId = `reg-${String(args.userCode ?? 'HARNESS')}`;
      const identity = state.identities[0];
      if (identity) {
        const now = '2026-07-15T12:00:00.000Z';
        identity.agents.push({
          summary: {
            registrationId,
            registrationType: 'service_auth',
            issuer: 'did:web:agent.example',
            subject: identity.did,
            scopes: ['repo:write', 'blob:upload'],
            status: 'claimed',
            createdAt: now,
            updatedAt: now,
          },
          audit: [{ id: `${registrationId}-1`, eventType: 'claim_confirmed', did: identity.did, createdAt: now }],
        });
      }
      return { registrationId, status: 'claimed', did: identity?.did ?? '' };
    },

    // ── biometric plugin (allow the gate) ────────────────────────────────────
    'plugin:biometric|authenticate': () => null,
    'plugin:biometric|status': () => ({
      isAvailable: true,
      biometryType: 1,
      error: null,
      errorCode: null,
    }),
  };
}

function removeIdentity(state: WalletState, did: string): RemovalOutcome {
  const before = state.identities.length;
  state.identities = state.identities.filter((i) => i.did !== did);
  return {
    tombstoneCid: `bafyharnesstombstone${did.slice(-6)}`,
    wasLastIdentity: before > 0 && state.identities.length === 0,
  };
}

/** An access/refresh expiry far enough out that the session never reads as expired. */
function farFuture(): number {
  return Date.parse('2030-01-01T00:00:00.000Z');
}

function isoInHours(hours: number): string {
  const base = Date.parse('2026-07-15T12:00:00.000Z');
  return new Date(base + hours * 3600_000).toISOString();
}
