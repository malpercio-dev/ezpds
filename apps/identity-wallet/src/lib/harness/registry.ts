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
  SignedRotationOp,
  RecoveryTarget,
  CollectedShare,
  EscrowReleaseStatus,
  RecoveredIdentity,
  RecoveryAnchor,
  EpilogueResult,
  PendingEpilogue,
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
  ConsentPreview,
  ConsentDecision,
  AppPasswordCreated,
  AppPasswordEntry,
  BlobBackupStatus,
  BlobBackupRunReport,
  BlobRestoreReport,
  RepoBackupStatus,
  RepoBackupRunReport,
  RepoExport,
  RegisterHandleResult,
  CreateAccountResult,
  DIDCeremonyResult,
  DidWebPreparation,
  RekeyPreview,
  RekeyResult,
} from '$lib/ipc';
import {
  DEFAULT_PDS_URL,
  RECOVERY_SET_ID,
  RECOVERY_WRONG_SET_ID,
  fakeAppPasswordSecret,
  fakeDeviceKeyId,
  fakePlcDid,
  fakeRecoveryKeyId,
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
 * Share 3 fixtures for the client-share ceremony fake: the shapes match the real
 * envelope contract — 68 base32 chars (a 42-byte v2 envelope) and a 42-word phrase
 * (one word per envelope byte) — so the backup screen renders exactly as on device.
 * Not cryptographically valid material; the harness never combines shares.
 */
const HARNESS_SHARE3_ENVELOPE =
  'HARNESSSHARETHREEB2C3D4E5F6G7A2B3C4D5E6F7HARNESSQ2R3S4T5U6V7W2X3Y4Z5';
const HARNESS_SHARE3_WORDS = [
  'anchor', 'baker', 'canyon', 'delta', 'ember', 'falcon', 'garnet',
  'harbor', 'island', 'jasper', 'kettle', 'lantern', 'meadow', 'nickel',
  'orchard', 'pebble', 'quarry', 'ribbon', 'saddle', 'timber', 'umbrella',
  'velvet', 'walnut', 'yonder', 'zephyr', 'atlas', 'bramble', 'cedar',
  'drift', 'echo', 'fable', 'glacier', 'hollow', 'ivory', 'juniper',
  'kindle', 'ledger', 'marble', 'north', 'opal', 'prairie', 'quill',
].join(' ');

/**
 * Every command the wallet frontend can invoke. Hand-maintained; `registry.test.ts`
 * cross-checks it against the live `$lib/ipc` source so drift fails a test.
 */
export type CommandName =
  // account.ts
  | 'create_account'
  | 'perform_did_ceremony'
  | 'confirm_share_backup'
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
  // diagnostics.ts
  | 'export_diagnostics'
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
  // share-recovery.ts
  | 'start_share_recovery'
  | 'add_recovery_share'
  | 'remove_recovery_share'
  | 'initiate_escrow_release'
  | 'request_escrow_release'
  | 'verify_recovery_shares'
  | 'recover_identity'
  | 'run_recovery_epilogue'
  | 'get_pending_recovery_epilogue'
  | 'confirm_recovery_backup'
  // removal.ts
  | 'request_identity_removal'
  | 'confirm_identity_removal'
  | 'tombstone_identity'
  | 'list_pending_removals'
  | 'forget_identity_locally'
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
  // disaster-recovery.ts
  | 'prepare_disaster_recovery'
  | 'enroll_recovery_signing_key'
  | 'await_recovery_key_visibility'
  | 'create_recovery_destination_account'
  | 'recovery_transfer_repo'
  // handle-change.ts
  | 'get_identity_handle_domains'
  | 'change_handle_cmd'
  // rotation.ts
  | 'build_repo_key_rotation_cmd'
  | 'submit_repo_key_rotation_cmd'
  // rekey.ts
  | 'build_rekey_cmd'
  | 'submit_rekey_cmd'
  | 'confirm_rekey_cmd'
  | 'rekey_in_progress_cmd'
  // agents.ts
  | 'list_agents'
  | 'revoke_agent'
  | 'get_agent_audit'
  | 'preview_agent_claim'
  | 'confirm_agent_claim'
  | 'preview_oauth_consent'
  | 'preview_oauth_consent_by_request_id'
  | 'confirm_oauth_consent'
  // app-passwords.ts
  | 'create_app_password'
  | 'list_app_passwords'
  | 'revoke_app_password'
  // blob-backup.ts
  | 'get_blob_backup_status'
  | 'set_blob_backup_enabled'
  | 'run_blob_backup'
  | 'restore_blob_backup'
  | 'get_background_backup_settings'
  | 'set_background_backup_settings'
  // repo-backup.ts
  | 'get_repo_backup_status'
  | 'set_repo_backup_enabled'
  | 'run_repo_backup'
  | 'export_repo_backup'
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

/** Render the fake's blob-backup model as the status the real command returns. */
function blobBackupStatus(identity: FakeIdentity): BlobBackupStatus {
  const backup = identity.blobBackup;
  const mirrored = backup.remote.filter((b) => backup.mirroredCids.includes(b.cid));
  return {
    enabled: backup.enabled,
    location: backup.location,
    backedUpCount: mirrored.length,
    backedUpBytes: mirrored.reduce((sum, b) => sum + b.size, 0),
    lastBackupAt: backup.lastBackupAt,
  };
}

/** Render the fake's repo-backup model as the status the real command returns. */
function repoBackupStatus(identity: FakeIdentity): RepoBackupStatus {
  const backup = identity.repoBackup;
  const mirrored = backup.mirroredRev !== null;
  return {
    enabled: backup.enabled,
    location: backup.location,
    rootCid: mirrored ? backup.rootCid : null,
    rev: backup.mirroredRev,
    sizeBytes: mirrored ? backup.sizeBytes : 0,
    lastBackupAt: backup.lastBackupAt,
  };
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
      // The client-share ceremony returns Share 3 in both forms: the base32 v2
      // envelope (68 chars, the QR payload) and the 42-word human-custody phrase.
      return {
        did,
        share3: HARNESS_SHARE3_ENVELOPE,
        share3Words: HARNESS_SHARE3_WORDS,
      };
    },
    // Teardown of the ceremony's Keychain staging slot — pure side effect on device,
    // nothing observable in the fake beyond succeeding.
    confirm_share_backup: () => null,
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
      // did:web stays on the legacy server-side share path: bare base32 share, no
      // word rendering — the backup screen falls back to the machine form.
      return {
        did,
        share3: 'HARNESSSHARETHREEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        share3Words: '',
      };
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

    // ── background media-backup settings (app-global) ─────────────────────────
    // The real BGProcessingTask scheduling is a device concern the harness never runs;
    // the fake just stores and echoes the settings so the Settings UI is scriptable.
    get_background_backup_settings: () => state.backgroundBackupSettings,
    set_background_backup_settings: (args) => {
      state.backgroundBackupSettings = args.settings as WalletState['backgroundBackupSettings'];
      return state.backgroundBackupSettings;
    },

    // ── diagnostics ──────────────────────────────────────────────────────────
    // The real report is rendered from a Rust-side ring buffer the fake has no
    // access to; return a representative empty-session report.
    export_diagnostics: (): string =>
      'Obsign diagnostics — network events\n\nNo network errors have been recorded this session.\n',

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
          // An externally-hosted identity being claimed: device key is not yet root, and the
          // account predates the client-share ceremony (old 2-key model — no recovery key).
          deviceKeyIsRoot: false,
          recoveryKey: false,
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
          // After claiming, the device key becomes the primary rotation key — but the
          // imported account stays on the old 2-key model until the MM-411 re-key runs.
          deviceKeyIsRoot: true,
          recoveryKey: false,
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

    // ── share recovery ("Recover existing identity") ─────────────────────────
    start_share_recovery: (args): RecoveryTarget => {
      const identifier = String(args.identifier ?? '').trim();
      const r = state.recovery;
      const isDid = identifier.startsWith('did:');
      r.did = isDid ? identifier : fakePlcDid(identifier);
      r.handle = isDid ? (r.handle ?? 'alice.harness.pds.local') : identifier;
      r.collected = r.share1Present ? [{ setId: RECOVERY_SET_ID, index: 1 }] : [];
      return {
        did: r.did,
        handle: r.handle,
        share1Loaded: r.share1Present,
        collected: [...r.collected],
      };
    },
    add_recovery_share: (args): CollectedShare => {
      const r = state.recovery;
      const share = String(args.share ?? '').trim();
      const { fixtures } = r;
      if (share === fixtures.corrupt) throw { code: 'SHARE_CHECKSUM' };
      if (share === fixtures.wrongSet) {
        throw {
          code: 'SHARE_SET_MISMATCH',
          expectedSetId: r.collected[0]?.setId ?? RECOVERY_SET_ID,
          gotSetId: RECOVERY_WRONG_SET_ID,
        };
      }
      if (share !== fixtures.share3 && share !== fixtures.share3Words) {
        throw { code: 'SHARE_FORMAT', message: 'harness: unrecognized share fixture' };
      }
      if (r.collected.some((s) => s.index === 3)) throw { code: 'DUPLICATE_SHARE', index: 3 };
      const collected = { setId: RECOVERY_SET_ID, index: 3 };
      r.collected.push(collected);
      return collected;
    },
    remove_recovery_share: (args): CollectedShare[] => {
      const r = state.recovery;
      r.collected = r.collected.filter((s) => s.index !== Number(args.index));
      return [...r.collected];
    },
    initiate_escrow_release: () => {
      state.recovery.escrow.initiated = true;
      return null;
    },
    request_escrow_release: (args): EscrowReleaseStatus => {
      const r = state.recovery;
      const esc = r.escrow;
      const otp = args.otp == null ? null : String(args.otp);
      const release = (): EscrowReleaseStatus => {
        esc.released = true;
        esc.pendingOpened = false;
        const share = { setId: RECOVERY_SET_ID, index: 2 };
        r.collected = [...r.collected.filter((s) => s.index !== 2), share];
        return { status: 'released', availableAt: null, share };
      };
      if (otp !== null) {
        // The OTP opens the release. 'wrong' models a bad/expired code.
        if (otp === 'wrong') throw { code: 'RELEASE_UNAUTHORIZED' };
        if (esc.delaySecs === 0) return release();
        esc.pendingOpened = true;
        return { status: 'pending', availableAt: '2026-07-16 12:00:00', share: null };
      }
      // Poll: no release in flight, or a cancelled one, answers the uniform 401.
      if (!esc.pendingOpened || esc.cancelled) throw { code: 'RELEASE_UNAUTHORIZED' };
      if (esc.releaseAfterPolls !== null) {
        esc.releaseAfterPolls -= 1;
        if (esc.releaseAfterPolls <= 0) return release();
      }
      return { status: 'pending', availableAt: '2026-07-16 12:00:00', share: null };
    },
    verify_recovery_shares: (): RecoveredIdentity => {
      const r = state.recovery;
      if (r.collected.length < 2) throw { code: 'SHARES_INCOMPLETE' };
      if (r.verifyOutcome === 'mismatch') throw { code: 'SHARES_DO_NOT_MATCH_IDENTITY' };
      const did = r.did ?? fakePlcDid('recovered');
      return {
        did,
        handle: r.handle,
        recoveryKeyId: fakeDeviceKeyId(`${did}:recovery`),
        rotationKeys: [
          fakeDeviceKeyId(`${did}:lost-device`),
          fakeDeviceKeyId(`${did}:recovery`),
          fakeDeviceKeyId(`${did}:pds`),
        ],
      };
    },
    recover_identity: (): RecoveryAnchor => {
      const r = state.recovery;
      const did = r.did ?? fakePlcDid('recovered');
      const identity = seedIdentity({
        handle: r.handle ?? 'alice.harness.pds.local',
        did,
        deviceKeyIsRoot: true,
      });
      upsertIdentity(state, identity);
      r.epilogue = {
        opSubmitted: false,
        escrowDeposited: false,
        escrowSkipped: false,
        share1Written: false,
      };
      return { did, opCid: `bafyharnessrecover${did.slice(-6)}`, alreadyAnchored: false };
    },
    run_recovery_epilogue: (args): EpilogueResult => {
      const r = state.recovery;
      const epilogue = r.epilogue;
      if (!epilogue) throw { code: 'NO_PENDING_EPILOGUE' };
      const skipEscrow = Boolean(args.skipEscrow ?? false);
      epilogue.opSubmitted = true;
      if (!epilogue.escrowDeposited && !epilogue.escrowSkipped) {
        if (skipEscrow) {
          epilogue.escrowSkipped = true;
        } else if (r.failEpilogueEscrowOnce) {
          // One-shot injected failure: progress so far stays durable, mirroring
          // the real epilogue's resume contract.
          r.failEpilogueEscrowOnce = false;
          throw { code: 'ESCROW_DEPOSIT_FAILED', message: 'harness: injected escrow failure' };
        } else {
          epilogue.escrowDeposited = true;
        }
      }
      epilogue.share1Written = true;
      return {
        share3: r.fixtures.share3,
        share3Words: r.fixtures.share3Words,
        escrowDeposited: epilogue.escrowDeposited,
        escrowSkipped: epilogue.escrowSkipped,
      };
    },
    get_pending_recovery_epilogue: (): PendingEpilogue | null => {
      const r = state.recovery;
      if (!r.epilogue) return null;
      return {
        did: r.did ?? state.identities[0]?.did ?? fakePlcDid('recovered'),
        opSubmitted: r.epilogue.opSubmitted,
        escrowDeposited: r.epilogue.escrowDeposited,
        escrowSkipped: r.epilogue.escrowSkipped,
        share1Written: r.epilogue.share1Written,
      };
    },
    confirm_recovery_backup: () => {
      state.recovery.epilogue = null;
      state.recovery.collected = [];
      return null;
    },

    // ── identity removal ─────────────────────────────────────────────────────
    request_identity_removal: () => null,
    confirm_identity_removal: (args): RemovalOutcome => removeIdentity(state, didArg(args)),
    tombstone_identity: (args): RemovalOutcome => removeIdentity(state, didArg(args)),
    // The fake removes an identity synchronously, so it never strands one mid-flow —
    // there is nothing to reconcile on launch. Real backend markers are covered by Rust.
    list_pending_removals: (): string[] => [],
    // The local-only escape hatch: drop the identity and report whether the wallet is now
    // empty, mirroring the backend's `wasLastIdentity`.
    forget_identity_locally: (args): boolean => removeIdentity(state, didArg(args)).wasLastIdentity,

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

    // ── sovereign disaster recovery ──────────────────────────────────────────
    prepare_disaster_recovery: (args) => {
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
        recovery: true,
        recoveryKeyEnrolled: false,
        // Two "not yet visible" polls before propagation, so the screen's polling
        // state is reachable in the harness.
        recoveryVisibilityPollsRemaining: 2,
      };
      return {
        handle:
          typeof args.handleOverride === 'string' && args.handleOverride.trim() !== ''
            ? args.handleOverride
            : (identity?.handle ?? 'alice.harness.pds.local'),
        destDid: 'did:web:destination.harness.pds.local',
        sourcePdsUrl: identity?.pdsUrl ?? DEFAULT_PDS_URL,
      };
    },
    enroll_recovery_signing_key: () => {
      if (state.migration) state.migration.recoveryKeyEnrolled = true;
      return {
        signingKeyId: 'did:key:zharnessRecoverySigningKey',
        opCid: 'bafyharnessenrollop',
        alreadyEnrolled: false,
      };
    },
    await_recovery_key_visibility: () => {
      const flow = state.migration;
      if (!flow?.recoveryKeyEnrolled) {
        throw { code: 'KEY_NOT_ENROLLED', message: 'run enroll_recovery_signing_key first' };
      }
      const remaining = flow.recoveryVisibilityPollsRemaining ?? 0;
      if (remaining > 0) {
        flow.recoveryVisibilityPollsRemaining = remaining - 1;
        return { visible: false };
      }
      flow.sourceAuthenticated = true;
      return { visible: true };
    },
    create_recovery_destination_account: () => {
      if (state.migration) state.migration.destinationCreated = true;
      return null;
    },
    recovery_transfer_repo: () => {
      if (state.migration) state.migration.repoTransferred = true;
      return null;
    },

    // ── change handle ────────────────────────────────────────────────────────
    get_identity_handle_domains: (): string[] => state.availableUserDomains,
    change_handle_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      if (identity) identity.handle = String(args.handle ?? identity.handle);
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },

    // ── rotate signing key ───────────────────────────────────────────────────
    build_repo_key_rotation_cmd: (args): SignedRotationOp => {
      const identity = findIdentity(state, didArg(args));
      const oldKey = identity?.rotationKeys[1] ?? 'did:key:zharnessOldRepoKey';
      return {
        diff: {
          addedKeys: ['did:key:zharnessRotatedRepoKey'],
          removedKeys: [oldKey],
          changedServices: [],
          prevCid: 'bafyharnessprevcid',
        },
        signedOp: {},
      };
    },
    submit_repo_key_rotation_cmd: (args): ClaimResult => {
      const identity = findIdentity(state, didArg(args));
      if (identity) {
        identity.rotationKeys = [identity.rotationKeys[0], 'did:key:zharnessRotatedRepoKey'];
      }
      return identity ? claimResult(identity) : { updatedDidDoc: {} };
    },

    // ── re-key (old-model upgrade, MM-411) ───────────────────────────────────
    build_rekey_cmd: (args): RekeyPreview => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      if (did.startsWith('did:web:')) throw { code: 'NOT_DID_PLC' };
      const recoveryKey = fakeRecoveryKeyId(did);
      // Resumable: a re-key already in flight (staging set) is always allowed, even after its op
      // landed and the identity reads as new-model. A fresh re-key needs the 2-key old model with
      // the device key at [0] — mirrors the Rust precheck (staging is the only escape).
      if (!identity.rekeyStagedRecoveryKey) {
        if (identity.rotationKeys.length !== 2) throw { code: 'ALREADY_REKEYED' };
        if (identity.rotationKeys[0] !== identity.deviceKeyId) {
          throw { code: 'WALLET_NOT_AUTHORIZED' };
        }
      }
      identity.rekeyStagedRecoveryKey = recoveryKey;
      return {
        diff: {
          addedKeys: [recoveryKey],
          removedKeys: [],
          changedServices: [],
          prevCid: 'bafyharnessrekeyprev',
        },
        recoveryKeyId: recoveryKey,
      };
    },
    submit_rekey_cmd: (args): RekeyResult => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      if (did.startsWith('did:web:')) throw { code: 'NOT_DID_PLC' };
      const recoveryKey = identity.rekeyStagedRecoveryKey ?? fakeRecoveryKeyId(did);
      identity.rekeyStagedRecoveryKey = recoveryKey;
      // Additively insert the recovery key at [1] (device stays [0], PDS shifts to [2]) — idempotent:
      // a resumed submit whose op already landed leaves the 3-key array untouched.
      if (!identity.rotationKeys.includes(recoveryKey)) {
        const [device, ...rest] = identity.rotationKeys;
        identity.rotationKeys = [device, recoveryKey, ...rest];
      }
      return {
        updatedDidDoc: makeDidDoc(identity),
        share3: HARNESS_SHARE3_ENVELOPE,
        share3Words: HARNESS_SHARE3_WORDS,
      };
    },
    confirm_rekey_cmd: (args) => {
      const identity = findIdentity(state, didArg(args));
      if (identity) identity.rekeyStagedRecoveryKey = null;
      return null;
    },
    rekey_in_progress_cmd: (args): boolean => {
      const identity = findIdentity(state, didArg(args));
      return Boolean(identity?.rekeyStagedRecoveryKey);
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

    // ── wallet-confirmed OAuth consent ───────────────────────────────────────
    preview_oauth_consent: (args): ConsentPreview => ({
      requestId: `poauth-${String(args.userCode ?? 'HARNESS')}`,
      clientId: 'https://app.example.com/client-metadata.json',
      clientName: 'Example App',
      redirectUri: 'https://app.example.com/callback',
      origin: 'https://app.example.com',
      ip: '203.0.113.5',
      requestedScope: ['atproto', 'transition:generic'],
      loginHint: null,
    }),
    // The scan path resolves the same pending request server-side by request_id — same preview shape.
    preview_oauth_consent_by_request_id: (args): ConsentPreview => ({
      requestId: String(args.requestId ?? 'poauth-HARNESS'),
      clientId: 'https://app.example.com/client-metadata.json',
      clientName: 'Example App',
      redirectUri: 'https://app.example.com/callback',
      origin: 'https://app.example.com',
      ip: '203.0.113.5',
      requestedScope: ['atproto', 'transition:generic'],
      loginHint: null,
    }),
    confirm_oauth_consent: (args): ConsentDecision => ({
      status: String(args.decision) === 'deny' ? 'denied' : 'approved',
      did: String(args.did ?? state.identities[0]?.did ?? ''),
    }),

    // ── app passwords ("Sign in to Bluesky and other apps") ──────────────────
    list_app_passwords: (args): AppPasswordEntry[] => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      return identity.appPasswords;
    },
    create_app_password: (args): AppPasswordCreated => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const name = String(args.name ?? '');
      const privileged = Boolean(args.privileged ?? false);
      if (identity.appPasswords.some((p) => p.name === name)) {
        throw { code: 'DUPLICATE_NAME' };
      }
      const entry = { name, createdAt: '2026-07-15T12:00:00.000Z', privileged };
      identity.appPasswords.push(entry);
      return { ...entry, password: fakeAppPasswordSecret(name) };
    },
    revoke_app_password: (args) => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const name = String(args.name ?? '');
      identity.appPasswords = identity.appPasswords.filter((p) => p.name !== name);
      return null;
    },

    // ── media backup (user-held blob mirror) ─────────────────────────────────
    get_blob_backup_status: (args): BlobBackupStatus => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      return blobBackupStatus(identity);
    },
    set_blob_backup_enabled: (args): BlobBackupStatus => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      identity.blobBackup.enabled = Boolean(args.enabled ?? false);
      return blobBackupStatus(identity);
    },
    run_blob_backup: (args): BlobBackupRunReport => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const backup = identity.blobBackup;
      if (backup.location === null) throw { code: 'BACKUP_UNAVAILABLE' };
      const missing = backup.remote.filter((b) => !backup.mirroredCids.includes(b.cid));
      backup.mirroredCids = [...backup.mirroredCids, ...missing.map((b) => b.cid)];
      backup.lastBackupAt = '2026-07-15T12:00:00.000Z';
      const mirrored = backup.remote.filter((b) => backup.mirroredCids.includes(b.cid));
      return {
        listed: backup.remote.length,
        alreadyPresent: backup.remote.length - missing.length,
        fetched: missing.length,
        fetchedBytes: missing.reduce((sum, b) => sum + b.size, 0),
        failed: [],
        backedUpCount: mirrored.length,
        backedUpBytes: mirrored.reduce((sum, b) => sum + b.size, 0),
      };
    },
    restore_blob_backup: (args): BlobRestoreReport => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const backup = identity.blobBackup;
      if (backup.location === null) throw { code: 'BACKUP_UNAVAILABLE' };
      // Evicted placeholders are "downloaded from iCloud first", then cleared — modeling
      // the real restore's on-demand materialization before upload.
      const downloaded = backup.evictedCids.filter((cid) => backup.mirroredCids.includes(cid));
      backup.evictedCids = backup.evictedCids.filter((cid) => !backup.mirroredCids.includes(cid));
      return {
        manifestCount: backup.mirroredCids.length,
        uploaded: backup.mirroredCids.length,
        downloadedFromIcloud: downloaded.length,
        failed: [],
      };
    },

    // ── repo backup (user-held CAR snapshot) ─────────────────────────────────
    get_repo_backup_status: (args): RepoBackupStatus => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      return repoBackupStatus(identity);
    },
    set_repo_backup_enabled: (args): RepoBackupStatus => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      identity.repoBackup.enabled = Boolean(args.enabled ?? false);
      return repoBackupStatus(identity);
    },
    run_repo_backup: (args): RepoBackupRunReport => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const backup = identity.repoBackup;
      if (backup.location === null) throw { code: 'BACKUP_UNAVAILABLE' };
      // Idempotent: a re-run at the same rev captures nothing new (`updated: false`) but
      // still advances the timestamp, mirroring the real rev short-circuit.
      const updated = backup.mirroredRev !== backup.rev;
      backup.mirroredRev = backup.rev;
      backup.lastBackupAt = '2026-07-15T12:00:00.000Z';
      return {
        rootCid: backup.rootCid,
        rev: backup.rev,
        sizeBytes: backup.sizeBytes,
        updated,
        lastBackupAt: backup.lastBackupAt,
      };
    },
    export_repo_backup: (args): RepoExport => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const backup = identity.repoBackup;
      if (backup.mirroredRev === null) {
        throw {
          code: 'STORAGE_ERROR',
          message: 'no repo snapshot has been backed up for this identity yet',
        };
      }
      return {
        rootCid: backup.rootCid,
        rev: backup.rev,
        sizeBytes: backup.sizeBytes,
        lastBackupAt: backup.lastBackupAt,
        // A stand-in for the base64 CAR bytes — the harness never imports it, only proves
        // the export surface returns validated metadata + a payload.
        carBase64: btoa(`fake-car:${backup.rootCid}`),
      };
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
