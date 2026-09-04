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
import { isDidWeb } from '$lib/did-doc-utils';
import type {
  IdentityInfo,
  VerifiedClaimOp,
  ClaimResult,
  SessionReady,
  SovereignLoginResult,
  IdentityStatus,
  MonitorHistory,
  SweepRecord,
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
  CustomHandleDnsCheck,
  MigrationPathDecision,
  PreparedMigration,
  AccountStatus,
  DidWebMigrationDocument,
  AgentSummary,
  AgentAuditPage,
  AgentClaimPreview,
  AgentClaimConfirmation,
  MintedChild,
  ChildSummary,
  ChildDeletion,
  ChildAssertion,
  ChildReconciliation,
  ChildKeyCheck,
  ConsentPreview,
  ConsentDecision,
  AppPasswordCreated,
  AppPasswordEntry,
  BlobBackupStatus,
  BlobBackupRunReport,
  BlobRestoreReport,
  RepoBackupStatus,
  RepoBackupRunReport,
  RegistrationOutcome,
  NotificationDiagnostics,
  RegisterHandleResult,
  CreateAccountResult,
  DIDCeremonyResult,
  DidWebPreparation,
  RekeyPreview,
  RekeyResult,
  SelfHeldKitPreview,
  SelfHeldKitResult,
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
  HARNESS_AGENT_SCOPES,
  type WalletState,
  type FakeIdentity,
  type FakeChild,
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
/** Share 2's harness envelope, distinct from Share 3's so the two-share backup screen can be
 *  read at a glance (and a screen that rendered one share twice would be visibly wrong). */
const HARNESS_SHARE2_ENVELOPE =
  'HARNESSSHARETWOAB2C3D4E5F6G7A2B3C4D5E6F7HARNESSQ2R3S4T5U6V7W2X3Y4Z56';
const HARNESS_SHARE2_WORDS = [
  'beacon', 'cobalt', 'dahlia', 'elm', 'fjord', 'gable', 'hazel',
  'indigo', 'jetty', 'kelp', 'lichen', 'mica', 'nectar', 'obsidian',
  'plume', 'quartz', 'rune', 'sable', 'thicket', 'umber', 'vellum',
  'willow', 'xenon', 'yarrow', 'zenith', 'amber', 'birch', 'cinder',
  'dune', 'estuary', 'flint', 'grove', 'harrow', 'inlet', 'jade',
  'kiln', 'loam', 'mesa', 'nimbus', 'onyx', 'pollen', 'quiver',
].join(' ');
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
  | 'import_did_web_identity'
  | 'check_handle_resolution'
  | 'get_pds_url'
  | 'save_pds_url'
  | 'get_pds_capabilities'
  // auth-session plugin (registered for the retired OAuth create-flow login; no live caller)
  | 'plugin:auth-session|start'
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
  // password-unlock.ts
  | 'get_identity_unlock_route'
  | 'unlock_identity_with_password'
  // monitor.ts
  | 'check_identity_status'
  | 'get_monitor_history'
  // recovery.ts
  | 'build_recovery_override_cmd'
  | 'submit_recovery_override_cmd'
  // share-recovery.ts
  | 'start_share_recovery'
  | 'add_recovery_share'
  | 'initiate_escrow_release'
  | 'request_escrow_release'
  | 'verify_recovery_shares'
  | 'recover_identity'
  | 'run_recovery_epilogue'
  | 'get_pending_recovery_epilogue'
  | 'confirm_recovery_backup'
  // removal.ts
  | 'get_identity_removal_route'
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
  | 'check_custom_handle_dns'
  // endpoint-repair.ts
  | 'repair_hosting_endpoint'
  // rotation.ts
  | 'build_repo_key_rotation_cmd'
  | 'submit_repo_key_rotation_cmd'
  // rekey.ts
  | 'build_rekey_cmd'
  | 'submit_rekey_cmd'
  | 'confirm_rekey_cmd'
  | 'rekey_in_progress_cmd'
  // self-held-kit.ts
  | 'build_self_held_kit_cmd'
  | 'submit_self_held_kit_cmd'
  | 'confirm_self_held_kit_cmd'
  | 'self_held_kit_in_progress_cmd'
  // agents.ts
  | 'list_agents'
  | 'revoke_agent'
  | 'get_agent_audit'
  | 'preview_agent_claim'
  | 'confirm_agent_claim'
  | 'agent_accounts_provisioned'
  | 'mint_child_from_claim'
  | 'list_children'
  | 'revoke_child'
  | 'delete_child'
  | 'remint_child_assertion'
  | 'reconcile_children'
  | 'preview_oauth_consent'
  | 'preview_oauth_consent_by_request_id'
  | 'confirm_oauth_consent'
  // notification-routes.ts
  | 'take_pending_notification_route'
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
  // notifications.ts
  | 'register_for_notifications'
  | 'get_notification_diagnostics'
  | 'clear_notification_failures'
  // biometric plugin (driven by $lib/biometric — resolves = allow the gate)
  | 'plugin:biometric|authenticate'
  | 'plugin:biometric|status';

export type Registry = Record<CommandName, Handler>;

/** Read `did` from an args object (the common single-arg case). */
function didArg(args: Record<string, unknown>): string {
  return String(args.did ?? '');
}

/** When a harness-minted child was created — the same pinned instant `seedAgent` uses. */
const HARNESS_CHILD_CREATED_AT = '2026-07-15T12:00:00.000Z';
/** The harness's stand-in for the server's `accounts.child_deletion_grace_secs`. */
const HARNESS_CHILD_GRACE_HOURS = 24 * 7;

/**
 * Find the child named by `childDid` under the parent `did` and apply `mutate` to it.
 *
 * Scoped to the parent on purpose: the real routes reach children only through
 * `get_child_of_parent`, and answer a uniform `AGENT_NOT_FOUND` for a child that is unknown *or*
 * belongs to someone else. A fake that searched every identity would let a screen pass here and
 * 404 in production.
 */
function mutateChild(
  state: WalletState,
  args: Record<string, unknown>,
  mutate: (child: FakeChild) => void
): FakeChild {
  const identity = findIdentity(state, didArg(args));
  const child = identity?.children.find((c) => c.did === String(args.childDid ?? ''));
  if (!child) throw { code: 'AGENT_NOT_FOUND' };
  mutate(child);
  return child;
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
    import_did_web_identity: (args) => {
      // Mirror the backend's normalization: bare domain, https:// URL, or did:web form.
      const raw = String(args.input ?? '')
        .trim()
        .toLowerCase()
        .replace(/^did:web:/, '')
        .replace(/^https?:\/\//, '')
        .replace(/\/$/, '');
      if (!raw || !raw.includes('.') || /[:/@]/.test(raw)) {
        throw { code: 'INVALID_DOMAIN', message: 'enter a public domain name without a path or port' };
      }
      const did = `did:web:${raw}`;
      // An imported did:web is managed but not root-key: its live document carries no
      // #device until the migration identity leg publishes one.
      const identity = seedIdentity({
        handle: raw,
        did,
        pdsUrl: state.pdsUrl ?? DEFAULT_PDS_URL,
        deviceKeyIsRoot: false,
      });
      upsertIdentity(state, identity);
      return { did, handle: raw, pdsUrl: identity.pdsUrl };
    },
    check_handle_resolution: (): boolean => true,
    get_pds_url: (): string | null => state.pdsUrl,
    save_pds_url: (args) => {
      state.pdsUrl = String(args.url ?? '');
      return null;
    },
    // The fake host stands in for a fully-featured Custos. Edit
    // `window.__harness.state().pdsCapabilities` to drive the screens the way a
    // reference PDS would (no `custos` extension at all → no capabilities).
    get_pds_capabilities: () => state.pdsCapabilities,

    // The auth-session plugin's `start()` command — registered for the retired OAuth
    // create-flow login (no live caller); the stub is kept so the plugin itself, still
    // registered in `run()`, has a harness handler if anything invokes it directly.
    'plugin:auth-session|start': () =>
      'org.obsign.identitywallet:/oauth/callback?code=harness-code&state=harness-state',

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
      // The enclave-liveness verdict, not a lookup failure: metadata present, key gone.
      if (identity?.deviceKeyUnusable) throw { code: 'DEVICE_KEY_UNUSABLE' };
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
    // Which unlock the identity's host can serve. Reads the same capability set the create
    // gate does, so the `foreign-pds` scenario routes to the password prompt and a Custos
    // scenario keeps the biometric one. An unreached probe stays SOVEREIGN — the wallet must
    // not tell a user their server lacks a feature because it could not be asked.
    get_identity_unlock_route: (args) => {
      const identity = findIdentity(state, didArg(args));
      const sovereign =
        !state.pdsCapabilities.reached ||
        state.pdsCapabilities.capabilities.includes('sovereignSessions');
      return {
        method: sovereign ? 'SOVEREIGN' : 'PASSWORD',
        pdsUrl: identity?.pdsUrl ?? DEFAULT_PDS_URL,
        handle: identity?.handle ?? null,
      };
    },
    // The password path. Any non-empty password succeeds here; drive the failure states
    // (`INVALID_CREDENTIALS`, `TWO_FACTOR_REQUIRED`, …) with
    // `window.__harness.failNext('unlock_identity_with_password', { code: '…' })`.
    unlock_identity_with_password: (args): SessionReady => ({
      did: didArg(args),
      pdsUrl: findIdentity(state, didArg(args))?.pdsUrl ?? DEFAULT_PDS_URL,
      accessExpiresAt: farFuture(),
      refreshExpiresAt: farFuture(),
      rotated: false,
    }),

    // ── PLC monitor ──────────────────────────────────────────────────────────
    // The sweep omits a did:web rather than reporting a verdict for it, mirroring
    // `check_all`: the audit log it diffs exists only for a did:plc, so a did:web is
    // skipped outright instead of asked about and marked failed. Keeping the omission
    // here is what lets a screen's did:web branch be exercised in the browser — a fake
    // that returned an entry (failed OR clear) would feed it a reading the real backend
    // never produces, in exactly the place a screen is most likely to get did:web wrong.
    check_identity_status: (): IdentityStatus[] => {
      const statuses = sweepStatuses(state);
      recordFakeSweep(state, statuses, 'foreground');
      return statuses;
    },

    get_monitor_history: (): MonitorHistory => {
      // The browser has no 15-minute timer, so a scenario meant to depict a wallet that
      // has been running for a while would otherwise show an empty log — the one reading
      // the Protection surface must not give when protection IS happening. Seed the
      // unattended passes the fake cannot run, once, on first read.
      if (state.monitorSweeps.length === 0 && sweepStatuses(state).length > 0) {
        for (const minutesAgo of [30, 15]) {
          recordFakeSweep(
            state,
            sweepStatuses(state),
            'background',
            Date.now() - minutesAgo * 60_000
          );
        }
      }

      return {
        sweeps: state.monitorSweeps,
        // Only swept identities carry a last-verified entry, mirroring `fold_sweep`, which
        // keeps entries for the DIDs the pass covered. A did:web is absent rather than
        // present-and-never-verified: the history reports what the monitor did, and it did
        // not look. The Protection surface still lists it — its rows come from the identity
        // store, not from here — and says so in its own words.
        identities: sweepStatuses(state).map((s) => ({
          did: s.did,
          lastVerifiedAt: state.monitorSweeps[0]?.at ?? null,
        })),
        intervalSecs: FAKE_MONITOR_INTERVAL_SECS,
      };
    },

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
      // Verification is also the provisioning path: the real backend derives and persists
      // the delegation seed here, which is what "Enable agent accounts" runs to backfill an
      // identity created before the seed existed.
      const provisioned = findIdentity(state, did);
      if (provisioned) provisioned.agentAccountsProvisioned = true;
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
    // Which credential removal needs. Reads the same capability set the other host gates do,
    // so the `foreign-pds` scenario shows the password field and a Custos scenario hides it.
    // Unlike the unlock route, an unreached probe here means "ask for the password": the
    // request would be refused anyway, and a field the user can ignore beats a missing one.
    get_identity_removal_route: (args) => {
      const identity = findIdentity(state, didArg(args));
      return {
        requiresPassword: !state.pdsCapabilities.capabilities.includes('walletAccountDelete'),
        pdsUrl: identity?.pdsUrl ?? DEFAULT_PDS_URL,
      };
    },
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
    // Deterministic scriptable outcomes, keyed by the typed handle so every state is
    // reachable from the UI without console scripting: a handle under `missing.` /
    // `propagating.` simulates that verdict, a handle another fake identity holds
    // reports WRONG_DID, anything else verifies. (`failNext` still injects the error
    // paths, e.g. NETWORK_ERROR.)
    check_custom_handle_dns: (args): CustomHandleDnsCheck => {
      const did = didArg(args);
      const handle = String(args.handle ?? '')
        .trim()
        .replace(/^@/, '')
        .toLowerCase();
      const base = {
        foundDid: null,
        recordName: `_atproto.${handle}`,
        recordValue: `did=${did}`,
      };
      if (handle.startsWith('missing.')) return { status: 'NOT_FOUND', ...base };
      if (handle.startsWith('propagating.')) return { status: 'PROPAGATING', ...base };
      const other = state.identities.find((i) => i.handle === handle && i.did !== did);
      if (other) return { status: 'WRONG_DID', ...base, foundDid: other.did };
      return { status: 'VERIFIED', ...base };
    },

    // ── repair hosting endpoint ──────────────────────────────────────────────
    repair_hosting_endpoint: (args) => {
      const identity = findIdentity(state, didArg(args));
      const oldEndpoint = identity?.pdsUrl ?? 'https://old.harness.example';
      const newEndpoint = String(args.newEndpoint ?? oldEndpoint).replace(/\/+$/, '');
      const changed = newEndpoint !== oldEndpoint;
      if (identity && changed) identity.pdsUrl = newEndpoint;
      return {
        oldEndpoint,
        newEndpoint,
        opCid: changed ? 'bafyharnessrepaircid' : null,
      };
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

    // ── self-held Shamir kit (escrow-less recovery key, MM-456) ──────────────
    build_self_held_kit_cmd: (args): SelfHeldKitPreview => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      if (did.startsWith('did:web:')) throw { code: 'NOT_DID_PLC' };
      const recoveryKey = fakeRecoveryKeyId(did);
      // Resumable: a kit already in flight is always allowed. A fresh one needs the device key
      // at [0] and a host with no escrow route — mirroring the Rust precheck exactly, so the
      // harness can reproduce both refusals.
      if (!identity.selfHeldKitStagedRecoveryKey) {
        if (identity.rotationKeys[0] !== identity.deviceKeyId) {
          throw { code: 'WALLET_NOT_AUTHORIZED' };
        }
        if (state.pdsCapabilities.capabilities.includes('escrow')) {
          throw { code: 'HOST_OFFERS_ESCROW' };
        }
      }
      identity.selfHeldKitStagedRecoveryKey = recoveryKey;
      return {
        diff: {
          addedKeys: [recoveryKey],
          removedKeys: [],
          changedServices: [],
          prevCid: 'bafyharnesskitprev',
        },
        recoveryKeyId: recoveryKey,
        pdsUrl: identity.pdsUrl,
      };
    },
    submit_self_held_kit_cmd: (args): SelfHeldKitResult => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      if (did.startsWith('did:web:')) throw { code: 'NOT_DID_PLC' };
      const recoveryKey = identity.selfHeldKitStagedRecoveryKey ?? fakeRecoveryKeyId(did);
      identity.selfHeldKitStagedRecoveryKey = recoveryKey;
      // Additively insert the recovery key at [1], shifting the whole claimed tail down —
      // idempotent, so a resumed submit whose op already landed changes nothing.
      if (!identity.rotationKeys.includes(recoveryKey)) {
        const [device, ...rest] = identity.rotationKeys;
        identity.rotationKeys = [device, recoveryKey, ...rest];
      }
      identity.selfHeldKitInstalled = true;
      return {
        updatedDidDoc: makeDidDoc(identity),
        share2: HARNESS_SHARE2_ENVELOPE,
        share2Words: HARNESS_SHARE2_WORDS,
        share3: HARNESS_SHARE3_ENVELOPE,
        share3Words: HARNESS_SHARE3_WORDS,
      };
    },
    confirm_self_held_kit_cmd: (args) => {
      const identity = findIdentity(state, didArg(args));
      if (identity) identity.selfHeldKitStagedRecoveryKey = null;
      return null;
    },
    self_held_kit_in_progress_cmd: (args): boolean => {
      const identity = findIdentity(state, didArg(args));
      return Boolean(identity?.selfHeldKitStagedRecoveryKey);
    },
    // ── agents ───────────────────────────────────────────────────────────────
    agent_accounts_provisioned: (args): boolean =>
      findIdentity(state, didArg(args))?.agentAccountsProvisioned ?? false,
    list_agents: (): AgentSummary[] => state.identities.flatMap((i) => i.agents.map((a) => a.summary)),
    revoke_agent: (args) => {
      const registrationId = String(args.registrationId ?? '');
      for (const identity of state.identities) {
        const agent = identity.agents.find((a) => a.summary.registrationId === registrationId);
        if (agent) agent.summary.status = 'revoked';
      }
      return null;
    },
    // Children are searched too: a child's registration is bound to the child's DID, so the
    // parent reads its trail through the /v1/agents *parent arm* rather than owning the row.
    get_agent_audit: (args): AgentAuditPage => {
      const registrationId = String(args.registrationId ?? '');
      for (const identity of state.identities) {
        const agent = identity.agents.find((a) => a.summary.registrationId === registrationId);
        if (agent) return { events: agent.audit };
        const child = identity.children.find((c) => c.registrationId === registrationId);
        if (child) return { events: child.audit };
      }
      return { events: [] };
    },
    // A user code starting with "CHILD" previews an *anonymous* registration carrying a proposed
    // handle — the only registration kind the server will mint a child for, and so the only way to
    // reach the own-account fork in a browser.
    preview_agent_claim: (args): AgentClaimPreview => {
      const userCode = String(args.userCode ?? 'HARNESS');
      if (userCode.startsWith('CHILD')) {
        return {
          registrationId: `reg-${userCode}`,
          registrationType: 'anonymous',
          scopes: [...HARNESS_AGENT_SCOPES],
          userCodeExpiresAt: isoInHours(1),
          handleHint: 'scribe.harness.pds.local',
        };
      }
      return {
        registrationId: `reg-${userCode}`,
        registrationType: 'service_auth',
        issuer: 'did:web:agent.example',
        subject: state.identities[0]?.did,
        scopes: [...HARNESS_AGENT_SCOPES],
        userCodeExpiresAt: isoInHours(1),
      };
    },
    // The cooperative arm. The real command reserves a signing key, derives the child's rotation
    // key at the next index, signs its genesis op and confirms the claim with it; the fake keeps
    // the two properties the screens depend on — an unprovisioned identity cannot mint, and a
    // handle already in use is refused *without* consuming the claim, so the user corrects and
    // retries rather than restarting the ceremony.
    mint_child_from_claim: (args): MintedChild => {
      const did = didArg(args);
      const identity = findIdentity(state, did) ?? state.identities[0];
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND' };
      if (!identity.agentAccountsProvisioned) throw { code: 'NOT_PROVISIONED' };

      const handle = String(args.handle ?? '').trim().toLowerCase();
      const taken =
        state.identities.some((i) => i.handle === handle) ||
        state.identities.some((i) => i.children.some((c) => c.handle === handle));
      if (taken) {
        throw { code: 'HANDLE_REJECTED', message: 'Handle is already taken on this server.' };
      }

      // The child DID stands in for the genesis-op hash: derived from the parent and the index, so
      // successive mints yield distinct children exactly as distinct derivation indices do.
      const child: FakeChild = {
        registrationId: `reg-${String(args.userCode ?? 'HARNESS')}`,
        did: fakePlcDid(`${identity.did}:child:${identity.children.length}`),
        handle,
        status: 'claimed',
        createdAt: HARNESS_CHILD_CREATED_AT,
        scopes: [...HARNESS_AGENT_SCOPES],
        audit: [
          {
            id: `ev-${identity.children.length}-claim`,
            eventType: 'claim_confirmed',
            createdAt: HARNESS_CHILD_CREATED_AT,
          },
        ],
      };
      identity.children.push(child);
      // The real command advances the index only after the server confirms, so a rejected handle
      // costs nothing — the two mutations belong together here for the same reason.
      identity.childIndex = Math.max(identity.childIndex, identity.children.length);
      return { registrationId: child.registrationId, did: child.did, handle: child.handle };
    },

    // ── child lifecycle (the parent console) ─────────────────────────────────
    // Children are per-identity here, unlike `list_agents`, which flattens every identity's
    // agents. That mirrors the server: a child is listed by its parent, never globally.
    // Projected field by field, not spread: `FakeChild` also carries the child's audit trail,
    // and a fake that handed a screen data the real route never returns is how a screen comes to
    // depend on it.
    list_children: (args): ChildSummary[] =>
      (findIdentity(state, didArg(args))?.children ?? []).map((c) => ({
        registrationId: c.registrationId,
        did: c.did,
        handle: c.handle,
        status: c.status,
        createdAt: c.createdAt,
        scopes: [...c.scopes],
        ...(c.deleteAfter ? { deleteAfter: c.deleteAfter } : {}),
      })),
    revoke_child: (args) => {
      mutateChild(state, args, (child) => {
        child.status = 'revoked';
      });
      return null;
    },
    delete_child: (args): ChildDeletion => {
      const child = mutateChild(state, args, (c) => {
        // Delete implies revoke on the server, so the fake must not model them as independent —
        // a screen that assumed otherwise would look right here and be wrong in production.
        c.status = 'revoked';
        c.deleteAfter = isoInHours(HARNESS_CHILD_GRACE_HOURS);
      });
      return {
        did: child.did,
        status: 'deletion_scheduled',
        deleteAfter: child.deleteAfter as string,
      };
    },
    // The recovery epilogue. The real command re-derives a key per index and checks each against
    // the child's plc.directory audit log; the fake keeps the two properties the screen depends
    // on — it reports nothing at all when the local counter already covers the server's list (so
    // the ordinary device never sees a banner), and it distinguishes a key that does not derive
    // from one the directory could not be asked about.
    reconcile_children: (args): ChildReconciliation => {
      const identity = findIdentity(state, didArg(args));
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND' };
      if (!identity.agentAccountsProvisioned) throw { code: 'NOT_PROVISIONED' };
      if (identity.childIndex >= identity.children.length) {
        return { rebuilt: false, children: [], nextIndex: identity.childIndex };
      }

      const children: ChildKeyCheck[] = identity.children.map((child, index) => {
        const base = { did: child.did, handle: child.handle };
        if (child.recoveryKey === 'lost') return { ...base, status: 'unmatched' };
        if (child.recoveryKey === 'unreachable') {
          return { ...base, status: 'unchecked', message: 'plc.directory could not be read' };
        }
        return { ...base, status: 'matched', index };
      });
      const nextIndex = children.reduce(
        (highest, check) => (check.status === 'matched' ? Math.max(highest, check.index + 1) : highest),
        identity.childIndex
      );
      identity.childIndex = nextIndex;
      return { rebuilt: true, children, nextIndex };
    },
    remint_child_assertion: (args): ChildAssertion => {
      const child = mutateChild(state, args, () => {});
      // Renewal is refused for anything not live — revocation is a one-way rung on the custody
      // ladder, and the real route answers 403 (ACCESS_DENIED), never a retryable error.
      if (child.status !== 'claimed') {
        throw { code: 'ACCESS_DENIED' };
      }
      return {
        did: child.did,
        registrationId: child.registrationId,
        identityAssertion: `harness.${child.registrationId}.assertion`,
        assertionExpires: isoInHours(24),
        scopes: child.scopes,
      };
    },
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
            scopes: [...HARNESS_AGENT_SCOPES],
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
    // A user code starting with "PUSH" fakes a push-delivered prompt (matchRequired), so the
    // number-match UI is reachable in a browser; the matching number is always "42".
    // A user code starting with "SPACE" previews a granular request carrying an Atproto
    // Spaces grant, so the space-scope consent copy is reachable in a browser.
    preview_oauth_consent: (args): ConsentPreview => ({
      requestId: `poauth-${String(args.userCode ?? 'HARNESS')}`,
      clientId: 'https://app.example.com/client-metadata.json',
      clientName: 'Example App',
      redirectUri: 'https://app.example.com/callback',
      origin: 'https://app.example.com',
      ip: '203.0.113.5',
      requestedScope: String(args.userCode ?? '').startsWith('SPACE')
        ? [
            'atproto',
            'repo:*?action=create&action=update',
            'space:org.example.bucket?authority=self&collection=org.example.note',
          ]
        : ['atproto', 'transition:generic'],
      loginHint: null,
      matchRequired: String(args.userCode ?? '').startsWith('PUSH'),
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
      matchRequired: String(args.requestId ?? '').includes('push'),
    }),
    confirm_oauth_consent: (args): ConsentDecision => {
      // Mirrors the server's Phase C rule: a push-delivered approval needs the number shown on
      // the sign-in surface, and a wrong one leaves the request pending (typed retry works).
      const requestId = String(args.requestId ?? '');
      const pushDelivered = requestId.startsWith('poauth-PUSH') || requestId.includes('push');
      if (
        String(args.decision) === 'approve' &&
        pushDelivered &&
        String(args.matchCode ?? '') !== '42'
      ) {
        throw { code: 'MATCH_CODE_MISMATCH' };
      }
      return {
        status: String(args.decision) === 'deny' ? 'denied' : 'approved',
        did: String(args.did ?? state.identities[0]?.did ?? ''),
      };
    },

    // ── notification tap routing (push-to-approve deep link) ─────────────────
    // No push can arrive in a browser, so the parked-route slot is always empty here; the
    // deep-link path itself is exercised on-device (the route store is host-tested in Rust).
    take_pending_notification_route: () => null,

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
      const personalDetails = Boolean(args.personalDetails ?? false);
      if (identity.appPasswords.some((p) => p.name === name)) {
        throw { code: 'DUPLICATE_NAME' };
      }
      const entry = { name, createdAt: '2026-07-15T12:00:00.000Z', privileged, personalDetails };
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
    // ── push notifications ───────────────────────────────────────────────────
    // The fake models the two states a browser can genuinely be in. With no `apnsToken` (the
    // default — a browser has no APNs) registration reports `AWAITING_APNS_TOKEN` exactly as a
    // simulator does; set `state().notifications.apnsToken` to drive the registered path.
    register_for_notifications: (args): RegistrationOutcome => {
      const did = didArg(args);
      const identity = findIdentity(state, did);
      if (!identity) throw { code: 'IDENTITY_NOT_FOUND', message: 'identity not found' };
      const notifications = state.notifications;

      if (notifications.apnsToken === null) {
        return {
          status: 'AWAITING_APNS_TOKEN',
          deviceUuid: notifications.deviceUuid,
          notificationKeyId: null,
        };
      }
      // The real backend mints the key before it talks to the host, so it holds one even when
      // the host turns out to serve no notification routes.
      notifications.notificationKeyMinted = true;

      // `relaySupported` is the host's own `[notifications] relay` config, which is what the
      // real routes answer 501 on — deliberately not read off `pdsCapabilities`, which
      // advertises nothing about notifications.
      if (!notifications.relaySupported) {
        return {
          status: 'UNSUPPORTED',
          deviceUuid: notifications.deviceUuid,
          notificationKeyId: notifications.notificationKeyId,
        };
      }
      if (!notifications.registeredDids.includes(did)) notifications.registeredDids.push(did);
      // The real command re-pins on the same contact, so the fake does too.
      notifications.pinnedHosts[identity.pdsUrl] = [
        { kid: 1, publicKey: 'did:key:zDnaeharnesssenderkey00000000000000000000001' },
      ];
      return {
        status: 'REGISTERED',
        deviceUuid: notifications.deviceUuid,
        notificationKeyId: notifications.notificationKeyId,
      };
    },
    get_notification_diagnostics: (): NotificationDiagnostics => ({
      deviceUuid: state.notifications.deviceUuid,
      // Read off whether a key was minted, never off the APNs token: the real command reads the
      // Keychain scalar, so a device that registered and later lost its token still has a key.
      notificationKeyId: state.notifications.notificationKeyMinted
        ? state.notifications.notificationKeyId
        : null,
      hasApnsToken: state.notifications.apnsToken !== null,
      pinnedHosts: state.notifications.pinnedHosts,
      recentFailures: state.notifications.recentFailures,
    }),
    // The real command deletes the Keychain slot the extension appends to; there is no
    // extension in a browser, so the fake truncates the seeded list in place.
    clear_notification_failures: (): null => {
      state.notifications.recentFailures.length = 0;
      return null;
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
    // A did:web has no PLC tombstone, so the real backend reports no CID for one. Mirroring
    // that here is what lets the harness reach RemoveIdentityScreen's did:web epilogue.
    tombstoneCid: did.startsWith('did:web:') ? null : `bafyharnesstombstone${did.slice(-6)}`,
    wasLastIdentity: before > 0 && state.identities.length === 0,
  };
}

/** An access/refresh expiry far enough out that the session never reads as expired. */
function farFuture(): number {
  return Date.parse('2030-01-01T00:00:00.000Z');
}

/**
 * What one sweep covers: the monitorable identities and their verdicts.
 *
 * Shared by the live fake check and the seeded background passes so both describe the same
 * sweep. `is_monitorable` in plc_monitor.rs is the rule being mirrored — a did:web has no
 * PLC audit log, so it is not in the pass at all, and every count derived from this
 * (`identitiesChecked`, `identitiesFailed`) is about identities the monitor really looked at.
 */
function sweepStatuses(state: WalletState): IdentityStatus[] {
  return state.identities
    .filter((i) => !isDidWeb(i.did))
    .map((i) => ({
      did: i.did,
      checkFailed: false,
      unauthorizedChanges: i.alerts,
    }));
}

/** The cadence the fake reports, mirroring `MONITOR_INTERVAL_SECS` in plc_monitor.rs. */
const FAKE_MONITOR_INTERVAL_SECS = 15 * 60;

/** Newest-first cap, mirroring `MAX_SWEEP_RECORDS` in plc_monitor.rs. */
const FAKE_MAX_SWEEPS = 20;

/**
 * Append a sweep to the fake log, coalescing an identical foreground repeat the way the
 * backend's `fold_sweep` does. Mirrored rather than shared because the fold lives in Rust:
 * a fake that let every screen entry push its own entry would show a log the real app
 * never produces, and the Protection surface would look correct here and wrong on device.
 */
function recordFakeSweep(
  state: WalletState,
  statuses: IdentityStatus[],
  trigger: 'background' | 'foreground',
  atMs: number = Date.now()
) {
  const at = new Date(Math.floor(atMs / 1000) * 1000).toISOString().replace(/\.000Z$/, 'Z');
  const record: SweepRecord = {
    at,
    trigger,
    identitiesChecked: statuses.length,
    identitiesFailed: statuses.filter((s) => s.checkFailed).length,
    unauthorizedFound: statuses.reduce((n, s) => n + s.unauthorizedChanges.length, 0),
  };

  const newest = state.monitorSweeps[0];
  const sameOutcome =
    newest !== undefined &&
    newest.trigger === record.trigger &&
    newest.identitiesChecked === record.identitiesChecked &&
    newest.identitiesFailed === record.identitiesFailed &&
    newest.unauthorizedFound === record.unauthorizedFound &&
    atMs - Date.parse(newest.at) < 5 * 60_000;

  if (sameOutcome) {
    state.monitorSweeps[0] = record;
  } else {
    state.monitorSweeps = [record, ...state.monitorSweeps].slice(0, FAKE_MAX_SWEEPS);
  }
}

/**
 * An ISO timestamp `hours` from now — live clock, for the same reason as `scenarios.ts`'s
 * `isoHoursAgo`. A future offset pinned to a literal base is worse than a stale one: it
 * lands in the past, so an expiry seeded an hour out reads as already expired.
 */
function isoInHours(hours: number): string {
  return new Date(Date.now() + hours * 3600_000).toISOString();
}
