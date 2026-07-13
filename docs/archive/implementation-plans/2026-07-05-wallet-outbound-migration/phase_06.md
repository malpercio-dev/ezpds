# Wallet Outbound Migration — Phase 6: TypeScript IPC wrappers + types

**Goal:** Make every new orchestrator command callable from the SvelteKit frontend through a typed wrapper in `src/lib/ipc.ts`, with an `AccountStatus` type and a `MigrationError` union that exactly matches the Rust enum's SCREAMING_SNAKE_CASE codes, and keep `apps/identity-wallet/AGENTS.md` in sync.

**Architecture:** `ipc.ts` wraps each Tauri command with `invoke('<snake_case_name>', { camelCaseArgs })` from `@tauri-apps/api/core`. Rust `#[serde(tag="code", rename_all="SCREAMING_SNAKE_CASE")]` errors surface as `invoke` rejections shaped `{ code: "...", ... }`, modeled as a discriminated union. The source-auth prepare/complete pair is wrapped as one `startSourceAuth` helper driving `plugin:auth-session|start`, mirroring the claim flow's `startPdsAuth`.

**Tech Stack:** TypeScript, SvelteKit 2, `@tauri-apps/api/core` `invoke`, `svelte-check` (via `pnpm check`).

**Scope:** Phase 6 of 7. This is a **verification-by-typecheck** phase (types are checked by the compiler; there are no runtime unit tests — `pnpm check` is the gate).

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC8: The commands are callable from the frontend with matching types
- **wallet-outbound-migration.AC8.1 Success:** `src/lib/ipc.ts` exposes a typed wrapper for every new orchestrator command.
- **wallet-outbound-migration.AC8.2 Success:** The TS `MigrationError` union matches the Rust enum's SCREAMING_SNAKE_CASE codes exactly.
- **wallet-outbound-migration.AC8.3 Success:** `pnpm check` (frontend type-check) passes.

---

## Verified codebase facts

File `apps/identity-wallet/src/lib/ipc.ts`:
- `import { invoke } from '@tauri-apps/api/core';` (line 1).
- Simple wrapper form: `export const createAccount = (params: CreateAccountParams): Promise<CreateAccountResult> => invoke('create_account', params);` (44–47).
- Command name is the **snake_case** Rust fn name; args are a **camelCase** object.
- Auth-session pair pattern (claim flow), `startPdsAuth` (498–514):
  ```ts
  export const startPdsAuth = async (pdsUrl: string): Promise<void> => {
    const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_pds_auth', { pdsUrl });
    let callbackUrl: string;
    try {
      callbackUrl = await invoke<string>('plugin:auth-session|start', {
        authUrl: prepared.authUrl, callbackUrlScheme: prepared.callbackScheme });
    } catch { throw { code: 'UNAUTHORIZED' } as ClaimError; }
    await invoke('complete_pds_auth', { callbackUrl });
  };
  ```
- Error-union style (OAuthError 243–254; RegisterHandleError 177–185): `| { code: 'X' }` / `| { code: 'X'; message: string }`.
- Response type mirroring (camelCase), e.g. `SessionInfo { did; handle; email; emailConfirmed; didDoc }` (294–301).
- Migration identity-leg wrappers already exist (684–694): `buildMigrationOp(did)` → `invoke('build_migration_op_cmd', { did })`, `submitMigrationOp(did)` → `invoke('submit_migration_op_cmd', { did })`.
- All types are inline in `ipc.ts`, exported at module level. No `types.ts`.
- `pnpm check` = `svelte-kit sync && svelte-check --tsconfig ./tsconfig.json` (package.json line 5). Run from `apps/identity-wallet/` (devenv provides Node 22 + pnpm).

File `apps/identity-wallet/AGENTS.md`:
- Lines 13–15: `**Exposes:**` → `src/lib/ipc.ts` with a comma-separated list of exported function names + `their associated types`. Ends with "migration wrappers (`buildMigrationOp()`, `submitMigrationOp()`)".
- ~line 49: a Rust-module "contract" area describing `migrate.rs`.

---

## Rust → TS mapping (must match exactly for AC8.2)

The Rust `MigrationError` (Phase 3) has these variants → codes:

| Rust variant | TS `code` | Extra fields |
|---|---|---|
| `MigrationNotReady { message }` | `MIGRATION_NOT_READY` | `message: string` |
| `DestinationUnreachable { message }` | `DESTINATION_UNREACHABLE` | `message: string` |
| `SourceAuthFailed { message }` | `SOURCE_AUTH_FAILED` | `message: string` |
| `ServiceAuthFailed { message }` | `SERVICE_AUTH_FAILED` | `message: string` |
| `AccountCreationFailed { message }` | `ACCOUNT_CREATION_FAILED` | `message: string` |
| `DestinationConflict { message }` | `DESTINATION_CONFLICT` | `message: string` |
| `RepoTransferFailed { message }` | `REPO_TRANSFER_FAILED` | `message: string` |
| `BlobTransferFailed { message }` | `BLOB_TRANSFER_FAILED` | `message: string` |
| `PreferencesTransferFailed { message }` | `PREFERENCES_TRANSFER_FAILED` | `message: string` |
| `VerificationIncomplete { imported, expected }` | `VERIFICATION_INCOMPLETE` | `imported: number; expected: number` |
| `ActivationFailed { message }` | `ACTIVATION_FAILED` | `message: string` |
| `DeactivationFailed { message }` | `DEACTIVATION_FAILED` | `message: string` |
| `NetworkError { message }` | `NETWORK_ERROR` | `message: string` |

**Executor note:** re-read the final Rust `MigrationError` enum in `migration_orchestrator.rs` before writing the union — if Phase 3–5 added/renamed a variant, the union must track it verbatim (AC8.2). This table reflects the plan; the code is the source of truth.

`AccountStatus` (Phase 2/4, `#[serde(rename_all="camelCase")]`) → TS type with camelCase fields and the same optionality (`repoCommit?`, `repoRev?`).

---

<!-- START_TASK_1 -->
### Task 1: `AccountStatus` + `MigrationError` types

**Verifies:** wallet-outbound-migration.AC8.2

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts` (add types near the other migration types, after the existing `SignedMigrationOp`/`MigrateError` block ~lines 646–664)

**Implementation:**
```ts
/** Mirrors the Rust AccountStatus (com.atproto.server.checkAccountStatus, ezpds shape). */
export type AccountStatus = {
  activated: boolean;
  validDid: boolean;
  repoCommit?: string;
  repoRev?: string;
  storedBlocks: number;       // ezpds returns "storedBlocks" (not canonical "repoBlocks")
  indexedRecords: number;
  privateStateValues: number;
  expectedBlobs: number;
  importedBlobs: number;
};

/** Matches the Rust migration_orchestrator::MigrationError SCREAMING_SNAKE_CASE codes exactly. */
export type MigrationError =
  | { code: 'MIGRATION_NOT_READY'; message: string }
  | { code: 'DESTINATION_UNREACHABLE'; message: string }
  | { code: 'SOURCE_AUTH_FAILED'; message: string }
  | { code: 'SERVICE_AUTH_FAILED'; message: string }
  | { code: 'ACCOUNT_CREATION_FAILED'; message: string }
  | { code: 'DESTINATION_CONFLICT'; message: string }
  | { code: 'REPO_TRANSFER_FAILED'; message: string }
  | { code: 'BLOB_TRANSFER_FAILED'; message: string }
  | { code: 'PREFERENCES_TRANSFER_FAILED'; message: string }
  | { code: 'VERIFICATION_INCOMPLETE'; imported: number; expected: number }
  | { code: 'ACTIVATION_FAILED'; message: string }
  | { code: 'DEACTIVATION_FAILED'; message: string }
  | { code: 'NETWORK_ERROR'; message: string };
```
(No `OutboundMigrationState` view type is needed — no command returns the full state; a status getter is deferred to the UI ticket MM-232.)

**Testing:** None (types; `svelte-check` verifies). Proven by Task 3's `pnpm check`.

**Commit:** `feat(wallet-ui): AccountStatus + MigrationError TS types`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Command wrappers

**Verifies:** wallet-outbound-migration.AC8.1

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts`

**Implementation:** Add one wrapper per new command (place near the existing migration wrappers ~line 684). Use the exact snake_case command names registered in `lib.rs` and camelCase args.
```ts
export const prepareMigration = (did: string, destPdsUrl: string): Promise<void> =>
  invoke('prepare_migration', { did, destPdsUrl });

/** Source-PDS OAuth: prepare -> in-app auth session -> complete (mirrors startPdsAuth). */
export const startSourceAuth = async (did: string): Promise<void> => {
  const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_source_auth', { did });
  let callbackUrl: string;
  try {
    callbackUrl = await invoke<string>('plugin:auth-session|start', {
      authUrl: prepared.authUrl, callbackUrlScheme: prepared.callbackScheme });
  } catch {
    throw { code: 'SOURCE_AUTH_FAILED', message: 'auth session cancelled' } as MigrationError;
  }
  await invoke('complete_source_auth', { did, callbackUrl });
};

export const createDestinationAccount = (did: string, email: string, inviteCode?: string): Promise<void> =>
  invoke('create_destination_account', { did, email, inviteCode });

export const transferRepo = (did: string): Promise<void> => invoke('transfer_repo', { did });
export const transferBlobs = (did: string): Promise<void> => invoke('transfer_blobs', { did });
export const transferPreferences = (did: string): Promise<void> => invoke('transfer_preferences', { did });
export const verifyImport = (did: string): Promise<AccountStatus> => invoke('verify_import', { did });
export const armIdentityLeg = (did: string): Promise<void> => invoke('arm_identity_leg', { did });
export const finalizeMigration = (did: string): Promise<void> => invoke('finalize_migration', { did });
```
The PLC diff render + submit reuse the **existing** `buildMigrationOp(did)` / `submitMigrationOp(did)` wrappers — do not duplicate them.

Confirm the `OAuthPrepared` field names returned to JS: the Rust `OAuthPrepared { auth_url, callback_scheme }` serializes as `authUrl`/`callbackScheme` (camelCase) — matching `startPdsAuth`. Verify against how `startPdsAuth` consumes `prepare_pds_auth`.

**Testing:** None (types). Proven by Task 3.

**Commit:** `feat(wallet-ui): migration orchestrator IPC wrappers`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update AGENTS.md + run `pnpm check`

**Verifies:** wallet-outbound-migration.AC8.3

**Files:**
- Modify: `apps/identity-wallet/AGENTS.md` (Exposes list ~13–15; Rust-module contracts ~line 49)

**Implementation:**
- Append the new function names and types to the `src/lib/ipc.ts` Exposes list (lines 13–15), in the existing comma-separated format: `prepareMigration()`, `startSourceAuth()`, `createDestinationAccount()`, `transferRepo()`, `transferBlobs()`, `transferPreferences()`, `verifyImport()`, `armIdentityLeg()`, `finalizeMigration()`, and the types `AccountStatus`, `MigrationError`.
- Add a contract entry near the `migrate.rs` description (~line 49) for the new backend module, e.g.:
  > `migration_orchestrator.rs` — wallet-authorized outbound migration state machine (ADR-0002 path 1). Fine-grained per-step commands (`prepare_migration`, `prepare_source_auth`/`complete_source_auth`, `create_destination_account`, `transfer_repo`, `transfer_blobs`, `transfer_preferences`, `verify_import`, `arm_identity_leg`, `finalize_migration`) driving source→dest transfer; hands the destination Bearer client to `migrate.rs` for the self-signed PLC identity op. State is in-memory only (`AppState.orchestration_state`).

**Verification:**
```
cd apps/identity-wallet && pnpm check
```
Expected: `svelte-check` reports 0 errors. Fix any type mismatch (e.g., a wrapper's arg object not matching the Rust command's camelCase params, or a `MigrationError` code typo) until clean.

**Commit:** `docs(wallet): document migration orchestrator IPC + module contract`
<!-- END_TASK_3 -->

---

## Phase 6 done when

- `ipc.ts` has a typed wrapper for every new orchestrator command (AC8.1) and `AccountStatus` + a `MigrationError` union whose codes match the Rust enum exactly (AC8.2).
- `apps/identity-wallet/AGENTS.md` lists the new exports and the module contract.
- `pnpm check` passes with 0 errors (AC8.3).
- Covers wallet-outbound-migration.AC8.1–AC8.3.
