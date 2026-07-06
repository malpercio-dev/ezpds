# Wallet Outbound Migration (MM-228) — Human Test Plan

**Coverage validation:** PASS — 40/40 acceptance sub-cases (`wallet-outbound-migration.AC1.1` … `AC10.3`)
map to a present, correctly-typed automated test. This document covers the irreducible
**live / on-device** portions that cannot be exercised by unit/integration tests.

Automated test modules (all green): `migration_orchestrator.rs` (51 tests, incl. the `#[ignore]`
full-pipeline / resume / abort socket tests), `pds_client.rs` (64), `oauth_client.rs` (16),
`ipc.ts` (via `pnpm check`), `tools/interop/src/{migrate,cli}.js` (via `node --check` + the
`--target-pds` guard).

> Note: two pre-existing `oauth::tests::par_*` failures in a whole-crate run need a live Custos on
> `localhost:8080` and are unrelated to this feature.

## Prerequisites

- A Mac with Xcode (the `identity-wallet` crate cannot run in Linux CI; on-device/simulator parts need it).
- **Two** running ezpds instances: a **source** PDS (the account's current home) and a **destination**
  PDS (`<dest-url>`), each reachable over HTTPS with valid `atproto_pds` service records.
- Interop CLI deps installed: `just interop-setup`.
- Automated gates green first (run from the repo root inside the dev shell):
  - `cargo test -p identity-wallet --lib migration_orchestrator -- --include-ignored` (51 pass)
  - `cargo test -p identity-wallet --lib pds_client -- --include-ignored` (64 pass); `oauth_client` (16 pass)
  - `cd apps/identity-wallet && pnpm check` (0 errors)
  - `node --check tools/interop/src/migrate.js && node --check tools/interop/src/cli.js`
- A test-account rotation key present in the interop `.state/state.json` (used to self-sign the PLC op).

## Phase 1 — Interop live migration: `migrate perform` (AC9.1, AC1.1 live)

| Step | Action | Expected |
|---|---|---|
| 1 | `just interop create-account --name mtest` (against the source instance) | Account created on source; `.state/state.json` gains an `mtest` entry with DID + rotation key |
| 2 | Note the source DID; confirm the repo is serveable on the source (`com.atproto.sync.getRepo`) | Non-empty CAR returned from source PDS |
| 3 | `just interop migrate perform --name mtest --target-pds <dest-url>` | The full flow runs (describe dest → source service-auth → createAccount on dest → repo import → blob drain → preferences → verify → self-signed PLC op → activate dest → deactivate source). Prints a step-by-step JSON summary with no error |
| 4 | Observe the `activateAccount` step | May need one or more retries immediately after the PLC write; succeeds once `checkAccountStatus.validDid` propagates (AC5.3 real-timing) |

## Phase 2 — Interop verification: `migrate verify` (AC9.2)

| Step | Action | Expected |
|---|---|---|
| 1 | `just interop migrate verify --name mtest --target-pds <dest-url>` | Prints `{ ok: true, pds: "<dest-url>", … }` |
| 2 | Independently fetch the PLC document; check `atproto_pds` service endpoint | Points at `<dest-url>`, not the source |
| 3 | Fetch `com.atproto.sync.getRepo` from `<dest-url>` for the DID | Repo is serveable on the destination |
| 4 | Fetch the same from the source PDS | Source account is deactivated (repo no longer served / account inactive) |
| 5 | Run `migrate perform` a second time against the same target (idempotency) | Tolerates `DidAlreadyExists` / already-active; does not double-post to plc.directory; completes or reports a coherent state |

## Phase 3 — Argument guard (AC9.3; fast, no second instance)

| Step | Action | Expected |
|---|---|---|
| 1 | `just interop migrate perform --name mtest` (omit `--target-pds`) | Errors: `migrate requires --target-pds <url> …` |
| 2 | Run the default `just interop suite` | `migrate` does not execute as part of the suite |

## End-to-End — Wallet on-device migration (AC8.\* runtime, AC1.1 wallet mirror)

Purpose: prove the Tauri IPC wrappers actually reach their Rust commands on a device and that
errors reject with the matching `MigrationError.code` — the part `pnpm check` cannot exercise.
(Until the MM-232 UI lands, invoke the `ipc.ts` wrappers from a debug harness.)

1. `prepareMigration(did, destPdsUrl)` with a reachable dest → resolves (void).
2. `prepareMigration(did, <unreachable-url>)` → rejects with `{ code: 'DESTINATION_UNREACHABLE' }`.
3. `startSourceAuth(did)` → ASWebAuthenticationSession opens; complete source OAuth → resolves.
   Cancel it → rejects `{ code: 'SOURCE_AUTH_FAILED' }`.
4. `createDestinationAccount(did, …)` → resolves; re-invoke → tolerates the existing account (coherent conflict).
5. `transferRepo` → `transferBlobs` → `transferPreferences` → `verifyImport(did)` in order →
   `verifyImport` resolves an `AccountStatus` object (camelCase fields populated).
6. Invoke a command out of order (e.g. `finalizeMigration` before `armIdentityLeg`) →
   rejects `{ code: 'MIGRATION_NOT_READY' }`.
7. `armIdentityLeg(did)` → resolves; then `finalizeMigration(did)` → dest activated, source deactivated.

## Human Verification Required (why these are manual)

| Criterion | Why manual | Steps |
|---|---|---|
| AC1.1 (live) | Mocks cannot exercise real server-side import/indexing, real service-auth, or a real plc.directory write between two instances | Phase 1 + Phase 2 |
| AC5.3 (real propagation timing) | plc.directory/cache propagation delay is external and non-deterministic | Phase 1 step 4 — observe `activateAccount` retry until `checkAccountStatus.validDid` is true |
| AC8.\* (on-device IPC runtime) | `pnpm check` verifies types only, not a real `invoke()` round-trip; the crate can't run in Linux CI | End-to-End wallet section |
| AC9.1 / AC9.2 (live run) | No unit-test harness for interop; requires a second live PDS | Phase 1 + Phase 2 |
| AC10.3 (literal process kill) | In-memory-only state loss on kill is a runtime behavior | Start a migration on device → force-kill the app → relaunch → confirm no in-progress migration is restorable and the flow restarts at `prepareMigration` |

## Traceability (AC → automated test → manual step)

| AC | Automated test | Manual step |
|---|---|---|
| AC1.1 | `test_full_migration_pipeline_happy_path` | Phase 1 + Phase 2 |
| AC1.2–AC1.5 | `finalize` / gate / `describe_server` tests | — (fully automated) |
| AC2.1–AC2.6 | `transfer_repo_impl` / `drain_missing_blobs` / `transfer_preferences_impl` tests | — |
| AC3.1–AC3.3 | `import_reconciles` / `verify_import_gate` tests | — |
| AC4.1–AC4.3 | `arm_identity_leg_core` / `finalize_migration_core` gate tests | — |
| AC5.1 | `test_create_account_migration_409` / `_impl_idempotent_with_existing_client` | — |
| AC5.2 | `test_full_migration_resume_partial_blobs` | Phase 2 step 5 (optional) |
| AC5.3 | `finalize_impl_idempotent_activate_200` / `_activate_failure_no_deactivate` | Phase 1 step 4 (real timing) |
| AC5.4 | `test_full_migration_abort_before_identity_leg_leaves_dest_deactivated` | — |
| AC6.1–AC6.4 | oauth_client Bearer/DPoP tests | — |
| AC7.1–AC7.3 | pds_client per-helper tests | — |
| AC8.1/AC8.2 | `ipc.ts` wrappers + `MigrationError` union, `pnpm check` | End-to-End wallet section |
| AC8.3 | `pnpm check` | — |
| AC9.1 | `migrate.js performMigration` + `node --check` | Phase 1 |
| AC9.2 | `migrate.js verifyMigration` + `node --check` | Phase 2 |
| AC9.3 | `cli.js` guard + `suite.js` absence | Phase 3 |
| AC10.1 | `test_migration_error_serialization_*` | — |
| AC10.2 | full-pipeline `plc_post.calls() == 1` | — |
| AC10.3 | mutex-storage / `DestinationConflict` tests | Kill-and-relaunch step |
