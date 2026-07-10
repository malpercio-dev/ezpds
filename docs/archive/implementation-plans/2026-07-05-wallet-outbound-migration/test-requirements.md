# Wallet Outbound Migration — Test Requirements

**Maps every acceptance criterion (`wallet-outbound-migration.AC1.1` … `AC10.3`) to its automated
test(s) or documented human verification.** This is the coverage-confirmation reference for the
engineer executing the 7-phase implementation plan
(`docs/implementation-plans/2026-07-05-wallet-outbound-migration/phase_01.md` … `phase_07.md`),
derived from the design's Acceptance Criteria
(`docs/design-plans/2026-07-05-wallet-outbound-migration.md`) and each phase's `Verifies:` fields
and `Testing` sections.

Last verified against the plan: 2026-07-05.

## How tests are run for this feature

The `identity-wallet` Tauri backend is a normal Rust workspace crate (crate name `identity-wallet`),
but it is **excluded from the CI `just ci-pds` lane** (`--exclude identity-wallet`, because the iOS /
Apple toolchain CI needs is absent on the Linux runner). Its tests therefore run **directly, not
through CI**:

- **Rust unit + integration tests** — from the **repo root** (devenv provides the toolchain;
  `CARGO_HOME`/`RUSTUP_HOME` resolve relative to the workspace root):
  ```
  cargo test -p identity-wallet --lib oauth_client
  cargo test -p identity-wallet --lib pds_client
  cargo test -p identity-wallet --lib migration_orchestrator
  ```
  - **Inline `httpmock` tests** in `oauth_client.rs` and `pds_client.rs` follow those files' existing
    convention: they bind an ephemeral localhost socket and run **inline** (not `#[ignore]`d). In a
    sandboxed shell, socket binding can be denied (`Operation not permitted`); re-run with the
    sandbox disabled if so.
  - **`MockServer::start()` socket-binding tests inside the state-machine module**
    (`migration_orchestrator.rs`) follow the `migrate.rs` / `recovery.rs` convention: they are marked
    `#[ignore] // Requires socket binding; ignore in sandboxed environments` and are run explicitly
    with:
    ```
    cargo test -p identity-wallet --lib migration_orchestrator -- --ignored
    ```
  - **Pure-core unit tests** (`ensure_phase_did`, `import_reconciles`, `drain_missing_blobs`,
    `jwt_exp_claim`, `MigrationError` serialization) are plain inline `#[test]`/`#[tokio::test]` with
    **no socket** — they run in the default (non-`--ignored`) pass and provide most of the
    fine-grained AC coverage without needing sockets.
- **Frontend type-check** — `ipc.ts` wrappers/types are verified by the TypeScript compiler, not
  runtime tests:
  ```
  cd apps/identity-wallet && pnpm check      # svelte-kit sync && svelte-check
  ```
- **Interop CLI** — the `migrate` command is verified **operationally** against a **second live PDS
  instance** (the interop tool has no unit-test harness). It is deliberately **not** part of the
  default single-PDS `suite` run and requires an explicit `--target-pds`:
  ```
  just interop create-account --name mtest
  just interop migrate perform --name mtest --target-pds <dest-url>
  just interop migrate verify  --name mtest --target-pds <dest-url>
  # syntax-only smoke (no second instance): node --check tools/interop/src/migrate.js
  ```

**Test-type legend used in the tables below:**
- **unit** — pure inline `#[test]`/`#[tokio::test]`, no socket (runs in the default pass).
- **httpmock-integration** — `httpmock::MockServer`-backed Rust test. Inline in `oauth_client.rs` /
  `pds_client.rs`; `#[ignore]`-gated (socket-binding, run with `-- --ignored`) in
  `migration_orchestrator.rs`.
- **typecheck** — verified by `pnpm check` (`svelte-check`); no runtime assertion.
- **operational-interop** — verified by running the interop CLI against a second live PDS (manual /
  operational; see the Human verification section for what remains manual).

---

## Automated tests

Every AC sub-case below maps to at least one automated test (or, where an AC has an irreducible
operational/on-device part, to the automated portion plus a pointer to the Human verification
section). Locations are the **expected** test sites from the phase plans — file + module/test-name
hint; the executing engineer confirms exact names.

| AC id | AC summary | Test type | Expected test location (file + hint) | Covering phase / task |
|---|---|---|---|---|
| **AC1.1** | Full pipeline (`prepare_migration` → source auth → `create_destination_account` → repo → blobs → prefs → `verify_import` → `arm_identity_leg` → identity submit → `finalize_migration`) drives to completion; repo serveable on new PDS, DID repointed | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` full-pipeline test (`-- --ignored`): three mock servers (source, dest, plc.directory), sequence completes and phase ends `Finalized`. *(End-to-end across two **live** ezpds instances → also Human verification, via interop AC9.1.)* | Phase 5, Task 3 |
| **AC1.2** | `finalize_migration` activates dest, then deactivates source, in that order | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `finalize_migration` test: mock dest `activateAccount` hit **before** mock source `deactivateAccount`; both hit exactly once on happy path | Phase 5, Task 2 (+ Task 3 ordering asserts) |
| **AC1.3** | Command invoked out of phase order returns `MIGRATION_NOT_READY` with no network side effects | unit | `migration_orchestrator.rs` `ensure_phase_did` tests (pure gate: state at `SourceAuthed`, require `RepoTransferred` → `MigrationNotReady`); plus `create_destination_account` gate at `Resolved` | Phase 3, Task 1 (+ Task 6) |
| **AC1.4** | Command whose `did` arg ≠ `OutboundMigrationState.did` returns `MIGRATION_NOT_READY` (defense-in-depth) | unit | `migration_orchestrator.rs` `ensure_phase_did` test (state did A, arg `did:plc:B` → `MigrationNotReady`); `prepare_source_auth("did:plc:OTHER")` gate test | Phase 3, Task 1 (+ Task 5) |
| **AC1.5** | `prepare_migration` against an unreachable destination PDS returns `DESTINATION_UNREACHABLE` | httpmock-integration + unit | `pds_client.rs` `describe_server` unreachable → `PdsUnreachable` (`#[ignore]` if it binds a socket); `migration_orchestrator.rs` `prepare_migration` maps `PdsUnreachable` → `DESTINATION_UNREACHABLE` (prefer `_impl` split so mapping is unit-testable without sockets) | Phase 3, Tasks 3 & 4 |
| **AC2.1** | `transfer_repo` exports source CAR and imports into deactivated dest | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `transfer_repo` test: mock source `sync.getRepo` bytes → mock dest `repo.importRepo` with `Content-Type: application/vnd.ipld.car`; phase → `RepoTransferred` | Phase 4, Task 1 |
| **AC2.2** | `transfer_blobs` drains `list_missing_blobs`, fetching each missing CID from source and uploading, until the missing set is empty | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `drain_missing_blobs` test w/ **shrinking-missing-set** mock: every missing CID fetched from source and uploaded to dest exactly once; loop converges to empty | Phase 4, Task 2 |
| **AC2.3** | Blob loop walks multiple `list_missing_blobs` pages via cursor and terminates on an empty page | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `drain_missing_blobs` test: page 1 `{blobs:[a,b],cursor:"c1"}`, page 2 `?cursor=c1` `{blobs:[c],cursor:null}`, then empty → terminates | Phase 4, Task 2 |
| **AC2.4** | `transfer_preferences` reads source preferences and writes them to dest | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `transfer_preferences` test: mock source `getPreferences` `{preferences:[...]}` → identical object POSTed to dest `putPreferences`; phase → `PreferencesTransferred` | Phase 4, Task 3 |
| **AC2.5** | `transfer_blobs` on an account with no missing blobs completes immediately (empty first page) | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `drain_missing_blobs` test: first `list_missing_blobs` returns `{blobs:[],cursor:null}` → `Ok(())` with zero `getBlob`/`uploadBlob` calls | Phase 4, Task 2 |
| **AC2.6** | Failed `getBlob`/`uploadBlob`/`list_missing_blobs` returns `BLOB_TRANSFER_FAILED` and leaves phase un-advanced (retry-safe) | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `transfer_blobs` test: source `getBlob` (or dest `uploadBlob`) returns 500 mid-drain → `BLOB_TRANSFER_FAILED`, phase stays `RepoTransferred` | Phase 4, Task 2 |
| **AC3.1** | `verify_import` returns `checkAccountStatus` fields and advances to `Verified` when `imported_blobs == expected_blobs` and record counts reconcile | unit + httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` pure `import_reconciles` test (true when `imported==expected` and `repo_commit=Some`); command-level `#[ignore]` mock: reconciled status → phase `Verified`, returns `AccountStatus` | Phase 4, Task 4 |
| **AC3.2** | `verify_import` does **not** require `valid_did` to be true | unit | `migration_orchestrator.rs` `import_reconciles` test: true even when `valid_did = false` | Phase 4, Task 4 |
| **AC3.3** | Non-reconciling blobs/records → `VERIFICATION_INCOMPLETE` carrying imported/expected counts | unit + httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `import_reconciles` false when `imported < expected`; command-level `#[ignore]` mock: unreconciled status → `VERIFICATION_INCOMPLETE { imported, expected }`, phase stays `PreferencesTransferred` | Phase 4, Task 4 |
| **AC4.1** | `arm_identity_leg` populates `migrate::MigrationState.dest_oauth_client` with the dest Bearer client and advances to `IdentityArmed` | httpmock-integration / state-inspection (`#[ignore]`) | `migration_orchestrator.rs` `arm_identity_leg` test: after arming a `Verified` state, `AppState.migration_state` holds a `migrate::MigrationState` (`Some`, matching `did`), phase `IdentityArmed` | Phase 5, Task 1 |
| **AC4.2** | Identity op runs after `verify_import` and before `finalize_migration`'s `activateAccount` | unit + httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `finalize_migration` gate: `migration_state` still `Some` (op not submitted) → `MIGRATION_NOT_READY`; full-pipeline test asserts plc.directory POST hit before dest `activateAccount` | Phase 5, Tasks 2 & 3 |
| **AC4.3** | `arm_identity_leg` before `verify_import` returns `MIGRATION_NOT_READY` | unit | `migration_orchestrator.rs` `arm_identity_leg` pure gate test: phase `PreferencesTransferred` (before `Verified`) → `MIGRATION_NOT_READY` | Phase 5, Task 1 |
| **AC5.1** | Re-running `create_destination_account` after the account exists tolerates `DidAlreadyExists` and re-establishes the dest Bearer session | httpmock-integration (`#[ignore]`) + unit | `pds_client.rs` `create_account_migration` 409 → `DidAlreadyExists` (inline mock); `migration_orchestrator.rs` `create_destination_account_impl`: `existing_dest_client: Some` returns cached client (no network); `Some` + mock 409 still returns `Ok(client)` | Phase 2, Task 3 + Phase 3, Task 6 |
| **AC5.2** | Re-running `transfer_blobs` after a partial drain uploads only still-missing blobs | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` full-pipeline resume scenario: `listMissingBlobs` first reports the still-missing subset → `uploadBlob` hit count equals the still-missing count, not the full set | Phase 5, Task 3 |
| **AC5.3** | `finalize_migration`'s `activateAccount` is retry-tolerant: repeat on already-active succeeds (idempotent); transient DID-propagation failure can be retried | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` `finalize_migration` test: 2nd call / already-active 200 succeeds; transient 4xx/5xx → `ACTIVATION_FAILED`, phase stays `IdentityArmed`, source NOT deactivated; a follow-up call with mock now 200 completes. *(Real plc.directory propagation timing → Human verification.)* | Phase 5, Task 2 |
| **AC5.4** | On abort before the identity op, the dest account remains deactivated (coherent, not half-live) | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` full-pipeline abort scenario: abort after `verify_import` before `arm_identity_leg`/submit → dest never activated (no `activateAccount` hit) | Phase 5, Task 3 |
| **AC6.1** | Bearer-mode client sends `Authorization: Bearer {token}` and no `DPoP` header | httpmock-integration (inline) | `oauth_client.rs` Bearer-header test: `httpmock` matcher asserts `Authorization: Bearer {token}` present and `DPoP` header absent | Phase 1, Task 2 |
| **AC6.2** | Bearer-mode client refreshes via `com.atproto.server.refreshSession`, not `/oauth/token` | httpmock-integration (inline) | `oauth_client.rs` Bearer-refresh test: expired session → `POST /xrpc/com.atproto.server.refreshSession` hit once, `/oauth/token` mock 0 hits; refresh `Authorization` is `Bearer {old_refresh}`; Keychain not written | Phase 1, Task 3 |
| **AC6.3** | `post_bytes` sends the provided body with the given `Content-Type` (e.g. `application/vnd.ipld.car`) | httpmock-integration (inline) | `oauth_client.rs` `post_bytes` test: `Content-Type` exactly `application/vnd.ipld.car`, body bytes equal input, `Authorization: Bearer` with no `DPoP` | Phase 1, Task 4 |
| **AC6.4** | Existing DPoP mode is unchanged — its tests still pass | httpmock-integration (inline, regression) | `oauth_client.rs` pre-existing DPoP tests (`refresh_dpop_proof_has_no_ath_claim`, `refresh_invalid_grant_returns_invalid_grant`, `refresh_token_nonce_retry_sends_exactly_two_requests`, etc.) still green | Phase 1, Tasks 1 & 4 |
| **AC7.1** | Each new client fn (`get_service_auth`, `create_account_migration`, `import_repo`, `upload_blob`, `list_missing_blobs`, `get_preferences`, `put_preferences`, `check_account_status`, `activate_account`, `deactivate_account`, `fetch_repo_car`, `fetch_blob`) issues correct method/path/auth and parses its response | httpmock-integration (inline) | `pds_client.rs` per-helper mock tests asserting method, path, auth header, and response parsing (incl. `reserve_signing_key`, `AccountStatus.stored_blocks`) | Phase 2, Tasks 2–5 |
| **AC7.2** | `get_service_auth` requests a token with `aud = dest_did` and `lxm = com.atproto.server.createAccount` | httpmock-integration (inline) | `pds_client.rs` `get_service_auth` test: GET query contains url-encoded `aud=did%3A…` and `lxm=com.atproto.server.createAccount`; parses `token` | Phase 2, Task 3 |
| **AC7.3** | `fetch_repo_car`/`fetch_blob` use the unauthenticated `PdsClient` (`auth: none`) | httpmock-integration (inline) | `pds_client.rs` tests: `fetch_repo_car` / `fetch_blob` issue `GET …sync.getRepo` / `…sync.getBlob` with **no** `Authorization` header; exact bytes round-trip | Phase 2, Task 2 |
| **AC8.1** | `src/lib/ipc.ts` exposes a typed wrapper for every new orchestrator command | typecheck | `src/lib/ipc.ts` wrappers (`prepareMigration`, `startSourceAuth`, `createDestinationAccount`, `transferRepo`, `transferBlobs`, `transferPreferences`, `verifyImport`, `armIdentityLeg`, `finalizeMigration`) verified by `pnpm check` | Phase 6, Task 2 |
| **AC8.2** | TS `MigrationError` union matches the Rust enum's SCREAMING_SNAKE_CASE codes exactly | typecheck | `src/lib/ipc.ts` `MigrationError` union (13 codes) verified against Rust `migration_orchestrator::MigrationError` via `pnpm check`; executor re-reads the final Rust enum before writing (source of truth) | Phase 6, Task 1 |
| **AC8.3** | `pnpm check` (frontend type-check) passes | typecheck | `cd apps/identity-wallet && pnpm check` → 0 errors. *(Runtime `invoke` round-trips need on-device Tauri → Human verification.)* | Phase 6, Task 3 |
| **AC9.1** | `migrate perform --name <n> --target-pds <url>` drives the seven-step flow against a live source→dest pair, self-signing the PLC op with the rotation key in `.state/state.json` | operational-interop | `tools/interop/src/migrate.js` `performMigration`; run `just interop migrate perform …` against a second instance. Syntax smoke: `node --check tools/interop/src/migrate.js`. *(Full run → Human verification.)* | Phase 7, Task 1 |
| **AC9.2** | `migrate verify --name <n> --target-pds <url>` confirms handle, DID, and repo resolve to the new PDS | operational-interop | `tools/interop/src/migrate.js` `verifyMigration`; run `just interop migrate verify …` → `{ ok: true, pds: "<dest-url>", … }`. *(Full run → Human verification.)* | Phase 7, Task 2 |
| **AC9.3** | `migrate` is not part of the default single-PDS `suite` and requires an explicit `--target-pds` | operational-interop (syntax-checkable) | `tools/interop/src/cli.js` `migrate` group throws without `--target-pds` (`just interop migrate perform --name x` errors); `migrate` absent from `suite.js`. `node --check tools/interop/src/cli.js` | Phase 7, Task 3 |
| **AC10.1** | `MigrationError` serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` (established error contract) | unit | `migration_orchestrator.rs` serialization test: `to_value(MigrationNotReady{message})` → `{"code":"MIGRATION_NOT_READY","message":…}`; `VerificationIncomplete{imported,expected}` → `{"code":"VERIFICATION_INCOMPLETE","imported":…,"expected":…}`; casing asserted for several variants | Phase 3, Task 1 |
| **AC10.2** | Orchestrator never POSTs to plc.directory; the only plc.directory write is `migrate::submit_migration_op_cmd` (prevents double-post) | httpmock-integration (`#[ignore]`) | `migration_orchestrator.rs` full-pipeline test: plc.directory mock hit **exactly once**; no orchestrator step posts to plc.directory | Phase 5, Task 3 |
| **AC10.3** | Migration state lives only in `AppState` (in-memory); an app kill loses it and the flow restarts from `prepare_migration` | unit / state-inspection | `migration_orchestrator.rs`: after `prepare_migration`, state present in `orchestration_state` mutex with no disk/Keychain write; `DidAlreadyExists`-without-`dest_client` path returns `DESTINATION_CONFLICT` (consistent with app-kill restart). *(Literal process-kill loss of in-memory state → Human verification.)* | Phase 3, Tasks 2 & 4 (+ decision in Task 6) |

---

## Human / manual verification

These cases (or parts of cases) cannot be **fully** verified by the automated suite that runs in the
non-CI dev flow. For each: what the automated tests already prove, and what remains manual/operational.

### AC1.1 — end-to-end across two **live** ezpds instances
- **Automated coverage:** the Phase 5 full-pipeline `#[ignore]` test drives every command in order
  against three `httpmock` servers and asserts the flow reaches `Finalized` with correct ordering
  (import→blobs, identity→activate, deactivate last). This proves the orchestration logic.
- **Remains manual:** proving the identity actually **moves between two real ezpds instances** (repo
  genuinely serveable on the new PDS, DID's `atproto_pds` genuinely repointed in the public did:plc
  log). Mocks cannot exercise real server-side import/indexing, real service-auth issuance, or a real
  plc.directory write.
- **Approach:** run the interop CLI (AC9.1/AC9.2) against a second live instance:
  `just interop create-account --name mtest` → `just interop migrate perform --name mtest
  --target-pds <dest-url>` → `just interop migrate verify --name mtest --target-pds <dest-url>`; the
  wallet flow mirrors the same seven steps.

### AC9.1 / AC9.2 — interop `migrate perform` / `migrate verify` full run
- **Automated coverage:** `node --check tools/interop/src/{migrate,cli}.js` proves the files parse and
  the CLI wires up; AC9.3's argument-guard is fully checkable. The interop tool has **no unit-test
  harness**, so the actual migration logic is not unit-tested.
- **Remains manual:** the seven-step self-signed migration and its verification only run **against a
  second live PDS instance** (`--target-pds`), which is not present in the default single-PDS `suite`
  or in CI.
- **Approach:** stand up a second ezpds instance, then run `just interop migrate perform … verify …`
  as above; confirm the printed JSON summary and `{ ok: true, pds: "<dest-url>", … }`, and
  independently that `fetchPlcDocument(did)` points `atproto_pds` at the new PDS and the repo is
  serveable there.

### AC5.3 (part) — real DID-document propagation timing
- **Automated coverage:** the Phase 5 `finalize_migration` `#[ignore]` test fully covers the
  **idempotency/retry logic** — repeat activate on an already-active mock returns 200; a transient
  activate failure yields `ACTIVATION_FAILED` with the phase un-advanced and the source not
  deactivated; a subsequent 200 completes. This is the entire retry contract.
- **Remains manual:** the **real timing** — how long the destination PDS takes to observe the
  repointed DID document from `plc.directory` before `activateAccount` reports `valid_did` — depends
  on external plc.directory/cache propagation and cannot be asserted deterministically. (The user-facing
  "waiting for identity to propagate" UX is MM-232's scope.)
- **Approach:** during the AC9.1 live run, observe that `activateAccount` may need one or more retries
  immediately post-PLC-write and succeeds once propagation completes (poll
  `checkAccountStatus.validDid`), matching Phase 7 Task 1 step 11.

### AC8 (part) — on-device Tauri IPC runtime round-trips
- **Automated coverage:** `pnpm check` (AC8.3) fully verifies the **types** — every wrapper's
  snake_case command name + camelCase args, the `AccountStatus` shape, and the 13-code `MigrationError`
  union against the Rust enum (AC8.1/AC8.2). Type mismatches fail the build.
- **Remains manual:** `pnpm check` does **not** exercise a real `invoke()` round-trip. The
  `identity-wallet` crate cannot run in Linux CI (iOS/Apple toolchain absent), so runtime evidence that
  a wrapper call actually reaches its Rust command and that an error rejection arrives shaped
  `{ code: … }` requires the app on a device/simulator.
- **Approach:** during on-device / simulator testing (MM-232 UI work, needs a Mac + Xcode), invoke each
  wrapper from the running app and confirm success paths return and error paths reject with the matching
  `MigrationError.code`.

### AC10.3 (part) — literal in-memory-only state loss on app kill
- **Automated coverage:** tests assert the state is parked in the `orchestration_state` mutex with no
  disk/Keychain write, and the design encodes app-kill semantics in code (the
  `DidAlreadyExists`-without-a-held-`dest_client` path returns `DESTINATION_CONFLICT`, i.e. "restart the
  migration"). This proves the storage location and the restart contract.
- **Remains manual:** confirming that a genuine **process kill** drops the state and the UI restarts
  from `prepare_migration` is a runtime/on-device behavior, not something the unit suite can observe.
- **Approach:** on device/simulator (MM-232), start a migration, kill and relaunch the app, confirm no
  in-progress migration is restorable and the flow begins again at `prepare_migration`.

---

## Coverage summary

**Every acceptance criterion (`wallet-outbound-migration.AC1.1` through `AC10.3`, 40 sub-cases) maps
to at least one automated test OR a documented human verification** — and the four cases with an
irreducible live/on-device part (AC1.1, AC5.3, AC8.*, AC10.3) map to **both** their automated portion
and an explicit manual-verification entry above, so nothing reads as fully covered when part of it is
not. No AC is left unmapped.
