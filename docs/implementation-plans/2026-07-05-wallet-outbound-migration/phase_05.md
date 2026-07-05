# Wallet Outbound Migration — Phase 5: Orchestrator — identity handoff + finalize

**Goal:** Arm the reused `migrate.rs` identity leg with the destination Bearer client, then finalize the migration (activate the destination, deactivate the source) — and prove the whole pipeline end-to-end with a mock integration test covering ordering and resume.

**Architecture:** `arm_identity_leg` constructs a `migrate::MigrationState` (with the Bearer `dest_client`) and parks it in `AppState.migration_state`, so the existing `migrate::build_migration_op_cmd` (renders the PLC diff) and `migrate::submit_migration_op_cmd` (self-signs? no — signs and POSTs to plc.directory, `take()`ing the op to prevent double-post) can run under UI/biometric control. `finalize_migration` runs after the op lands: `activateAccount` on the destination (retry-tolerant / server-idempotent), then `deactivateAccount` on the source, last.

**Tech Stack:** Rust, Tauri commands, the reused `migrate.rs` (MM-229) unchanged, `httpmock` (three mock servers), `#[ignore]` socket-binding integration test.

**Scope:** Phase 5 of 7.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC1: A wallet-authorized outbound migration drives to completion
- **wallet-outbound-migration.AC1.1 Success:** Given a wallet-controlled DID and a reachable destination PDS, running the commands in phase order (`prepare_migration` → `prepare/complete_source_auth` → `create_destination_account` → `transfer_repo` → `transfer_blobs` → `transfer_preferences` → `verify_import` → `arm_identity_leg` → identity submit → `finalize_migration`) moves the identity between two ezpds instances with the repo serveable on the new PDS and the DID's `atproto_pds` repointed.
- **wallet-outbound-migration.AC1.2 Success:** `finalize_migration` activates the destination account, then deactivates the source account, in that order.

### wallet-outbound-migration.AC4: The identity leg is handed off for user approval
- **wallet-outbound-migration.AC4.1 Success:** `arm_identity_leg` populates `migrate::MigrationState.dest_oauth_client` with the destination Bearer client and advances to `IdentityArmed`, so the existing `migrate::build_migration_op_cmd` can render the PLC diff and `migrate::submit_migration_op_cmd` can submit after biometric approval.
- **wallet-outbound-migration.AC4.2 Success:** The identity op runs after `verify_import` and before `finalize_migration`'s `activateAccount`.
- **wallet-outbound-migration.AC4.3 Failure:** `arm_identity_leg` before `verify_import` returns `MIGRATION_NOT_READY`.

### wallet-outbound-migration.AC5: Partial failure is resumable and leaves a coherent state
- **wallet-outbound-migration.AC5.2 Success:** Re-running `transfer_blobs` after a partial drain resumes and uploads only the still-missing blobs (verified via `list_missing_blobs`).
- **wallet-outbound-migration.AC5.3 Success:** `finalize_migration`'s `activateAccount` is retry-tolerant: a repeat call on an already-active account succeeds (idempotent), and a call that fails on transient DID-propagation can be retried.
- **wallet-outbound-migration.AC5.4 Edge:** On abort before the identity op, the destination account remains deactivated (coherent, not half-live).

### wallet-outbound-migration.AC10: Cross-cutting behaviors
- **wallet-outbound-migration.AC10.2:** The orchestrator never POSTs to plc.directory itself; the only plc.directory write is `migrate::submit_migration_op_cmd`, which prevents double-post.

---

## Verified codebase facts

- `migrate::MigrationState` (migrate.rs 59–66): **`{ did: String, dest_oauth_client: std::sync::Arc<OAuthClient>, signed_op: Option<serde_json::Value> }`**. `dest_oauth_client` is **`Arc<OAuthClient>` (NOT `Option<...>`)** — its doc comment says it is "populated by the migration orchestrator."
- `migrate::build_migration_op_cmd(state, did) -> Result<SignedMigrationOp, MigrateError>` (604–649): clones `dest_oauth_client` under lock, calls `build_migration_op(pds_client, &dest_client, &did)` (uses `getRecommendedDidCredentials` on the dest), parks `signed_op`.
- `migrate::submit_migration_op_cmd(state, did) -> Result<ClaimResult, MigrateError>` (652–689): `take()`s `signed_op`, calls `submit_migration_op(pds_client, &did, &signed_op)` which POSTs to plc.directory, **clears `migration_state` on success**.
- `AppState.migration_state: tokio::sync::Mutex<Option<migrate::MigrationState>>` (oauth.rs 52).
- `activate_account` / `deactivate_account` client helpers (Phase 2). The ezpds server: `activateAccount` is idempotent (already-active → 200 no-op); `deactivateAccount` is idempotent (already-deactivated → 200 no-op) and accepts optional `deleteAfter`.
- Test convention for socket-binding integration tests in the state-machine modules: `#[tokio::test]` + `#[ignore] // Requires socket binding; ignore in sandboxed environments` (see `migrate.rs:1050`, `recovery.rs:737/888`). Pure logic uses inline `#[test]`.

## Design decisions locked (from verification)

1. **`arm_identity_leg` constructs a fresh `migrate::MigrationState`** (because `dest_oauth_client` is non-`Option`): `MigrationState { did, dest_oauth_client: <bearer client Arc>, signed_op: None }`, stored in `AppState.migration_state`. It does not mutate an existing field.
2. **AC10.2 (no double-post):** the orchestrator never POSTs to plc.directory. The single plc.directory write stays in `migrate::submit_migration_op_cmd`, which `take()`s the op under lock; `arm_identity_leg`/`finalize_migration` do not touch plc.directory.
3. **`finalize_migration` precondition = `phase == IdentityArmed` AND the `migrate::migration_state` is cleared (== `None`).** Because `submit_migration_op_cmd` clears `migration_state` on success, a cleared state proves the identity op was submitted (AC4.2). If `migration_state` is still `Some`, finalize returns `MIGRATION_NOT_READY` ("identity op not yet submitted").
4. **`activateAccount` retry model (AC5.3):** finalize calls `activate_account` once; on failure it returns `ACTIVATION_FAILED` and does **not** advance the phase, so the UI (MM-232) re-invokes finalize while the DID doc propagates. Idempotency comes from the server (re-activate on already-active → 200; re-deactivate → 200), so re-invocation is safe. No in-command sleep (keeps the command non-blocking and testable). The "waiting for identity to propagate" UX is MM-232's job (design's Additional Considerations).
5. **`deactivate_account(source_client, None)`** — no `deleteAfter` for this ticket.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `arm_identity_leg`

**Verifies:** wallet-outbound-migration.AC4.1, wallet-outbound-migration.AC4.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::arm_identity_leg`)

**Implementation:**
```rust
#[tauri::command]
pub async fn arm_identity_leg(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(&*orchestration_state.lock().await, &did, MigrationPhase::Verified);
    //       clone dest_client (Arc<OAuthClient>) out; drop the orchestration lock.
    // Build the identity-leg state (dest_oauth_client is Arc<OAuthClient>, NOT Option):
    //   let ms = crate::migrate::MigrationState { did: did.clone(), dest_oauth_client: dest_client, signed_op: None };
    //   *state.migration_state.lock().await = Some(ms);
    // Advance orchestration phase -> IdentityArmed.
    Ok(())
}
```
Confirm the exact field names of `migrate::MigrationState` before writing (investigation: `did`, `dest_oauth_client`, `signed_op`). If additional fields exist, populate them.

**Testing:**
- AC4.3 (pure gate): `arm_identity_leg` when phase is `PreferencesTransferred` (before `Verified`) returns `MIGRATION_NOT_READY`.
- AC4.1 (`#[ignore]` mock or state-inspection): after `arm_identity_leg` on a `Verified` state, `AppState.migration_state` holds a `migrate::MigrationState` whose `dest_oauth_client` is the same Bearer client, and the orchestration phase is `IdentityArmed`. (Assert by locking `migration_state` and checking `did` + that it is `Some`.)

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): arm_identity_leg (populate migrate::MigrationState)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `finalize_migration`

**Verifies:** wallet-outbound-migration.AC1.2, wallet-outbound-migration.AC4.2, wallet-outbound-migration.AC5.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::finalize_migration`)

**Implementation:**
```rust
#[tauri::command]
pub async fn finalize_migration(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::IdentityArmed).
    // AC4.2 defense-in-depth: require the identity op to have been submitted, i.e. the
    //   migrate migration_state is cleared: if state.migration_state.lock().await.is_some()
    //   -> Err(MigrationNotReady { "identity op not yet submitted" }).
    // clone dest_client + source_client; drop locks.
    // 1. activate_account(&dest_client).await   // new PDS FIRST (AC1.2). Idempotent server-side.
    //        err -> ActivationFailed { message }  (phase stays IdentityArmed -> UI re-invokes; AC5.3)
    // 2. deactivate_account(&source_client, None).await   // old PDS LAST (AC1.2)
    //        err -> DeactivationFailed { message }
    // 3. re-lock, re-validate did, phase = Finalized.
    Ok(())
}
```

**Testing (mock `httpmock`, `#[ignore]`):**
- AC1.2: with mock dest `activateAccount` and mock source `deactivateAccount`, `finalize_migration` calls activate on the dest **before** deactivate on the source — assert via ordering (e.g. record hit timestamps/sequence, or make deactivate assert activate already happened). Both must be hit exactly once on the happy path.
- AC5.3 (idempotent): a second `finalize_migration` call (or activate on an already-active mock returning 200) succeeds. A dest `activateAccount` returning a transient 4xx/5xx → `ACTIVATION_FAILED`, phase stays `IdentityArmed`, source is NOT deactivated (retry-safe); a subsequent call with the mock now returning 200 completes.
- AC4.2 gate: `finalize_migration` when `AppState.migration_state` is still `Some` (op not submitted) returns `MIGRATION_NOT_READY`.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
cargo build -p identity-wallet
```

**Commit:** `feat(wallet): finalize_migration (activate new -> deactivate old)`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->
### Task 3: Full-pipeline mock integration test (ordering + resume)

**Verifies:** wallet-outbound-migration.AC1.1, wallet-outbound-migration.AC4.2, wallet-outbound-migration.AC5.2, wallet-outbound-migration.AC5.4, wallet-outbound-migration.AC10.2

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs` (test module)

**Implementation (test only):** A `#[tokio::test] #[ignore] // Requires socket binding; ignore in sandboxed environments` that stands up **three** `httpmock::MockServer`s — old-PDS (source), new-PDS (dest), plc.directory — and drives the pipeline. Because Tauri commands take `tauri::State`, drive the **pure cores** (`create_destination_account_impl`, `drain_missing_blobs`, `import_reconciles`, `migrate::build_migration_op`, `migrate::submit_migration_op`, and the `activate_account`/`deactivate_account` helpers) in phase order, or construct a real `AppState` and seed `OutboundMigrationState` with pre-built `source_client`/`dest_client` (Bearer/DPoP clients pointed at the mocks) to exercise the command wrappers. Prefer whichever `recovery.rs`'s `#[ignore]` tests use as their harness idiom.

The test must set up mocks for and drive, in order:
1. dest `reserveSigningKey` → `{signingKey}`; source `getServiceAuth` → `{token}`; dest `createAccount` → session → build `dest_client`.
2. source `getRepo` → CAR bytes; dest `importRepo` (assert hit **before** any `uploadBlob`).
3. dest `listMissingBlobs` (a couple of pages then empty); source `getBlob` per CID; dest `uploadBlob` per CID.
4. source `getPreferences` → dest `putPreferences`.
5. dest `checkAccountStatus` → reconciled status (`importedBlobs == expectedBlobs`, `repoCommit` set, `validDid:false`).
6. `arm_identity_leg`; then `migrate::build_migration_op` (dest `getRecommendedDidCredentials` mock) → `migrate::submit_migration_op` (**plc.directory** POST mock).
7. `finalize_migration`: dest `activateAccount`, then source `deactivateAccount`.

Assertions:
- **AC1.1**: the full sequence completes and phase ends `Finalized`.
- **AC4.2 / ordering**: assert `importRepo` hit before `uploadBlob`; assert the **plc.directory POST** hit before dest `activateAccount`; assert source `deactivateAccount` is the **last** hit.
- **AC10.2**: assert the plc.directory mock is hit **exactly once** (the only plc.directory write, from `submit_migration_op`), and that no orchestrator step posts to plc.directory.
- **AC5.2 (resume)**: a second scenario where `listMissingBlobs` first reports a non-empty set (a partial prior drain), the loop uploads only those, and a follow-up `listMissingBlobs` returns empty → the drain resumes and completes uploading only the still-missing CIDs (assert `uploadBlob` hit count equals the still-missing count, not the full set).
- **AC5.4**: a scenario that aborts after `verify_import` but before `arm_identity_leg`/identity submit — assert the dest was never activated (no `activateAccount` hit) so the destination remains deactivated and coherent.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator -- --ignored
```
Expected: the pipeline + resume + ordering test passes when run with `--ignored` (needs socket binding; in a sandboxed shell, run with the sandbox disabled).

**Commit:** `test(wallet): full-pipeline migration integration test (ordering + resume)`
<!-- END_TASK_3 -->

---

## Phase 5 done when

- `arm_identity_leg` builds `migrate::MigrationState { did, dest_oauth_client, signed_op: None }` and advances to `IdentityArmed` (AC4.1); it refuses before `Verified` (AC4.3).
- `finalize_migration` activates the destination then deactivates the source, in that order (AC1.2), requires the identity op already submitted (AC4.2), and is retry-tolerant/idempotent (AC5.3).
- The full-pipeline `#[ignore]` test drives every command, asserts import-before-blobs, identity-before-activate, deactivate-last (AC1.1/AC4.2), exactly-one plc.directory POST (AC10.2), a partial-blob resume (AC5.2), and an abort-before-identity coherent state (AC5.4).
- `cargo test -p identity-wallet --lib migration_orchestrator` (and `-- --ignored` for the socket tests) passes.
- Covers wallet-outbound-migration.AC1.1–AC1.2, AC4.1–AC4.3, AC5.2–AC5.4, AC10.2.
