# Wallet Outbound Migration — Phase 4: Orchestrator — data transfer + verification

**Goal:** Move the repo, blobs, and preferences from the source PDS to the deactivated destination account, then verify the import completed — implementing `transfer_repo`, `transfer_blobs` (the cursor-paginated blob-drain loop), `transfer_preferences`, and `verify_import`.

**Architecture:** Four more `migration_orchestrator.rs` commands, each following the Phase 3 pattern: pure prerequisite gate (`ensure_phase_did`), clone `Arc<OAuthClient>`(s) + read `source_pds_url` out of the lock, run the network legs via the Phase 2 client surface, then re-lock and advance the phase. The blob-drain loop is factored into a testable `_impl`. `import_repo` must precede the blob loop (blobs uploaded before the repo is indexed are garbage-collected for lack of record references).

**Tech Stack:** Rust, Tauri commands, Phase 2 XRPC helpers (`fetch_repo_car`, `import_repo`, `list_missing_blobs`, `fetch_blob`, `upload_blob`, `get_preferences`, `put_preferences`, `check_account_status`), `httpmock`.

**Scope:** Phase 4 of 7.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC2: Repo, blobs, and preferences transfer to the destination
- **wallet-outbound-migration.AC2.1 Success:** `transfer_repo` exports the source CAR and imports it into the deactivated destination account.
- **wallet-outbound-migration.AC2.2 Success:** `transfer_blobs` drains `list_missing_blobs` on the destination, fetching each missing CID from the source and uploading it, until the missing set is empty.
- **wallet-outbound-migration.AC2.3 Success:** The blob loop walks multiple `list_missing_blobs` pages via cursor and terminates when a page returns an empty set.
- **wallet-outbound-migration.AC2.4 Success:** `transfer_preferences` reads source preferences and writes them to the destination.
- **wallet-outbound-migration.AC2.5 Edge:** `transfer_blobs` on an account with no missing blobs completes immediately (empty first page) without error.
- **wallet-outbound-migration.AC2.6 Failure:** A failed `getBlob`/`uploadBlob`/`list_missing_blobs` leg returns `BLOB_TRANSFER_FAILED` and leaves the phase un-advanced so the step can be retried.

### wallet-outbound-migration.AC3: Import completeness is verified before the identity leg
- **wallet-outbound-migration.AC3.1 Success:** `verify_import` returns the destination `checkAccountStatus` fields and advances to `Verified` when `imported_blobs == expected_blobs` and record counts reconcile.
- **wallet-outbound-migration.AC3.2 Success:** `verify_import` does **not** require `valid_did` to be true (the DID doc still points at the old PDS pre-identity-op).
- **wallet-outbound-migration.AC3.3 Failure:** When blobs/records do not yet reconcile, `verify_import` returns `VERIFICATION_INCOMPLETE` carrying the imported/expected counts.

---

## Which client each leg uses

| Leg | Source (old PDS) | Destination (new PDS) |
|---|---|---|
| `transfer_repo` | `PdsClient::fetch_repo_car` (auth: none) | `import_repo(dest_client)` (Bearer) |
| `transfer_blobs` | `PdsClient::fetch_blob` (auth: none) | `list_missing_blobs`/`upload_blob(dest_client)` (Bearer) |
| `transfer_preferences` | `get_preferences(source_client)` (DPoP) | `put_preferences(dest_client)` (Bearer) |
| `verify_import` | — | `check_account_status(dest_client)` (Bearer) |

`source_client` (DPoP) and `dest_client` (Bearer) live in `OutboundMigrationState`; `source_pds_url` too. `PdsClient` is `state.pds_client()`.

## Design decisions locked (from verification)

1. **Blob upload MIME:** `com.atproto.sync.getBlob` returns bytes; `com.atproto.repo.uploadBlob` **auto-detects** the MIME from the bytes, and blob CIDs are content-addressed (the bytes, not the declared type, determine the CID). So `transfer_blobs` uploads each blob with `Content-Type: application/octet-stream` and the server sniffs/stores the real MIME; the CID-keyed missing set drains correctly. (Preserving the exact source `Content-Type` is a cosmetic nicety not required for the missing set to drain, and would couple Phase 2's `fetch_blob` signature to this phase — deliberately avoided.)
2. **Drain termination:** the loop calls `list_missing_blobs`, uploads every blob on the page, and repeats; it **terminates when a `list_missing_blobs` call returns an empty `blobs` array** (AC2.3/AC2.5). Because uploaded blobs leave the missing set, re-listing naturally converges to empty.
3. **`verify_import` gate:** `imported_blobs == expected_blobs` AND `repo_commit.is_some()` (the repo was imported and indexed — the record-side check, since the server exposes `indexedRecords` but no "expected records" count). It explicitly does **not** require `valid_did` (AC3.2). On mismatch → `VerificationIncomplete { imported, expected }` (AC3.3).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `transfer_repo`

**Verifies:** wallet-outbound-migration.AC2.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::transfer_repo` to `generate_handler!`)

**Implementation:**
```rust
#[tauri::command]
pub async fn transfer_repo(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::DestCreated); clone dest_client (Arc),
    //       read source_pds_url; drop lock.
    // 1. car = state.pds_client().fetch_repo_car(&source_pds_url, &did).await
    //        err -> MigrationError::RepoTransferFailed { message }
    // 2. import_repo(&dest_client, car).await
    //        err -> MigrationError::RepoTransferFailed { message }
    // 3. re-lock, re-validate did, phase = RepoTransferred.
    Ok(())
}
```

**Testing (mock `httpmock`, `#[ignore] // Requires socket binding; ...`):**
- AC2.1: with a mock source serving CAR bytes at `com.atproto.sync.getRepo` and a mock dest accepting `com.atproto.repo.importRepo`, `transfer_repo` fetches the CAR and POSTs the exact bytes to the dest with `Content-Type: application/vnd.ipld.car`, then the state advances to `RepoTransferred`.
- Failure leaves phase un-advanced: if the dest `importRepo` returns 500, `transfer_repo` returns `REPO_TRANSFER_FAILED` and the phase stays `DestCreated`.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): transfer_repo (getRepo old -> importRepo new)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `transfer_blobs` — the cursor-paginated drain loop

**Verifies:** wallet-outbound-migration.AC2.2, wallet-outbound-migration.AC2.3, wallet-outbound-migration.AC2.5, wallet-outbound-migration.AC2.6

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::transfer_blobs`)

**Implementation:** Factor the loop into a testable `_impl`:
```rust
/// Drain the destination's missing-blob set: list a page, pull each CID from the source, push
/// it to the destination; repeat until a page returns no blobs. Any leg failing aborts with
/// BlobTransferFailed WITHOUT advancing the phase, so the whole step is retry-safe (AC2.6).
async fn drain_missing_blobs(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: &str,
    did: &str,
) -> Result<(), MigrationError> {
    let mut cursor: Option<String> = None;
    loop {
        let page = list_missing_blobs(dest_client, cursor.as_deref()).await
            .map_err(|e| MigrationError::BlobTransferFailed { message: e.to_string() })?;
        if page.blobs.is_empty() {
            return Ok(());                       // AC2.3 / AC2.5 terminate on empty page
        }
        for b in &page.blobs {
            let bytes = pds_client.fetch_blob(source_pds_url, did, &b.cid).await
                .map_err(|e| MigrationError::BlobTransferFailed { message: e.to_string() })?;
            upload_blob(dest_client, "application/octet-stream", bytes).await
                .map_err(|e| MigrationError::BlobTransferFailed { message: e.to_string() })?;
        }
        cursor = page.cursor;                    // walk pages; None -> next loop re-lists (now-drained) -> empty -> done
    }
}

#[tauri::command]
pub async fn transfer_blobs(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::RepoTransferred); clone dest_client, read source_pds_url; drop lock.
    // drain_missing_blobs(state.pds_client(), &dest_client, &source_pds_url, &did).await?;
    // re-lock, re-validate did, phase = BlobsTransferred.
}
```

**Testing (mock `httpmock`, `#[ignore]`):**
- AC2.5: dest `list_missing_blobs` returns `{blobs:[],cursor:null}` on the first call → `drain_missing_blobs` returns `Ok(())` without any `getBlob`/`uploadBlob` calls.
- AC2.2/AC2.3: use the **shrinking-missing-set mock model** (do NOT use a stateless mock that returns the same non-empty page — the loop only terminates on an empty `blobs` array, so a constant non-empty page would loop forever). Model the destination's missing set as server-side state the mock mutates: back the `list_missing_blobs` mock with a shared `Arc<Mutex<Vec<Cid>>>` (or httpmock sequenced responses in a fixed order) that returns the currently-missing CIDs — split across pages via `cursor` (e.g. page 1 → `{blobs:[a,b], cursor:"c1"}`, page 2 with `?cursor=c1` → `{blobs:[c], cursor:null}`) — and have the `upload_blob` mock **remove** the uploaded CID from that set, so a subsequent re-list returns the remaining/empty set. The source mock serves each CID. Assert: every missing CID was fetched from source and uploaded to dest exactly once, the loop walks the two cursor pages, and it terminates when the set drains to empty.
- AC2.6: make the source `getBlob` (or dest `uploadBlob`) return 500 mid-drain; assert `transfer_blobs` returns `BLOB_TRANSFER_FAILED` and the phase remains `RepoTransferred` (un-advanced, retry-safe).

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): transfer_blobs cursor-drain loop (listMissingBlobs)`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: `transfer_preferences`

**Verifies:** wallet-outbound-migration.AC2.4

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::transfer_preferences`)

**Implementation:**
```rust
#[tauri::command]
pub async fn transfer_preferences(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::BlobsTransferred); clone source_client AND dest_client; drop lock.
    // prefs = get_preferences(&source_client).await   // old PDS, DPoP
    //        err -> PreferencesTransferFailed
    // put_preferences(&dest_client, &prefs).await      // new PDS, Bearer
    //        err -> PreferencesTransferFailed
    // re-lock, re-validate did, phase = PreferencesTransferred.
}
```
`get_preferences` returns the whole `{ preferences: [...] }` object (Phase 2); `put_preferences` echoes it back — the server accepts the same shape it emits.

**Testing (mock `httpmock`, `#[ignore]`):**
- AC2.4: mock source `getPreferences` returning a non-empty `{preferences:[...]}`; assert `transfer_preferences` POSTs the identical object to the dest `putPreferences`, and the phase advances to `PreferencesTransferred`.
- Failure on either leg → `PREFERENCES_TRANSFER_FAILED`, phase un-advanced.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): transfer_preferences (getPreferences old -> putPreferences new)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `verify_import`

**Verifies:** wallet-outbound-migration.AC3.1, wallet-outbound-migration.AC3.2, wallet-outbound-migration.AC3.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append `migration_orchestrator::verify_import`)

**Implementation:**
```rust
/// Pure completeness check — testable without a server.
fn import_reconciles(status: &crate::pds_client::AccountStatus) -> bool {
    // Gate on blobs complete AND repo present. Explicitly NOT valid_did (AC3.2): the DID doc
    // still points at the old PDS until the identity op lands.
    status.imported_blobs == status.expected_blobs && status.repo_commit.is_some()
}

#[tauri::command]
pub async fn verify_import(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<crate::pds_client::AccountStatus, MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::PreferencesTransferred); clone dest_client; drop lock.
    // status = check_account_status(&dest_client).await -> NetworkError on failure
    // if import_reconciles(&status) { re-lock; phase = Verified; Ok(status) }
    // else { Err(MigrationError::VerificationIncomplete {
    //          imported: status.imported_blobs, expected: status.expected_blobs }) }
}
```
`AccountStatus` must derive `serde::Serialize` (it is returned to the frontend). Add `Serialize` to its derive list in `pds_client.rs` if Phase 2 only derived `Deserialize` — confirm and add.

**Testing:**
- AC3.1 (pure): `import_reconciles(&status)` is true when `imported_blobs == expected_blobs` and `repo_commit = Some(..)`.
- AC3.2 (pure): `import_reconciles` is true even when `valid_did = false` (construct such a status).
- AC3.3 (pure): `import_reconciles` is false when `imported_blobs < expected_blobs`.
- Command-level (`#[ignore]` mock): dest `checkAccountStatus` returning a reconciled status advances phase to `Verified` and returns the `AccountStatus`; an unreconciled status returns `VERIFICATION_INCOMPLETE` with the counts and leaves phase at `PreferencesTransferred`.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): verify_import (checkAccountStatus completeness gate)`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 4 done when

- `transfer_repo`, `transfer_blobs`, `transfer_preferences`, `verify_import` implemented and registered.
- The blob-drain `_impl` walks cursor pages and terminates on an empty set (AC2.3), no-ops on an already-drained account (AC2.5), and leaves the phase un-advanced on any leg failure (AC2.6).
- `verify_import` gates on blobs+repo, not `valid_did` (AC3.1/AC3.2), and returns `VERIFICATION_INCOMPLETE` with counts otherwise (AC3.3).
- `cargo test -p identity-wallet --lib migration_orchestrator` passes (socket `#[ignore]` tests may need the sandbox disabled).
- Covers wallet-outbound-migration.AC2.1–AC2.6, AC3.1–AC3.3.
