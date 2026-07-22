# Wallet-Held MST Repo Backup to iCloud

**Status: design + recommendation (2026-07-22). Not yet built.** This plan proposes
a `repo_backup.rs` module in the identity wallet that mirrors a user's ATProto repo
(their signed commit + MST + records — the CAR) into their iCloud Drive, as the
sibling of the shipped user-held blob backup (`blob_backup.rs`, MM-434). It closes
the last gap in the wallet's self-custody story: the repo is currently the only
account asset that lives *only* on the PDS.

## Summary

The wallet already gives a user three self-controlled copies of the pieces of their
identity: the **keys** (device key in the Secure Enclave, recovery Share 1 in the
iCloud Keychain), and the **blobs** (media mirrored to iCloud Drive by
`blob_backup.rs`). The one asset with no user-held copy is the **repo** — the signed
commit + Merkle Search Tree + record blocks that hold every post, like, follow, and
profile edit. It lives on the PDS as the primary and only copy
(`docs/pds-architecture.md`: "Repo location: PDS (primary and only copy)"). If the
PDS loses the repo — the exact "row present, bytes gone" class of failure that
motivated the blob backup (MM-394) — the user has their keys and their media but
nothing to reconstruct their timeline from.

This plan adds a fourth self-custody copy: a periodic **CAR snapshot** of the repo,
written to the same iCloud Drive ubiquity container the blob mirror already uses.
Backup fetches the repo over the public, unauthenticated `com.atproto.sync.getRepo`
endpoint (no session needed, exactly like the blob backup's public reads), validates
the signed commit, and writes one atomically-replaced `.car` file per DID plus a
small manifest. The stored CAR is the canonical, directly-importable artifact — the
same bytes `com.atproto.repo.importRepo` and the wallet's existing migration
`transfer_repo` leg already consume — so it doubles as the account's portable exit.

## The core design decision

The obvious framing is a choice between two options:

- **(A)** an occasional full-repo **CAR snapshot** tucked into the wallet, or
- **(B)** replicating the repo **tree** (individual IPLD blocks) into iCloud and
  **generating a CAR on-device** when the user wants to import to a new provider.

These are not two independent features — they are the same feature with a different
**storage format**, and the "generate a CAR on-device" step is a *consequence* of (B)'s
storage choice, not a separate capability:

- A **CAR is already the portable, importable artifact.** If we store a full CAR
  snapshot, we hold the exact bytes `importRepo` wants. There is nothing to
  "generate" at restore/export time — we read the file and hand it over.
- On-device CAR **generation** only becomes necessary if we deliberately store the
  repo as **unpacked, deduplicated blocks** (B), because then a CAR must be
  *reassembled* from the root CID (an MST walk) before any provider can accept it.

So the real axis is: **store one replaceable CAR blob, or store a content-addressed
block tree and reassemble on demand.** Portability comes free either way. (B)'s only
genuine advantage is **incremental efficiency** — `getRepo?since=<rev>` lets the
wallet fetch only blocks added since the last backup, and deduplicated blocks avoid
re-storing unchanged history.

That advantage is small in this system, because **the byte-heavy asset is blobs, and
blobs are backed up separately.** A repo *minus* its blobs is just records (text) and
MST nodes — typically a few MB even for a prolific poster. `getRepo` streams the
export block-by-block server-side with no size cap, so re-fetching the whole CAR on
each opportunistic pass is cheap. (B) pays for MST-walking, superseded-block-GC, and
a repo-engine dependency on-device to save bandwidth we don't meaningfully spend.

## Recommendation

**Build (A): a periodic full-CAR snapshot, cloned structurally from `blob_backup.rs`.**
Treat (B) as a documented future upgrade, reached only if measured repo sizes make
full snapshots painful — the server-side `getRepo?since=` support and repo-engine's
`collect_reachable_cids` + `build_car_from_cids` primitives make it a clean upgrade
that this plan deliberately leaves on the table.

Rationale:

1. **It completes the self-custody set with no new crypto surface.** Keys (already) +
   blobs (already) + repo CAR (this) = a user who can reconstruct their entire account
   from iCloud and their device alone.
2. **It reuses proven, already-shipped infrastructure end to end**: the CAR fetch
   (`PdsClient::fetch_repo_car`), the iCloud ubiquity-container mirror
   (`blob_backup::resolve_backup_root` + the `objc2`/`NSFileManager` path), the atomic
   temp-file+rename write, the per-DID manifest + opt-in-flag pattern, and the CAR
   import leg (`pds_client::import_repo`, driven today by `transfer_repo`).
3. **Integrity is free.** The CAR's declared root is the account's **signed commit**;
   content addressing makes the snapshot self-verifying, the same "content-addressed =
   trustless" property the blob mirror relies on. No encryption is needed — the repo
   is public data served by an `auth: none` endpoint, the identical posture already
   accepted for blobs (iCloud is E2EE only under Advanced Data Protection).
4. **No on-device CAR generation, no repo-engine dependency, no MST logic in the
   wallet.** The wallet fetches bytes and writes a file; the file *is* the export.

## Definition of Done

This plan is complete when:

1. **A `repo_backup.rs` module** exists in `apps/identity-wallet/src-tauri/`, sibling
   to `blob_backup.rs`, exposing four fine-grained Tauri commands
   (`get_repo_backup_status`, `set_repo_backup_enabled`, `run_repo_backup`,
   `export_repo_backup`) plus one `pub(crate)` helper (`mirror_repo_car`) for the
   migration orchestrator's fallback source.
2. **Backup** is opt-in per DID (`{did}:repo-backup-enabled` Keychain slot), fetches
   the full CAR via the public `getRepo` on the DID's current hosting PDS, **validates
   the CAR's single root + commit signature before writing**, and atomically replaces
   `{root}/repo/{sanitized-did}.car` with a versioned manifest at
   `{root}/repo/{sanitized-did}.json` recording `{ rootCid, rev, sizeBytes,
   lastBackupAt }`. It runs on demand ("Back up now") and opportunistically on app
   open, mirroring the blob backup.
3. **The stored CAR is consumable by the existing import path.** The migration
   orchestrator's `transfer_repo` gains an iCloud-mirror fallback source
   (`repo_backup::mirror_repo_car`), the exact parallel of the blob drain's
   `mirror_fallback_blob` — so a migration whose *source* PDS can't serve `getRepo`
   heals from the user's iCloud copy, and the copy is proven wired into a real import.
4. **The mirror root and opt-in resolution are shared, not duplicated**, with
   `blob_backup` (both feed the same ubiquity container; `resolve_backup_root` and
   `BackupLocation` are reused).
5. **A "Back up your posts" surface** exists — either folded into the existing
   `MediaBackupScreen` (renamed to a combined backup screen) or a sibling screen —
   showing the opt-in, the snapshot size, and the last-backup time, and the
   opportunistic pass fires from `+page.svelte` on app open alongside the blob pass.
6. **Tests + parity**: Rust `_impl`/httpmock unit tests for the fetch→validate→write
   loop, manifest round-trip, and the mirror-fallback source; TypeScript IPC wrappers
   in `src/lib/ipc/` with a `RepoBackupError` union matching the Rust enum; a browser
   harness fake for the ubiquity path so the surface stays scriptable off-device;
   `pnpm check` green; the AGENTS.md contract + Bruno parity (no new routes — `getRepo`
   and `importRepo` already have `.bru` files) updated.

## Acceptance Criteria

### AC1: The repo is snapshotted to a user-controlled iCloud copy
- **AC1.1** With the feature opted in and iCloud Drive available, `run_repo_backup(did)`
  discovers the DID's current PDS, fetches the full CAR over public `getRepo`,
  validates it, and writes it atomically to `{root}/repo/{sanitized-did}.car`.
- **AC1.2** The manifest records the backed-up commit `rootCid`, repo `rev`, CAR
  `sizeBytes`, and `lastBackupAt`; `get_repo_backup_status` surfaces them for the UI.
- **AC1.3** On a real iOS device with iCloud Drive off, backup reports
  `BACKUP_UNAVAILABLE` — never a silent local-only fallback (matches blob backup).
- **AC1.4** A backup pass is idempotent: re-running when the repo `rev` is unchanged
  re-writes the same snapshot without error (and may short-circuit on matching `rev`).

### AC2: The snapshot is integrity-checked, never trusting the PDS blindly
- **AC2.1** A fetched CAR that fails validation (not exactly one root, unparseable
  framing, commit `version != 3`, commit `did` ≠ the backed-up DID, or a broken MST
  walk) is rejected as `CAR_INVALID` and the prior good snapshot is left in place.
- **AC2.2** The declared root is verified to be a signed commit before the snapshot is
  considered good (self-verifying via content addressing).

### AC3: The stored CAR restores/exports through the existing import machinery
- **AC3.1** `export_repo_backup(did)` reads and re-validates the stored CAR and returns
  its bytes (and manifest metadata) for a caller to import.
- **AC3.2** `migration_orchestrator::transfer_repo` falls back to
  `repo_backup::mirror_repo_car(did)` when the migration source PDS cannot serve
  `getRepo`, importing the iCloud copy instead — the repo twin of the blob drain's
  `mirror_fallback_blob`.
- **AC3.3** The fallback is used only when the mirror holds a CID/commit-valid CAR for
  the DID; otherwise the transfer surfaces the original source failure unchanged.

### AC4: Opt-in, opportunistic, and shared with the blob backup
- **AC4.1** Opt-in is per DID via `{did}:repo-backup-enabled`; `IdentityStore::remove_identity`
  cleans the slot up (added to its per-DID suffix list).
- **AC4.2** `+page.svelte` fires a silent, fire-and-forget `runRepoBackup(did)` pass on
  app open for every opted-in identity, alongside the existing blob pass.
- **AC4.3** `resolve_backup_root`/`BackupLocation` are shared with `blob_backup`, not
  re-implemented; both features write under the same ubiquity container.

### AC5: The surface is honest about size and scriptable off-device
- **AC5.1** The backup surface always shows the snapshot size before and after opt-in
  (iCloud's free tier is a shared 5 GB), and the last-backup time.
- **AC5.2** A browser-harness fake covers the ubiquity path (via `EZPDS_..._DIR` env
  override) so every state is reachable in fake mode; the fake-handler-coverage test
  passes for the new commands.

## Architecture

`repo_backup.rs` is a structural clone of `blob_backup.rs`, simplified because a repo
is **one artifact** rather than a set of content-addressed files — there is no
per-item diff loop, no pagination, no `MANIFEST_SAVE_EVERY` checkpointing. The whole
CAR is fetched, validated, and written in one atomic replace.

**Storage layout** (under the shared backup root; blob uses `blobs/` + `manifests/`):
```
{root}/repo/{sanitized-did}.car     # the full CARv1 snapshot (declared root = signed commit)
{root}/repo/{sanitized-did}.json    # the manifest
```
`sanitized-did` reuses blob backup's `:` → `_` transform.

**Manifest** (`RepoManifest`, `version: u32 = 1`, serde camelCase):
```rust
struct RepoManifest {
    version: u32,
    did: String,
    root_cid: String,       // the backed-up commit root CID
    rev: String,            // the repo revision (TID) at snapshot time
    size_bytes: u64,        // CAR length on disk
    last_backup_at: Option<String>,  // RFC 3339
}
```

**Status readout** (`RepoBackupStatus`, serde camelCase) — the UI model:
```rust
struct RepoBackupStatus {
    enabled: bool,
    location: Option<BackupLocation>,   // reused from blob_backup
    root_cid: Option<String>,
    rev: Option<String>,
    size_bytes: u64,
    last_backup_at: Option<String>,
}
```

**Command surface** (four Tauri commands + one `pub(crate)` helper):

| Command | Does |
|---|---|
| `get_repo_backup_status(did)` | manifest → status readout (location, size, rev, last-backup) |
| `set_repo_backup_enabled(did, enabled)` | flip the `{did}:repo-backup-enabled` slot |
| `run_repo_backup(did)` | discover PDS → `fetch_repo_car` → **validate** → atomic write + manifest |
| `export_repo_backup(did)` | read + re-validate the stored CAR; return bytes + manifest for import |
| `mirror_repo_car(root, did) -> Option<Vec<u8>>` (`pub(crate)`) | the migration-orchestrator fallback source, twin of `blob_backup::mirror_fallback_blob` |

**Backup flow** (`run_repo_backup`):
1. Resolve the backup root (`blob_backup::resolve_backup_root`; `BACKUP_UNAVAILABLE`
   when none).
2. `PdsClient::discover_pds(did)` → the DID's current hosting PDS URL (via plc.directory).
3. `PdsClient::fetch_repo_car(pds_url, did)` — the existing unauthenticated public
   fetch (`auth: none`, no session), reused verbatim from the migration path.
4. **Validate** the CAR: exactly one root, well-formed framing, commit `version == 3`,
   commit `did` matches, MST walk resolves. (This is the client-side twin of the
   server's `car_import::validate_car`; the wallet applies the same defensive checks
   the destination PDS would, so a corrupt fetch is never enshrined.)
5. Atomic temp-file + rename to `{root}/repo/{sanitized-did}.car`; write the manifest.
   Short-circuit when the fetched `rev` equals the manifest's (no-op re-backup).

**Restore/export flow.** Unlike blobs — which restore by re-`uploadBlob` into a *live*
account — a repo import (`com.atproto.repo.importRepo`) requires a **deactivated**
account (it is the account-migration leg). So this plan does **not** ship a
"push my repo back to my live PDS" button; there is no such operation in ATProto.
Instead the stored CAR is made consumable two ways:
- **`export_repo_backup`** hands the validated bytes to a caller (diagnostics, a future
  disaster-recovery flow, or an "export my repo to a file" affordance).
- **`transfer_repo` mirror fallback** — the migration orchestrator, when its source PDS
  can't serve `getRepo`, sources the CAR from `repo_backup::mirror_repo_car` instead.
  This gets the backup *wired into a real import path in v1* and directly parallels how
  the blob drain already falls back to `mirror_fallback_blob`.

**Error enum** (`RepoBackupError`, `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`):
`BACKUP_UNAVAILABLE`, `RATE_LIMITED`, `IDENTITY_NOT_FOUND`, `PLC_DIRECTORY_ERROR`
(PDS discovery), `SERVER_ERROR`, `NETWORK_ERROR`, `STORAGE_ERROR`, `MANIFEST_CORRUPT`
(fail-closed, file preserved), `CAR_INVALID`, `KEYCHAIN_ERROR`. Note there is **no
`SESSION_LOCKED`** — backup reads a public endpoint and export reads local disk;
neither needs a full-access session (a genuine advantage over the blob restore path).

## Existing Patterns

This design copies patterns already established in the wallet:

- **`blob_backup.rs` as the structural template** — opt-in per-DID Keychain slot,
  `resolve_backup_root` order (env override → iCloud ubiquity container → device with
  iCloud off = unavailable → local dev fallback), atomic temp+rename writes, versioned
  per-DID manifest, fail-closed corrupt manifest, opportunistic pass on app open,
  SCREAMING_SNAKE_CASE error enum. `repo_backup` reuses `resolve_backup_root`,
  `BackupLocation`, and the `BACKUP_DIR_ENV` override directly.
- **The migration `transfer_repo` leg** already does `fetch_repo_car(source) →
  import_repo(dest)` (`migration_orchestrator.rs:658` `transfer_repo_impl`). The backup
  fetch is the first half of that, and the mirror fallback slots into it exactly like
  the blob drain's does.
- **`mirror_fallback_blob`** (`blob_backup.rs:876`, `pub(crate) async fn … -> Option<Vec<u8>>`)
  is the precise shape for `mirror_repo_car`.
- **Server-side CAR primitives already exist and need no change**: `getRepo`
  (`crates/pds/src/routes/get_repo.rs`, streamed, `auth: none`, no size cap) and
  `importRepo` (`crates/pds/src/routes/import_repo.rs`, deactivated account, 100 MiB
  cap). Both already have `.bru` fixtures, so `just bruno-check` needs nothing new.
- **The browser-harness fake + coverage test** — every `$lib/ipc` command needs a
  handler in `src/lib/harness/registry.ts`; the new commands get fakes driven by the
  `EZPDS_..._DIR` env override, same as the blob backup's harness treatment.

## Implementation Phases

### Phase 1: `repo_backup.rs` core — status, opt-in, backup, validate
The module, the manifest/status/error types, the four command cores as `_impl`
functions (Tauri-`State`-free, httpmock-tested), reusing `blob_backup::resolve_backup_root`.
CAR validation ported as the client twin of `car_import::validate_car`. **Done when**
`_impl` tests cover fetch→validate→atomic-write, the rev short-circuit, a rejected
`CAR_INVALID` fetch leaving the prior snapshot intact, and manifest round-trip.

### Phase 2: Migration mirror-fallback wiring
`mirror_repo_car` + a fallback branch in `transfer_repo_impl` that tries the iCloud
CAR when the source `getRepo` fails (mirroring the blob drain). **Done when** an
integration test drives `transfer_repo` with a failing source and a populated mirror
and sees the import succeed from iCloud.

### Phase 3: Commands + IPC + AGENTS.md
Register the commands in `lib.rs`; add `src/lib/ipc/repo-backup.ts` typed wrappers +
`RepoBackupError` union; add the `{did}:repo-backup-enabled` suffix to
`IdentityStore::remove_identity`'s cleanup list; extend the AGENTS.md `ipc.ts` exports
and module contract. **Done when** `pnpm check` passes and the error unions match.

### Phase 4: UI surface + opportunistic pass + harness fake
Fold a "Back up your posts" section into `MediaBackupScreen` (or a sibling screen) with
size + last-backup shown; fire `runRepoBackup` opportunistically on app open in
`+page.svelte`; add the harness registry fakes + scenario. **Done when** the surface is
reachable in fake mode and the registry-coverage test passes.

## Additional Considerations (sharp edges)

**The disaster case is the interesting one, and it's a follow-on.** Standard ATProto
migration assumes the *source* PDS is alive to mint the `getServiceAuth` token that
authorizes `createAccount` on the destination. If the reason for restoring is that the
old PDS is *gone*, that token path is dead — so a true "rebuild my account from iCloud
onto a fresh PDS" flow needs a **wallet-signed `createAccount`/import authorization** (a
device-key proof over the DID, which the wallet already holds as `rotationKeys[0]`)
rather than source service-auth. That is the piece that turns this backup from a
migration *convenience* into a genuine credible-exit *guarantee*, and it intersects
ADR-0002 and needs a PDS-side change. **This plan deliberately scopes that out** and
delivers the backup + the migration mirror-fallback first; the sovereign
disaster-recovery flow is a tracked follow-on.

**A CAR is records, not blobs.** The MST references blobs by CID but does not contain
their bytes. A full account restore is therefore **import the repo CAR (this backup) +
re-upload blobs (the existing blob mirror, via `listMissingBlobs`)** — the two backups
are complementary and together are the whole account. They are captured independently,
so a snapshot can reference a not-yet-mirrored blob (or vice versa); content addressing
makes this safely eventually-consistent (`listMissingBlobs` reconciles on import), but
the snapshots are not a single atomic point-in-time.

**Import caps at 100 MiB** (`MAX_IMPORT_CAR_BYTES`) while `getRepo` export has no cap.
A repo of records rarely approaches this, but the status surface should show size, and
a snapshot exceeding the import cap is a known (documented) limitation for extreme
accounts — another data point that would argue for (B)'s incremental model if it ever
bites.

**Encryption / privacy.** None is added: the repo is public data (`getRepo` is
`auth: none`), so plaintext-in-iCloud is the same posture already accepted for the blob
mirror. The mirror is Files-app-visible, reinforcing user-legible sovereignty.

**Entitlements ride the existing template.** The iCloud container
(`iCloud.dev.malpercio.identitywallet`) and `Entitlements.ios.plist` are already in
place for the blob backup; repo backup writes under the same container and needs no new
entitlement, capability, or `just ios-template-check`/`ios-check` change.

## Out of scope (tracked as follow-ons)

- **Sovereign disaster-recovery flow** (source PDS dead → wallet-signed `createAccount`
  authorization → import from iCloud CAR → activate). The credible-exit guarantee;
  needs a PDS-side auth change (ADR-0002 territory).
- **Option B: block-level incremental mirror** via `getRepo?since=<rev>` + on-device CAR
  reassembly (`collect_reachable_cids` + `build_car_from_cids`, a repo-engine dep in the
  wallet). Only if measured repo sizes justify it.
- **`BGProcessingTask` background scheduling** — shared with the blob backup's existing
  open follow-on; both mirrors would refresh together off-foreground.

## Glossary

- **CAR (Content Addressable aRchive)**: the `application/vnd.ipld.car` binary format
  that packages a whole repo (signed commit + MST nodes + record blocks) in one
  transfer; the unit `getRepo` exports and `importRepo` imports.
- **MST (Merkle Search Tree)**: the tree ATProto stores repo records in; its nodes and
  the records are DAG-CBOR IPLD blocks addressed by CID.
- **Repo / commit / rev**: the repo's head is a **signed commit** naming a root CID; its
  **rev** is a TID revision that advances on every write and drives `getRepo?since=`.
- **Ubiquity container**: the app's iCloud Drive directory
  (`NSFileManager.URLForUbiquityContainerIdentifier`), reached from Rust via
  `objc2-foundation`; iOS syncs anything written to its `Documents/` and it is
  Files-app-visible. The blob mirror and this repo mirror share it.
- **`getRepo` / `importRepo`**: `com.atproto.sync.getRepo` (public, streamed, full or
  `since`-incremental CAR export) and `com.atproto.repo.importRepo` (imports a CAR into
  a **deactivated** account — the migration leg).
- **`fetch_repo_car`**: `PdsClient::fetch_repo_car(pds_url, did)`, the wallet's existing
  unauthenticated CAR fetch (`pds_client.rs:1277`), reused by this backup.
- **Mirror fallback**: the pattern where the migration transfer substitutes a
  CID/commit-verified local iCloud copy when the source PDS can't serve the asset —
  shipped for blobs as `mirror_fallback_blob`, added here for the repo as
  `mirror_repo_car`.
