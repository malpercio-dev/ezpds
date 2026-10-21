# custos-blobs

Last verified: 2026-10-21

The blob feature crate: `com.atproto.repo.uploadBlob`, `repo.listMissingBlobs`, `sync.getBlob`,
`sync.listBlobs`, and the three blob sweeps (garbage collection, the integrity scrub, and the
optional S3 mirror with its restore-on-boot reconcile). It depends on
[`custos-core`](../custos-core/AGENTS.md) and [`custos-db`](../custos-db/AGENTS.md), never on `pds`
or a sibling feature. The blob file store (`custos_core::blob_store`) and the `blobs` table queries
(`custos_db::blobs`) stay below the features, because every repo write reads them. The
feature-crate contract is [`custos-spaces`' map](../custos-spaces/AGENTS.md#what-pds-consumes);
this crate owns no state.

This file is a map; mechanism and invariants live in each module's `//!` doc.

## What `pds` consumes

| Export | Use in `pds` |
|---|---|
| `router()` | merged into `app.rs`'s public (CORS'd) group before the layer stack. Always on |
| `prepare_mirror(&CoreState)` | `main.rs`, BEFORE the listener binds: builds the mirror client when `[blob_mirror]` names a bucket and reconciles the volume against it |
| `spawn_sweeps(&mut Scheduler, &Config, Option<Arc<BlobMirror>>)` | `main.rs`; registers GC, the mirror sweep (bucket only), and the scrub on `pds`'s scheduler |
| `BlobMirror` | the opaque mirror client `prepare_mirror` returns and `spawn_sweeps` takes |
| `test_support` (`test-support` feature) | `test_app(state)`, the GC fixtures (`gc_state`, `add_blob`, `blob_record`, `blob_file_exists`, `write_record`, `run_blob_gc`) `pds`'s cross-feature GC test uses, plus `custos_core::test_support` re-exported |

Blob GC unions space-record blob references in through its own read of `space_records`
(`db/space_record_blocks.rs`); the table is `custos-spaces`' to write. The test proving a blob
referenced only from a space record is pinned lives in `pds` (`blob_gc_spaces_test.rs`), the one
crate that depends on both features.

## Module Map

```
src/
  lib.rs            — the exports above; aliases `custos_core`'s `auth`, `blob_store`, `lexicon`, `metrics`, `sweep`, `sweep_status`, `time` at the crate root so the moved files' `crate::…` paths resolve
  router.rs         — the route table (`scripts/bruno-parity.sh` and `scripts/generate-docs-reference.mjs` read its `.route(` literals)
  blob_gc.rs        — periodic blob GC over per-account ownership rows (`blob_owners`, V039); references union the public MST and stored space records (V065); fails closed on a failed reconcile (that account leaks disk until fixed) — see module doc
  blob_mirror/      — off-volume blob replication to an S3-compatible bucket (`[blob_mirror]` / `EZPDS_BLOB_MIRROR_*`); boot restore runs before the listener binds; `s3.rs` is a hand-rolled SigV4 client — see module doc
  blob_scrub.rs     — periodic blob-integrity scrub: re-hash every stored blob + walk both orphan directions; auto-heals from the mirror when configured — see module doc
  db/               — `space_record_blocks.rs`: blob GC's keyset-paged read of an account's stored space record blocks; `custos_db` is re-exported crate-privately
  routes/           — one file per endpoint (table below); private, only handler functions leave it
  test_support.rs   — `test-support` feature (and this crate's own tests): `test_app` wraps `router()` in the layers `pds` applies to its public group
```

### `routes/`

| File | Endpoint |
|---|---|
| `upload_blob.rs` | `POST /xrpc/com.atproto.repo.uploadBlob` — blob store + metadata insert, dual auth (access token or method-scoped service-auth JWT, the video-service path) — see module doc |
| `get_blob.rs` | `GET /xrpc/com.atproto.sync.getBlob` — ownership-scoped, re-hash-verified blob serving with immutable caching — see module doc |
| `list_blobs.rs` | `GET /xrpc/com.atproto.sync.listBlobs` — paginated blob CIDs for a DID |
| `list_missing_blobs.rs` | `GET /xrpc/com.atproto.repo.listMissingBlobs` — MST-referenced blobs diffed against uploads, paginated |

## Rules

- **Routes do not import routes.**
- **Never depend on `pds` or a sibling feature crate.** Anything another feature also needs moves
  down to `custos-core` (or `custos-db` for a table).
- **A new blob route** is registered in `router.rs` and gets a `.bru` file in `bruno/` (root
  AGENTS.md).
- **Migrations stay in `custos-db`.**
