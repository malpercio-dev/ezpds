# Blobstore Resilience

**Status: survey + recommendations (2026-07-18). Nothing here is implemented yet.**

Prompted by the MM-394 real-identity migration
([validation record](../validation/2026-07-17-mm-394-real-identity-migration.md)):
the source reference PDS served repo/record/`listBlobs` reads fine while 500ing on
**every** `getBlob` for the DID — blob metadata present, file reads failing server-side
— and the blobs proved permanently unrecoverable (AppView CDN derivatives are
re-encoded, so they can never match the original CIDs). That fault happened to a
*source* PDS, but nothing structural prevents the same class of failure on Custos. As
production accounts move in, "row present, bytes gone" becomes an unrecoverable loss of
users' media, and there is no external copy anywhere on the network to heal from.

## Current posture

- Blob bytes are plain files at `{data_dir}/blobs/{cid[0:2]}/{cid}` on the Railway
  `/data` volume (`crates/pds/src/blob_store.rs`). Metadata lives in SQLite (`blobs` +
  per-account `blob_owners`, V039).
- **Litestream replicates only the SQLite database.** Blob files have zero replication:
  volume loss or corruption destroys every user's media with no restore path — the
  exact catastrophe the KEK runbook exists to prevent for keys, unaddressed for blobs.
  There is also a restore asymmetry: the DB can be restored to a point in time; the
  blob directory cannot, and nothing reconciles the two after a restore.
- The write path (`store_blob`) is `tokio::fs::write` straight to the final
  content-addressed path — no temp-file + atomic rename, no fsync of file or
  directory. A crash or power loss can leave truncated bytes at a valid CID path, or a
  WAL-durable `blobs` row pointing at bytes the page cache never flushed. That is
  precisely the "metadata present, reads failing" fault observed on the source PDS.
- Nothing ever re-verifies stored bytes against their CID after upload. Bitrot,
  truncation, or a bad restore stays silent until a `getBlob` — or a migration drain —
  trips over it. `getBlob` streams whatever the file contains, with
  `Cache-Control: immutable`, so corrupt bytes would also be cached as canonical.
- Working in our favor: content addressing makes both verification (re-hash, compare
  to filename) and incremental replication (immutable, add-only files) trivial; the
  blob GC is authoritative by MST walk; `checkAccountStatus` /
  `listMissingBlobs` already give migration tooling a reconciliation view.

## Recommendations, in priority order

### 1. Replicate blob bytes off the volume (the disaster gap)

Two viable shapes:

- **(a) Bucket mirror, Litestream-analogous (small, immediate).** A periodic
  sweep (existing template: `blob_gc.rs` / `account_reaper.rs`) that syncs
  `{data_dir}/blobs/` to an S3-compatible bucket, plus a restore-on-boot path.
  Content addressing makes this trivially safe and incremental: files are immutable
  and add-only, so sync is "upload missing keys"; delete propagation may lag GC
  harmlessly (worst case the bucket briefly retains collected blobs). No schema
  change, no serving-path change.
- **(b) S3-compatible backend as the primary store** — the
  [blob-handling spec](../blob-handling-spec.md) §4 v1.0 plan (R2/Tigris/MinIO via
  `rust-s3` or `opendal`, `storage_backend` column, local→S3 migration tool). Removes
  the volume dependency entirely and gets object-storage durability, at the cost of a
  real backend abstraction and a serving-path change.

Recommendation: do **(a)** now — it closes the total-loss window with a day-scale
change — and treat **(b)** as the structural v1.0 move it already is in the spec.
(a)'s bucket becomes (b)'s bucket; nothing is thrown away.

### 2. Make the write path crash-durable

In `store_blob`: write to a temp file in the same directory, fsync the file, rename
onto the final CID path, fsync the directory — and only then let the caller insert the
DB row. This eliminates the torn-write / row-without-durable-bytes state machine at
its source. (The existing write order — file before row — is already correct; the
missing piece is durability of the file write itself.)

### 3. Integrity scrub sweep

A periodic background task that walks stored blobs, re-hashes each file, and compares
hash + size against the row (`blob_scrub_*` metrics + `sweep_status` + admin-health
entry, same failed-pass-leaves-timestamp-stale posture as the other sweeps). A
full-directory walk also catches both orphan directions: rows whose file is missing
(the migration-blocking fault, surfaced as an alarm instead of a 500 mid-drain) and
files no row owns (a leak the GC never scans for). With №1 in place the scrub can
auto-heal a bad file from the bucket; without it, it at least converts silent rot into
an operator signal months before a migration depends on the bytes.

### 4. Verify on serve

`getBlob` already buffers the whole file (`read_blob` → `Vec<u8>`); re-hashing a
few-MB blob before streaming is cheap at this fleet's scale. On mismatch: 404 +
error-log + flag for the scrub, never serve wrong bytes under an `immutable` cache
header. Config-gated if the cost ever matters.

### 5. Migration-drain ergonomics (wallet + server)

Already noted in the MM-394 record: `MigrationError::BlobTransferFailed` carries the
failing CID and direction, but the wallet's `describeError` drops it. Beyond that fix,
the drain should degrade per-blob rather than all-or-nothing: retry each blob, then
offer "continue with an explicit loss manifest" so one dead blob doesn't park the
migration and the user makes an informed skip instead of abandoning the run.

## Suggested sequencing

№2 (write durability) and №3 (scrub) are self-contained server changes with existing
patterns to copy and no new infrastructure. №1(a) needs a bucket + credentials on the
production environment (same shape as the Litestream vars) and is the highest-impact
single change. №4 rides on №3's helpers. №5 is mostly wallet-side.
