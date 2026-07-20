# Blobstore Resilience

**Status: survey + recommendations (2026-07-18). Partially implemented:**
recommendations 1–3 shipped — the off-volume bucket mirror (#367), crash-durable
blob writes (#375), and the periodic integrity scrub sweep (MM-431, #376).
Recommendations 4 (verify on serve) and 5 (migration-drain ergonomics) and the
wallet-side iCloud blob backup remain open.

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
  trips over it. `getBlob` buffers the whole file and returns whatever it contains
  (with `Content-Type`/CSP/`nosniff` headers; it does not currently set
  `Cache-Control` — the [blob-handling spec](../blob-handling-spec.md) §7.3 recommends
  `immutable`, which is safe only once bytes are verified). Because blobs are
  content-addressed, downstream consumers cache them as immutable regardless, so
  served corrupt bytes would stick as canonical.
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
  change, no serving-path change. Two integrity rules keep the mirror trustworthy:
  **verify before replicating** — re-hash and size-check each local file before
  upload (the write path can currently leave truncated bytes at a valid CID path,
  №2; a corrupt local file must never become the trusted recovery copy), and apply
  the same verification before any restore or scrub auto-heal trusts a bucket copy.
  And **restore must gate serving**: restore-on-boot has to complete — blob files
  restored and reconciled against the (Litestream-restored) rows — before the server
  takes traffic, else a half-restored volume recreates the "metadata present, bytes
  missing" fault; rows whose blobs remain missing are surfaced (scrub alarm), not
  silently served.
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
few-MB blob before returning it is cheap at this fleet's scale. On mismatch: 404 +
error-log + flag for the scrub — never serve wrong bytes that downstream caches
would keep as canonical. Verification is unconditional in the correctness path; if
an emergency bypass ever proves necessary, degraded mode must be explicit and
observable (metric + log on every unverified serve), never a silent config default.

### 5. Migration-drain ergonomics (wallet + server)

Already noted in the MM-394 record: `MigrationError::BlobTransferFailed` carries the
failing CID and direction, but the wallet's `describeError` drops it. Beyond that fix,
the drain should degrade per-blob rather than all-or-nothing: retry each blob, then
offer "continue with an explicit loss manifest" so one dead blob doesn't park the
migration and the user makes an informed skip instead of abandoning the run.

## Wallet-side option: user-held blob backup to iCloud

A complement to the server tiers above, not a substitute — but it is the only layer
that survives *the PDS itself* failing, which is exactly the MM-394 scenario (the
source PDS lost the bytes and no other copy existed anywhere on the network). It also
fits the product's existing custody story: Share 1 of the recovery key already lives
in the iCloud Keychain, so "your Apple account holds a user-controlled copy" is
established trust language, and content addressing makes a user-held mirror fully
trustless — restored bytes re-hash to the same CID, so records never need rewriting.

**Existing pieces.** The wallet's `pds_client.rs` already speaks `listBlobs` /
`getBlob` / `uploadBlob` (the migration drain uses all three); the XcodeGen template
(`scripts/ios/project.yml`) already owns the entitlements file; swift-rs bridging is
an established wallet pattern.

**Mechanism.** Three candidates on iOS:

1. **iCloud Drive ubiquity container (recommended).** Add the iCloud
   container/Documents entitlements, a small swift-rs bridge for
   `URLForUbiquityContainerIdentifier`, then plain file I/O into
   `Documents/blobs/{cid}` — iOS syncs it. User-legible sovereignty: the mirror is
   visible in the Files app. Caveats: sync is asynchronous/best-effort; restore must
   handle undownloaded placeholder files (`NSMetadataQuery`/file coordination); E2EE
   only under Advanced Data Protection (acceptable — blobs are public content, served
   unauthenticated by `getBlob`; nothing here weakens the key-custody posture).
2. **CloudKit private database.** Handles large assets fine but needs far more bridge
   surface and has no Files-app visibility. Not worth it.
3. **Ride the iOS device backup (interim, near-free).** Mirror blobs into the app's
   Documents dir without the `isExcludedFromBackup` flag. Restore only via
   whole-device restore, invisible to the user — insufficient as the feature, fine as
   a stopgap while (1) is built.

**Sync logic.** Reuse the drain's calls: paginated `listBlobs` → diff against local
CIDs → `getBlob` → **recompute the full CID from the fetched bytes (CIDv1, raw
codec, SHA-256 multihash — `blob_store::build_cid`'s exact encoding) and compare it
to the listed CID before writing** (never back up corrupt bytes — the client-side
twin of №4) → append to a manifest
(`cid, mimeType, size, fetchedAt`). Immutable content-addressed files make the sync
incremental and idempotent by construction. Start with an explicit "Back up media"
action plus an opportunistic pass on app open; background scheduling
(`BGProcessingTask`, another entitlement) can come later.

**Restore path.** Walk the manifest, `uploadBlob` each file with its stored MIME type;
CIDs recompute identically, records untouched. The migration drain should also accept
the local mirror as a *fallback blob source* when the source PDS fails `getBlob` —
turning the MM-394 blocker into a non-event for backed-up users.

**Costs and cautions.** iCloud free tier is 5 GB shared, and video-capable accounts
can be large — the feature must be opt-in with the mirror size shown (the server
already exposes per-account blob totals). Entitlement changes ride the committed
XcodeGen template and `just ios-template-check`; the browser harness needs a fake for
the ubiquity path so the surface stays scriptable off-device.

## Suggested sequencing

№2 (write durability) and №3 (scrub) are self-contained server changes with existing
patterns to copy and no new infrastructure. №1(a) needs a bucket + credentials on the
production environment (same shape as the Litestream vars) and is the highest-impact
single change. №4 rides on №3's helpers. №5 is mostly wallet-side.

The iCloud wallet backup is independent of all five and can proceed in parallel, but
the server bucket mirror still comes first: it protects every account automatically,
while the wallet mirror protects only opted-in users with the app installed and iCloud
space free. For those users — once a backup pass has completed and iCloud sync has
actually finished — there are three independent copies (volume, operator bucket,
user's iCloud) with different failure domains and different owners; everyone else has
at most the volume and the operator bucket.
