# Blob Handling Spec

PDS Blob Upload, Storage, Proxy & CDN

v0.1 Draft — March 2026

Companion to: Provisioning API Spec, Mobile Architecture Spec, Data Migration Spec

---

## 1. Overview

Blobs (images, video, media files) are a core part of ATProto but are handled separately from the repo. They are not stored in CAR files and have their own upload, serving, and sync endpoints. This document specifies how the PDS handles blobs across all lifecycle phases.

### 1.1 Why This Matters

Every image a user posts through Bluesky is a blob. Without blob handling, the PDS can't serve a functional PDS — users can't upload profile pictures, attach images to posts, or share media. Blob support is on the critical path alongside OAuth.

### 1.2 ATProto Blob Model

Key protocol facts that drive the design:

- Blobs are uploaded via `com.atproto.repo.uploadBlob` before any record references them.
- After upload, blobs are temporary until a record references them (then permanent).
- Unreferenced blobs are garbage-collected after a grace period (spec recommends ≥1 hour).
- Blobs are served via `com.atproto.sync.getBlob` (server-to-server) and typically mirrored to CDNs for end-user serving.
- Blobs are NOT in CAR files. They sync separately via `getBlob` and `listBlobs`.
- Each blob is identified by its CID (Content Identifier, raw multicodec, base32 `b` prefix).
- The ATProto spec does not mandate global size limits — those are per-Lexicon and per-server.

---

## 2. Lifecycle Phase Behavior

### 2.1 Mobile-Only Phase

The PDS is a full PDS. Blob handling is straightforward:

1. Third-party app uploads blob → PDS stores it.
2. App creates a record referencing the blob → blob becomes permanent.
3. AppView/CDN fetches blob via `getBlob` for serving to users.
4. If record is deleted and no other records reference the blob → blob is garbage-collected.

The PDS is the authoritative blob store. Standard PDS behavior.

### 2.2 Desktop-Enrolled Phase

Blobs need to exist in two places: the PDS (for serving to the network) and the desktop (authoritative copy). The flow changes:

**Upload path (third-party app uploads via XRPC):**

1. Bluesky calls `uploadBlob` on the PDS (the public XRPC endpoint).
2. PDS stores the blob locally and assigns a temporary CID.
3. When the app creates a record referencing the blob, the PDS proxies the record-creation to the desktop (per mobile spec §4.2).
4. The PDS forwards the blob data to the desktop via Iroh alongside the record data.
5. Desktop stores the blob locally as the authoritative copy.
6. PDS retains its copy as a cache for serving.

**Upload path (desktop creates content locally — future):**

If/when the desktop supports local content creation (e.g., a local client):

1. Desktop stores the blob locally.
2. Desktop pushes the blob to the PDS via Iroh (alongside the unsigned commit).
3. PDS stores and serves the blob.

**Read path:**

1. `getBlob` requests hit the PDS.
2. PDS serves from its local cache.
3. If cache miss (blob was garbage-collected from PDS but exists on desktop), PDS fetches from desktop via Iroh and re-caches.

### 2.3 Desktop Offline (During Desktop-Enrolled)

- Reads: PDS serves blobs from cache. Previously-uploaded blobs remain available.
- Writes: not applicable — write XRPC returns 503 when desktop is offline, so no new blobs can be uploaded.
- Cache miss: if a `getBlob` request arrives for a blob not in the PDS's cache while the desktop is offline, PDS returns 404. This should be rare if the PDS's cache TTL is reasonable.

---

## 3. Rust Implementation Stack

### 3.1 Existing Reference: rsky-pds

The `blacksky-algorithms/rsky` project includes a full Rust PDS implementation (`rsky-pds`) that already handles blob upload, storage, and serving with S3-compatible backends. This is our primary reference for blob implementation patterns.

Repo: https://github.com/blacksky-algorithms/rsky

### 3.2 Recommended Crates

| Crate | Version | Purpose | Downloads/mo |
|-------|---------|---------|-------------|
| **rust-s3** | 0.37.0+ | S3-compatible object storage (R2, MinIO, S3) | ~357K |
| **cid** | 0.11.1+ | Content Identifier generation/parsing (ATProto blob refs) | ~13.7M all-time |
| **opendal** | 0.55.0+ | Alternative: unified storage abstraction (Apache project) | — |

**rust-s3 vs opendal vs aws-sdk-s3:**

- **rust-s3** is the pragmatic choice — lightweight, supports async and sync, well-tested with R2 and MinIO. Lower dependency footprint than the official AWS SDK.
- **opendal** (Apache OpenDAL) provides a unified API across storage backends. Heavier abstraction but lets you swap from local filesystem → S3 → R2 → MinIO without code changes. Worth considering if we want backend flexibility from the start.
- **aws-sdk-s3** is the official AWS SDK. Excellent maintenance but heavyweight (~100+ transitive deps) and async-only (Tokio). Overkill if R2 or MinIO is the primary target.

**Recommendation:** Start with **rust-s3** for v0.1 (lowest friction). Evaluate migrating to **opendal** for v1.0 if multi-backend support becomes important. Use the **cid** crate for all CID operations — it's the standard multiformats implementation used across the IPFS/content-addressing ecosystem.

### 3.3 MIME Type Sniffing

For validating blob content types, use the `infer` crate (https://crates.io/crates/infer) — it detects file type from magic bytes without external dependencies. Lightweight and widely used (~5M downloads).

---

## 4. Storage Architecture

### 4.1 PDS Storage

Blob data lives in S3-compatible object storage. Blob metadata lives in the PDS's database (SQLite for single-node, PostgreSQL for production).

**Blob metadata table:**

| Column | Type | Description |
|--------|------|-------------|
| cid | TEXT PK | Content identifier (base32, `b` prefix) |
| account_id | TEXT FK | Owning account |
| mime_type | TEXT | MIME type (validated via sniffing) |
| size_bytes | INTEGER | Blob size |
| status | TEXT | `temporary` / `permanent` / `pending_gc` |
| uploaded_at | TEXT | ISO 8601 |
| referenced_at | TEXT | When first referenced by a record (null if temporary) |
| last_accessed_at | TEXT | For cache eviction decisions |
| storage_backend | TEXT | `local` / `s3` — where the blob data lives |

**Object storage key format:**

`{bucket}/{account_id}/{cid[0:2]}/{cid[2:4]}/{cid}`

The two-level prefix hash prevents S3 listing performance issues with large flat namespaces. The CID is the filename — content-addressed storage is naturally deduplicated.

**Backend configuration (pds.toml):**

```toml
[blobs]
backend = "s3"  # "local" for dev, "s3" for production

[blobs.s3]
endpoint = "https://account-id.r2.cloudflarestorage.com"  # R2, MinIO, S3
bucket = "pds-blobs"
region = "auto"  # R2 uses "auto"
access_key = "..."
secret_key = "..."
```

For local development, blobs fall back to filesystem storage at `{data_dir}/blobs/` using the same key structure. The `storage_backend` column in the metadata table lets the PDS serve blobs from either backend during migration.

### 4.2 S3-Compatible Providers

Tested/supported providers:

| Provider | Notes |
|----------|-------|
| **Cloudflare R2** | No egress fees. Native CDN integration via Workers. Recommended for production. |
| **MinIO** | Self-hosted S3. Ideal for BYO PDS operators. Ships as a single binary. |
| **AWS S3** | Standard. Higher egress costs than R2. |
| **Backblaze B2** | Cheap storage, S3-compatible API. |

BYO PDS operators who don't want to run object storage can use `backend = "local"` — blobs stay on the local filesystem. This is the default for the open-source PDS binary.

### 4.3 Desktop Storage

The desktop PDS stores blobs in its local filesystem, indexed in its local SQLite. The desktop is the authoritative copy when enrolled. No S3 dependency on the desktop — blob data stays local.

### 4.4 Storage Migration Path

v0.1 (dev/beta): `backend = "local"` — filesystem only, no S3 dependency.
v1.0 (production): `backend = "s3"` — R2 or MinIO. A migration tool copies existing local blobs to the S3 bucket and updates the `storage_backend` column.

---

## 4. XRPC Endpoints

The PDS must implement these standard ATProto endpoints:

### 4.1 com.atproto.repo.uploadBlob

**Method:** POST
**Auth:** Required (OAuth bearer token)
**Request:** Raw binary body with `Content-Type` header
**Response:**
```json
{
  "$type": "blob",
  "ref": {"$link": "bafkrei..."},
  "mimeType": "image/jpeg",
  "size": 54499
}
```

**PDS behavior:**
1. Validate MIME type (sniff bytes if needed, reject disallowed types).
2. Check account storage quota.
3. Store blob with `status: temporary`.
4. Return blob reference.
5. In desktop-enrolled mode: also forward blob to desktop via Iroh (can be async, before record creation).

### 4.2 com.atproto.sync.getBlob

**Method:** GET
**Params:** `did` (string), `cid` (string)
**Response:** Raw blob data with appropriate `Content-Type`

**PDS behavior:**
1. Look up blob in local cache.
2. If found, serve directly.
3. If not found and desktop is online, fetch from desktop via Iroh, re-cache, serve.
4. If not found and desktop is offline, return 404.

**Security:** Must set Content Security Policy headers. Blobs are untrusted user content — serving them without CSP is a parsing vulnerability risk.

### 4.3 com.atproto.sync.listBlobs

**Method:** GET
**Params:** `did` (string), `since` (string, optional — repo revision)
**Response:** Array of blob CIDs

Lists all committed (permanent) blobs for an account, optionally since a given revision. Used by AppViews and relays for synchronization.

---

## 5. Size Limits & Quotas

### 5.1 Per-Blob Limits

ATProto doesn't mandate global limits, but the PDS should enforce sensible defaults:

| Tier | Max blob size | Rationale |
|------|--------------|-----------|
| Free | 5 MB | Covers images, short audio. Matches common PDS limits. |
| Pro | 50 MB | Covers video, large media. |
| Business | 100 MB | Enterprise media needs. |

These limits apply at upload time. Lexicon-specific limits (e.g., Bluesky's 1 MB for images) are enforced at record creation time.

### 5.2 Per-Account Storage Quotas

Blob storage counts toward the account's total storage quota (defined in provisioning API §8):

| Tier | Total storage (repo + blobs) |
|------|------------------------------|
| Free | 500 MB |
| Pro | 50 GB |
| Business | 500 GB |

When an account exceeds its quota, `uploadBlob` returns 413 (Payload Too Large) with a `STORAGE_EXCEEDED` error code.

### 5.3 MIME Type Restrictions

The PDS should accept a generous allowlist and reject known-dangerous types:

**Allowed:** `image/*`, `video/*`, `audio/*`, `application/pdf`, `text/plain`, `application/octet-stream`

**Blocked:** Executable types (`application/x-executable`, `application/x-mach-binary`, `application/javascript`, etc.), archive types that could contain executables (`.zip`, `.tar.gz` unless explicitly needed by a Lexicon).

The PDS should sniff blob bytes to validate the declared MIME type and reject mismatches (e.g., a blob declared as `image/jpeg` that's actually a PE executable).

---

## 6. Garbage Collection

### 6.1 Temporary Blob Cleanup

Blobs uploaded but never referenced by a record are garbage-collected:

- **Grace period:** 6 hours (ATProto spec recommends ≥1 hour; 6 hours gives apps plenty of time).
- **Check frequency:** Every 30 minutes, a background job scans for temporary blobs past the grace period.
- **Action:** Delete blob data and metadata row.

### 6.2 Dereferenced Blob Cleanup

When a record is deleted, check if any other records in the same repo reference the blob's CID:

- If no references remain → mark blob as `pending_gc`.
- Run a second check after 24 hours (in case a new record references it).
- If still unreferenced → delete.

### 6.3 Account Deletion Cleanup

On account teardown (provisioning API §7), all blobs are deleted:

- During grace period: blobs are retained (account is read-only).
- After grace period: bulk-delete all blobs for the account.

### 6.4 PDS Cache Eviction (Desktop-Enrolled)

When the desktop is the authoritative blob store, the PDS's copy is a cache. Eviction strategy:

- **LRU eviction** when PDS storage exceeds a per-account cache limit.
- Cache limit per tier: Free = 100 MB, Pro = 5 GB, Business = 50 GB.
- Evicted blobs can be re-fetched from the desktop on demand (via `getBlob` → Iroh → desktop).
- Never evict blobs that are less than 7 days old (matches commit buffer retention).

---

## 7. CDN Integration

### 7.1 Why CDN

The ATProto spec recommends that AppViews mirror blobs to their own CDN rather than hitting `getBlob` directly. But for a desktop PDS that goes offline, having a PDS-side CDN cache prevents blob unavailability.

### 7.2 Architecture

For Pro and Business tiers, the PDS can optionally front blob serving with a CDN (Cloudflare R2 + Workers, or similar):

```
[AppView] → CDN → [PDS getBlob] → (cache or Iroh → desktop)
```

The CDN caches public blob responses with appropriate cache headers. This reduces load on the PDS and ensures blobs remain available even during brief PDS restarts.

### 7.3 Cache Headers

`getBlob` responses should include:
- `Cache-Control: public, max-age=31536000, immutable` — blobs are content-addressed, so they never change.
- `Content-Type`: the validated MIME type.
- `Content-Security-Policy: default-src 'none'; sandbox` — prevent blob content from executing.

The `immutable` directive is safe because CIDs are content hashes — if the content changed, the CID would change.

---

## 8. Data Migration Implications

### 8.1 Planned Device Swap

During a planned swap (migration spec §3), the blob archive is included in the transfer bundle:

1. Old device exports blobs alongside the CAR file.
2. Bundle includes a blob manifest mapping CIDs → MIME types → sizes.
3. New device imports blobs and verifies CIDs match.

### 8.2 Unplanned Device Loss

On the free tier, blobs not crawled by an AppView may be permanently lost (migration spec §4.3). The PDS's cache retention helps:

- **Paid tiers:** PDS holds a full blob mirror. All blobs recoverable from PDS.
- **Free tier:** PDS holds only recently-accessed blobs (cache eviction). Older blobs attempted via `getBlob` against known AppView CDNs. Blobs never crawled are lost.

### 8.3 Proactive Crawl

After every blob upload, the PDS should call `requestCrawl` to the configured AppView. This maximizes the chance that blobs are indexed before any loss event. Already noted in the migration spec (§4.3) but important to implement at the PDS level.

---

## 9. Implementation Milestones

### v0.1 — Basic Blob Support (blocks mobile-only phase)

- `uploadBlob` endpoint with local filesystem storage
- `getBlob` endpoint for serving
- `listBlobs` endpoint
- CID generation/validation via `cid` crate
- Temporary blob garbage collection (6-hour grace)
- MIME type validation via `infer` crate
- Per-blob size limits
- Account storage quota enforcement
- `requestCrawl` after record creation with blob references
- S3 backend support via `rust-s3` (optional, configurable — local is default)

### v1.0 — Production Blobs

- S3 backend as default for managed PDS (R2 recommended)
- Local → S3 migration tool
- Dereferenced blob cleanup
- CDN integration for Pro/Business tiers (R2 + Workers or equivalent)
- Cache eviction for desktop-enrolled accounts
- Blob forwarding to desktop via Iroh on upload
- Desktop → PDS blob fetch on cache miss
- Blob manifest in device transfer bundle
- MinIO deployment docs for BYO PDS operators

### Later

- Video transcoding (serve multiple resolutions)
- Blob deduplication across accounts (content-addressed storage makes this natural)
- Blob access analytics (which blobs are hot/cold for cache optimization)

---

## 10. Design Decisions

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| rust-s3 crate for S3 operations | Lightweight, async/sync flexible, well-tested with R2 and MinIO. 357K downloads/month. Lower deps than aws-sdk-s3. | aws-sdk-s3 (heavyweight, 100+ deps), opendal (heavier abstraction, may adopt later). |
| S3-compatible object storage for blob data | Blobs are large, write-once, and content-addressed — a perfect fit for object storage. R2 has no egress fees. MinIO works for self-hosted. | Local filesystem only (doesn't scale, no redundancy), database BLOBs (terrible performance at scale). |
| Local filesystem as default, S3 as production option | BYO PDS operators shouldn't need to run MinIO for a small instance. Local works fine for single-user. S3 for managed PDS at scale. | S3 required from day one (barrier to self-hosting), local only (no production path). |
| Cloudflare R2 as recommended provider | Zero egress fees (biggest cost for blob serving). Native CDN via Workers. S3-compatible API. | AWS S3 (egress costs add up), Backblaze B2 (less ecosystem integration). |
| 6-hour temp blob grace period | 6x the ATProto minimum. Generous for apps with slow record creation. Low storage cost. | 1 hour (spec minimum — too aggressive), 24 hours (unnecessary). |
| MIME type sniffing via infer crate | Prevents content-type spoofing. No external deps. Critical for security — a mislabeled executable served as an image is dangerous. | Trust client Content-Type (unsafe), reject without sniffing (too strict). |
| CDN with immutable cache headers | Blobs are content-addressed — the CID changes if content changes. Immutable caching is safe and eliminates invalidation complexity. | Short TTL caching (wastes CDN bandwidth), no CDN (higher PDS load). |
| PDS caches blobs in desktop-enrolled mode | Ensures blobs are served when desktop is offline. `getBlob` from AppViews needs to work 24/7. | No PDS cache (blobs unavailable when desktop sleeps — breaks federation), desktop-only (same problem). |
| Reference rsky-pds for implementation patterns | Production Rust PDS with S3 blob storage already implemented. Don't reinvent. | Build from scratch (slower, more bugs), fork rsky-pds (too coupled). |
