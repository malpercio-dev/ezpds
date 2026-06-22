---
type: source
title: "Blob storage implementation pitfalls"
slug: blob-storage-pitfalls
status: insight
created: 2026-06-22
updated: 2026-06-22
category: architecture
---
# Blob storage implementation pitfalls
Key pitfalls discovered while implementing [[concepts/ezpds-workspace|ezpds]] blob storage (MM-107, MM-108):

## axum body limits
`axum::body::to_bytes(body, limit)` already enforces the limit — do not add redundant post-read size checks. Map its error directly to `PayloadTooLarge`. For defense-in-depth, also check the `Content-Length` header before reading.

## Content-addressable idempotency
`store_blob` computes a CID from content. If two users upload identical content, the CID is the same. The `INSERT INTO blobs` must use `ON CONFLICT(cid) DO UPDATE` — a bare INSERT panics the handler on the second upload.

## TOCTOU in filesystem cleanup
`exists()` then `remove_file()` is a race. Prefer `remove_file()` directly and match on `ErrorKind::NotFound`.

## MIME detection fallback
`infer::get()` returns `None` for content without magic bytes (plain text, small files). Always fall back to `application/octet-stream`.

## assert vs debug_assert
`build_cid` used `assert_eq!` on hash length. Since SHA-256 always produces 32 bytes, this never triggers — but if it did, the server would panic. Use `debug_assert_eq!` in library code.
*Category: architecture*
---
*Captured: 2026-06-22*
## Related
_Add links to related pages._