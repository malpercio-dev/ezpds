---
type: source
title: "Observation: Blob storage CID implementation details"
slug: obs-2026-06-22-blob-storage-cid-implementation-details
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: medium
observed_at: 2026-06-22T01:54:50.117Z
tags: ["blob-storage", "cid", "sha256", "infer", "mime"]
source_context: "MM-107 blob storage backend implementation"
---
# 🔍 Observation: Blob storage CID implementation details
CIDv1 for blob content addressing: raw codec (0x55) + SHA-256 multihash (0x12, 0x20), base32-encoded with `bafk` prefix. Binary layout: [0x01, 0x55, 0x12, 0x20, <32-byte hash>]. Storage path uses 2-char prefix fanout: `blobs/{cid[0:2]}/{cid}`. The `infer` crate detects MIME from magic bytes; falls back to `application/octet-stream` for unrecognized content (plain text, etc.).
*Relevance: medium*

*Context: MM-107 blob storage backend implementation*

*Tags: blob-storage cid sha256 infer mime*
---
*Observed: 2026-06-22T01:54:50.117Z*