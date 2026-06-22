---
type: source
title: "Observation: BlobsConfig was empty stub, now has max_blob_size"
slug: obs-2026-06-22-blobsconfig-was-empty-stub-now-has-max-blob-size
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: medium
observed_at: 2026-06-22T01:54:50.119Z
tags: ["config", "blobs", "common"]
source_context: "MM-108 uploadBlob — needed configurable size limit"
---
# 🔍 Observation: BlobsConfig was empty stub, now has max_blob_size
BlobsConfig in crates/common/src/config.rs was an empty `pub struct BlobsConfig {}` stub. Added `max_blob_size: u64` field (default 50 MiB) for uploadBlob size enforcement. Default is computed via `default_max_blob_size()` function. The struct now implements Default manually instead of deriving it.
*Relevance: medium*

*Context: MM-108 uploadBlob — needed configurable size limit*

*Tags: config blobs common*
---
*Observed: 2026-06-22T01:54:50.119Z*