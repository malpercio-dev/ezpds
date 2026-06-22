---
type: source
title: "Observation: MM-110 listBlobs endpoint implemented"
slug: obs-2026-06-22-mm-110-listblobs-endpoint-implemented
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T19:49:43.315Z
tags: ["ezpds", "wave4", "blobs", "api"]
source_context: "Completing Wave 4 of ezpds project"
---
# ⭐ Observation: MM-110 listBlobs endpoint implemented
Implemented com.atproto.sync.listBlobs endpoint for ezpds. DB function list_blob_cids() in db/blobs.rs uses limit+1 pagination pattern. Route handler in routes/list_blobs.rs trims the extra item and returns cursor. Cursor-based pagination uses CID lexicographic ordering. Limit clamped to 1-2000. All 558 tests pass. Wave 4 (Repo + Blobs) now complete: MM-107, MM-108, MM-109, MM-110 all done.
*Relevance: high*

*Context: Completing Wave 4 of ezpds project*

*Tags: ezpds wave4 blobs api*
---
*Observed: 2026-06-22T19:49:43.315Z*