---
type: source
title: "Observation: ATProto extension updated with deleteRecord and listBlobs tools"
slug: obs-2026-06-23-atproto-extension-updated-with-deleterecord-and-listblobs-to
status: observation
created: 2026-06-23
updated: 2026-06-23
relevance: high
observed_at: 2026-06-23T13:36:16.559Z
tags: ["atproto", "extension", "relay", "sync"]
source_context: "Syncing ATProto pi extension with relay account creation refactor"
---
# ⭐ Observation: ATProto extension updated with deleteRecord and listBlobs tools
Updated .pi/extensions/atproto/index.ts to sync with relay changes: fixed putRecord to use POST (was PUT), added atproto_delete_record tool for POST /xrpc/com.atproto.repo.deleteRecord, added atproto_list_blobs tool for GET /xrpc/com.atproto.sync.listBlobs, and updated prompt guidelines to document ATProto data model handling ($link for CID links, $bytes for byte strings, float rejection).
*Relevance: high*

*Context: Syncing ATProto pi extension with relay account creation refactor*

*Tags: atproto extension relay sync*
---
*Observed: 2026-06-23T13:36:16.559Z*