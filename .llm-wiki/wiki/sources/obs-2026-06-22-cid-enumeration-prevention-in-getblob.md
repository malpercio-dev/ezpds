---
type: source
title: "Observation: CID enumeration prevention in getBlob"
slug: obs-2026-06-22-cid-enumeration-prevention-in-getblob
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T19:32:05.360Z
tags: ["security", "atpro", "xrpc", "blob", "enumeration"]
source_context: "MM-109 getBlob implementation, PR feat/sync-get-blob"
---
# ⭐ Observation: CID enumeration prevention in getBlob
When implementing com.atproto.sync.getBlob, original design returned distinct HTTP status codes for "blob not found" (404) vs "blob exists but wrong DID" (400). This would allow unauthenticated attackers to probe CID existence. Fixed by returning identical 404 "blob not found" for both cases, with no CID or DID in the error message. Pattern: read endpoints that scope access by identity should not distinguish "not found" from "forbidden" — both should return 404 with generic messages.
*Relevance: high*

*Context: MM-109 getBlob implementation, PR feat/sync-get-blob*

*Tags: security atpro xrpc blob enumeration*
---
*Observed: 2026-06-22T19:32:05.360Z*