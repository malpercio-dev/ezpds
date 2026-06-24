---
type: source
title: "Observation: ATProto extension updated with createRecord tool"
slug: obs-2026-06-24-atproto-extension-updated-with-createrecord-tool
status: observation
created: 2026-06-24
updated: 2026-06-24
relevance: medium
observed_at: 2026-06-24T02:18:06.367Z
tags: ["extension", "atproto", "create-record", "tool"]
source_context: "Adding createRecord tool to ATProto extension"
---
# 🔍 Observation: ATProto extension updated with createRecord tool
Added `atproto_create_record` tool to .pi/extensions/atproto/index.ts. Uses POST to /xrpc/com.atproto.repo.createRecord with JSON body. Supports optional rkey (auto-generates TID if omitted/empty). Rejects duplicate rkeys with 409 Conflict per the ATProto spec. Placed before put_record in the tool list. Staging URL: https://ezpds-staging.up.railway.app
*Relevance: medium*

*Context: Adding createRecord tool to ATProto extension*

*Tags: extension atproto create-record tool*
---
*Observed: 2026-06-24T02:18:06.367Z*