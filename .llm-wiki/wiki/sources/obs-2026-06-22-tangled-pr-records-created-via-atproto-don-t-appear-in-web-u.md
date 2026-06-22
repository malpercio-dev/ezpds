---
type: source
title: "Observation: Tangled PR records created via ATProto don't appear in web UI"
slug: obs-2026-06-22-tangled-pr-records-created-via-atproto-don-t-appear-in-web-u
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T18:32:10.348Z
tags: ["tangled", "appview", "projection"]
source_context: "Tangled PR creation test"
---
# ⭐ Observation: Tangled PR records created via ATProto don't appear in web UI
Created PR record at://did:web:malpercio.dev/sh.tangled.repo.pull/3movjglozjs2l via com.atproto.repo.createRecord with correct structure (gzipped patch in rounds[0].patchBlob). Record exists on PDS but doesn't show up in Tangled web UI. Root cause is AppView projection issue tracked at https://tangled.org/tangled.org/core/issues/576. The workaround is still to use the web form.
*Relevance: high*

*Context: Tangled PR creation test*

*Tags: tangled appview projection*
---
*Observed: 2026-06-22T18:32:10.348Z*