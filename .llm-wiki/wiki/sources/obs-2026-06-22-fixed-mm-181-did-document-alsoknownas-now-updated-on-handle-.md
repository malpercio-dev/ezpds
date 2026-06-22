---
type: source
title: "Observation: Fixed MM-181: DID document alsoKnownAs now updated on handle changes"
slug: obs-2026-06-22-fixed-mm-181-did-document-alsoknownas-now-updated-on-handle-
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T18:01:54.118Z
tags: ["did", "handle", "fix", "alsoKnownAs"]
source_context: "MM-181 fix implementation"
---
# ⭐ Observation: Fixed MM-181: DID document alsoKnownAs now updated on handle changes
Fixed MM-181 by adding update_also_known_as() to crates/relay/src/db/dids.rs and calling it from both create_handle_handler and delete_handle_handler. The function fetches the current DID document, updates the alsoKnownAs array with all current handles (as at:// URIs), and writes it back. Local cache only — PLC directory update for did:plc DIDs is a separate task.
*Relevance: high*

*Context: MM-181 fix implementation*

*Tags: did handle fix alsoKnownAs*
---
*Observed: 2026-06-22T18:01:54.118Z*