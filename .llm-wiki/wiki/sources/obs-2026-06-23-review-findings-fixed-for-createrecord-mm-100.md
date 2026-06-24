---
type: source
title: "Observation: Review findings fixed for createRecord (MM-100)"
slug: obs-2026-06-23-review-findings-fixed-for-createrecord-mm-100
status: observation
created: 2026-06-23
updated: 2026-06-23
relevance: high
observed_at: 2026-06-23T17:31:30.932Z
tags: ["review", "fix", "create-record", "refactor", "shared-helper"]
source_context: "Fixing PR review findings for MM-100 createRecord"
---
# ⭐ Observation: Review findings fixed for createRecord (MM-100)
Fixed all 6 review findings for PR #27 (createRecord): 1) HIGH: Added existence check to reject duplicate rkeys with 409 Conflict. 2) MEDIUM: Bruno example no longer sends empty rkey; handler normalizes empty to None. 3) MEDIUM: Moved load_repo_signer to auth/signing_key.rs and gc_repo_blocks to record_write.rs to eliminate cross-route imports. 4) MEDIUM: Created shared record_write::write_record helper reducing create_record.rs from 522 to 170 lines. 5) LOW: Moved generate_tid to repo-engine (Functional Core). 6) Minor: Fixed TID doc comment bit ranges. All 22 tests pass. Pushed to feat/create-record.
*Relevance: high*

*Context: Fixing PR review findings for MM-100 createRecord*

*Tags: review fix create-record refactor shared-helper*
---
*Observed: 2026-06-23T17:31:30.932Z*