---
type: source
title: "Observation: Linear extension search root-cause fixed"
slug: obs-2026-06-22-linear-extension-search-root-cause-fixed
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T20:09:49.523Z
tags: ["pi-extension", "linear", "tooling", "reliability"]
source_context: "Harness reliability review of recent session history"
---
# ⭐ Observation: Linear extension search root-cause fixed
Fixed the long-standing "linear_search_issues misses Backlog issues" problem in .pi/extensions/linear/index.ts. Root cause: linear_search_issues fetched only the 20-50 most-recently-updated issues via the `issues` query, then filtered client-side — so older Backlog issues fell outside the window and returned "No issues found". Fix: switched to Linear's server-side full-text `searchIssues(term:, first:, filter:)` GraphQL query. Also added a `label` filter to linear_list_issues (`labels: { name: { eq: ... } }`) and raised its default limit from 30 to 50, so wave/label scans (e.g. "all Wave 4 issues") are a single exhaustive query. Updated the ezpds-linear-pr-workflow skill Pick step + pitfall accordingly. NOTE: extension changes require a pi restart/reload to take effect.
*Relevance: high*

*Context: Harness reliability review of recent session history*

*Tags: pi-extension linear tooling reliability*
---
*Observed: 2026-06-22T20:09:49.523Z*