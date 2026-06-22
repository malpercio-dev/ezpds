---
type: source
title: "Observation: Two-pass review: code quality then adversarial"
slug: obs-2026-06-22-two-pass-review-code-quality-then-adversarial
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T02:23:47.129Z
tags: ["review", "workflow", "adversarial", "pr", "process"]
source_context: "MM-107/MM-108 blob storage PR review cycle"
---
# ⭐ Observation: Two-pass review: code quality then adversarial
PR reviews should use two distinct passes. Pass 1 (code quality): dead code, stale comments, unused imports, missing tests, API shape matches spec, error variants used, status_code_mapping entries. Pass 2 (adversarial): TOCTOU races, idempotency, resource exhaustion, crash orphans, assert vs debug_assert, known-answer tests, edge cases, path traversal, MIME spoofing. All findings must be fixed before merge. This pattern emerged from the MM-107/MM-108 blob storage PR where pass 1 found 4 issues and pass 2 found 10 more.
*Relevance: high*

*Context: MM-107/MM-108 blob storage PR review cycle*

*Tags: review workflow adversarial pr process*
---
*Observed: 2026-06-22T02:23:47.129Z*