---
type: source
title: "Observation: SQLite sessions.db keeps corrupting"
slug: obs-2026-06-22-sqlite-sessions-db-keeps-corrupting
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: medium
observed_at: 2026-06-22T18:58:13.103Z
tags: ["sqlite", "corruption", "pi-hermes-memory"]
source_context: "SQLite corruption recovery"
---
# 🔍 Observation: SQLite sessions.db keeps corrupting
pi-hermes-memory sessions.db at ~/.pi/agent/pi-hermes-memory/sessions.db corrupted twice during this session (tree page issues, out-of-order rowids, wrong index counts). User decided to delete and let pi recreate fresh rather than keep recovering. Root cause unknown — may be concurrent writes or WAL issues.
*Relevance: medium*

*Context: SQLite corruption recovery*

*Tags: sqlite corruption pi-hermes-memory*
---
*Observed: 2026-06-22T18:58:13.103Z*