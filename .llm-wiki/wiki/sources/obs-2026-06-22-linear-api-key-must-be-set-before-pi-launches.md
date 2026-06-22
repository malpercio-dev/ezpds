---
type: source
title: "Observation: LINEAR_API_KEY must be set before pi launches"
slug: obs-2026-06-22-linear-api-key-must-be-set-before-pi-launches
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: medium
observed_at: 2026-06-22T18:58:13.103Z
tags: ["linear", "extension", "environment"]
source_context: "Linear extension debugging"
---
# 🔍 Observation: LINEAR_API_KEY must be set before pi launches
Linear extension requires LINEAR_API_KEY in environment before pi session starts. Mid-session export doesn't activate tools. Workaround: use curl with Linear GraphQL API directly. Extension path: .pi/extensions/linear/index.ts.
*Relevance: medium*

*Context: Linear extension debugging*

*Tags: linear extension environment*
---
*Observed: 2026-06-22T18:58:13.103Z*