---
type: source
title: "Observation: Linear API key required for extension tools"
slug: obs-2026-06-22-linear-api-key-required-for-extension-tools
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: medium
observed_at: 2026-06-22T17:13:52.960Z
tags: ["linear", "extension", "environment", "setup"]
source_context: "Creating MM-181 for handle/alsoKnownAs bug"
---
# 🔍 Observation: Linear API key required for extension tools
Linear extension at .pi/extensions/linear/index.ts registers 9 tools but only loads them if LINEAR_API_KEY is set at session start. The key must be in the environment before pi launches — mid-session export won't help. Team key is MM (Mal's Machinations).
*Relevance: medium*

*Context: Creating MM-181 for handle/alsoKnownAs bug*

*Tags: linear extension environment setup*
---
*Observed: 2026-06-22T17:13:52.960Z*