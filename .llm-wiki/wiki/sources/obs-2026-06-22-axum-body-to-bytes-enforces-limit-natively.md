---
type: source
title: "Observation: axum::body::to_bytes enforces limit natively"
slug: obs-2026-06-22-axum-body-to-bytes-enforces-limit-natively
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T02:12:51.346Z
tags: ["axum", "body", "limit", "review-finding"]
source_context: "PR review fix — oversize body handling in upload_blob"
---
# ⭐ Observation: axum::body::to_bytes enforces limit natively
In axum 0.7, `axum::body::to_bytes(body, limit)` takes a limit parameter and returns an error if the body exceeds it. Do not add redundant post-read size checks — they're dead code. Map the to_bytes error directly to PayloadTooLarge. For additional defense, check Content-Length header before reading.
*Relevance: high*

*Context: PR review fix — oversize body handling in upload_blob*

*Tags: axum body limit review-finding*
---
*Observed: 2026-06-22T02:12:51.346Z*