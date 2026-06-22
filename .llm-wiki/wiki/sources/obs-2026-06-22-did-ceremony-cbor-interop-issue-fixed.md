---
type: source
title: "Observation: DID ceremony CBOR interop issue fixed"
slug: obs-2026-06-22-did-ceremony-cbor-interop-issue-fixed
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T17:36:38.536Z
tags: ["atproto", "did-plc", "crypto", "fix"]
source_context: "Fixing ATProto extension DID ceremony"
---
# ⭐ Observation: DID ceremony CBOR interop issue fixed
Fixed the DID:plc CBOR interop issue in the ATProto extension. The problem was not with CBOR encoding (dag-cbor was fine) but with the ECDSA signature format. Node.js crypto produces DER-encoded signatures that are incompatible with plc.directory. Switched to using the official @atproto/crypto library (P256Keypair) which produces raw 64-byte signatures that work correctly. All 9 ATProto extension tools now functional.
*Relevance: high*

*Context: Fixing ATProto extension DID ceremony*

*Tags: atproto did-plc crypto fix*
---
*Observed: 2026-06-22T17:36:38.536Z*