---
type: source
title: "Observation: ATProto pi extension fully functional"
slug: obs-2026-06-22-atproto-pi-extension-fully-functional
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T17:47:54.278Z
tags: ["atproto", "extension", "did:plc", "crypto"]
source_context: "ATProto extension development"
---
# ⭐ Observation: ATProto pi extension fully functional
ATProto pi extension at .pi/extensions/atproto/index.ts now works end-to-end. Fixed publicKeyBytes() method call. Tested atproto_create_full_account against staging ezpds: creates claim code, mobile account, performs DID ceremony via @atproto/crypto P256Keypair, registers handle, and returns session tokens + Shamir shares. DID created: did:plc:jswfuuz725zgjkk2dg4weun7 on staging.
*Relevance: high*

*Context: ATProto extension development*

*Tags: atproto extension did:plc crypto*
---
*Observed: 2026-06-22T17:47:54.278Z*