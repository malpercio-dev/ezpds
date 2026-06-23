---
type: source
title: "Observation: ATProto extension fully tested after per-account signing key refactor"
slug: obs-2026-06-23-atproto-extension-fully-tested-after-per-account-signing-key
status: observation
created: 2026-06-23
updated: 2026-06-23
relevance: critical
observed_at: 2026-06-23T14:11:50.978Z
tags: ["atproto", "extension", "testing", "provisioning"]
source_context: "End-to-end testing of ATProto pi extension after refactor"
---
# 🔴 Observation: ATProto extension fully tested after per-account signing key refactor
All 12 ATProto extension tools verified working against staging relay after the per-account signing key refactor. The full provisioning flow (claim code → mobile account → repo signing key → DID ceremony) completes successfully. Record CRUD (put/get/delete) and repo export all functional. Three bugs fixed during testing: putRecord was using PUT instead of POST, generateP256KeypairRaw wasn't exporting private key bytes, and create_mobile_account/create_full_account were calling generateP256Keypair instead of generateP256KeypairRaw.
*Relevance: critical*

*Context: End-to-end testing of ATProto pi extension after refactor*

*Tags: atproto extension testing provisioning*
---
*Observed: 2026-06-23T14:11:50.978Z*