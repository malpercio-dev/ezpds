---
type: source
title: "Observation: ATProto extension updated with per-account signing key flow"
slug: obs-2026-06-23-atproto-extension-updated-with-per-account-signing-key-flow
status: observation
created: 2026-06-23
updated: 2026-06-23
relevance: critical
observed_at: 2026-06-23T13:40:40.379Z
tags: ["atproto", "extension", "provisioning", "signing-key"]
source_context: "Syncing ATProto pi extension with per-account signing key flow"
---
# 🔴 Observation: ATProto extension updated with per-account signing key flow
Updated .pi/extensions/atproto/index.ts to match the per-account repo signing key provisioning flow. Added atproto_get_repo_signing_key tool (GET /v1/repo-signing-key) which must be called after create_mobile_account and before complete_did_ceremony. The DID ceremony now automatically fetches the relay-issued key and uses it as rotationKeys[1] + verificationMethods.atproto, while the device key remains rotationKeys[0] and signs the op. The atproto_create_full_account tool also includes this step. The relay verifies the op's verificationMethods.atproto matches the issued key.
*Relevance: critical*

*Context: Syncing ATProto pi extension with per-account signing key flow*

*Tags: atproto extension provisioning signing-key*
---
*Observed: 2026-06-23T13:40:40.379Z*