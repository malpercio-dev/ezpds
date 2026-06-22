---
type: source
title: "Observation: ATProto extension created for pi"
slug: obs-2026-06-22-atproto-extension-created-for-pi
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T17:27:32.853Z
tags: ["atproto", "extension", "pi", "did-plc"]
source_context: "Building ATProto extension for pi"
---
# ⭐ Observation: ATProto extension created for pi
Created .pi/extensions/atproto/ with tools for ezpds provisioning relay: atproto_create_claim_code, atproto_create_mobile_account, atproto_complete_did_ceremony, atproto_create_full_account, atproto_create_session, atproto_register_handle, atproto_xrpc, atproto_describe_server, atproto_generate_keypair. Requires EZPDS_BASE_URL and optionally EZPDS_ADMIN_TOKEN env vars. DID ceremony has a CBOR interop issue with plc.directory signature verification - the TypeScript @ipld/dag-cbor produces different encoding than Rust ciborium.
*Relevance: high*

*Context: Building ATProto extension for pi*

*Tags: atproto extension pi did-plc*
---
*Observed: 2026-06-22T17:27:32.853Z*