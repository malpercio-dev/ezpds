---
type: source
title: "Observation: accounts table uses DID as TEXT primary key"
slug: obs-2026-06-22-accounts-table-uses-did-as-text-primary-key
status: observation
created: 2026-06-22
updated: 2026-06-22
relevance: high
observed_at: 2026-06-22T01:54:50.118Z
tags: ["database", "schema", "accounts", "fk"]
source_context: "MM-107 blob migration — initial V015 used integer account_id, had to fix to TEXT account_did"
---
# ⭐ Observation: accounts table uses DID as TEXT primary key
The `accounts` table uses `did` (TEXT) as its primary key — there is no integer `id` column. V008 rebuilt the table to make `password_hash` nullable (for mobile-provisioned accounts). FK references from other tables (like `blobs.account_did`) must use `TEXT REFERENCES accounts(did)`, not integer IDs.
*Relevance: high*

*Context: MM-107 blob migration — initial V015 used integer account_id, had to fix to TEXT account_did*

*Tags: database schema accounts fk*
---
*Observed: 2026-06-22T01:54:50.118Z*