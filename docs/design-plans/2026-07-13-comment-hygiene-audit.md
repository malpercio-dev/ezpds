# Comment Hygiene Audit

Status: **planned** — captured from the 2026-07-13 codebase review.
Tracked in Linear: [MM-337](https://linear.app/malpercio/issue/MM-337) (ticket/AC/Phase refs),
[MM-338](https://linear.app/malpercio/issue/MM-338) (temporal narration),
[MM-339](https://linear.app/malpercio/issue/MM-339) (stale comments),
[MM-340](https://linear.app/malpercio/issue/MM-340) (narrate-the-obvious),
[MM-346](https://linear.app/malpercio/issue/MM-346) (frontend comments),
[MM-349](https://linear.app/malpercio/issue/MM-349) (tooling comments).

## Standard

From AGENTS.md: comments should be **informative but terse**, and **temporal
references must not exist**; **no ticket or AC references in source code**
(`// MM-123`, `// AC2.1:`). Comments describe *why* in terms of the system, not
which ticket required the change or what the code used to be. Design/test plans
in `docs/` are the home for ticket traceability.

This document is the durable file:line index the review produced, so the cleanup
issues can be executed without re-running the audit. Pattern comments required
by `crates/pds/AGENTS.md` were **not** flagged.

## Summary counts

| Crate / app | Temporal | Ticket/AC/Phase (lines) | Stale | Noise/long |
|---|---|---|---|---|
| crates/pds | 30 | 22 | 4 | ~28 |
| crates/common | 2 | 2 | 1 | 0 |
| crates/crypto | 1 | 3 | 0 | 0 |
| crates/repo-engine | 0 | 0 | 0 | 0 |
| apps/identity-wallet | 11 | ~80 (69 in migration_orchestrator.rs) | 0 | 0 |
| apps/admin-companion | 5 | 4 | 0 | 0 |
| tooling (justfile/scripts/workflows) | ~15 | 1 (justfile Wave 8) | 0 | 0 |

## 1. Temporal / history-narrating comments (MM-338, MM-346, MM-349)

The pattern: a comment describes the current design by reference to a previous
one ("no longer", "previously", "used to", "is now", "not yet", "today",
"future", "replaces the old"). Rewrite each to state the current invariant.

### crates/pds

| Location | Offending text | Suggested fix |
|---|---|---|
| firehose.rs:11 | "a process restart / redeploy **no longer** resets the sequence to 0…" | "…so the sequence and replay backlog survive a process restart / redeploy:" |
| firehose.rs:355 | "Because replay **no longer** locks out the sweep, a slow reader can have rows pruned…" | "Replay does not lock out the sweep, so a slow reader…" |
| firehose.rs:626 | "The wedge **no longer** surfaces as an outage…" | "The wedge never surfaces as an outage, so…" |
| firehose.rs:1836 | "Regression: replay **no longer** locks out the retention sweep…" | "Replay must not lock out the retention sweep: a slow reader…" |
| firehose_gc.rs:266 | "Replay safety **no longer** needs a lock either" | "Replay safety needs no lock either" |
| firehose_gc.rs:622-624 | "The sweep **no longer** takes an exclusive lock… (**previously** it would deadlock…)" | drop the parenthetical; state the no-lock invariant |
| auth/guards.rs:217-221 | "…the 415 guard axum's `Json` extractor **previously provided**… **as before device-signature support was added**" | "…the 415 guard axum's `Json` extractor would otherwise provide… so raw-body handlers keep the same rejection statuses." |
| record_write.rs:475 | "so the GC **no longer** recomputes full-repo reachability…" | "so the GC does not recompute full-repo reachability per write" |
| record_write.rs:69-70 | "`new_root` has no reader **yet**… **future sequencer emission**" | stale (see §3) — name the real consumer or delete the field |
| blob_store.rs:217 | "store_blob **no longer** sniffs…" | "store_blob does not sniff — it stores exactly the caller-resolved type." |
| rate_limit.rs:88-89 | "the reference XRPC path (**not yet routed**)… routes **that exist today**" | "the reference XRPC path and the native provisioning routes" |
| app.rs:630 | "An absent header keeps **today's** default routing" | "An absent header keeps the default routing" |
| db/blocks.rs:102-103 | "the live read paths **currently** fetch… no route calls this **yet**" | "the live read paths fetch blocks directly rather than probe; test-only." |
| db/blocks.rs:25 | "the **legacy first-writer** value from `blocks`" | "the first-writer value from `blocks`" |
| db/blobs.rs:158/191 | "only tests consume … **today**" (×2) | "test-only: live read paths are ownership-scoped" |
| db/oauth.rs:16-17 | "created_at is included **for future handlers**… not read **yet**" | "created_at is unread by handlers (kept for audit value)" — or delete field |
| db/oauth.rs:41-42 | "No HTTP handler calls this **yet**; a **future** … endpoint **will call it**" | "Unwired: no handler registers clients dynamically (RFC 7591)." — or delete |
| routes/resolve_identity.rs:391 | "since refreshIdentity **no longer** serves the cached document" | "since refreshIdentity never serves the cached document" |
| routes/service_proxy.rs:724-725 | "The forwarded Authorization **is now** a minted service-auth JWT… **no longer** match on its value" | "The forwarded Authorization is a minted service-auth JWT, not the inbound token, so its value is not matched" |
| routes/service_proxy.rs:1185-1187 | "**Before this**, the header was honored only for `com.atproto.moderation.*`…" | state the invariant: which NSIDs are honored and why |
| routes/resolve_handle.rs:218-220 | "**Previously this returned 500**… (observed on the staging deploy…)" | "A 500 here would break the fallback chain and surface transient DNS failures as server errors." |
| routes/import_repo.rs:113 | "Import is **no longer** strictly first-write-wins" | "Import is not strictly first-write-wins" |
| routes/import_repo.rs:156/464 | "…**replaces the old first-write-wins 409**…" (×2) | delete history clause; keep idempotency rationale |
| routes/oauth_authorize.rs:988-990 | "**now** validates… **it never did before** granular scopes… **what this test used to check**" | state what the GET-path scope validation guarantees |
| routes/agent_auth_test.rs:683 | "so it was **previously untested**" | describe what the journey covers |
| routes/oauth_token.rs:1149 | "── Phase 4 tests (**retained**) ──" | rename divider to what the tests cover (grant-type dispatch) |
| routes/admin_devices.rs:270 | "Granted scopes (**currently** always \"full\")." | "Granted scopes (always \"full\")." |
| routes/get_repo_signing_key.rs:10-11 | "**Replaces** the shared operator key…" | "Repo commits are signed with this per-account key, not the shared operator key." |
| auth/oauth_scopes.rs:1310 | "Custos **used to accept it here**; MM-289 tightened it…" | "bsky.social refuses it; Custos must match." (also ticket ref) |

### crates/common, crates/crypto

| Location | Offending text | Suggested fix |
|---|---|---|
| common/config.rs:60 | "Account-lifecycle knobs (**currently** the reaper interval)." | drop "currently" |
| common/config.rs:62-63 | "admin-device knobs (**currently** the stale-nonce sweep…)." | drop "currently" |
| crypto/plc.rs:1490-1491 | "captured live during the **MM-241 migration run on 2026-07-11**" | "captured live from a real bsky.social migration" (also ticket + date) |

### apps (Rust)

- identity-wallet `pds_client.rs:2846/3359/3422/3559` ("**is now classified** as Unauthorized" ×4), `:3129` ("**no longer swallows**"); `claim.rs:369` ("**Replaces** the claim flow's old OAuth login"), `:596-597` ("**previously** a fragile substring scrape… **which structured classification broke**"), `:1531` ("**now** a typed XrpcError"); `http.rs:133` ("the PDS **currently ignores** it"); `oauth_client.rs:402` ("carry no query **today**").
- admin-companion `keychain.rs:108/111/119-120` ("**Phase 8+**", "**Legacy accounts from Phase 7**… **New** pairings…"), `relay_client.rs:1199-1202` ("**predate** the multi-relay document… **when the legacy triple helpers were removed**"), `pairings.rs:4` ("**currently** target").

### Deliberately NOT flagged (domain terms / real compat rationale)

The HS256 "legacy" session-token class; `routes/get_record.rs:20-21` `did=`
alias rationale; `db/mod.rs:968/1064` migration tests describing what V004/V006
changed (versioned history is the point); admin-companion `keychain.rs:126-130`
one-time-cleanup doc (upgrade-compat behavior that actually runs);
`oauth_token.rs:1740` ("written before granular scopes were persisted" —
describes real rows in production DBs); the "earlier builds cached the W3C
document…" self-heal rationale in the wallet (`did-doc-utils.ts:35`,
`ipc.ts:596`, `IdentityListHome.svelte:82`) — the history *is* the reason the
self-heal exists. `crates/repo-engine` is clean.

## 2. Ticket / AC / project-phase references (MM-337, MM-346)

Banned by AGENTS.md. Every occurrence has a behavior clause after the tag that
stands alone — the mechanical fix is to strip the tag and keep/restore the
system-level "why".

- **Worst offender:** `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
  — 69 comment lines: header Phase refs (7-9), and ~55 `// ACx.y:` test-section
  comments (1221–3190), plus assert message at 2543
  (`"AC1.2: destination activated before source deactivated"`). Strip `ACx.y:`
  prefixes; behavior text already follows each.
- `crates/pds/src/auth/permission_sets.rs:527/599/741` — AC section dividers,
  **and** the test function names encode AC numbers (`ac1_1_resolves_nsid…`);
  the full fix renames them to behavior-descriptive names.
- crates/pds scattered: `jwks.rs:392` (MM-274), `oauth_scopes.rs:849/1310/1317`
  (MM-289), `permission_sets.rs`, `iroh_tunnel.rs:135/164` (AC2.2/3.1/3.2),
  `record_write.rs:718` (MM-260), `oauth_server_metadata.rs:220`,
  `oauth_protected_resource.rs:131`, `oauth_authorize.rs:1574/1803`,
  `outbound_migration_test.rs:3/446`, `service_proxy.rs:1183` (MM-319),
  `admin_devices.rs:1003` (Phase 4), `db/admin_devices.rs:421` (Phase 3),
  `tests/http_suite.rs:30/98/301`, `tests/common/mod.rs:61`.
- crates/common `config.rs:1374/3954` (MM-313); crates/crypto `keys.rs:84`
  (AC3.4), `plc.rs:871/876` (AC1.5, C2), `plc.rs:1491` (MM-241 + date).
- wallet: `pds_client.rs:522/868` (MM-289 ×2), `:827` (AC1.5), `:3320/3382`
  (AC7.3 ×2), `:3722` ("fields Phase 3 consumes"), `claim.rs:9/188/372`
  (MM-289 ×3), `migration_orchestrator.rs` (above), `oauth.rs:33` (Phase 4).
- admin-companion: `relay_client.rs:1444/1653` (AC2.1, AC6.2),
  `keychain.rs:108/119`.
- Frontend TS/Svelte: `claim-errors.ts:1` (MM-290), `ipc.ts:508/511/532/746`
  (MM-290/289/228); admin `ipc.ts:7-8`, `errors.ts:7`, `+page.svelte:15`,
  `settings/+page.svelte:30-32`, `biometric.test.ts:44/61` (MM-240).

**Not violations:** `blob_gc.rs:97/118` and `create_did.rs:96-209` "Phase 1/2/3"
are in-file algorithm step labels, not project phases (though "Step" would
remove the ambiguity); `oauth.rs:343/417` "Phase 1/Phase 2 of the create-flow"
are flow-step labels.

## 3. Stale comments that contradict the code (MM-339)

Highest priority — these actively mislead:

1. `routes/oauth_token.rs:401-402` — "today any granted atproto scope is treated
   as full access." Contradicted by `auth/oauth_scopes.rs` (granular per-route
   enforcement) + `extractors.rs`. Rewrite to what token issuance records.
2. `routes/service_proxy.rs:1144-1145` — "verbatim in Phase 1 (before munging is
   wired)." Munging ships (`read_after_write/`); the test passes because empty
   local records fall back to the buffered original.
3. `record_write.rs:69-70` — `new_root` "future sequencer emission"; sequencer
   ships, field is `#[allow(dead_code)]`. Name the real consumer or remove.
4. `routes/delete_handle.rs:100 and :114` — two consecutive blocks both labeled
   "Step 5b". Renumber or drop.
5. `common/error.rs:96-103` — `TODO: add remaining codes from Appendix A` + 8
   unreferenced codes with no in-repo anchor; several belong to unshipped
   designs. Move to a design doc and delete the TODO.

## 4. Noise / narrate-the-obvious (MM-340)

- `routes/create_did.rs:1-52` — 52-line header transcribing the handler
  line-by-line. Compress to the non-obvious facts: ceremony ordering, the
  pending_did retry-resilience branch, why handles are not inserted here, the
  post-commit self-announce.
- Step-label narration restating the next line: `create_handle.rs` (8),
  `delete_handle.rs` (8), `update_handle.rs` (6), `reset_password.rs` (4). Keep
  only labels carrying rationale (good example: `delete_handle.rs:56-59`,
  DNS-before-DB ordering).
- Small: `delete_handle.rs:101`, `get_pds_signing_key.rs:4`; frontend
  `IdentityListHome.svelte:132`, `RecoveryOverrideScreen.svelte:69`.

## 5. Tooling (MM-349)

Covered in full in the MM-349 issue: iOS "template era" narration
(`scripts/ios/*`), vestigial "Patch A/G" lettering, workflow-header history
(`ci.yml:4/6`, `nix-check.yml:5-8`, rust-cache retrospectives), justfile
past-design comments, `docker-entrypoint.sh:13`, `tools/interop/records.js:19`.

## 6. Missing invariant comments

Comment coverage on load-bearing invariants is unusually high; only one gap
worth a line — `record_write.rs` `WriteRecordResult.new_root` should name its
real consumer if the field stays (§3). The security review separately flagged
the missing timing-safety note on hashed token lookups
([MM-336](https://linear.app/malpercio/issue/MM-336)).

## Execution note

Several files appear in more than one section (e.g. `oauth_scopes.rs:1310` is
both temporal and a ticket ref). Coordinate MM-337 and MM-338/346 so each file
is touched once. `just ci-pds` after; no behavior changes.
