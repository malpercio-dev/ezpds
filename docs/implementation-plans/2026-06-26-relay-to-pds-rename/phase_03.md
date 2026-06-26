# Phase 03 — Internal Rust symbols (Sense-A, non-wire)

**Goal:** Rename internal Rust identifiers, local variables, test names, and code comments that mean OUR component (Sense-A) — *excluding* the public wire API (Phase 04) and the Sense-B crawler code (kept).

**Architecture:** Behavior-preserving identifier rename inside `crates/pds/`. No route paths, no response field names, no DB identifiers change here. The compiler + existing tests prove correctness.

**Scope:** Phase 3 of 6.

**Codebase verified:** 2026-06-26.

**Verifies:** None (refactor — verified by `cargo test -p pds` staying green).

> ⚠️ Re-read the overview keep-list. In this phase it is easy to over-reach. **Do NOT touch:** `crawler.rs`, `CrawlersConfig`, `default_crawler_urls`, `app.rs:158/160` doc-comments, the `crawlers` AppState field, or `relay_signing_keys` SQL. Those are Sense-B or immutable.

---

<!-- START_TASK_1 -->
### Task 1: Inventory Sense-A internal identifiers

**Step 1: Produce the candidate list** (filter the keep-list tokens, including the broadened `BGS` filter):
```bash
cd crates/pds
grep -rn 'relay' src/ \
  | grep -v 'crawler.rs' \
  | grep -v -i 'requestCrawl' \
  | grep -v 'relay_signing_keys' \
  | grep -v -i 'BGS'
# Also sweep sibling crates for Sense-A prose (test fixtures, comments):
cd .. && grep -rn 'relay' repo-engine/src/ crypto/src/ common/src/ | grep -v -i 'BGS' | grep -v -i 'requestCrawl' | grep -v 'CrawlersConfig\|crawler'
```

**Step 2: Triage each hit** into:
- **Rename (Sense-A internal):** local vars like `relay_url`, test fn names (`relay_url_matches_config_public_url`, `websocket_url_is_derived_from_relay_url_*`), internal doc-comments describing *our* server (e.g. `firehose.rs:166` "The relay holds a single `Arc<Firehose>`" → "The PDS holds…"), and `relay.example.com` test fixtures in `crypto/src/plc.rs` etc. (→ `pds.example.com`, for consistency).
- **DEFER to Phase 04 (wire API):** handler fn names (`get_device_relay`, `get_relay_signing_key`), response structs (`GetDeviceRelayResponse`), the `relay_url` *response field*, route registrations in `app.rs:237/243-244`. Leave these for Phase 04.
- **KEEP (Sense-B / immutable):** anything in the overview keep-list — `crawler.rs`, `firehose.rs:213` ("a real relay's buffer"), `list_repos.rs:46`, `sync_subscribe_repos.rs:5`, `car_export.rs:74`, `app.rs:158/160`, `main.rs:170-171`, `relay_signing_keys`.

Write the triaged list to the scratchpad before editing so the boundary with Phase 04 is explicit. **Reference the per-line keep-list in `00-overview.md` for the firehose/sync/list_repos/car_export classifications — these are easy to get wrong.**

**Verification:** list produced; each hit categorized rename / defer-04 / keep, cross-checked against the overview keep-list.
<!-- END_TASK_1 -->

<!-- START_TASK_1B -->
### Task 1b: Rename the CLI binary identity and default config path (main.rs)

**Files:**
- Modify: `crates/pds/src/main.rs:42` — `#[command(name = "relay", about = "ezpds relay server")]` → `#[command(name = "pds", about = "ezpds PDS server (Custos)")]` (user-visible in `--help`).
- Modify: `crates/pds/src/main.rs` — default config filename `relay.toml` → `pds.toml` (lines ~44 doc-comment, ~61, ~67-68, ~78). This is the production default config path the binary auto-loads; it pairs with the dev `pds.dev.toml` from Phase 02. (The `EZPDS_CONFIG` env override is unaffected.)
- Modify: `crates/pds/src/main.rs:95` — log line `"relay starting"` → `"pds starting"` (and any matching "relay shut down" line).
- **KEEP:** `main.rs:170-171` crawler comments (Sense-B), and the `/var/pds/relay.db` example comment at ~102 if it documents the kept prod DB filename (Sense-A-but-kept; align with the Phase 02 DB-filename decision — leave `relay.db` in the example).

**Verification:** `grep -n 'relay' crates/pds/src/main.rs` → only the Sense-B crawler comments (~170-171) and the kept `relay.db` example (~102) remain; `cargo run -p pds -- --help` shows `pds`.
<!-- END_TASK_1B -->

<!-- START_TASK_2 -->
### Task 2: Rename internal local variables and helpers

**Files (confirm exact lines with the Task 1 grep):**
- `crates/pds/src/routes/get_device_relay.rs` — internal *local* `relay_url` binding (lines ~45, ~48, ~52) → `pds_url`. **Leave the response struct field and fn name for Phase 04** (do not rename `GetDeviceRelayResponse.relay_url` field yet — that is wire-facing).

> Boundary note: the *local variable* `relay_url` is internal; the *struct field* `relay_url` is wire-facing. If renaming the local while leaving the field is awkward in one file, it is acceptable to defer this whole file to Phase 04 and note it here. Prefer whichever keeps each commit compiling. Record the choice.

- Any other Sense-A internal `let relay_* =` bindings surfaced by Task 1 → `pds_*`.

**Implementation:** Rename bindings; the compiler enforces consistency within the function.

**Verification:** `cargo build -p pds` compiles.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Rename Sense-A test function names and internal comments

**Files (from Task 1):**
- Test fn names containing `relay` that describe our component → `pds` (e.g. `relay_url_matches_config_public_url` → `pds_url_matches_config_public_url`). Keep test *bodies* asserting the same behavior.
- Internal doc-comments / line comments describing our server as "the relay" → "the PDS" / "Custos". Explicitly includes `firehose.rs:166` ("The relay holds a single `Arc<Firehose>`" → "The PDS holds…"). **Skip** the Sense-B lines: `app.rs:158/160`, `crawler.rs`, `firehose.rs:213`, `list_repos.rs:46`, `sync_subscribe_repos.rs:5`, `car_export.rs:74`, `main.rs:170-171`.
- Sense-A test fixtures across crates: `relay.example.com` (e.g. in `crypto/src/plc.rs`) → `pds.example.com`. These are illustrative URLs in tests; rename for consistency (behavior unaffected — they're not real hosts).

**Verification:**
```bash
cargo test -p pds
```
Expected: all tests pass (renamed test fns run; same assertions).
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Re-grep to confirm only deferred/kept references remain, then commit

**Step 1: Confirm the boundary**
```bash
cd crates/pds && grep -rn 'relay' src/ | grep -v crawler.rs | grep -v -i requestCrawl | grep -v relay_signing_keys | grep -v -i 'BGS'
```
Expected: remaining hits are ONLY (a) the wire-API items explicitly deferred to Phase 04 (handler fns, route paths, response field), (b) the Sense-B doc-comments (`app.rs:158/160`, `firehose.rs:213`, `list_repos.rs:46`, `sync_subscribe_repos.rs:5`, `main.rs:170-171`), and (c) the kept `relay.db` example comment in `main.rs`. No stray internal Sense-A identifiers.

**Step 2: Full test + lint**
```bash
cargo test -p pds
cargo clippy -p pds --all-targets -- -D warnings
```
Expected: green.

**Step 3: Commit**
```bash
git add -A
git commit -m "refactor(pds): rename internal Sense-A relay identifiers to pds

Local vars, test names, and internal comments for our component.
Wire API (routes, handler names, response fields) deferred to the
next phase; crawler/Relay (Sense-B) code intentionally untouched."
```
<!-- END_TASK_4 -->
