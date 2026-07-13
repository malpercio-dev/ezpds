# Read-After-Write Implementation Plan — Phase 7: Best-effort hardening, docs, Bruno

**Goal:** Guarantee graceful fallback across every failure mode, cap response buffering, and document the surface.

**Architecture:** Complete the best-effort fallback ladder in `pipethrough_munged`, add a response buffer cap, add example Bruno requests, and update `crates/pds/AGENTS.md`. No new endpoints.

**Tech Stack:** Rust, serde_json, wiremock (tests), Bruno `.bru` files, Markdown docs.

**Scope:** Phase 7 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC4: Best-effort behavior & lag header
- **read-after-write.AC4.1 Failure:** A malformed / schema-invalid AppView response body is passed through untouched (no munge, no error).
- **read-after-write.AC4.2 Failure:** When quote-post hydration's AppView call fails or the URI is unknown, the post still renders with an `app.bsky.embed.record#viewNotFound` embed.
- **read-after-write.AC4.4 Edge:** When the AppView's `atproto-repo-rev` equals the current repo rev (nothing unindexed), the response is passed through unchanged with no lag header.

### read-after-write.AC7: Fast path preserved
- **read-after-write.AC7.1 Success:** Non-munged `app.bsky.*` / `chat.bsky.*` / `com.atproto.moderation.*` NSIDs continue to stream verbatim; existing `service_proxy.rs` tests pass unchanged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Complete the fallback ladder + response buffer cap

**Verifies:** read-after-write.AC4.1, read-after-write.AC4.2, read-after-write.AC4.4

**Files:**
- Modify: `crates/pds/src/read_after_write/mod.rs`

**Implementation:**

Ensure `pipethrough_munged` implements the full ladder (most already present from Phases 4/6 — this task audits and closes gaps, and adds explicit tests):

1. `proxy_request` error ⇒ return its `Err` response (upstream unreachable → 503, already handled by `proxy_request`).
2. Non-2xx upstream ⇒ return buffered original **except** `getPostThread` `400 NotFound` (Phase 6).
3. Body fails to parse as JSON ⇒ return buffered original bytes (`read-after-write.AC4.1`).
4. `local.count == 0` ⇒ return buffered original, **no** lag header (`read-after-write.AC4.4`).
5. Munge/hydration panics or errors ⇒ log at `warn` + return buffered original. Quote-hydration failures are already contained in Phase 3 (degrade to `#viewNotFound`, `read-after-write.AC4.2`).

Add a response buffer cap constant (e.g. `const MAX_MUNGE_RESPONSE_BODY: usize = 10 * 1024 * 1024;`). Buffer with `axum::body::to_bytes(body, MAX_MUNGE_RESPONSE_BODY)` (or the reqwest equivalent); on overflow, log and return the upstream error envelope (these JSON endpoints sit far under 10 MiB, so this is a guard, not a normal path).

Wrap the parse→select→munge→serialize section so any error path yields the buffered original; never propagate a munge error to the client.

**Testing (integration, wiremock AppView):**
- `read-after-write.AC4.1`: mock a munged NSID (e.g. `getTimeline`) returning `200` with a non-JSON / schema-invalid body + a fresh local write present; assert the client receives the AppView body untouched (no 500).
- `read-after-write.AC4.2`: (may reuse Phase 3's test) mock `getPosts` failing during a `getTimeline` munge with a quote-post; assert the injected post renders with `#viewNotFound`.
- `read-after-write.AC4.4`: mock `getProfile` with `atproto-repo-rev` equal to the account's current repo rev (no unindexed writes); assert passthrough with no `Atproto-Upstream-Lag` header.

**Verification:** `cargo test -p pds` — passes.

**Commit:** `feat(pds): complete read-after-write best-effort fallback ladder + response cap`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Fast-path regression assertion

**Verifies:** read-after-write.AC7.1

**Files:**
- Modify: `crates/pds/src/routes/service_proxy.rs` test module (add one assertion if not already covered)

**Implementation:**

Confirm (add a test if a gap exists) that a non-munged `app.bsky.*` NSID (e.g. `app.bsky.graph.getFollows`) and a `chat.bsky.*`/`com.atproto.moderation.*` request still go through the streaming `proxy_xrpc` path and are returned verbatim — i.e. the six-NSID branch does not capture anything outside the set. The existing `proxies_get_query_to_appview` / chat / moderation tests largely cover this; add an explicit assertion for a non-listed `app.bsky.*` NSID if absent.

**Testing:**
- `read-after-write.AC7.1`: a non-listed `app.bsky.*` GET streams verbatim (no buffering / no lag header); all pre-existing `service_proxy.rs` tests pass unchanged.

**Verification:** `cargo test -p pds --lib routes::service_proxy` — passes.

**Commit:** `test(pds): assert non-munged app.bsky NSIDs keep the streaming fast path`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Bruno example requests

**Files:**
- Create: `bruno/` `.bru` files for the six munged endpoints (next `seq` numbers), e.g. `app-bsky-feed-getTimeline.bru`, `app-bsky-feed-getAuthorFeed.bru`, `app-bsky-feed-getPostThread.bru`, `app-bsky-feed-getActorLikes.bru`, `app-bsky-actor-getProfile.bru`, `app-bsky-actor-getProfiles.bru` (follow the naming/structure of existing `.bru` files in `bruno/`).

**Implementation:**

Each `.bru` is a GET to `{{baseUrl}}/xrpc/<nsid>` with the appropriate query params (e.g. `getPostThread?uri=...`, `getProfile?actor=...`) and `Authorization: Bearer {{accessJwt}}`. These document the read-after-write endpoints; the `app.bsky.*` catch-all path coverage is unchanged, so `bruno-check` remains green either way.

**Verification:**
Run: `just bruno-check`
Expected: Passes (route ⇄ Bruno parity intact).

**Commit:** `docs(bruno): add example requests for read-after-write endpoints`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Documentation

**Files:**
- Modify: `crates/pds/AGENTS.md` (Module Map + `routes/service_proxy.rs` row)

**Implementation:**

- Add a `read_after_write/` entry to the Module Map describing the buffered munge path, the six NSIDs, rev-faithful selection via `atproto-repo-rev` + `repo_seq`, `LocalViewer` hydration, best-effort fallback, and the `Atproto-Upstream-Lag` header.
- Note the `service_proxy.rs` `proxy_request` extraction (shared streaming + buffered inner) and that `mint_service_auth` is now `pub(crate)`.
- Note the new `[appview] cdn_url` config knob (`EZPDS_APPVIEW_CDN_URL`, default `https://cdn.bsky.app`).
- Update the "Last verified" date at the top of `crates/pds/AGENTS.md`.

Do **not** add ticket references (MM-226) to source or AGENTS.md per repo convention.

**Verification:** `just ci-pds` green (fmt, clippy `-D warnings`, tests, audit). Manual read-through of the AGENTS.md diff.

**Commit:** `docs(pds): document read_after_write module and config`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
