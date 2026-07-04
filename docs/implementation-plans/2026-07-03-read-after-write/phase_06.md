# Read-After-Write Implementation Plan — Phase 6: Thread munge

**Goal:** Show a just-created post's thread (which the AppView returns as `NotFound`), and inject the requester's unindexed replies into an existing thread.

**Architecture:** `get_post_thread` in `munge.rs` handles two cases: a `threadViewPost` returned by the AppView (splice own unindexed replies + refresh focus author), and a `400 NotFound` for a just-created post (reconstruct the `threadViewPost` from the local record). This requires a small change to `pipethrough_munged` so a `getPostThread` `NotFound` is treated as a munge trigger rather than an error passthrough.

**Tech Stack:** Rust, serde_json, wiremock (tests), reuse of Phase 2 selection + Phase 3 post hydration.

**Scope:** Phase 6 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC3: Own thread renders immediately
- **read-after-write.AC3.1 Success:** Fetching `getPostThread` for a just-created post, for which the AppView returns `400 NotFound`, yields a `threadViewPost` reconstructed from the local record.
- **read-after-write.AC3.2 Success:** An unindexed reply authored by the requester is spliced into an existing AppView `threadViewPost` reply tree.
- **read-after-write.AC3.3 Failure:** A thread whose focus post is not the requester's and has no local replies is passed through unchanged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: `getPostThread` NotFound handling in `pipethrough_munged`

**Files:**
- Modify: `crates/pds/src/read_after_write/mod.rs` (the status-check step from Phase 4 Task 1)

**Implementation:**

`getPostThread` returns `400` with an XRPC error body `{ "error": "NotFound", ... }` when the AppView doesn't know the post. For this NSID only, a `400 NotFound` must reach the munge (so it can reconstruct from the local record) instead of being passed through as an error.

In the status-check step:

```rust
// Phase 4 default: non-2xx -> return buffered original.
// Exception: getPostThread + 400 + body error == "NotFound" -> parse the (error) body and munge.
let is_thread_not_found = nsid == "app.bsky.feed.getPostThread"
    && status == StatusCode::BAD_REQUEST
    && parsed_error_code(&buffered) == Some("NotFound");
if !status.is_success() && !is_thread_not_found {
    return buffered_response;
}
```

When `is_thread_not_found`, pass the parsed error body (or a synthesized `{ thread: null }` placeholder) into `get_post_thread`, which detects the NotFound and reconstructs. Ensure the final response status is `200` when reconstruction succeeds, and falls back to the original `400` when the requested URI is not a local post.

**Verification:** `cargo build -p pds`; existing tests still pass.

**Commit:** `feat(pds): treat getPostThread 400 NotFound as a munge trigger`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `get_post_thread` — reconstruct + splice

**Verifies:** read-after-write.AC3.1, read-after-write.AC3.2, read-after-write.AC3.3

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs`
- Modify: `crates/pds/src/read_after_write/mod.rs` (dispatch route)

**Implementation:**

The munge receives the parsed body (either a success `{ thread: threadViewPost | notFoundPost | blockedPost }` or, via Task 1, the NotFound error body) plus the requested `uri` (thread this via the dispatch, like `actor` in Phase 5). Two cases:

```rust
pub(crate) async fn get_post_thread(
    viewer: &LocalViewer, original: serde_json::Value, local: &LocalRecords, requester: &str,
    requested_uri: &str,
) -> serde_json::Value {
    // Case A — AppView returned a threadViewPost:
    //   * refresh thread.post.author if it is the requester's (local profile).
    //   * splice the requester's unindexed *replies* (local posts whose record.reply.root/parent
    //     references a uri present in this thread) into thread.replies, hydrated via post_view,
    //     wrapped as threadViewPost nodes. Insert by createdAt order.
    // Case B — NotFound and requested_uri is one of local.posts:
    //   * build a threadViewPost from the local record (post = post_view(that record)),
    //     parent = resolved from AppView if the record has reply.parent (best-effort; else omitted),
    //     replies = any local replies to it. Return { thread: <that threadViewPost> }.
    //   * if requested_uri is NOT a local post -> return original unchanged (the 400 stands).
}
```

Reply matching: a local post is a reply when its record has `reply.parent.uri` / `reply.root.uri`. For Case A, splice replies whose `parent.uri` matches any post URI already in the thread (or the focus URI). For Case B, the focus is the requested post; its replies are local posts whose `parent.uri == requested_uri`.

Keep depth shallow and best-effort — full recursive thread reconstruction is not required; the AC is that the just-created post and direct own replies appear.

**Testing (integration, wiremock AppView):**
- `read-after-write.AC3.1`: write a top-level post; mock `getPostThread?uri=<post>` returning `400 {"error":"NotFound"}`; assert the response is `200` with a `threadViewPost` whose `post.uri == <post>` and local author.
- `read-after-write.AC3.2`: mock `getPostThread` returning a `threadViewPost` for a parent post; write a reply to it locally; assert the reply appears in `thread.replies` as a `threadViewPost`.
- `read-after-write.AC3.3`: mock a `threadViewPost` for another user's post with no local replies; assert the response equals the AppView body.

**Verification:** `cargo test -p pds` — passes; `just ci-pds` green.

**Commit:** `feat(pds): getPostThread read-after-write reconstruction + reply splice`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `parsed_error_code` helper + dispatch wiring cleanup

**Files:**
- Modify: `crates/pds/src/read_after_write/mod.rs`

**Implementation:**

Add a small helper `fn parsed_error_code(bytes: &[u8]) -> Option<String>` that best-effort parses `{ "error": "<code>" }` from a buffered body (returns `None` on parse failure). Ensure the dispatch passes `requested_uri`/`actor` query params to the thread/authorFeed munges consistently (capture them from the request URI in `pipethrough_munged` before the request is consumed).

**Testing:** covered by Task 2's AC3.1 (exercises `parsed_error_code` via the NotFound path). A focused unit test on `parsed_error_code` (valid error body, non-error body, garbage) is recommended.

**Verification:** `cargo test -p pds` — passes.

**Commit:** `refactor(pds): error-code parse helper + query-param threading for munges`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->
