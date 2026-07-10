# Read-After-Write Implementation Plan — Phase 5: Feed munges

**Goal:** Inject the requester's fresh posts into their `getTimeline` and own `getAuthorFeed`, and refresh own-authored items across `getTimeline`/`getAuthorFeed`/`getActorLikes`.

**Architecture:** Three munge functions in `munge.rs`, wired into the dispatch. `getTimeline` and own `getAuthorFeed` use `insert_posts_in_feed` (Phase 3) after a single quote-hydration pass; `getActorLikes` only refreshes the requester's author view on existing items. `getAuthorFeed` is guarded so injection happens only when the `actor` param resolves to the requester.

**Tech Stack:** Rust, serde_json, wiremock (tests), reuse of Phase 2 selection + Phase 3 viewer/insert helper.

**Scope:** Phase 5 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC1: Own fresh posts appear in feeds
- **read-after-write.AC1.1 Success:** A post created via ezpds, absent from the AppView `getTimeline` response, appears at the top of the munged timeline.
- **read-after-write.AC1.2 Success:** The same post appears in the account's own `getAuthorFeed` (when `actor` resolves to the requester).
- **read-after-write.AC1.3 Success:** `getActorLikes` refreshes the author view on the requester's own items and inserts no posts.
- **read-after-write.AC1.6 Failure:** Viewing another actor's `getAuthorFeed` does not inject the requester's posts (passthrough).
- **read-after-write.AC1.7 Edge:** Multiple injected posts are spliced in chronological (`indexed_at`) order, newest first, relative to the existing feed items.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: `get_timeline` munge

**Verifies:** read-after-write.AC1.1, read-after-write.AC1.7

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs`
- Modify: `crates/pds/src/read_after_write/mod.rs` (dispatch: route `app.bsky.feed.getTimeline` to `get_timeline`)

**Implementation:**

```rust
/// getTimeline returns { feed: [feedViewPost], cursor? }. Inject the requester's unindexed posts
/// and refresh the author on any existing own-authored items.
pub(crate) async fn get_timeline(
    viewer: &LocalViewer, mut original: serde_json::Value, local: &LocalRecords, requester: &str,
) -> serde_json::Value {
    // 1. quotes = viewer.hydrate_quotes(&local.posts).await  (single getPosts call; Phase 3).
    // 2. Refresh author on existing feed items whose post.author.did == requester
    //    (viewer.update_profile_view_basic on the embedded author) if a local profile exists.
    // 3. viewer.insert_posts_in_feed(&mut feed, &local.posts, &quotes).await.
}
```

**Testing (integration, wiremock AppView):**
- `read-after-write.AC1.1`: write a post; mock `getTimeline` returning a feed without it (+ old `atproto-repo-rev` header); assert the post appears at the top of the munged feed as a `feedViewPost` with a local-author `postView`.
- `read-after-write.AC1.7`: write two posts with distinct `indexed_at`; assert they splice in newest-first, correctly ordered against a couple of existing (older) feed items.

**Verification:** `cargo test -p pds` — passes.

**Commit:** `feat(pds): getTimeline read-after-write munge`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `get_author_feed` munge with actor-guard

**Verifies:** read-after-write.AC1.2, read-after-write.AC1.6

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs`
- Modify: `crates/pds/src/read_after_write/mod.rs` (dispatch route; the munge needs the request's `actor` query param — pass it through the dispatch, e.g. extract query params before proxying and thread the `actor` value into the munge, or resolve from the returned feed's subject)

**Implementation:**

The `actor` param arrives as a handle or DID. Resolve it to a DID and compare against `requester`:
- If the `actor` resolves to `requester` → inject own posts + refresh author (same body as `get_timeline`).
- Otherwise → return `original` unchanged (never inject the requester's posts into another user's author feed).

Simplest resolution that avoids an extra lookup: an author feed's items are all authored by the subject actor, so if the feed is non-empty and `feed[0].post.author.did == requester`, it is the requester's own feed; additionally accept when the `actor` query param equals `requester` verbatim (DID form) or matches the requester's `handle` (from `LocalViewer.handle`). Document the chosen resolution in a comment. **Threading the `actor` query param** through the dispatch is the robust choice — capture it in `pipethrough_munged` from the request URI before `proxy_request` consumes the request.

**Testing (integration):**
- `read-after-write.AC1.2`: mock `getAuthorFeed?actor=<requester-did>`; write a post; assert it is injected.
- `read-after-write.AC1.6`: mock `getAuthorFeed?actor=<other-did>` returning another user's feed; local posts present; assert the response equals the AppView body (no injection).

**Verification:** `cargo test -p pds` — passes.

**Commit:** `feat(pds): getAuthorFeed read-after-write munge with actor-guard`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `get_actor_likes` munge

**Verifies:** read-after-write.AC1.3

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs`
- Modify: `crates/pds/src/read_after_write/mod.rs` (dispatch route)

**Implementation:**

```rust
/// getActorLikes returns { feed: [feedViewPost], cursor? }. Likes are not the requester's own post
/// records, so this only refreshes the author view on items authored by the requester — it inserts
/// nothing.
pub(crate) async fn get_actor_likes(
    viewer: &LocalViewer, mut original: serde_json::Value, local: &LocalRecords, requester: &str,
) -> serde_json::Value {
    // for each feed item where post.author.did == requester ->
    //     post.author = viewer.update_profile_view_basic(post.author) (if local profile exists).
}
```

**Testing (integration):**
- `read-after-write.AC1.3`: mock `getActorLikes` whose feed includes an item authored by the requester; local profile present (fresh displayName). Assert the requester's author view is refreshed and **no** new items were inserted (feed length unchanged).

**Verification:** `cargo test -p pds` — passes; `just ci-pds` green.

**Commit:** `feat(pds): getActorLikes read-after-write author refresh`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->
