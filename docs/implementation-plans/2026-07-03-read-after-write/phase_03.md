# Read-After-Write Implementation Plan — Phase 3: `LocalViewer` hydration

**Goal:** Turn raw local records into the lexicon *view* shapes AppView responses use — profile views, post views, and embeds (including quote-posts).

**Architecture:** `LocalViewer` is constructed per request with `state`, the requester's `did`, `handle`, and the local profile record. It builds `profileViewBasic`/`profileViewDetailed`, `postView` (zero counts, local author), and hydrates embeds: images/external locally via CDN URLs; `record`/`recordWithMedia` quote-posts via a single service-auth'd `app.bsky.feed.getPosts` call, degrading to `#viewNotFound`.

**Tech Stack:** Rust, serde_json, reqwest (AppView getPosts call), reuse of `service_proxy::mint_service_auth`.

**Scope:** Phase 3 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC1 (partial): post hydration
- **read-after-write.AC1.4 Success:** A local post record hydrates to a `postView` with a locally-built author (did/handle/displayName/avatar), the record value, and zero like/reply/repost counts.
- **read-after-write.AC1.5 Success:** A local post with an image or external embed hydrates with CDN image URLs / external view.

### read-after-write.AC2 (partial): profile hydration
- **read-after-write.AC2.3 Success:** `update_profile_detailed` overwrites displayName, description, avatar, and banner from the local record.
- **read-after-write.AC2.4 Success:** An avatar/banner blob ref becomes a `{cdn_url}/img/{kind}/plain/{did}/{cid}@jpeg` URL.

### read-after-write.AC6: Embed hydration
- **read-after-write.AC6.1 Success:** Image and external embeds are hydrated locally (no AppView call).
- **read-after-write.AC6.2 Success/Failure:** A record (quote) embed is hydrated via one service-auth'd `getPosts` call on success, and degrades to `#viewNotFound` on failure without dropping the post.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->
<!-- START_TASK_1 -->
### Task 1: `LocalViewer` construction + profile views

**Verifies:** read-after-write.AC2.3, read-after-write.AC2.4

**Files:**
- Modify: `crates/pds/src/read_after_write/viewer.rs` (`// pattern: Imperative Shell` — it reads config + may call the AppView)

**Implementation:**

```rust
pub(crate) struct LocalViewer<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) did: String,
    pub(crate) handle: Option<String>,     // from db::accounts::get_session_account
    pub(crate) profile: Option<serde_json::Value>, // local app.bsky.actor.profile/self record
}
```

Profile helpers (operate on `serde_json::Value` so only the touched fields change):
- `profile_view_basic() -> serde_json::Value` — `{ did, handle, displayName?, avatar? }` from the local profile record (avatar via `image_url("avatar", cid)`).
- `update_profile_view(view) -> view` — overwrite `displayName`, `description`, `avatar`.
- `update_profile_detailed(view) -> view` — the above plus `banner`.

Image URL builder:

```rust
/// {cdn_url}/img/{kind}/plain/{did}/{cid}@jpeg — kind is "avatar" | "banner" | "feed_thumbnail" |
/// "feed_fullsize". `cid` is extracted from a blob ref value's ref.$link.
fn image_url(&self, kind: &str, cid: &str) -> String {
    format!("{}/img/{}/plain/{}/{}@jpeg", self.state.config.appview.cdn_url, kind, self.did, cid)
}
```

Add a small helper to pull the blob CID string out of a record's blob-ref value (`{"$type":"blob","ref":{"$link":"<cid>"},...}` — note repo-engine JSON encodes CID links as `{"$link": ...}`).

**Testing:**
- `read-after-write.AC2.3`: given an AppView `profileViewDetailed` and a local profile record with all four fields set, assert `update_profile_detailed` overwrites displayName/description/avatar/banner.
- `read-after-write.AC2.4`: assert an avatar blob ref yields `{cdn_url}/img/avatar/plain/{did}/{cid}@jpeg`.

**Verification:** `cargo test -p pds --lib read_after_write::viewer` — passes.

**Commit:** `feat(pds): LocalViewer profile views + CDN image URLs`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `post_view` with local embeds (images/external)

**Verifies:** read-after-write.AC1.4, read-after-write.AC1.5, read-after-write.AC6.1

**Files:**
- Modify: `crates/pds/src/read_after_write/viewer.rs`

**Implementation:**

```rust
/// Build an app.bsky.feed.defs#postView from one of the requester's local post RecordDescripts.
/// Author is built locally (profile_view_basic); counts are zero; embed hydrated from record.embed.
async fn post_view(&self, post: &RecordDescript) -> serde_json::Value { /* ... */ }
```

Shape: `{ "$type": "app.bsky.feed.defs#postView", uri, cid, author: profile_view_basic(), record, indexedAt, likeCount: 0, replyCount: 0, repostCount: 0, embed? }`.

Embed hydration (this task: local kinds only; quote-posts in Task 3):
- `app.bsky.embed.images` → `app.bsky.embed.images#view` with `images[].thumb`/`fullsize` = `image_url("feed_thumbnail"/"feed_fullsize", cid)` and `alt` preserved.
- `app.bsky.embed.external` → `app.bsky.embed.external#view` (title/description/uri passthrough; `thumb` via `image_url("feed_thumbnail", cid)` when a thumb blob is present).
- other/absent embed → omit `embed`.

**Testing:**
- `read-after-write.AC1.4`: a bare text post → `postView` with local author (did/handle), record value, zero counts.
- `read-after-write.AC1.5` / `read-after-write.AC6.1`: an images-embed post and an external-embed post hydrate with CDN thumb/fullsize URLs and the external card, with no AppView call made.

**Verification:** `cargo test -p pds --lib read_after_write::viewer` — passes.

**Commit:** `feat(pds): LocalViewer postView with image/external embed hydration`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Quote-post embed hydration via `getPosts`

**Verifies:** read-after-write.AC6.2

**Files:**
- Modify: `crates/pds/src/read_after_write/viewer.rs`
- Uses: `crate::routes::service_proxy::mint_service_auth` (made `pub(crate)` in Phase 1)

**Implementation:**

Define a named type for the quote map (used here and by Phase 5's feed munges) — put it in `viewer.rs` (or `types.rs`):

```rust
/// uri -> the quoted post's postView, from a single getPosts hydration pass.
pub(crate) type QuoteMap = std::collections::HashMap<String, serde_json::Value>;
```

Add a batch hydration method `async fn hydrate_quotes(&self, posts: &[RecordDescript]) -> QuoteMap` invoked by the munges before building post views: collect all referenced record URIs across the local posts' `record` / `recordWithMedia` embeds, make **one** authenticated `GET {appview.url}/xrpc/app.bsky.feed.getPosts?uris=...` call (mint service auth with `nsid = "app.bsky.feed.getPosts"`, `aud`/proxy = `appview.did`, via `state.http_client`), and build the `uri -> postView` `QuoteMap` from the response `posts[]`. On call failure, return an empty `QuoteMap` (every embed then degrades to `#viewNotFound`).

Then `post_view`'s embed step, for a `record` embed:
- If the referenced URI is in the map → `app.bsky.embed.record#view` with `record` = `app.bsky.embed.record#viewRecord` derived from the fetched postView.
- If absent, or the `getPosts` call failed → `app.bsky.embed.record#view` with `record` = `app.bsky.embed.record#viewNotFound` (`{ "$type": "...#viewNotFound", uri, notFound: true }`). **The post still renders.**
- `recordWithMedia` → combine the media view (image/external, local) with the record view (as above).

Design the hydration map as an input to `post_view` (e.g. `post_view(&self, post, &quotes)`), so a single `getPosts` call serves an entire feed/thread munge rather than one call per post.

**Testing:**
- `read-after-write.AC6.2` success: mock AppView `getPosts` returning the quoted post; assert the local post's embed is a populated `#viewRecord`.
- `read-after-write.AC6.2` failure: mock `getPosts` returning 5xx (or omitting the URI); assert the embed degrades to `#viewNotFound` and the post is still present.

**Verification:** `cargo test -p pds --lib read_after_write` — passes.

**Commit:** `feat(pds): quote-post embed hydration via getPosts with viewNotFound fallback`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `insert_posts_in_feed` shared helper

**Files:**
- Modify: `crates/pds/src/read_after_write/viewer.rs` (or `munge.rs` — keep with the viewer since it hydrates)

**Implementation:**

```rust
/// Merge the requester's unindexed posts into an app.bsky feed array (getTimeline/getAuthorFeed
/// shape: [{ post: postView, ... }]). Filters to posts with indexed_at newer than the page's
/// oldest item, hydrates each to a postView, and splices newest-first into chronological position.
/// Rev-selection guarantees these are unindexed, so no URI-dedup against the page is required.
async fn insert_posts_in_feed(
    &self,
    feed: &mut Vec<serde_json::Value>,
    posts: &[RecordDescript],
    quotes: &QuoteMap,
) { /* ... */ }
```

Logic mirrors the reference: `last_time` = the `post.indexedAt` of the last feed item (or epoch if empty); keep posts with `indexed_at > last_time`; hydrate; for each (newest→oldest) find the first feed item whose `post.indexedAt < this.indexedAt` and insert `{ "post": postView }` before it, else push.

**Testing:** covered by Phase 5 feed integration tests (this helper has no standalone AC; it is exercised via `getTimeline`/`getAuthorFeed`). A focused unit test on ordering is optional but recommended.

**Verification:** `cargo build -p pds` — compiles; `cargo test -p pds --lib read_after_write` — existing tests pass.

**Commit:** `feat(pds): insert_posts_in_feed chronological splice helper`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->
