# Read-After-Write for Proxied `app.bsky` Reads — Design

Linear: [MM-226](https://linear.app/malpercio/issue/MM-226) (Wave 7: Hardening)

## Summary

Bluesky's AppView (the service that indexes the firehose into `app.bsky.*` reads) is eventually consistent: a post or profile edit written to this PDS doesn't show up in `getTimeline`, `getPostThread`, `getProfile`, etc. until the AppView has processed the corresponding firehose event, which can lag by seconds. Read-after-write closes that gap for the *writer's own data only*: when a munged endpoint is proxied to the AppView, the PDS also reads back — directly from its own authoritative local repo — any of the requester's records written since the AppView's last-seen repo revision, and splices/overwrites them into the AppView's JSON response before it reaches the client. The result is that a user always sees their own fresh writes reflected immediately, without the PDS maintaining any cache or write-side bookkeeping to invalidate.

Mechanically, this slots into the existing proxy as a parallel path rather than a new subsystem: `xrpc_handler` already special-cases certain NSIDs ahead of the generic streaming proxy (`proxy_xrpc`), and the six read-after-write endpoints (`getProfile`, `getProfiles`, `getTimeline`, `getAuthorFeed`, `getPostThread`, `getActorLikes`) are added as another such branch. Where the fast path streams the AppView response straight through, the munged path buffers it, compares the AppView's `atproto-repo-rev` header against this account's firehose log to find any newer local writes, hydrates those raw records into proper lexicon view shapes (author, embeds, etc.) via a `LocalViewer`, and runs an endpoint-specific munge function that patches them into the parsed response body. Every step in that pipeline is best-effort: any failure at any stage — selection, hydration, munging, even a malformed AppView body — falls back to returning the original buffered response untouched, so this layer can only improve a read, never break one.

## Definition of Done

- A post created via ezpds appears in the account's own `getTimeline`, `getAuthorFeed`, and `getPostThread` responses **immediately**, before the AppView has indexed the corresponding firehose event.
- A profile record edit (displayName/description/avatar/banner) is reflected immediately in the account's own `getProfile` and `getProfiles` responses.
- All six read-after-write endpoints are munged for full reference parity: `app.bsky.actor.getProfile`, `app.bsky.actor.getProfiles`, `app.bsky.feed.getAuthorFeed`, `app.bsky.feed.getPostThread`, `app.bsky.feed.getTimeline`, `app.bsky.feed.getActorLikes`.
- Munged responses carry an `Atproto-Upstream-Lag` header whenever unindexed local records were merged, matching the reference computation (ms since the oldest merged record).
- Munging is strictly best-effort: any selection, parsing, or hydration failure falls back to returning the raw AppView response. Read-after-write never fails a read.
- Only the authenticated requester's own records are ever merged; other users' data is passed through untouched.
- The existing streaming proxy fast path for all other `app.bsky.*` / `chat.bsky.*` / `com.atproto.moderation.*` NSIDs is behaviorally unchanged.

## Acceptance Criteria

### read-after-write.AC1: Own fresh posts appear in feeds
- **read-after-write.AC1.1 Success:** A post created via ezpds, absent from the AppView `getTimeline` response, appears at the top of the munged timeline.
- **read-after-write.AC1.2 Success:** The same post appears in the account's own `getAuthorFeed` (when `actor` resolves to the requester).
- **read-after-write.AC1.3 Success:** `getActorLikes` refreshes the author view on the requester's own items and inserts no posts.
- **read-after-write.AC1.4 Success:** A local post record hydrates to a `postView` with a locally-built author (did/handle/displayName/avatar), the record value, and zero like/reply/repost counts.
- **read-after-write.AC1.5 Success:** A local post with an image or external embed hydrates with CDN image URLs / external view.
- **read-after-write.AC1.6 Failure:** Viewing another actor's `getAuthorFeed` does not inject the requester's posts (passthrough).
- **read-after-write.AC1.7 Edge:** Multiple injected posts are spliced in chronological (`indexed_at`) order, newest first, relative to the existing feed items.

### read-after-write.AC2: Profile edits reflect immediately
- **read-after-write.AC2.1 Success:** A stale AppView `getProfile` plus a fresh local profile record yields a response showing the local displayName/description, with an `Atproto-Upstream-Lag` header.
- **read-after-write.AC2.2 Success:** In a `getProfiles` batch, only the entry whose `did == requester` is overwritten; other profiles are untouched.
- **read-after-write.AC2.3 Success:** `update_profile_detailed` overwrites displayName, description, avatar, and banner from the local record.
- **read-after-write.AC2.4 Success:** An avatar/banner blob ref becomes a `{cdn_url}/img/{kind}/plain/{did}/{cid}@jpeg` URL.
- **read-after-write.AC2.5 Failure:** No local profile record ⇒ the AppView profile is passed through unchanged.

### read-after-write.AC3: Own thread renders immediately
- **read-after-write.AC3.1 Success:** Fetching `getPostThread` for a just-created post, for which the AppView returns `400 NotFound`, yields a `threadViewPost` reconstructed from the local record.
- **read-after-write.AC3.2 Success:** An unindexed reply authored by the requester is spliced into an existing AppView `threadViewPost` reply tree.
- **read-after-write.AC3.3 Failure:** A thread whose focus post is not the requester's and has no local replies is passed through unchanged.

### read-after-write.AC4: Best-effort behavior & lag header
- **read-after-write.AC4.1 Failure:** A malformed / schema-invalid AppView response body is passed through untouched (no munge, no error).
- **read-after-write.AC4.2 Failure:** When quote-post hydration's AppView call fails or the URI is unknown, the post still renders with an `app.bsky.embed.record#viewNotFound` embed.
- **read-after-write.AC4.3 Success:** `Atproto-Upstream-Lag` equals milliseconds since the oldest merged record's `indexed_at`, set only when local records were merged.
- **read-after-write.AC4.4 Edge:** When the AppView's `atproto-repo-rev` equals the current repo rev (nothing unindexed), the response is passed through unchanged with no lag header.

### read-after-write.AC5: Rev-faithful selection
- **read-after-write.AC5.1 Success:** `get_records_since_rev` returns exactly the records written in commits with `rev >` the AppView header rev (bucketed into profile + posts).
- **read-after-write.AC5.2 Edge:** A record created then deleted since the header rev reads back as absent (not merged).
- **read-after-write.AC5.3 Failure:** A missing `atproto-repo-rev` header yields empty `LocalRecords` and no munge.

### read-after-write.AC6: Embed hydration
- **read-after-write.AC6.1 Success:** Image and external embeds are hydrated locally (no AppView call).
- **read-after-write.AC6.2 Success/Failure:** A record (quote) embed is hydrated via one service-auth'd `getPosts` call on success, and degrades to `#viewNotFound` on failure without dropping the post.

### read-after-write.AC7: Fast path preserved
- **read-after-write.AC7.1 Success:** Non-munged `app.bsky.*` / `chat.bsky.*` / `com.atproto.moderation.*` NSIDs continue to stream verbatim; existing `service_proxy.rs` tests pass unchanged.

## Glossary

- **AppView**: The Bluesky-operated (or Bluesky-compatible) service that indexes firehose events into queryable `app.bsky.*` views (feeds, threads, profiles). It is eventually consistent — it lags behind the PDS's own repo by however long indexing takes.
- **PDS (Personal Data Server)**: The server that owns a user's repo and is the source of truth for their records; ezpds's own server implementation. Reads served by the PDS itself are always fully up to date; reads proxied to the AppView are not.
- **Read-after-write**: The pattern (borrowed from the reference PDS) of patching a stale downstream read with the requester's own fresher writes, so a user immediately sees the effects of their own actions.
- **Pipethrough / proxy**: The mechanism by which the PDS forwards `app.bsky.*` (and similar) XRPC requests to the configured AppView and relays the response back to the client, rather than answering them itself.
- **NSID**: Namespaced ID — the dotted identifier for an XRPC method or lexicon type (e.g. `app.bsky.feed.getTimeline`), AT Protocol's naming scheme for RPC methods and record types.
- **XRPC**: AT Protocol's HTTP-based RPC convention (`/xrpc/{nsid}`) used for both queries and procedures.
- **Repo / commit / rev**: A user's repo is the versioned, content-addressed tree of their records (Merkle Search Tree); each write produces a new signed commit with a monotonically increasing `rev` string, used here as the freshness boundary between "AppView has seen this" and "AppView hasn't yet."
- **`atproto-repo-rev` header**: An AppView response header stating the repo revision the AppView had indexed as of that response — the mechanism this design uses to find writes made since.
- **Firehose**: The append-only stream of repo commit events a PDS emits and the AppView (among others) consumes to build its index. Locally, ezpds persists this stream in `repo_seq` (`db::firehose_seq`).
- **`indexed_at`**: A per-record timestamp used in feed ordering. ezpds has no true equivalent (it doesn't index its own records), so this design substitutes the firehose commit's `sequenced_at`.
- **MST (Merkle Search Tree)**: The authenticated, versioned data structure backing an AT Protocol repo; used here to read back the current value (or absence, if deleted) of a record by collection/rkey.
- **Munge / munging**: This document's term for the transformation that rewrites/injects local records into a proxied AppView response body. Not an AT Protocol term — an internal name for the patching step.
- **`MungeFn`**: The internal function-signature contract each of the six endpoint-specific munges implements, operating on an untyped `serde_json::Value` rather than a typed lexicon struct.
- **`LocalViewer`**: The internal component that turns a raw local record (post, profile) into the JSON "view" shape (`postView`, `profileViewBasic`, etc.) that AppView responses use.
- **`LocalRecords`**: The internal struct holding the requester's records written since the AppView's last-seen rev, bucketed into profile vs. posts.
- **`Atproto-Upstream-Lag` header**: A response header this design adds, reporting milliseconds elapsed since the oldest merged local record, so clients/observability can see how far behind the AppView currently is.
- **Service-auth JWT**: A short-lived, PDS-signed JWT used to make authenticated calls on a user's behalf to another service (here, the AppView) — reused from the existing `getServiceAuth` / `service_proxy.rs` machinery to fetch quote-post data during embed hydration.
- **Embed (image / external / record)**: AT Protocol's mechanism for attaching rich content to a post — inline images, an external-link card, or a "quote post" referencing another record (`record` / `recordWithMedia`).
- **`#viewNotFound`**: The AT Protocol lexicon's typed "couldn't resolve this embed" variant (`app.bsky.embed.record#viewNotFound`), used here as the degrade-gracefully outcome when a quoted post can't be hydrated.
- **CDN URL (`cdn_url`)**: The base URL used to build image URLs for blobs (avatars, banners, post images); defaults to Bluesky's `cdn.bsky.app`, which lazily fetches blobs from the PDS on first request.
- **Functional Core / Imperative Shell**: The project's overall architectural pattern (pure logic vs. side-effecting orchestration), relevant here because `read_after_write/` is explicitly placed as a crate-root orchestration module (like `record_write.rs`) rather than under the pure `db/`/`auth/` layers.

## Architecture

Read-after-write patches the AppView's eventual-consistency lag by re-reflecting the requesting account's own recent writes — read back out of the local repo (the authoritative, strongly-consistent record store) — into the proxied `app.bsky` response before it reaches the client. It is a per-user, per-request visibility layer, not a cache: there is no write-side state and nothing to invalidate.

**New crate-root module `crates/pds/src/read_after_write/`** (a directory, mirroring the reference PDS's own `read-after-write/` layout and ezpds's precedent of crate-root orchestration helpers such as `record_write.rs`, `genesis.rs`, `plc_ops.rs` — not under `routes/`, since it is shared logic the router calls; not in `auth/`/`db/`, since it is neither pure-auth nor a bare query):

- `mod.rs` — the `pipethrough_munged` orchestrator and `LocalRecords` selection (`get_records_since_rev`).
- `viewer.rs` — `LocalViewer`: turns raw local records into lexicon *view* shapes (profiles, posts, embeds).
- `munge.rs` — the six per-endpoint munge functions.
- `types.rs` — `LocalRecords`, `RecordDescript`, and the `MungeFn` signature.

**Interception seam.** `app.rs::xrpc_handler` today branches `app.bsky.*` → `proxy_xrpc` (streamed). We add a static set of the six munged NSIDs; a match routes them to `read_after_write::pipethrough_munged(state, nsid, did, req, munge_fn)` instead of the streaming proxy. Every other NSID keeps the untouched streaming fast path. This mirrors how `getPreferences`/`putPreferences` are already special-cased ahead of the catch-all — the same dispatch idiom, one branch point.

**Buffer/stream split.** `proxy_xrpc` currently does `Body::from_stream(...)` and never buffers. Munging needs the whole body, so we extract a shared inner that performs the request / service-auth-JWT mint / send and returns the raw `reqwest::Response`. The existing path streams it; the munge path buffers it (bounded), reads the `atproto-repo-rev` response header, and deserializes to `serde_json::Value`. The streaming hot path for all other `app.bsky.*` is unchanged.

**`MungeFn` contract** — the seam every endpoint plugs into:

```rust
// async closure shape; operates on serde_json::Value to avoid vendoring the
// entire app.bsky lexicon type tree — each munge touches only the fields it rewrites.
async fn munge(
    viewer: &LocalViewer,
    original: serde_json::Value,   // parsed AppView response body
    local: &LocalRecords,          // the requester's unindexed records
    requester: &str,               // authenticated DID
) -> serde_json::Value             // munged body
```

**Data flow (munged NSID):** inbound request → shared inner proxy to AppView → buffer body + read `atproto-repo-rev` → `get_records_since_rev` builds `LocalRecords` → if empty, return original; else run `munge_fn` via `LocalViewer` → serialize + attach `Atproto-Upstream-Lag` → respond. Any error at any step → return the buffered original.

## Existing Patterns

- **Crate-root orchestration modules.** `record_write.rs`, `genesis.rs`, `plc_ops.rs` are shared, non-route orchestration helpers that compose `db/` queries with `repo-engine` calls. `read_after_write/` follows this precedent rather than living in `routes/` (one-file-per-endpoint) or `auth/`/`db/` (pure/queries only), per `crates/pds/CLAUDE.md`.
- **Catch-all interception ahead of the proxy.** `get_preferences.rs`/`put_preferences.rs` are registered ahead of the `/xrpc/{method}` catch-all so local handling wins over proxying. The six munged NSIDs use the same "handle locally before proxying" principle, expressed as a branch inside `xrpc_handler` (they share one handler shape, so a match set is cleaner than six route registrations).
- **Service-auth minting.** `service_proxy.rs::mint_service_auth` (delegating to `auth::signing_key::mint_account_service_auth`) is reused verbatim for the shared inner proxy and for the quote-post `getPosts` hydration call — the same path `getServiceAuth` uses, so the three never drift.
- **Repo reads.** `db::accounts::get_repo_root_cid` → `SqliteBlockStore::new(db, did)` → `repo_engine::Repository::open` → `repo_engine::get_record_json` / `list_records_json`, as used by `routes/get_record.rs` and `routes/list_records.rs`.
- **Firehose log queries.** `db::firehose_seq` owns `repo_seq` reads (`events_in_range`, `decode_stored_event`); the new since-rev commit scan is added here, keeping SQL in `db/`.
- **Proxy integration tests.** `service_proxy.rs` tests (wiremock `MockServer`, `state_with_appview`, `seed_account_with_repo`, `bearer`) are the template for the munge integration tests.

**Divergences from the reference, chosen deliberately:**
- Unresolvable quote-post embeds degrade to `app.bsky.embed.record#viewNotFound` and the post still renders, rather than the reference dropping the whole post — preserving the "your post appears" guarantee even when a quote can't resolve.
- Explicit actor-guard on `getAuthorFeed`: own posts are injected only when the `actor` query param resolves to the requester, never into another user's author feed (the reference is ambiguous here).

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Interception seam, module scaffold, config
**Goal:** Route the six munged NSIDs through a buffered pass-through path that is behaviorally identical to the current proxy, with no munging yet — establishing the seam without changing observable behavior.

**Components:**
- `crates/pds/src/read_after_write/` scaffold: `mod.rs` (`pipethrough_munged`, currently buffer-and-return), `types.rs` (`LocalRecords`, `RecordDescript`, `MungeFn`), empty `viewer.rs`/`munge.rs`. `// pattern:` comments per crate convention.
- `crates/pds/src/routes/service_proxy.rs` — extract a shared inner (request/JWT-mint/send → raw `reqwest::Response`); existing `proxy_xrpc` streams it, new buffered path consumes it.
- `crates/pds/src/app.rs::xrpc_handler` — static six-NSID set; branch to `pipethrough_munged` (with a no-op munge) instead of `proxy_xrpc`.
- `crates/common` config — add `[appview] cdn_url` (env `EZPDS_APPVIEW_CDN_URL`), default `https://cdn.bsky.app`.

**Dependencies:** None (first phase).

**Done when:** Workspace builds; existing `service_proxy.rs` tests pass unchanged; a request to each of the six NSIDs returns the AppView response body verbatim (buffered) with correct status/content-type.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Rev-faithful local-record selection
**Goal:** Build `LocalRecords` from the requester's unindexed writes, using the AppView's `atproto-repo-rev` header as the freshness boundary.

**Components:**
- `crates/pds/src/db/firehose_seq.rs` — query returning this DID's `commit` events newest-first above a seq floor (raw rows + `sequenced_at`), for decode-and-filter in the orchestrator.
- `crates/pds/src/read_after_write/mod.rs::get_records_since_rev` — parse `atproto-repo-rev`; walk commit events newest-first, stopping at `rev <= header_rev`; collect distinct `(collection, rkey)` with newest `sequenced_at`; read current MST value per key (`None` ⇒ deleted ⇒ skip); bucket into `profile` (`app.bsky.actor.profile/self`) + `posts` (`app.bsky.feed.post/*`).
- `Atproto-Upstream-Lag` computation (ms since oldest merged `indexed_at`); header attached when `count > 0`.

**Dependencies:** Phase 1.

**Done when:** Unit tests pass for: records-since-rev returns exactly the unindexed set (`read-after-write.AC5.1`); a delete-since-rev reads back as absent (`read-after-write.AC5.2`); missing `atproto-repo-rev` header ⇒ empty `LocalRecords`, no munge (`read-after-write.AC5.3`); lag header value derives from oldest record (`read-after-write.AC4.3`).
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: `LocalViewer` hydration
**Goal:** Turn raw local records into lexicon view shapes, including embeds.

**Components:**
- `crates/pds/src/read_after_write/viewer.rs::LocalViewer` — constructed with `state`, requester `did`, `handle` (`db::accounts::get_session_account`), and the local profile record.
- Profile views: `profile_view_basic`, `update_profile_view`, `update_profile_detailed` (overwrite displayName/description/avatar/banner).
- Image URLs: blob ref → `{cdn_url}/img/{kind}/plain/{did}/{cid}@jpeg`.
- `post_view`: uri/cid/author/record/indexedAt, zero counts; embed hydration for `images` + `external` (local), `record`/`recordWithMedia` quote-posts via one service-auth'd `app.bsky.feed.getPosts` call, degrading to `#viewNotFound`.

**Dependencies:** Phase 2 (consumes `LocalRecords`).

**Done when:** Unit tests pass for: post→`postView` with local author (`read-after-write.AC1.4`); profile overwrite of all four fields (`read-after-write.AC2.3`); CDN URL construction from a blob ref (`read-after-write.AC2.4`); image/external embed hydration (`read-after-write.AC1.5`); quote-post hydration success and `#viewNotFound` fallback (`read-after-write.AC6.2`).
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Profile munges (`getProfile`, `getProfiles`)
**Goal:** Reflect a local profile edit immediately.

**Components:**
- `crates/pds/src/read_after_write/munge.rs` — `get_profile` (overwrite when `local.profile` set and `original.did == requester`); `get_profiles` (overwrite the entry whose `did == requester`, others untouched).
- Wire both into the `xrpc_handler` munge dispatch.

**Dependencies:** Phase 3.

**Done when:** Integration tests (wiremock AppView) pass: stale AppView profile + fresh local record ⇒ response shows local fields + `Atproto-Upstream-Lag` (`read-after-write.AC2.1`); `getProfiles` batch munges only the requester's entry (`read-after-write.AC2.2`); no local profile ⇒ passthrough (`read-after-write.AC2.5`).
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Feed munges (`getTimeline`, `getAuthorFeed`, `getActorLikes`)
**Goal:** Inject the requester's fresh posts into their feeds and refresh own-authored items.

**Components:**
- `read_after_write/munge.rs` — `insert_posts_in_feed` (filter `indexed_at` newer than the page's oldest item, hydrate, splice newest-first by `indexed_at`); `get_timeline` (insert + author refresh); `get_author_feed` (insert + refresh **only when `actor` resolves to requester**); `get_actor_likes` (author refresh on own-authored items, no insertion).
- Actor-param resolution helper (handle/DID → requester check).

**Dependencies:** Phase 3.

**Done when:** Integration tests pass: fresh post absent from AppView timeline appears at top (`read-after-write.AC1.1`); own `getAuthorFeed` injects, another actor's does not (`read-after-write.AC1.2`, `read-after-write.AC1.6`); `getActorLikes` refreshes own author, inserts nothing (`read-after-write.AC1.3`); posts spliced in chronological order (`read-after-write.AC1.7`).
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Thread munge (`getPostThread`)
**Goal:** Show a just-created post's thread, and inject own unindexed replies.

**Components:**
- `read_after_write/munge.rs::get_post_thread` — when AppView returns a `threadViewPost`, splice the requester's unindexed replies into the reply tree by position and refresh the focus author; when AppView returns `400 NotFound` and the requested URI is one of `local.posts`, build the `threadViewPost` from the local record (parent chain resolved from AppView where possible).
- `pipethrough_munged` special-case: for `getPostThread`, a `400 NotFound` is a munge trigger, not a passthrough.

**Dependencies:** Phase 3 (post hydration), Phase 5 (`insert`/tree helpers as applicable).

**Done when:** Integration tests pass: AppView `400 NotFound` for a just-created post ⇒ thread reconstructed locally (`read-after-write.AC3.1`); own unindexed reply spliced into an existing thread (`read-after-write.AC3.2`); non-requester thread passthrough (`read-after-write.AC3.3`).
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Best-effort hardening, docs, Bruno
**Goal:** Guarantee graceful fallback across all failure modes and document the surface.

**Components:**
- `pipethrough_munged` fallback ladder: non-2xx passthrough (except `getPostThread` NotFound); unparseable body ⇒ buffered passthrough; munge/hydration error ⇒ log `warn` + passthrough; response buffer cap (~10 MiB) overflow ⇒ upstream error envelope.
- `bruno/` — example `.bru` requests for the six munged endpoints (documentation; catch-all path coverage is unchanged, so `bruno-check` stays green).
- `crates/pds/CLAUDE.md` — document `read_after_write/` and the `service_proxy.rs` entry; note the `[appview] cdn_url` config.

**Dependencies:** Phases 4–6.

**Done when:** Integration tests pass: malformed AppView JSON ⇒ original passed through (`read-after-write.AC4.1`); quote-hydration AppView failure ⇒ post still renders with `#viewNotFound` (`read-after-write.AC4.2`); `rev` header equal to current repo rev ⇒ passthrough, no lag header (`read-after-write.AC4.4`); `just ci-pds` green.
<!-- END_PHASE_7 -->

## Additional Considerations

**Error handling.** The entire selection + munge pipeline runs inside a best-effort envelope; the raw buffered AppView response is the fallback for every failure. This is a UX enhancement layer — correctness of the underlying proxied read is never contingent on it.

**Retention caveat.** Records are selected by scanning `repo_seq`. If `firehose_gc` has pruned commits in the `(header_rev, now]` window, those records are silently missed. Acceptable: the GC keeps the recent frontier that read-after-write actually cares about (AppView lag is seconds), and the layer is best-effort by design.

**Timestamp source.** ezpds stores no per-record `indexedAt`. The commit's `repo_seq.sequenced_at` (RFC 3339) is reused as each record's `indexed_at` — a real server-side timestamp, more accurate than the record's self-reported `createdAt`.

**Image CDN.** `cdn_url` defaults to `https://cdn.bsky.app`, which lazily fetches blobs from this PDS on first request (the same mechanism the reference relies on); a freshly-set avatar resolves after the CDN's first fetch. Operators pointing at a non-bsky AppView override `EZPDS_APPVIEW_CDN_URL`.

**Scope.** Read-after-write runs only for the authenticated requester (the six NSIDs sit behind the `AuthenticatedUser` gate), and every munge rewrites only records where `did == requester`. No new auth scope surface.
