# Read-After-Write — Test Requirements

Maps every acceptance criterion in `docs/design-plans/2026-07-03-read-after-write.md`
(read-after-write.AC1.1 … AC7.1 — 27 cases across AC1..AC7) to its verification method:
an **automated test** (unit | integration | e2e) at a specific inline-test location, or
**documented human verification** where automation is insufficient.

## Conventions

- **Test placement.** This project has no separate `tests/` directory for these crates.
  Tests live inline in `#[cfg(test)] mod tests` within the crate source file they
  exercise (e.g. `crates/pds/src/read_after_write/mod.rs`,
  `crates/pds/src/routes/service_proxy.rs`). Paths below are the source file whose
  inline test module hosts the test.
- **Test types.**
  - **unit** — a pure/near-pure function tested in-process with hand-built
    `serde_json::Value` / `RecordDescript` / `LocalRecords` inputs; no HTTP, no AppView.
  - **integration** — drives the assembled router (`app(state).oneshot(...)`) with a
    **wiremock `MockServer`** standing in for the AppView, per the existing
    `service_proxy.rs` pattern (`state_with_appview`, `seed_account_with_repo`,
    `put_record_request`, `bearer`). Real local repo writes populate `repo_seq`; the mock
    supplies the `atproto-repo-rev` header and the stale AppView body.
  - **e2e / live** — a check against the **real Bluesky AppView** (or a real deployed
    PDS↔AppView pair). Reserved for behavior that wiremock cannot faithfully reproduce
    (real `atproto-repo-rev` emission, real CDN image resolution). See
    [Human Verification](#human-verification).
- **Wiremock is the AppView.** Integration tests never call the real AppView. The mock
  returns a canned body + headers, so any AC that depends on *the real AppView's actual
  behavior* is flagged for a live check even when a wiremock integration test also exists.
- **Best-effort invariant.** Every munge path falls back to the raw buffered AppView
  response on any failure. Several ACs are *negative* (passthrough) assertions; these are
  fully automatable and require no live check.
- **Two deliberate divergences from the reference PDS**, both asserted by automated tests:
  1. Unresolvable quote embed ⇒ `app.bsky.embed.record#viewNotFound`, post still renders
     (reference drops the post) — AC4.2 / AC6.2.
  2. `getAuthorFeed` actor-guard: own posts injected only when `actor` resolves to the
     requester — AC1.2 / AC1.6.

---

## AC1: Own fresh posts appear in feeds

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC1.1** Success — fresh post at top of munged timeline | integration | `crates/pds/src/read_after_write/mod.rs` (or `munge.rs` test mod) | Write a post; mock `getTimeline` returning a feed without it + stale `atproto-repo-rev`; assert the post appears at the top as a `feedViewPost` with a local-author `postView`. (Phase 5 Task 1) |
| **AC1.2** Success — appears in own `getAuthorFeed` | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock `getAuthorFeed?actor=<requester-did>`; write a post; assert it is injected. Exercises the actor-guard positive branch. (Phase 5 Task 2) |
| **AC1.3** Success — `getActorLikes` refreshes own author, inserts nothing | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock `getActorLikes` whose feed has a requester-authored item; fresh local profile; assert author view refreshed and feed length unchanged (no insertion). (Phase 5 Task 3) |
| **AC1.4** Success — post → `postView` with local author + zero counts | unit | `crates/pds/src/read_after_write/viewer.rs` | Bare text post `RecordDescript` → `post_view`; assert `author` (did/handle/displayName/avatar), `record` value, and `likeCount`/`replyCount`/`repostCount == 0`. (Phase 3 Task 2) |
| **AC1.5** Success — image/external embed → CDN URLs / external view | unit | `crates/pds/src/read_after_write/viewer.rs` | Images-embed and external-embed posts hydrate to `#view` with `image_url(...)` thumb/fullsize and external card, **no AppView call**. (Phase 3 Task 2) See live note on CDN resolution. |
| **AC1.6** Failure — another actor's `getAuthorFeed` not injected (passthrough) | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock `getAuthorFeed?actor=<other-did>` returning another user's feed; local posts present; assert response byte-equals the AppView body (actor-guard negative branch — divergence #2). (Phase 5 Task 2) |
| **AC1.7** Edge — multiple injected posts spliced newest-first by `indexed_at` | integration (+ optional unit) | `crates/pds/src/read_after_write/mod.rs` / `munge.rs`; optional focused unit on `insert_posts_in_feed` in `viewer.rs` | Write two posts with distinct `indexed_at`; assert newest-first splice ordering relative to older existing feed items. (Phase 5 Task 1; ordering helper Phase 3 Task 4) |

**Live check flag:** AC1.5 verifies *URL construction*, not that the CDN serves an actual
image. Real image resolution is a live check (see Human Verification).

---

## AC2: Profile edits reflect immediately

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC2.1** Success — stale AppView `getProfile` + local record ⇒ local fields + lag header | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Write a profile record; mock `getProfile` (did == requester, stale displayName) + `atproto-repo-rev` older than the profile commit rev; assert `displayName`/`description` come from local record and `Atproto-Upstream-Lag` header present. (Phase 4 Task 2) |
| **AC2.2** Success — `getProfiles` batch overwrites only requester's entry | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock `getProfiles` with two profiles (requester + other DID); local profile present; assert only requester's entry overwritten, the other byte-identical. (Phase 4 Task 3) |
| **AC2.3** Success — `update_profile_detailed` overwrites displayName/description/avatar/banner | unit | `crates/pds/src/read_after_write/viewer.rs` | Given a `profileViewDetailed` + local profile record with all four fields, assert all four overwritten from the local record. (Phase 3 Task 1) |
| **AC2.4** Success — avatar/banner blob ref ⇒ `{cdn_url}/img/{kind}/plain/{did}/{cid}@jpeg` | unit | `crates/pds/src/read_after_write/viewer.rs` | Assert `image_url("avatar", cid)` builds the exact CDN URL from a blob ref's `ref.$link`. (Phase 3 Task 1) |
| **AC2.5** Failure — no local profile record ⇒ AppView profile passthrough | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Same mock as AC2.1 but no local profile write (header rev current); assert response equals the AppView body, no lag header. (Phase 4 Task 2) |

**Live check flag:** AC2.4 verifies the URL *string*; that a freshly-set avatar/banner
CDN URL actually resolves to an image (the CDN lazily fetches the blob from this PDS on
first request) is a live check.

---

## AC3: Own thread renders immediately

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC3.1** Success — AppView `400 NotFound` ⇒ `threadViewPost` reconstructed from local record | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Write a top-level post; mock `getPostThread?uri=<post>` returning `400 {"error":"NotFound"}`; assert response is `200` with a `threadViewPost` whose `post.uri == <post>` and local author. Exercises the NotFound-as-munge-trigger seam (Phase 6 Task 1). |
| **AC3.2** Success — own unindexed reply spliced into existing thread | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock `getPostThread` returning a `threadViewPost` for a parent; write a local reply to it; assert the reply appears in `thread.replies` as a `threadViewPost`. (Phase 6 Task 2) |
| **AC3.3** Failure — non-requester thread, no local replies ⇒ passthrough | integration | `crates/pds/src/read_after_write/mod.rs` / `munge.rs` | Mock a `threadViewPost` for another user's post, no local replies; assert response equals the AppView body. (Phase 6 Task 2) |

**Live check flag:** AC3.1 depends on the AppView returning `400 NotFound` for a
just-created post. Wiremock reproduces the *shape*; that the **real** AppView actually
emits `400 NotFound` (rather than an empty/blocked/other envelope) for an un-indexed post
is a live check.

---

## AC4: Best-effort behavior & lag header

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC4.1** Failure — malformed/schema-invalid AppView body ⇒ untouched passthrough | integration | `crates/pds/src/read_after_write/mod.rs` | Mock e.g. `getTimeline` returning `200` with a non-JSON / schema-invalid body + a fresh local write; assert client receives the AppView body untouched, no 500. (Phase 7 Task 1) |
| **AC4.2** Failure — quote hydration fails / URI unknown ⇒ post renders with `#viewNotFound` | integration | `crates/pds/src/read_after_write/mod.rs` / `viewer.rs` | Mock `getPosts` failing (5xx or omitted URI) during a `getTimeline` munge with a quote-post; assert the injected post renders with `app.bsky.embed.record#viewNotFound` and is present (divergence #1). (Phase 7 Task 1; core in Phase 3 Task 3) |
| **AC4.3** Success — lag = ms since oldest merged record's `indexed_at`, set only when merged | unit | `crates/pds/src/read_after_write/mod.rs` | With a known-old `indexed_at` in a `LocalRecords`, assert `local_lag_ms` is positive and derived from the oldest record; assert `None` when no records merged. (Phase 2 Task 2) |
| **AC4.4** Edge — `atproto-repo-rev` == current repo rev ⇒ passthrough, no lag header | integration | `crates/pds/src/read_after_write/mod.rs` | Mock `getProfile` with `atproto-repo-rev` equal to the account's current repo rev (no unindexed writes); assert passthrough, no `Atproto-Upstream-Lag` header. (Phase 7 Task 1) |

**Live check flag:** none of AC4 requires the real AppView — all four are fully covered
by unit + wiremock integration tests (they test *this PDS's* fallback logic, which the
mock can drive deterministically). The real-AppView aspect of AC4.4 (does the real
AppView emit the header at all) is covered under AC7/live below.

---

## AC5: Rev-faithful selection

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC5.1** Success — `get_records_since_rev` returns exactly commits with `rev >` header rev, bucketed | integration | `crates/pds/src/read_after_write/mod.rs` | Write two posts + a profile after a captured `header_rev`; assert the returned `LocalRecords` bucket exactly those (profile + posts) and exclude records at/below the header rev. Uses `put_record_request` so real `repo_seq` commits exist. (Phase 2 Task 2) |
| **AC5.2** Edge — created-then-deleted since header rev reads back absent | integration | `crates/pds/src/read_after_write/mod.rs` | Create a post then delete it (both after `header_rev`); assert it is absent from `posts` (MST current value `None` ⇒ skip). (Phase 2 Task 2) |
| **AC5.3** Failure — missing `atproto-repo-rev` header ⇒ empty `LocalRecords`, no munge | unit | `crates/pds/src/read_after_write/mod.rs` | Call `get_records_since_rev(..., header_rev = None)`; assert `LocalRecords::default()` (`count == 0`). (Phase 2 Task 2) |
| **AC5.1 support** — `recent_commits_for_did` DID-scoped, newest-first, limit-bounded | unit | `crates/pds/src/db/firehose_seq.rs` | Insert commit events for the DID + one for another DID + one non-commit event; assert only this DID's commit rows return, newest-first, respecting `limit`. (Phase 2 Task 1) |

**Note:** AC5.1/AC5.2 are classed **integration** because they require real repo writes
through the router to populate `repo_seq` + the MST, even though they call a selection
function directly rather than asserting on a munged HTTP response. AC5.3 is a pure unit
case (no header ⇒ short-circuit). None require the real AppView.

---

## AC6: Embed hydration

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC6.1** Success — image + external embeds hydrated locally (no AppView call) | unit | `crates/pds/src/read_after_write/viewer.rs` | Images-embed and external-embed posts → `#view` with CDN thumb/fullsize + external card; assert **no** outbound AppView request made. (Phase 3 Task 2) Overlaps AC1.5. |
| **AC6.2** Success/Failure — record (quote) embed via one `getPosts` call; `#viewNotFound` on failure | integration | `crates/pds/src/read_after_write/viewer.rs` (wiremock `getPosts`) | Success: mock `getPosts` returning the quoted post ⇒ populated `#viewRecord`. Failure: mock `getPosts` 5xx / omitting URI ⇒ embed degrades to `#viewNotFound`, post still present (divergence #1). (Phase 3 Task 3) |

**Live check flag:** AC6.2's `getPosts` hydration is a *proxied AppView call*; wiremock
covers both branches deterministically. A live check confirms the real AppView's
`getPosts` response shape maps correctly into `#viewRecord` (field-level parity with the
real lexicon) — see Human Verification.

---

## AC7: Fast path preserved

| Case | Type | Test location | Description |
|------|------|---------------|-------------|
| **AC7.1** Success — non-munged `app.bsky.*` / `chat.bsky.*` / `com.atproto.moderation.*` stream verbatim; existing tests pass | integration | `crates/pds/src/routes/service_proxy.rs` (test mod) | Assert a non-listed `app.bsky.*` NSID (e.g. `app.bsky.graph.getFollows`) plus a `chat.bsky.*` / `com.atproto.moderation.*` request still go through streaming `proxy_xrpc` verbatim (no buffering, no lag header); confirm the six-NSID branch captures nothing outside the set. All pre-existing `service_proxy.rs` tests pass unchanged after the `proxy_request` extraction. (Phase 7 Task 2; groundwork Phase 1 Task 4) |

**Phase 1 seam check (infrastructure, not an AC):** Phase 1 Task 4 adds a passthrough
integration test — each of the six munged NSIDs returns the AppView body verbatim through
`pipethrough_munged` when no `atproto-repo-rev`/local records exist. It hosts in
`crates/pds/src/app.rs` (or `service_proxy.rs`) test mod and guards the seam wiring; it is
groundwork for AC7.1, not a distinct AC.

---

## Coverage summary

| AC group | Cases | Automated (unit) | Automated (integration) | Needs live e2e confirmation |
|----------|-------|------------------|-------------------------|-----------------------------|
| AC1 | 7 | AC1.4, AC1.5 | AC1.1, AC1.2, AC1.3, AC1.6, AC1.7 | AC1.5 (CDN image resolves) |
| AC2 | 5 | AC2.3, AC2.4 | AC2.1, AC2.2, AC2.5 | AC2.4 (avatar/banner CDN resolves) |
| AC3 | 3 | — | AC3.1, AC3.2, AC3.3 | AC3.1 (real AppView emits `400 NotFound`) |
| AC4 | 4 | AC4.3 | AC4.1, AC4.2, AC4.4 | — |
| AC5 | 3 | AC5.3 (+ `recent_commits_for_did`) | AC5.1, AC5.2 | — |
| AC6 | 2 | AC6.1 | AC6.2 | AC6.2 (real `getPosts` shape parity) |
| AC7 | 1 | — | AC7.1 | AC7.1 (real AppView emits `atproto-repo-rev`) |

**All 27 cases map to at least one automated test.** Five cases additionally warrant a
one-time live confirmation because wiremock cannot reproduce the real AppView's/CDN's
actual behavior (only its response *shape*).

---

## Human Verification

Wiremock integration tests fully cover this PDS's own logic — selection, hydration,
munging, and the best-effort fallback ladder — because the mock deterministically supplies
whatever the AppView "would" return. What the mock **cannot** do is prove that the *real*
Bluesky AppView and CDN behave the way the tests assume. The following need a one-time
live end-to-end pass against the real AppView (`https://api.bsky.app` / a Bluesky-compatible
AppView) and the real image CDN (`https://cdn.bsky.app`), run from a deployed ezpds PDS
federated into the network with a real account.

### HV-1 — Real AppView emits the `atproto-repo-rev` response header (underpins AC5.1, AC7.1, AC4.4)
- **Why not automated:** The entire selection boundary keys off the AppView's
  `atproto-repo-rev` response header. Wiremock *sets* this header by fiat; it proves our
  parsing, not that the real AppView emits it (or emits it on these six endpoints, with a
  value comparable via TID string-ordering to our repo revs).
- **Approach:** From a deployed PDS, `curl -i` a proxied `getProfile`/`getTimeline` for a
  real account through the PDS and inspect response headers for `atproto-repo-rev`. Confirm
  the value is a repo rev (TID) that string-compares correctly against a freshly-written
  local commit rev. If the header is absent, read-after-write silently no-ops (AC5.3
  path) — this check confirms it does not.

### HV-2 — Fresh avatar/banner/image CDN URLs actually resolve to images (confirms AC2.4, AC1.5, AC2.3)
- **Why not automated:** AC2.4/AC1.5 assert the *constructed URL string*. Whether
  `https://cdn.bsky.app/img/avatar/plain/{did}/{cid}@jpeg` returns real image bytes depends
  on the CDN lazily fetching the blob from this PDS on first request — an external,
  networked, time-dependent behavior no unit test can assert.
- **Approach:** On a deployed, federated PDS: set a new avatar + banner and create a post
  with an image embed, then immediately fetch own `getProfile`/`getTimeline` through the
  PDS. Confirm the munged response's `avatar`/`banner`/embed `thumb`/`fullsize` URLs load
  actual images in a browser (allowing for the CDN's first-fetch warm-up). Verify the blob
  is reachable from the CDN's perspective (PDS `getBlob` publicly resolvable).

### HV-3 — Real AppView returns `400 NotFound` for a just-created, un-indexed post (confirms AC3.1)
- **Why not automated:** AC3.1's trigger is the *real* AppView not yet knowing a post.
  Wiremock returns a canned `400 {"error":"NotFound"}`; only a live race proves the real
  AppView actually responds this way (vs. an empty thread, a `blockedPost`, or a different
  error code) in the sub-indexing-lag window.
- **Approach:** On a deployed PDS, create a post and *immediately* call `getPostThread` for
  it through the PDS (before AppView indexing). Confirm the un-munged upstream would be
  `400 NotFound`, and that the munged response is a `200` locally-reconstructed
  `threadViewPost`. Repeat until the timing window is caught, or temporarily point at a
  known-lagging AppView.

### HV-4 — Real `getPosts` response shape maps correctly into a quote `#viewRecord` (confirms AC6.2 success branch)
- **Why not automated:** Wiremock returns a hand-authored `getPosts` body; a live check
  confirms the real AppView's actual `getPosts` `posts[]` shape hydrates into a valid
  `app.bsky.embed.record#viewRecord` with the fields clients expect (author, value,
  embeds, labels).
- **Approach:** On a deployed PDS, create a quote post referencing a real, already-indexed
  post, then fetch own `getTimeline`/`getAuthorFeed`. Confirm the quoted record renders as
  a populated `#viewRecord` (not `#viewNotFound`) in a real Bluesky client.

### HV-5 — End-to-end "your own fresh write appears immediately" acceptance (Definition of Done, spans AC1/AC2/AC3)
- **Why not automated:** The headline product guarantee — "a user always sees their own
  fresh writes before the AppView indexes them" — is only *fully* demonstrated live, since
  it is defined relative to real AppView lag. The wiremock tests prove each mechanism; this
  proves the mechanisms compose against reality.
- **Approach:** On a deployed, federated PDS from a real client: (a) create a post → confirm
  it appears immediately at the top of own `getTimeline` and in own `getAuthorFeed` and its
  own `getPostThread`; (b) edit displayName/description/avatar → confirm own `getProfile`
  reflects it immediately; (c) confirm an `Atproto-Upstream-Lag` header is present on the
  munged responses while the AppView is still behind, and disappears once the AppView
  catches up. Confirm other users' data in the same responses is untouched.

### Note on divergences from the reference PDS
Both deliberate divergences are covered by **automated** tests (no live check required for
the divergence itself):
- **viewNotFound-instead-of-drop** — AC4.2 / AC6.2 failure branch
  (`crates/pds/src/read_after_write/viewer.rs` + `mod.rs`).
- **getAuthorFeed actor-guard** — AC1.2 (positive) / AC1.6 (negative)
  (`crates/pds/src/read_after_write/munge.rs` + `mod.rs`).
HV-4 exists only to confirm the *success* branch's field-level parity against the real
`getPosts`, not the divergence behavior.
