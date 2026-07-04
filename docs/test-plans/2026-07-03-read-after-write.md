# Read-After-Write — Human Test Plan

Companion to the automated suite for the read-after-write feature (MM-226). All 27
automated acceptance criteria are covered by tests that genuinely exercise their behavior
(`cargo test -p pds read_after_write` → 55 passed / 0 failed; full pds suite 1350 / 0).

The five items below (HV-1…HV-5) cannot be reproduced by wiremock: they depend on the
**real** Bluesky AppView (`https://api.bsky.app`) and CDN (`https://cdn.bsky.app`) behavior
that the mechanism is built around — the `atproto-repo-rev` freshness header, live CDN
blob first-fetch, the AppView returning `400 NotFound` for a just-created post, and the
real `getPosts` response shape. They require a deployed, federated ezpds PDS.

## Prerequisites

- A deployed ezpds PDS federated into the atproto network (see
  `docs/project_federation_readiness.md`): `EZPDS_PUBLIC_URL` set to the DID-doc
  `serviceEndpoint`, wildcard DNS + TLS live, blobs publicly resolvable via `getBlob`.
- A real account on that PDS with a full-access session token.
- `[appview] url = https://api.bsky.app` (default) and `EZPDS_APPVIEW_CDN_URL` default
  (`https://cdn.bsky.app`).
- `curl`, a real Bluesky client (official app or a web client) authenticated to the PDS account.
- Baseline: `nix develop --impure --accept-flake-config -c cargo test -p pds read_after_write`
  green (55/55).

## HV-1 — Real AppView emits `atproto-repo-rev` (underpins AC5.1, AC7.1, AC4.4)

The entire selection boundary keys off this header; wiremock sets it by fiat.

| Step | Action | Expected |
|------|--------|----------|
| 1 | `curl -i -H "Authorization: Bearer <token>" "https://<pds-host>/xrpc/app.bsky.actor.getProfile?actor=<your-did>"` | 200; headers include `atproto-repo-rev: <value>` |
| 2 | Compare the header value (TID string-ordering) against your account's current repo rev after a fresh `putRecord` | Header value is a repo rev (TID) that string-compares sensibly (`<=` current head) |
| 3 | Repeat for `getTimeline` | Header present on this endpoint too |

If the header is absent, read-after-write silently no-ops (the AC5.3 empty-LocalRecords path).

## HV-2 — Fresh avatar/banner/image CDN URLs resolve to real images (AC2.4, AC1.5, AC2.3)

AC2.4/AC1.5 assert the constructed URL *string*; only a live CDN first-fetch proves bytes load.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From a real client, set a **new** avatar and banner on the PDS account | Write succeeds |
| 2 | Immediately (before AppView indexes) `curl -H "Authorization: Bearer <token>" "https://<pds-host>/xrpc/app.bsky.actor.getProfile?actor=<your-did>"` | Munged `avatar`/`banner` are `https://cdn.bsky.app/img/{avatar,banner}/plain/<did>/<cid>@jpeg` |
| 3 | Open those URLs in a browser (allow a few seconds for CDN first-fetch warm-up) | Actual images render (CDN lazily fetched the blob from your PDS) |
| 4 | Create a post with an image embed; immediately fetch own `getTimeline`; open the embed `thumb`/`fullsize` URLs | Images render |

## HV-3 — Real AppView returns `400 NotFound` for a just-created post (AC3.1)

AC3.1's whole trigger is the real AppView not yet knowing a post; wiremock returns a canned 400.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Create a top-level post from a real client | Write succeeds; note its `at://` uri |
| 2 | **Immediately** `curl -i -H "Authorization: Bearer <token>" "https://<pds-host>/xrpc/app.bsky.feed.getPostThread?uri=<encoded-uri>"` | 200 with a locally-reconstructed `threadViewPost` whose `post.uri == <uri>` and `post.author.did == <your-did>` |
| 3 | To confirm upstream really would 400: `curl` `https://api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=<uri>` directly (no PDS) in the same window | Direct AppView call returns `400 {"error":"NotFound"}` |
| 4 | If timing is missed, retry with a fresh post | Window eventually caught |

## HV-4 — Real `getPosts` shape maps into a quote `#viewRecord` (AC6.2 success branch)

Wiremock returns a hand-authored getPosts body; confirm the real shape hydrates correctly.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Create a **quote post** referencing a real, already-indexed post (from any account) | Write succeeds |
| 2 | Immediately fetch own `getTimeline` (or `getAuthorFeed?actor=<your-did>`) through the PDS | The quote renders as a populated `app.bsky.embed.record#viewRecord` (author, record value, embeds, labels) — **not** `#viewNotFound` |
| 3 | View the same post in a real Bluesky client | Quoted card renders correctly with author + text |

## HV-5 — End-to-end "your own fresh write appears immediately" (Definition of Done; AC1/AC2/AC3)

The headline product guarantee, only fully demonstrable against real AppView lag.

| Step | Action | Expected |
|------|--------|----------|
| 1 | From a real client on the PDS account, create a post | Appears **immediately** at the top of own `getTimeline`, in own `getAuthorFeed`, and in its own `getPostThread` — before the AppView indexes it |
| 2 | Edit displayName + description + avatar | Own `getProfile` reflects all three immediately |
| 3 | While the AppView is still behind, inspect response headers on the munged calls | `Atproto-Upstream-Lag` header present (ms since oldest merged record) |
| 4 | Wait for the AppView to catch up (poll until `atproto-repo-rev >=` your write's rev), re-fetch | `Atproto-Upstream-Lag` header **disappears**; content still correct |
| 5 | In any response that also contains other users' data (e.g. a timeline), inspect their entries | Other users' posts/profiles are byte-for-byte untouched (only your own records are merged) |

## Deliberate reference-PDS divergences (already automated — listed for reviewer awareness)

- **`#viewNotFound`-instead-of-drop** (AC4.2 / AC6.2 failure): pinned by
  `hydrate_quotes_degrades_to_empty_on_appview_5xx`, `record_embed_view_not_found_when_quote_missing`.
- **`getAuthorFeed` actor-guard** (AC1.2 positive / AC1.6 negative): pinned by
  `get_author_feed_ac1_2_injects_own_posts_when_actor_is_requester` and
  `get_author_feed_ac1_6_no_injection_for_other_actor` (byte-equal passthrough).

## Traceability (AC → automated test → manual step)

| AC | Automated test | Manual |
|----|----------------|--------|
| AC1.1 | `get_timeline_ac1_1_injects_local_post_at_top` | HV-5.1 |
| AC1.2 | `get_author_feed_ac1_2_injects_own_posts_when_actor_is_requester` | HV-5.1 |
| AC1.3 | `get_actor_likes_ac1_3_refreshes_author_only` | HV-5.5 |
| AC1.4 | `post_view_includes_author_and_zero_counts` | HV-5.1 |
| AC1.5 | `post_view_hydrates_{image,external}_embed_locally` | HV-2.4 |
| AC1.6 | `get_author_feed_ac1_6_no_injection_for_other_actor` | HV-5.5 |
| AC1.7 | `get_timeline_ac1_7_multiple_posts_chronological_order` | HV-5.1 |
| AC2.1 | `test_pipethrough_munged_ac2_1_stale_appview_plus_fresh_local_profile` | HV-5.2/3 |
| AC2.2 | `test_pipethrough_munged_ac2_2_getprofiles_overwrites_requester_only` | HV-5.5 |
| AC2.3 | `update_profile_detailed_overwrites_all_fields` | HV-2 / HV-5.2 |
| AC2.4 | `image_url_formats_correctly` | HV-2.2/3 |
| AC2.5 | `test_pipethrough_munged_ac2_5_no_local_profile` | HV-5.4 |
| AC3.1 | `test_pipethrough_munged_ac3_1_getpostthread_notfound_reconstructs` + `..._nonlocal_notfound_stays_400` | HV-3 |
| AC3.2 | `test_pipethrough_munged_ac3_2_getpostthread_splices_own_replies` | HV-5.1 |
| AC3.3 | `test_pipethrough_munged_ac3_3_getpostthread_other_user_unchanged` | HV-5.5 |
| AC4.1 | `test_pipethrough_munged_ac4_1_non_json_body_passthrough` | — |
| AC4.2 | `test_pipethrough_munged_ac4_2_quote_post_with_failed_get_posts` + `hydrate_quotes_degrades_to_empty_on_appview_5xx` | — |
| AC4.3 | `local_lag_ms_*` | HV-5.3/4 |
| AC4.4 | `test_pipethrough_munged_ac4_4_no_lag_when_current` | HV-1 / HV-5.4 |
| AC5.1 | `test_get_records_since_rev_ac5_1_returns_records_after_header_rev` + `recent_commits_for_did_*` | HV-1 |
| AC5.2 | `test_get_records_since_rev_ac5_2_excludes_deleted_records` | — |
| AC5.3 | `test_get_records_since_rev_ac5_3_none_header_rev_returns_empty` | HV-1 (absence) |
| AC6.1 | `post_view_hydrates_*` + `record_with_media_embed_nests_full_record_view_and_media` | HV-2.4 |
| AC6.2 | `hydrate_quotes_fetches_from_appview_and_populates_map` + `..._degrades_to_empty_on_appview_5xx` | HV-4 |
| AC7.1 | `non_munged_appbsky_nsid_streams_verbatim` + `read_after_write_nsids_return_appview_response_verbatim` | HV-1 |
