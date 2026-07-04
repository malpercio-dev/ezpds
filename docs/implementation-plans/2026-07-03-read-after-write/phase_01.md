# Read-After-Write Implementation Plan — Phase 1: Interception seam, module scaffold, config

**Goal:** Route the six read-after-write NSIDs through a buffered pass-through path that is behaviorally identical to the current streaming proxy, with no munging yet — establishing the seam and shared plumbing without changing observable behavior.

**Architecture:** Extract a shared `proxy_request` inner from `service_proxy::proxy_xrpc` that returns the raw `reqwest::Response`; the existing path streams it, a new `read_after_write::pipethrough_munged` buffers it. Add a `read_after_write/` crate-root module (scaffold only) and branch the six NSIDs to it inside `app.rs::xrpc_handler`. Add an `[appview] cdn_url` config field.

**Tech Stack:** Rust, axum 0.8, reqwest 0.12, serde/serde_json, sqlx (SQLite). All internal — no new external dependencies.

**Scope:** Phase 1 of 7 from `docs/design-plans/2026-07-03-read-after-write.md`.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase is **infrastructure** — verified operationally (builds, clippy clean, existing proxy tests still pass, and the six NSIDs still return the AppView response verbatim). It stands up the seam that later phases fill in.

**Verifies:** None (infrastructure). Partial groundwork for `read-after-write.AC7.1` (non-munged NSIDs continue to stream verbatim; existing `service_proxy.rs` tests must still pass).

---

<!-- START_TASK_1 -->
### Task 1: Add `cdn_url` to `AppViewConfig`

**Files:**
- Modify: `crates/common/src/config.rs:328-336` (add field to `AppViewConfig`)
- Modify: `crates/common/src/config.rs:347-353` (add default function near `default_appview_url`)
- Modify: `crates/common/src/config.rs` env-override block (immediately after the `EZPDS_APPVIEW_DID` override at ~line 643)

**Implementation:**

Add a `cdn_url` field to `AppViewConfig` following the exact existing pattern:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AppViewConfig {
    #[serde(default = "default_appview_url")]
    pub url: String,
    #[serde(default = "default_appview_did")]
    pub did: String,
    /// Base URL of the AppView's image CDN (scheme + authority, no trailing slash),
    /// used to build avatar/banner/embed-image URLs for the account's own not-yet-indexed
    /// records. Defaults to Bluesky's public image CDN.
    #[serde(default = "default_appview_cdn_url")]
    pub cdn_url: String,
}
```

Add the default function beside `default_appview_did`:

```rust
fn default_appview_cdn_url() -> String {
    "https://cdn.bsky.app".to_string()
}
```

Add the env override immediately after the `EZPDS_APPVIEW_DID` block:

```rust
if let Some(v) = env.get("EZPDS_APPVIEW_CDN_URL") {
    raw.appview.cdn_url = v.clone();
}
```

**Verification:**
Run: `cargo build -p common`
Expected: Builds without errors. All existing `AppViewConfig` construction sites still compile (the new field has a serde default, so TOML without `cdn_url` still deserializes; check any struct-literal constructions in tests and add `cdn_url: default_appview_cdn_url()` or a literal if the compiler flags them).

**Commit:** `feat(config): add [appview] cdn_url for read-after-write image URLs`
<!-- END_TASK_1 -->

<!-- START_SUBCOMPONENT_A (tasks 2-4) -->
<!-- START_TASK_2 -->
### Task 2: Extract shared `proxy_request` inner; expose `mint_service_auth`

**Files:**
- Modify: `crates/pds/src/routes/service_proxy.rs:58-171` (`proxy_xrpc` — refactor to call a new inner)
- Modify: `crates/pds/src/routes/service_proxy.rs:210` (`mint_service_auth` → `pub(crate)`)

**Implementation:**

Extract everything `proxy_xrpc` does up to and including `outbound.send().await` into a new `pub(crate)` function that returns the raw upstream response (or a built error `Response`), so both the streaming path and the future buffered munge path share one request-building/JWT-mint/send code path:

```rust
/// Build and send the upstream XRPC request (query passthrough, body buffering with the
/// MAX_PROXY_BODY cap, service-auth JWT mint, atproto-proxy header), returning the raw upstream
/// response. Both `proxy_xrpc` (streaming) and `read_after_write::pipethrough_munged` (buffering)
/// build on this so request construction never diverges.
pub(crate) async fn proxy_request(
    state: &AppState,
    upstream_url: &str,
    proxy_did: &str,
    nsid: &str,
    did: &str,
    moderation_guard: Option<&ModerationProxyGuard>,
    req: Request,
) -> Result<reqwest::Response, Response> {
    // ... body of current proxy_xrpc lines 67-144, returning Ok(upstream) instead of
    // continuing to the streaming build; error paths return Err(<built Response>).
}
```

Then reduce `proxy_xrpc` to:

```rust
pub async fn proxy_xrpc(
    state: &AppState,
    upstream_url: &str,
    proxy_did: &str,
    nsid: &str,
    did: &str,
    moderation_guard: Option<&ModerationProxyGuard>,
    req: Request,
) -> Response {
    let upstream = match proxy_request(state, upstream_url, proxy_did, nsid, did, moderation_guard, req).await {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };
    // existing status/content-type/location mapping + Body::from_stream(upstream.bytes_stream())
    // (current lines 146-170) unchanged.
}
```

Change `async fn mint_service_auth` (line 210) to `pub(crate) async fn mint_service_auth` so the quote-post hydration in Phase 3 can reuse it.

**Verification:**
Run: `cargo build -p pds`
Expected: Builds without errors.
Run: `cargo test -p pds --lib routes::service_proxy`
Expected: All existing `service_proxy` tests pass unchanged (streaming behavior, error passthrough, JWT mint, oversized body, query preservation, chat, moderation).

**Commit:** `refactor(pds): extract proxy_request inner shared by streaming + buffered proxy`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Scaffold the `read_after_write/` module

**Files:**
- Create: `crates/pds/src/read_after_write/mod.rs`
- Create: `crates/pds/src/read_after_write/types.rs`
- Create: `crates/pds/src/read_after_write/viewer.rs` (placeholder — `// pattern: Imperative Shell` + empty)
- Create: `crates/pds/src/read_after_write/munge.rs` (placeholder — `// pattern: Functional Core` + empty)
- Modify: the crate module list (`crates/pds/src/main.rs` or `lib.rs` — wherever sibling modules like `record_write`, `genesis`, `plc_ops` are declared with `mod ...;`) to add `mod read_after_write;`

**Implementation:**

`types.rs` (`// pattern: Functional Core`):

```rust
/// One of the requester's records selected for merging, with the metadata a munge needs.
#[derive(Debug, Clone)]
pub struct RecordDescript {
    pub uri: String,
    pub cid: String,
    /// RFC 3339 timestamp — the commit's emission time (firehose CommitEvent.time),
    /// used as the record's indexedAt for feed ordering and lag computation.
    pub indexed_at: String,
    pub record: serde_json::Value,
}

/// The requester's records written since the AppView's last-indexed rev.
#[derive(Debug, Clone, Default)]
pub struct LocalRecords {
    pub count: usize,
    pub profile: Option<RecordDescript>,
    pub posts: Vec<RecordDescript>,
}
```

The `MungeFn` seam: because Rust async closures are awkward as trait-object args, model each munge as a `pub(crate) async fn(viewer, original, local, requester) -> serde_json::Value` and dispatch by NSID in `pipethrough_munged` (a `match` on the method string). Document this in a comment in `types.rs`; no boxed-closure type is needed.

`mod.rs` (`// pattern: Imperative Shell`) — for this phase, a pass-through orchestrator:

```rust
/// Proxy a munged NSID to the AppView, buffer the response, and (in later phases) merge the
/// requester's own unindexed records. In Phase 1 this is a behavioral no-op: it buffers and
/// returns the AppView response verbatim.
pub(crate) async fn pipethrough_munged(
    state: &AppState,
    nsid: &str,
    did: &str,
    req: axum::extract::Request,
) -> axum::response::Response {
    let upstream = match crate::routes::service_proxy::proxy_request(
        state, &state.config.appview.url, &state.config.appview.did, nsid, did, None, req,
    ).await {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };
    // Buffer status + content-type + body, rebuild an axum Response. Reads the body fully
    // (response buffer cap introduced in Phase 7); returns the bytes verbatim for now.
    // ... build and return the response ...
}
```

**Verification:**
Run: `cargo build -p pds`
Expected: Builds without errors (module compiles, unused-code warnings acceptable for placeholders — but ensure `-D warnings` in later `just ci-pds` runs is satisfied by `#[allow(dead_code)]` on not-yet-used items or by the wiring in Task 4).

**Commit:** `feat(pds): scaffold read_after_write module (types + pass-through orchestrator)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Branch the six NSIDs in `xrpc_handler`

**Files:**
- Modify: `crates/pds/src/app.rs:498-593` (`xrpc_handler` — add the munged-NSID branch before the generic AppView proxy)

**Implementation:**

Define the munged set and branch to `pipethrough_munged` for those NSIDs (only when the upstream is the AppView and auth succeeded), keeping the existing `proxy_xrpc` call for everything else. The six NSIDs:

```rust
const READ_AFTER_WRITE_NSIDS: [&str; 6] = [
    "app.bsky.actor.getProfile",
    "app.bsky.actor.getProfiles",
    "app.bsky.feed.getAuthorFeed",
    "app.bsky.feed.getPostThread",
    "app.bsky.feed.getTimeline",
    "app.bsky.feed.getActorLikes",
];
```

After the `AuthenticatedUser` is resolved to `user.did` and the upstream is determined to be the AppView, insert the branch. Match against whatever binding form exists at the insertion point — in `app.rs`, `upstream` is unwrapped from `Option` before the AppView arm (the surrounding code uses `matches!(upstream, ProxyUpstream::Chat)` **without** `Some`), so use the same bare form:

```rust
if matches!(upstream, ProxyUpstream::AppView)
    && READ_AFTER_WRITE_NSIDS.contains(&method.as_str())
{
    return crate::read_after_write::pipethrough_munged(&state, &method, &user.did, req).await;
}
```

Place this so it runs after auth extraction (the six endpoints stay behind the same `AuthenticatedUser` gate) and before the generic `proxy_xrpc(...)` call at lines 583-592. The moderation/chat branches are untouched.

**Testing:**
Add an integration test (in `app.rs` test module or `service_proxy.rs` test module, reusing `state_with_appview`, `seed_repo_key`/`seed_account_with_repo`, `bearer`) asserting each munged NSID still returns the AppView body verbatim through the new path — e.g. mock `app.bsky.feed.getTimeline` returning `{"feed":[]}` with no `atproto-repo-rev` header and assert the client receives `{"feed":[]}` and 200. This proves the seam is wired without changing behavior.

**Verification:**
Run: `cargo test -p pds`
Expected: New passthrough test passes; all existing tests pass.
Run: `just ci-pds`
Expected: fmt, clippy (`-D warnings`), tests, audit all green.

**Commit:** `feat(pds): route read-after-write NSIDs through pipethrough_munged (no-op)`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->
