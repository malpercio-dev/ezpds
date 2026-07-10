# Read-After-Write Implementation Plan — Phase 4: Profile munges

**Goal:** Reflect a local profile edit immediately in `getProfile` and `getProfiles`.

**Architecture:** Two munge functions in `munge.rs` overwrite the requester's own profile view fields from `LocalRecords.profile`, wired into `pipethrough_munged`'s NSID dispatch. This phase turns the Phase 1 no-op path into a real munge for the two profile endpoints and establishes the end-to-end integration-test pattern (mock AppView + `atproto-repo-rev` header + local write).

**Tech Stack:** Rust, serde_json, wiremock (tests), reuse of Phase 2 selection + Phase 3 `LocalViewer`.

**Scope:** Phase 4 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC2: Profile edits reflect immediately
- **read-after-write.AC2.1 Success:** A stale AppView `getProfile` plus a fresh local profile record yields a response showing the local displayName/description, with an `Atproto-Upstream-Lag` header.
- **read-after-write.AC2.2 Success:** In a `getProfiles` batch, only the entry whose `did == requester` is overwritten; other profiles are untouched.
- **read-after-write.AC2.5 Failure:** No local profile record ⇒ the AppView profile is passed through unchanged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: `pipethrough_munged` full pipeline + NSID dispatch

**Files:**
- Modify: `crates/pds/src/read_after_write/mod.rs` (upgrade the Phase 1 pass-through to the real pipeline)

**Implementation:**

Replace the Phase 1 buffer-and-return body with the full pipeline (still best-effort — errors fall back to the buffered original; the full fallback ladder is hardened in Phase 7):

```rust
pub(crate) async fn pipethrough_munged(state, nsid, did, req) -> Response {
    // 1. proxy_request(...) -> upstream reqwest::Response (or return the Err response).
    // 2. Capture status + content-type + the `atproto-repo-rev` header value; buffer the body.
    // 3. If status is not success -> return the buffered response unchanged
    //    (getPostThread's 400 NotFound exception is added in Phase 6).
    // 4. Parse body as serde_json::Value; on parse error -> return buffered original.
    // 5. local = get_records_since_rev(state, did, header_rev.as_deref()).
    //    If local.count == 0 -> return buffered original (no lag header).
    // 6. viewer = LocalViewer::new(state, did, handle, local.profile).
    //    munged = dispatch(nsid, &viewer, parsed, &local, did).await.
    // 7. Serialize munged; attach Atproto-Upstream-Lag when local_lag_ms is Some; return 200 JSON.
    // Any error in 5-7 -> log warn + return buffered original.
}
```

Add the NSID→munge dispatch (a `match nsid { ... }`) calling the per-endpoint functions. For this phase, only `getProfile`/`getProfiles` are implemented; the other four fall through to returning `parsed` unchanged (they are filled in Phases 5–6).

Build the `LocalViewer.handle` via `db::accounts::get_session_account(&state.db, did)` (returns `SessionAccountRow { handle: Option<String>, .. }`).

**Verification:** `cargo build -p pds`; existing Phase 1 passthrough test still green (no local records ⇒ passthrough).

**Commit:** `feat(pds): pipethrough_munged full best-effort pipeline + NSID dispatch`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `get_profile` munge

**Verifies:** read-after-write.AC2.1, read-after-write.AC2.5

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs` (`// pattern: Functional Core` — pure transform over Values, aside from the viewer's async image/handle lookups)

**Implementation:**

```rust
/// getProfile returns a profileViewDetailed at the top level (has a `did` field).
pub(crate) async fn get_profile(
    viewer: &LocalViewer, original: serde_json::Value, local: &LocalRecords, requester: &str,
) -> serde_json::Value {
    // if local.profile is None -> return original.
    // if original["did"] != requester -> return original.
    // else -> viewer.update_profile_detailed(original).
}
```

**Testing (integration, wiremock AppView):**
- `read-after-write.AC2.1`: seed account + write a profile record (via `put_record_request` app.bsky.actor.profile/self) so `repo_seq` has a commit; mock `getProfile` returning a `profileViewDetailed` with `did == requester` and a stale `displayName`, plus an `atproto-repo-rev` header older than the profile commit's rev. Assert the response `displayName`/`description` come from the local record and an `Atproto-Upstream-Lag` header is present.
- `read-after-write.AC2.5`: same mock but no local profile write (header rev current) ⇒ response equals the AppView body, no lag header.

**Verification:** `cargo test -p pds` — passes.

**Commit:** `feat(pds): getProfile read-after-write munge`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `get_profiles` munge

**Verifies:** read-after-write.AC2.2

**Files:**
- Modify: `crates/pds/src/read_after_write/munge.rs`

**Implementation:**

```rust
/// getProfiles returns { profiles: [profileViewDetailed, ...] }.
pub(crate) async fn get_profiles(
    viewer: &LocalViewer, mut original: serde_json::Value, local: &LocalRecords, requester: &str,
) -> serde_json::Value {
    // if local.profile is None -> return original.
    // for each entry in original["profiles"] where entry["did"] == requester ->
    //     replace it with viewer.update_profile_detailed(entry). Others untouched.
}
```

**Testing (integration):**
- `read-after-write.AC2.2`: mock `getProfiles` returning two profiles (requester + another DID); local profile record present. Assert only the requester's entry is overwritten; the other is byte-identical to the AppView entry.

**Verification:** `cargo test -p pds` — passes; `just ci-pds` green.

**Commit:** `feat(pds): getProfiles read-after-write munge`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->
