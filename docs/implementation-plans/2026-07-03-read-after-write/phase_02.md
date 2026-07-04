# Read-After-Write Implementation Plan — Phase 2: Rev-faithful local-record selection

**Goal:** Build `LocalRecords` from the requester's unindexed writes, using the AppView's `atproto-repo-rev` response header as the freshness boundary.

**Architecture:** A new DID-scoped, seq-descending query in `db/firehose_seq.rs` yields this account's commit events newest-first. `get_records_since_rev` walks them, stops at `rev <= header_rev`, collects the distinct touched `(collection, rkey)`, re-reads each record's current value from the MST (absent ⇒ deleted ⇒ skip), and buckets into profile + posts. `Atproto-Upstream-Lag` is computed from the oldest merged record.

**Tech Stack:** Rust, sqlx (SQLite), serde_ipld_dagcbor (via existing `decode_stored_event`), repo-engine (`get_record_json`), atrium-repo block store.

**Scope:** Phase 2 of 7.

**Codebase verified:** 2026-07-03.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### read-after-write.AC5: Rev-faithful selection
- **read-after-write.AC5.1 Success:** `get_records_since_rev` returns exactly the records written in commits with `rev >` the AppView header rev (bucketed into profile + posts).
- **read-after-write.AC5.2 Edge:** A record created then deleted since the header rev reads back as absent (not merged).
- **read-after-write.AC5.3 Failure:** A missing `atproto-repo-rev` header yields empty `LocalRecords` and no munge.

### read-after-write.AC4 (partial): lag header
- **read-after-write.AC4.3 Success:** `Atproto-Upstream-Lag` equals milliseconds since the oldest merged record's `indexed_at`, set only when local records were merged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: DID-scoped commit query in `db/firehose_seq.rs`

**Files:**
- Modify: `crates/pds/src/db/firehose_seq.rs` (add a query beside `events_in_range` at line 178; reuse the existing `StoredEventRow` struct at lines 15-20)

**Implementation:**

`events_in_range` filters by seq range only, ascending — not by DID. Add a DID-scoped, newest-first query so the selector can walk just this account's recent commits and stop early:

```rust
/// This DID's `commit` events, newest-first, capped at `limit`. Read-after-write walks these
/// from the top and stops as soon as a commit's rev is at or below the AppView's indexed rev,
/// so `limit` only bounds the pathological case (a burst of unindexed writes); a small value
/// (e.g. 200) is ample given AppView lag is seconds.
pub async fn recent_commits_for_did(
    db: &SqlitePool,
    did: &str,
    limit: u32,
) -> Result<Vec<StoredEventRow>, sqlx::Error> {
    sqlx::query_as::<_, StoredEventRow>(
        "SELECT seq, event_type, event FROM repo_seq \
         WHERE did = ? AND event_type = 'commit' ORDER BY seq DESC LIMIT ?",
    )
    .bind(did)
    .bind(limit)
    .fetch_all(db)
    .await
}
```

**Testing:**
Unit test in `firehose_seq.rs` test module: insert several commit events for a DID (and one for a different DID / one `account` event), call `recent_commits_for_did`, assert only this DID's commit rows return, newest-first, respecting `limit`.

**Verification:**
Run: `cargo test -p pds --lib db::firehose_seq`
Expected: New query test passes.

**Commit:** `feat(pds): add recent_commits_for_did query for read-after-write selection`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `get_records_since_rev` selection logic

**Verifies:** read-after-write.AC5.1, read-after-write.AC5.2, read-after-write.AC5.3, read-after-write.AC4.3

**Files:**
- Modify: `crates/pds/src/read_after_write/mod.rs` (add `get_records_since_rev` + a lag helper)
- Modify: `crates/pds/src/read_after_write/types.rs` if a small helper (e.g. `at_uri`) belongs there

**Implementation:**

Signature and flow (the orchestrator composes `db` + `repo-engine`, per the crate's Imperative-Shell rule):

```rust
/// Build the requester's unindexed LocalRecords relative to the AppView's indexed rev.
/// Returns an empty LocalRecords when `header_rev` is None (missing header) or nothing is newer.
pub(crate) async fn get_records_since_rev(
    state: &AppState,
    did: &str,
    header_rev: Option<&str>,
) -> LocalRecords {
    let Some(header_rev) = header_rev else { return LocalRecords::default(); };
    // 1. recent_commits_for_did(db, did, LIMIT); decode each row's `event` blob via
    //    crate::firehose::decode_stored_event(seq, "commit", &row.event) -> FirehoseEvent::Commit.
    //    (Note: the StoredEventRow struct + query live in db::firehose_seq, but the DECODER lives in
    //    crate::firehose — do not look for decode_stored_event under db::firehose_seq.)
    // 2. Walk newest-first; stop when CommitEvent.rev <= header_rev (string compare — TIDs sort by time).
    //    Collect distinct (collection, rkey) touched, keeping the newest CommitEvent.time seen per key.
    //    (CommitEvent.time is the RFC 3339 emission time and equals repo_seq.sequenced_at by
    //    construction, so there is no need to also SELECT sequenced_at into StoredEventRow.)
    // 3. For each key, read current MST value:
    //      get_repo_root_cid -> SqliteBlockStore::new(db, did) -> Repository::open
    //      -> repo_engine::get_record_json(&mut repo, &format!("{collection}/{rkey}"))
    //    None => deleted since rev => skip.
    // 4. Bucket: "app.bsky.actor.profile" (rkey "self") -> profile; "app.bsky.feed.post" -> posts.
    //    uri = format!("at://{did}/{collection}/{rkey}"); cid from get_record_cid or the op cid;
    //    indexed_at = the kept CommitEvent.time.
    // Any repo-open / read error for a given key: skip that key (best-effort), do not fail.
}
```

Notes for the implementer:
- Open the repo **once** and reuse it across all key reads (don't reopen per record).
- Only `app.bsky.actor.profile` and `app.bsky.feed.post` collections are needed by any munge; ignore other collections when bucketing (still fine to read them, but skip).
- Use the **op `cid`** from the decoded `RepoOp` for the descriptor's `cid` when the current MST value matches; simplest is to re-derive via `repo_engine::get_record_cid` at read time so cid always matches the current value.
- `count = profile.is_some() as usize + posts.len()`.

Lag helper:

```rust
/// Milliseconds since the oldest merged record's indexed_at, or None when there are none.
/// Uses SystemTime::now(); parse indexed_at as RFC 3339.
fn local_lag_ms(local: &LocalRecords) -> Option<i64> { /* ... */ }
```

**Testing:**
Unit/integration tests (reuse `seed_account_with_repo`, `put_record_request` via `app(state).oneshot(...)` to write real records so `repo_seq` is populated; capture the repo rev before/after writes to synthesize a `header_rev`):
- `read-after-write.AC5.1`: write two posts + a profile after `header_rev`; assert `get_records_since_rev` returns exactly those (bucketed), and older records (rev ≤ header) are excluded.
- `read-after-write.AC5.2`: create a post then delete it (both after `header_rev`); assert it is absent from `posts`.
- `read-after-write.AC5.3`: `header_rev = None` ⇒ empty `LocalRecords` (`count == 0`).
- `read-after-write.AC4.3`: with a known-old `indexed_at`, assert `local_lag_ms` is positive and derived from the oldest record.

**Verification:**
Run: `cargo test -p pds --lib read_after_write`
Expected: Selection tests pass.

**Commit:** `feat(pds): rev-faithful LocalRecords selection (get_records_since_rev)`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
