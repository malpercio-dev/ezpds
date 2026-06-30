# Persist the firehose sequencer (MM-199)

Last verified: 2026-06-30

## Problem

The firehose sequencer (`crates/pds/src/firehose.rs`) was **in-memory only**. The monotonic
`seq` counter reset to 0 and the bounded replay backlog emptied on every process restart /
Railway redeploy. Consequences observed during the 2026-06-30 federation bring-up:

- A relay reconnecting to `com.atproto.sync.subscribeRepos` with a saved cursor could not be
  replayed correctly across a restart — the new process had no record of the events behind that
  cursor, and its `seq` had reset.
- Commits written before a restart were dropped from the in-memory backlog, so they never
  back-propagated. A follow written before the host was onboarded never reached the AppView;
  only a fresh live write did.

## Goal / acceptance

- `seq` is monotonic across restarts.
- After a redeploy, a relay reconnecting with a prior cursor replays the missed commits.

## Design

Persist every sequenced event to SQLite and make cursor replay read from that durable log,
following the reference PDS's `repo_seq` pattern.

### Schema — `V028__repo_seq.sql`

```sql
repo_seq(seq INTEGER PRIMARY KEY, did TEXT, event_type TEXT, event BLOB, sequenced_at TEXT)
```

- `seq` is an explicit `INTEGER PRIMARY KEY` (rowid alias → index-backed `seq > ?` range scans),
  assigned by the in-process sequencer rather than `AUTOINCREMENT` so a **failed insert does not
  consume a number** (no hole in the dense prefix that replay relies on).
- `event` is the DAG-CBOR-serialized payload, carrying everything needed to rebuild the exact
  wire frame on replay — including the commit's CARv1 `blocks`. The blocks are stored here (not
  regenerated from the block store) because post-commit GC may have already reclaimed the
  superseded blocks the diff was computed against. The record `value` is **not** stored (it is
  not part of the wire frame).

### Sequencer — `firehose.rs`

`Firehose` now holds the shared `SqlitePool`, an async `emit_lock` (`tokio::sync::Mutex`), and
an `AtomicU64 last_seq`. It no longer keeps an in-memory replay backlog.

- **Construction** (`Firehose::new(db).await`) seeds `last_seq` from `MAX(seq)`, so `seq`
  continues monotonically across restarts.
- **Emit** (`emit_commit` / `emit_account`, now `async` and fallible) serialise the event, then
  under `emit_lock`: compute `seq = last_seq + 1`, **persist the row, advance `last_seq`, then
  broadcast**. Persisting before broadcasting means every event a live subscriber can see is
  already durable; serialising the whole step keeps broadcast order = `seq` order and the log a
  dense prefix. A failed insert leaves `last_seq` untouched, so the number is retried (no hole).
- **Subscribe** (`subscribe_from(cursor).await`) takes `emit_lock`, subscribes to the live
  channel, and snapshots `upper = last_seq` — all atomically against emission. It returns the
  live `rx`, the `cursor`, and `upper`. Because `rx` and `upper` are captured together under the
  lock, every live event has `seq > upper`, while `(cursor, upper]` is fully durable. The two
  ranges are exactly disjoint → **no gap, no duplicate** across the replay→live boundary, with no
  dedup filter required.

Emit is best-effort at the call sites (`record_write::emit_firehose_commit`, the
activate/deactivate routes): a sequencer write failure is logged and dropped, since the commit /
status change is already durable and a subscriber can backfill via `getRepo`.

### Replay — `routes/sync_subscribe_repos.rs`

The handler pages the durable log for `(cursor, upper]` via
`db::firehose_seq::events_in_range(after, upper, REPLAY_BATCH)`, decoding each row back into a
`FirehoseEvent` (`firehose::decode_stored_event`) and encoding the same wire frame as the live
path. Paging (batch 256) bounds replay memory for a subscriber resuming from a very old cursor.
After replay it streams live from `rx` exactly as before. A corrupt stored row is skipped (not
fatal); a DB read error closes the connection with an `InternalError` frame.

### Queries — `db/firehose_seq.rs`

- `max_seq` — startup seed.
- `insert_event` — append (explicit `seq`).
- `events_in_range(after, upper, limit)` — the replay page query.

## Notes / future work

- The log is **append-only and currently unbounded**. A retention sweep (drop rows at/below a
  cursor every relay has consumed past, or a time/size cap) is future work.
- During a long replay the broadcast buffer can overflow if live writes outpace it; the
  subscriber then gets `ConsumerTooSlow` and reconnects with its advanced cursor — self-healing,
  matching the pre-existing slow-consumer behaviour.
