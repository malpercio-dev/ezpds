// pattern: Imperative Shell

//! Persistent firehose event pipeline backing `com.atproto.sync.subscribeRepos`.
//!
//! Every repo commit (and account-status change) produces a sequenced event that is both
//! **persisted** to the `repo_seq` table and fanned out to all current subscribers over a Tokio
//! broadcast channel. The WebSocket handler (`routes/sync_subscribe_repos.rs`) encodes each event
//! into a DAG-CBOR frame.
//!
//! **Durability & restart safety.** The monotonic `seq` and the event log live in SQLite, so a
//! process restart / redeploy no longer resets the sequence to 0 or empties the replay backlog:
//! the sequencer loads `MAX(seq)` on construction and continues from there, and cursor replay
//! reads missed events back out of `repo_seq` (see `db::firehose_seq`). An event is persisted
//! *before* it is broadcast, so anything a live subscriber can observe is already durable — which
//! is what lets a fresh subscription bound its DB replay and the live stream against each other
//! with no gap and no duplicate.
//!
//! **Backpressure.** The broadcast channel is bounded. Producers never block: when the buffer is
//! full the oldest events are overwritten and a lagging subscriber observes
//! [`broadcast::error::RecvError::Lagged`] on its next `recv`, which the consumer treats as "you
//! fell too far behind" and disconnects (it reconnects with its last cursor and replays from the
//! durable log).
//!
//! **Ordering.** A single async `emit_lock` serialises each emit's *persist → advance counter →
//! broadcast* so events are delivered in strictly increasing `seq` order and the persisted log is
//! a dense prefix (no holes a failed insert could leave). The lock is held across the DB write, so
//! it is a `tokio::sync::Mutex`, not a `std::sync::Mutex`.
//!
//! **Lock/connection ordering.** The PDS's DB pool serves a single connection (see
//! `db::open_pool`), so a task holding an open transaction holds that connection until it
//! commits or rolls back. `emit_commit`/`emit_account`/`emit_identity` acquire `emit_lock`
//! *before* touching the pool for their `repo_seq` insert. A caller that instead wants to insert
//! that row into its *own* transaction (`EmitGuard::stage_commit`/`stage_account`) must acquire
//! the same lock first too — via [`Firehose::lock_emit`], *before* opening that transaction —
//! for the same reason: otherwise one path could hold the connection while waiting on
//! `emit_lock` and the other could hold `emit_lock` while waiting on that same connection,
//! deadlocking both.

// Dead code allow: a few accessors (`subscriber_count`, the `at_uri`/`as_str` wire helpers) are
// exercised only by this module's unit tests and the `subscribeRepos` handler's tests.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction};
use tokio::sync::broadcast;

/// Default capacity of the broadcast ring buffer: the number of events retained for slow
/// consumers before they begin to observe `Lagged`.
const DEFAULT_CAPACITY: usize = 1024;

/// The `com.atproto.sync.subscribeRepos` lexicon caps `#sync.blocks` (the commit-block CAR) at
/// 10,000 bytes. A `#sync` whose CAR exceeds this cannot be a valid wire frame, so it is rejected
/// before it enters the durable log rather than replaying later as an oversized frame a strict
/// subscriber would reject. In practice a single signed commit block is well under this, so the
/// check is a guard against a future caller (e.g. `importRepo`) staging an over-large CAR.
const MAX_SYNC_BLOCKS_BYTES: usize = 10_000;

/// Errors from sequencing (persisting + broadcasting) or reconstructing a firehose event.
#[derive(Debug, thiserror::Error)]
pub enum FirehoseError {
    #[error("failed to encode firehose event for storage: {0}")]
    Encode(String),
    #[error("failed to decode stored firehose event: {0}")]
    Decode(String),
    #[error("failed to persist firehose event: {0}")]
    Db(#[from] sqlx::Error),
}

/// The kind of change a single [`RepoOp`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpAction {
    Create,
    Update,
    Delete,
}

impl OpAction {
    /// The ATProto `#repoOp.action` wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            OpAction::Create => "create",
            OpAction::Update => "update",
            OpAction::Delete => "delete",
        }
    }

    /// Parse a stored/wire `action` string back into an [`OpAction`].
    fn from_wire(s: &str) -> Option<OpAction> {
        match s {
            "create" => Some(OpAction::Create),
            "update" => Some(OpAction::Update),
            "delete" => Some(OpAction::Delete),
            _ => None,
        }
    }
}

/// A single record-level operation within a commit.
#[derive(Debug, Clone)]
pub struct RepoOp {
    /// Whether the record was created, updated, or deleted.
    pub action: OpAction,
    /// Record collection NSID (e.g. `app.bsky.feed.post`).
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// New record CID for create/update; `None` for delete.
    pub cid: Option<String>,
    /// Previous record CID — the ATProto `#repoOp.prev`. Set for `update`/`delete` (the CID of
    /// the record this op replaced or removed), `None` for `create`. Per proposal 0006, a Sync
    /// v1.1 relay pairs this per-op `prev` with the commit's `prevData` to invert the MST diff and
    /// inductively validate each op without archival state. Part of the wire frame and persisted,
    /// so it round-trips through cursor replay.
    pub prev: Option<String>,
    /// New record value for create/update; `None` for delete.
    ///
    /// Carried on live events for in-process consumers, but **not** part of the `subscribeRepos`
    /// wire frame, so it is not persisted; an op reconstructed from the durable log has
    /// `value: None`.
    pub value: Option<serde_json::Value>,
}

impl RepoOp {
    /// The MST path (`<collection>/<rkey>`) used by the firehose `#repoOp.path` field.
    pub fn path(&self) -> String {
        format!("{}/{}", self.collection, self.rkey)
    }

    /// The fully-qualified AT URI of the record for a given repo `did`.
    pub fn at_uri(&self, did: &str) -> String {
        format!("at://{}/{}/{}", did, self.collection, self.rkey)
    }
}

/// A `#commit` firehose event: one repo commit, ready to encode into a subscribeRepos frame.
#[derive(Debug, Clone)]
pub struct CommitEvent {
    /// Monotonic sequence number assigned by the [`Firehose`] sequencer.
    pub seq: u64,
    /// RFC 3339 timestamp of emission.
    pub time: String,
    /// The repo owner's DID.
    pub repo: String,
    /// The new commit (repo root) CID.
    pub commit: String,
    /// The new repo revision (TID).
    pub rev: String,
    /// The previous repo revision, or `None` for the first commit.
    pub since: Option<String>,
    /// The previous commit's MST root (`data`) CID — Sync v1.1's `prevData`, which lets a relay
    /// validate this commit's diff inductively without archival state. `None` for the first
    /// (genesis) commit, which has no predecessor.
    pub prev_data: Option<String>,
    /// Record operations applied in this commit.
    pub ops: Vec<RepoOp>,
    /// CARv1 blocks introduced by this commit (CAR root = `commit`), for BGS consumption.
    pub blocks: Vec<u8>,
}

/// An `#account` firehose event: a change to an account's hosting status — activation,
/// deactivation, or takedown. Unlike a `#commit` it carries no repo blocks, only the new
/// status, so a relay can stop or resume serving the repo accordingly.
#[derive(Debug, Clone)]
pub struct AccountEvent {
    /// Monotonic sequence number assigned by the [`Firehose`] sequencer.
    pub seq: u64,
    /// RFC 3339 timestamp of emission.
    pub time: String,
    /// The account's DID.
    pub did: String,
    /// Whether the account is now active (repo readable, commits emitted).
    pub active: bool,
    /// The non-active status when `active` is false — one of `deactivated`, `takendown`,
    /// `suspended`, `deleted` per the lexicon. `None` when the account is active.
    pub status: Option<String>,
}

/// An `#identity` firehose event: a change to an account's handle or DID document. Relays /
/// AppViews use it to re-resolve a user's identity promptly, rather than waiting to notice via
/// the next `#commit`. Like `#account`, it carries no repo blocks — only the (optional) new
/// handle and a timestamp — so its wire encoding is infallible.
#[derive(Debug, Clone)]
pub struct IdentityEvent {
    /// Monotonic sequence number assigned by the [`Firehose`] sequencer.
    pub seq: u64,
    /// RFC 3339 timestamp of emission.
    pub time: String,
    /// The account's DID.
    pub did: String,
    /// The account's current handle when known, so a relay can short-circuit re-resolution. `None`
    /// when the new handle is unknown (e.g. a handle was removed and no canonical replacement is
    /// asserted); the relay re-resolves the DID document to discover the current `alsoKnownAs`.
    pub handle: Option<String>,
}

/// A `#sync` firehose event: a Sync v1.1 state assertion carrying the account's current signed
/// commit block. Unlike `#commit` it is not a diff — it names the current repo head and ships just
/// the commit block (in a small CARv1) so a relay that has drifted from this host can re-anchor to
/// it. Emitted on account genesis, activation, and (once wired) repo import — the moments a relay
/// most needs an authoritative head to auto-repair against.
#[derive(Debug, Clone)]
pub struct SyncEvent {
    /// Monotonic sequence number assigned by the [`Firehose`] sequencer.
    pub seq: u64,
    /// RFC 3339 timestamp of emission.
    pub time: String,
    /// The repo owner's DID.
    pub did: String,
    /// The current repo revision (TID), which must match the `rev` inside the commit block.
    pub rev: String,
    /// A CARv1 whose root is the current commit and which contains the signed commit block
    /// (kept small — the lexicon caps `#sync.blocks` at 10 KB).
    pub blocks: Vec<u8>,
}

/// A frame broadcast to firehose subscribers. Modelled as an enum so further frame types can be
/// added without changing the channel item type.
#[derive(Debug, Clone)]
pub enum FirehoseEvent {
    Commit(Arc<CommitEvent>),
    Account(Arc<AccountEvent>),
    Identity(Arc<IdentityEvent>),
    Sync(Arc<SyncEvent>),
}

impl FirehoseEvent {
    /// The sequence number of the underlying event.
    pub fn seq(&self) -> u64 {
        match self {
            FirehoseEvent::Commit(c) => c.seq,
            FirehoseEvent::Account(a) => a.seq,
            FirehoseEvent::Identity(i) => i.seq,
            FirehoseEvent::Sync(s) => s.seq,
        }
    }

    /// The wire frame type as a metrics label value (`firehose_events_total{frame=...}`).
    pub fn frame_label(&self) -> &'static str {
        match self {
            FirehoseEvent::Commit(_) => "commit",
            FirehoseEvent::Account(_) => "account",
            FirehoseEvent::Identity(_) => "identity",
            FirehoseEvent::Sync(_) => "sync",
        }
    }
}

/// Inputs to [`Firehose::emit_commit`] — everything about a commit except the
/// sequencer-assigned `seq` and the emission `time`.
pub struct CommitInput {
    pub repo: String,
    pub commit: String,
    pub rev: String,
    pub since: Option<String>,
    pub prev_data: Option<String>,
    pub ops: Vec<RepoOp>,
    pub blocks: Vec<u8>,
}

/// Inputs to [`Firehose::emit_sync`] / [`EmitGuard::stage_sync`] — everything about a `#sync`
/// state assertion except the sequencer-assigned `seq` and the emission `time`.
pub struct SyncInput {
    pub did: String,
    pub rev: String,
    /// CARv1 whose root is the current commit and which carries the signed commit block.
    pub blocks: Vec<u8>,
}

/// A new subscription: an optional durable replay reader first, then the live event stream.
///
/// `replay` pages the `(cursor, upper]` range back from the durable log (oldest first); the
/// consumer drains it before streaming live events from `rx`. Because `rx` was taken and the
/// frontier `upper` snapshotted together under the sequencer lock — before any later emit could
/// advance the counter — every live event has `seq > upper`, so replay and the live stream are
/// exactly disjoint: no event is dropped between them and none is delivered twice.
pub struct Subscription<'f> {
    /// The missed events with `cursor < seq <= upper`, oldest first, to send before live streaming.
    /// `None` for a live-only subscription (no cursor).
    pub replay: Option<ReplayReader<'f>>,
    /// Live event stream for everything emitted after this subscription was created
    /// (all with `seq > upper`).
    pub rx: broadcast::Receiver<FirehoseEvent>,
}

/// The outcome of [`Firehose::subscribe_from`].
pub enum SubscribeOutcome<'f> {
    /// The subscription was established; drain `replay`, then stream `rx`.
    Subscribed(Subscription<'f>),
    /// The requested cursor is ahead of the latest assigned sequence (`current`), so it cannot
    /// be honoured — the client is claiming to have seen events that do not exist.
    FutureCursor { current: u64 },
}

/// How many backlog rows to read per query during cursor replay from the durable log, so a
/// subscriber resuming from an old cursor never issues one unbounded query or buffers the whole
/// backlog.
const REPLAY_BATCH: u32 = 256;

/// Paged cursor replay over the durable firehose log.
///
/// Does **not** lock out the retention sweep: instead each [`next_batch`](Self::next_batch)
/// consults the firehose's [`prune_floor`](Firehose::prune_floor), so a sweep that prunes past this
/// reader's position mid-drain is classified as a prune (best-effort re-anchor) rather than a
/// durability hole. That keeps a slow reader from serialising against other readers or blocking the
/// sweep. Each call returns at most `REPLAY_BATCH` decoded events, keeping memory bounded and
/// allowing the socket loop to interleave replay with heartbeat/read-timeout work.
pub struct ReplayReader<'f> {
    firehose: &'f Firehose,
    cursor: u64,
    upper: u64,
    after: u64,
    anchored: bool,
    first_page: bool,
    cursor_present: bool,
    done: bool,
}

impl<'f> ReplayReader<'f> {
    fn new(firehose: &'f Firehose, cursor: u64, upper: u64) -> Self {
        Self {
            firehose,
            cursor,
            upper,
            after: cursor,
            anchored: false,
            first_page: true,
            cursor_present: false,
            done: cursor >= upper,
        }
    }

    /// Read and decode the next replay page, oldest first.
    ///
    /// The range is a dense prefix (the sequencer advances `last_seq` only after a row is
    /// persisted), so this enforces density between **consecutive** rows — each `seq` must be
    /// exactly the previous plus one, and the last must reach `upper` — and returns
    /// [`FirehoseError`] on any gap rather than silently skipping a missing `seq`. A negative
    /// stored `seq` (which can't occur from our writer) or a row that won't decode is likewise a
    /// hard error: replay must be exact or fail closed.
    ///
    /// **Best-effort at the pruned prefix.** The retention sweep (`firehose_gc`) prunes a
    /// *contiguous* prefix `seq ≤ watermark`, so the first row above a cursor that falls inside
    /// the pruned window is the oldest retained row, not `cursor + 1`. The first-row density check
    /// is **relaxed only when the cursor sits below the oldest retained row** (no row at or below
    /// the cursor): that is a genuine pruned prefix, so replay degrades to best-effort (the
    /// subscriber receives the retained suffix) rather than failing closed. When a row *does* exist
    /// at or below the cursor, replay is dense from the cursor and any jump on the first row is a
    /// mid-range gap that fails closed. The first replay page projects that cursor-presence bit in
    /// the same SQL statement that reads the rows, so the pruned-prefix decision observes one
    /// SQLite snapshot (no TOCTOU between the batch and the cursor-presence check).
    ///
    /// **Best-effort mid-drain, too.** Because replay no longer locks out the sweep, a *slow*
    /// reader can have rows pruned out from under it between pages. Each gap or short/empty tail is
    /// therefore also checked against the firehose's [`prune_floor`](Firehose::prune_floor): when
    /// the next expected `seq` is at or below the floor, the missing rows were pruned, so the reader
    /// re-anchors to the retained suffix (best-effort) instead of failing closed. A gap or missing
    /// tail *above* the floor is a genuine mid-range hole (a durability bug, not a prune) and still
    /// fails closed. The floor is published before the sweep's `DELETE` (see
    /// [`Firehose::note_pruned`]) and read here after the page query, so the classification never
    /// misreads a prune as a hole.
    pub async fn next_batch(&mut self) -> Result<Vec<FirehoseEvent>, FirehoseError> {
        if self.done {
            return Ok(Vec::new());
        }

        let batch = if self.first_page {
            let page = crate::db::firehose_seq::first_events_in_range_with_cursor_presence(
                &self.firehose.db,
                self.cursor,
                self.upper,
                REPLAY_BATCH,
            )
            .await?;
            self.first_page = false;
            self.cursor_present = page.cursor_present;
            page.rows
        } else {
            crate::db::firehose_seq::events_in_range(
                &self.firehose.db,
                self.after,
                self.upper,
                REPLAY_BATCH,
            )
            .await?
        };

        // Read the prune floor *after* the page query so it reflects any sweep whose deletions this
        // page could have observed (`note_pruned` is published before the `DELETE`). The floor only
        // grows, so a value read here is a safe lower bound for the whole page's decisions.
        let prune_floor = self.firehose.prune_floor();

        if batch.is_empty() {
            self.done = true;
            if self.after < self.upper {
                // The remaining `(after, upper]` range is empty. If a sweep pruned past our
                // position (its floor reaches our next expected seq), the tail we were still owed
                // was pruned — degrade to best-effort (deliver nothing more) rather than fail
                // closed. Otherwise the missing rows are a genuine durability hole.
                if prune_floor > self.after {
                    return Ok(Vec::new());
                }
                return Err(FirehoseError::Decode(format!(
                    "firehose replay backlog ended at seq {} before the frontier {}",
                    self.after, self.upper
                )));
            }
            return Ok(Vec::new());
        }

        let page_len = batch.len();
        let mut events = Vec::with_capacity(page_len);
        for row in batch {
            let seq = u64::try_from(row.seq).map_err(|_| {
                FirehoseError::Decode(format!("negative stored firehose seq {}", row.seq))
            })?;
            if seq != self.after + 1 {
                // A gap. Decide pruned run vs mid-range hole. If the next expected seq
                // (`after + 1`) is at or below the prune floor — i.e. `after < prune_floor` — a
                // sweep removed the run we were about to read, so re-anchor to this (retained) row
                // and continue best-effort. This covers both a first-row gap and one that opened up
                // mid-drain after we had already anchored.
                if self.after < prune_floor {
                    self.anchored = true;
                    self.after = seq;
                    events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
                    continue;
                }
                // Not explained by pruning, and we've already anchored: a mid-range hole — fail
                // closed.
                if self.anchored {
                    return Err(FirehoseError::Decode(format!(
                        "firehose replay gap: expected seq {}, found {seq}",
                        self.after + 1
                    )));
                }
                // First-row gap not below the floor: fall back to the same-snapshot cursor-presence
                // bit. If a row still exists at or below the cursor, the gap is a real mid-range
                // hole → fail closed; if the cursor row is gone, a sweep pruned the prefix →
                // best-effort. (The floor can lag a prefix prune performed before this reader was
                // constructed, so the SQL-snapshot check is the authority for the first row.)
                if self.cursor_present {
                    return Err(FirehoseError::Decode(format!(
                        "firehose replay gap: expected seq {}, found {seq}",
                        self.after + 1
                    )));
                }
                // Pruned prefix: best-effort. Anchor here and continue dense from this row.
                self.anchored = true;
                self.after = seq;
                events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
                continue;
            }
            self.anchored = true;
            self.after = seq;
            events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
        }

        if self.after >= self.upper {
            self.done = true;
        } else if (page_len as u32) < REPLAY_BATCH {
            // A short page that didn't reach the frontier: the rows between `after` and `upper` are
            // missing. Prefix pruning removes *low* seqs, so within the retained suffix the range
            // stays dense — a short tail here is a genuine hole unless the sweep's floor has climbed
            // past our position (the retained tail we snapshotted was pruned out from under us).
            self.done = true;
            if prune_floor <= self.after {
                return Err(FirehoseError::Decode(format!(
                    "firehose replay backlog ended at seq {} before the frontier {}",
                    self.after, self.upper
                )));
            }
        }

        Ok(events)
    }

    /// Own this reader while fetching the next replay page.
    ///
    /// This lets route code keep a single in-flight page-read future pinned across `select!`
    /// iterations without borrowing the reader from an outer slot. When the future completes, the
    /// caller gets the reader back with its updated cursor state intact.
    pub async fn into_next_batch(mut self) -> (Self, Result<Vec<FirehoseEvent>, FirehoseError>) {
        let result = self.next_batch().await;
        (self, result)
    }
}

#[cfg(test)]
pub(crate) async fn collect_replay_seqs(
    mut replay: Option<ReplayReader<'_>>,
) -> Result<Vec<u64>, FirehoseError> {
    let mut seqs = Vec::new();
    let Some(reader) = replay.as_mut() else {
        return Ok(seqs);
    };
    loop {
        let batch = reader.next_batch().await?;
        if batch.is_empty() {
            break;
        }
        seqs.extend(batch.iter().map(FirehoseEvent::seq));
    }
    Ok(seqs)
}

/// The persistent firehose: a durable monotonic sequencer plus a broadcast fan-out.
///
/// The PDS holds a single `Arc<Firehose>` in `AppState`; every request handler shares it. The
/// `db` pool is the same one the rest of the PDS uses (the event log lives alongside the repo
/// data), so cursor replay reads exactly the events `emit_*` persisted.
pub struct Firehose {
    /// Shared SQLite pool; the firehose persists every event to `repo_seq` here.
    db: SqlitePool,
    /// Serialises each emit's persist → counter-advance → broadcast so broadcast order matches
    /// `seq` order and the persisted log stays a dense prefix. Held across the DB write, hence a
    /// `tokio::sync::Mutex`. Also taken (briefly, no await) by `subscribe_from` so it can snapshot
    /// the live receiver and the sequence frontier atomically against emission.
    emit_lock: tokio::sync::Mutex<()>,
    /// The highest `seq` the retention sweep (`firehose_gc`) has pruned, or 0 if it has pruned
    /// nothing this process. Monotonic (advanced via `fetch_max`). A cursor-replay reader consults
    /// it per page: when its next expected `seq` sits at or below this floor, a sweep removed rows
    /// it was about to read, so the reader degrades to best-effort (re-anchors to the retained
    /// suffix) rather than misreading the gap as a durability hole and failing closed. This replaces
    /// the old exclusive lock that made replay readers serialise against each other and blocked the
    /// sweep for a slow reader's whole drain (see [`ReplayReader::next_batch`]).
    prune_floor: AtomicU64,
    /// The last sequence number assigned. Written only under `emit_lock` (after the row is
    /// persisted), so a value `<= last_seq` is always already durable. Read locklessly for
    /// diagnostics (`current_seq`) and under the lock for the subscribe frontier. May lag the
    /// durable log when a caller is cancelled between its transaction commit and
    /// `Pending*::finish`; the next insert detects the collision and re-derives the frontier
    /// from `MAX(seq)` (see [`Firehose::insert_at_frontier`]).
    last_seq: AtomicU64,
    tx: broadcast::Sender<FirehoseEvent>,
    /// Counts broadcast frames into `firehose_events_total`. `None` for bare test
    /// constructions; `main.rs`/`test_state()` attach the shared handle before Arc-wrapping.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl Firehose {
    /// Create a firehose with the default broadcast-buffer capacity, seeding the sequence
    /// counter from the persisted log so `seq` continues monotonically across restarts.
    pub async fn new(db: SqlitePool) -> Result<Self, sqlx::Error> {
        Self::with_capacity(db, DEFAULT_CAPACITY).await
    }

    /// Create a firehose whose broadcast buffer retains `capacity` events for slow consumers,
    /// seeding the sequence counter from `MAX(seq)` in the persisted log.
    pub async fn with_capacity(db: SqlitePool, capacity: usize) -> Result<Self, sqlx::Error> {
        let last = crate::db::firehose_seq::max_seq(&db).await?;
        let (tx, _rx) = broadcast::channel(capacity);
        Ok(Self {
            db,
            emit_lock: tokio::sync::Mutex::new(()),
            prune_floor: AtomicU64::new(0),
            last_seq: AtomicU64::new(last),
            tx,
            metrics: None,
        })
    }

    /// Attach the shared metrics handle so broadcast frames are counted. Called before the
    /// firehose is Arc-wrapped into `AppState`; constructions that never attach (bare unit
    /// tests) simply record nothing.
    pub fn attach_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        self.metrics = Some(metrics);
    }

    /// Broadcast one already-persisted event to live subscribers, counting it by frame type.
    /// The send result is deliberately ignored: having no live subscribers is not an error
    /// (the event is already durable and replayable).
    fn broadcast(&self, event: FirehoseEvent) {
        if let Some(metrics) = &self.metrics {
            metrics.firehose_events.add(
                1,
                &[crate::metrics::label(
                    crate::metrics::names::LABEL_FRAME,
                    event.frame_label(),
                )],
            );
        }
        let _ = self.tx.send(event);
    }

    /// Subscribe to the live event stream only (no replay). Each subscriber receives every
    /// event emitted after it subscribes; a subscriber that falls more than the broadcast
    /// capacity behind observes `RecvError::Lagged` on its next `recv`.
    pub fn subscribe(&self) -> broadcast::Receiver<FirehoseEvent> {
        self.tx.subscribe()
    }

    /// Insert one event row at the sequence frontier, self-healing a stale in-memory frontier.
    ///
    /// Must be called under `emit_lock`. Normally the next seq is `last_seq + 1`, but a caller
    /// cancelled between its `tx.commit()` and `Pending*::finish()` (a client disconnect in that
    /// window drops the handler future) leaves a durable `repo_seq` row *above* `last_seq` —
    /// the row landed, the frontier never advanced. Every later insert would then collide with
    /// that orphaned row's PRIMARY KEY forever (a full write outage until a restart re-seeds the
    /// counter). On a unique violation, re-derive the next seq from the durable `MAX(seq)` and
    /// retry once; a second collision is a real sequencer bug and propagates. The orphaned event
    /// is never broadcast live — exactly as after a restart, subscribers pick it up from the
    /// durable log via cursor replay.
    ///
    /// Takes a bare connection (not an executor) because the retry needs to reuse it: the
    /// staged paths pass their caller's open transaction, which holds the single-connection
    /// pool's only connection.
    async fn insert_at_frontier(
        &self,
        conn: &mut SqliteConnection,
        did: &str,
        event_type: &str,
        blob: &[u8],
        time: &str,
    ) -> Result<u64, FirehoseError> {
        let seq = self.last_seq.load(Ordering::Acquire) + 1;
        match crate::db::firehose_seq::insert_event(&mut *conn, seq, did, event_type, blob, time)
            .await
        {
            Ok(()) => Ok(seq),
            Err(e) if crate::db::is_unique_violation(&e) => {
                let durable = crate::db::firehose_seq::max_seq(&mut *conn).await?;
                let healed_seq = durable + 1;
                // The wedge no longer surfaces as an outage, so this log line is the only
                // signal the cancellation window was actually hit in production.
                tracing::warn!(
                    did,
                    event_type,
                    collided_seq = seq,
                    healed_seq,
                    "firehose sequencer self-heal: frontier lagged the durable log (a caller \
                     was cancelled between its transaction commit and finish); re-seeded from \
                     MAX(seq) and retrying"
                );
                crate::db::firehose_seq::insert_event(
                    &mut *conn, healed_seq, did, event_type, blob, time,
                )
                .await?;
                Ok(healed_seq)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Subscribe with optional cursor replay.
    ///
    /// Returns a [`Subscription`] whose `replay` pages the `(cursor, upper]` backlog from the
    /// durable log (oldest first) and whose `rx` streams every later event. A cursor ahead of the
    /// latest assigned sequence yields [`SubscribeOutcome::FutureCursor`]; a `cursor = None` gives
    /// `replay = None` (live-only).
    ///
    /// The live receiver and the `upper` frontier are captured together under `emit_lock`, so no
    /// concurrent emit can slip an event past both the replay range and the receiver, nor advance
    /// the counter into a spurious `FutureCursor`. Replay pages are then read outside `emit_lock`,
    /// bounded by `upper`, so they stay disjoint from the live stream. The retention sweep is *not*
    /// serialised against replay: a reader that falls behind while `firehose_gc` prunes past its
    /// position observes the [`prune_floor`](Self::prune_floor) and degrades to best-effort replay
    /// per page (see [`ReplayReader::next_batch`]) instead of blocking the sweep or other readers.
    ///
    /// Replay errors surface from [`ReplayReader::next_batch`]: a DB read failure, a stored row
    /// that won't decode, or a *mid-range* gap in the `(cursor, upper]` range not explained by
    /// pruning. A cursor (or a slow reader's position) that falls inside a **pruned prefix**
    /// degrades to best-effort instead — the subscriber receives the retained suffix — because the
    /// retention sweep only ever removes a contiguous prefix below the live frontier.
    pub async fn subscribe_from(
        &self,
        cursor: Option<u64>,
    ) -> Result<SubscribeOutcome<'_>, FirehoseError> {
        let (rx, upper) = {
            let _guard = self.emit_lock.lock().await;
            // Subscribe to the live channel *before* releasing the lock so that no event emitted
            // after this snapshot can slip past both the replay range and the receiver, and read
            // the frontier under the same lock so `upper` reflects exactly what is already durable.
            (self.tx.subscribe(), self.last_seq.load(Ordering::Acquire))
        };

        let replay = match cursor {
            Some(c) if c > upper => return Ok(SubscribeOutcome::FutureCursor { current: upper }),
            Some(c) => Some(ReplayReader::new(self, c, upper)),
            None => None,
        };

        Ok(SubscribeOutcome::Subscribed(Subscription { replay, rx }))
    }

    /// Publish that the retention sweep has pruned every row with `seq <= watermark`.
    ///
    /// Advances the [`prune_floor`](Self::prune_floor) monotonically. `firehose_gc` calls this
    /// *before* it issues the `DELETE`, so any in-flight replay reader that later observes the
    /// resulting gap sees a floor already high enough to classify it as a prune (best-effort)
    /// rather than a durability hole (fail closed). Publishing before the delete — and reading the
    /// floor with `Acquire` after the page read — is what keeps that classification race-free over
    /// the single-connection pool (the reader only consults the floor once it has actually observed
    /// a missing row, which cannot happen until the delete this call precedes has committed).
    pub(crate) fn note_pruned(&self, watermark: u64) {
        self.prune_floor.fetch_max(watermark, Ordering::Release);
    }

    /// The highest `seq` the retention sweep has pruned so far (0 if none). Read by
    /// [`ReplayReader::next_batch`] to tell a prune-induced gap from a genuine mid-range hole.
    pub(crate) fn prune_floor(&self) -> u64 {
        self.prune_floor.load(Ordering::Acquire)
    }

    /// Number of live subscribers. Primarily for diagnostics and tests.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// The last sequence number assigned (0 if nothing has been emitted yet).
    pub fn current_seq(&self) -> u64 {
        self.last_seq.load(Ordering::Acquire)
    }

    /// Persist, sequence, and broadcast a `#commit` event.
    ///
    /// The commit's wire CIDs (the root and each op `cid`) are validated *before* the row is
    /// persisted, so an un-encodable commit is rejected here rather than entering the durable log as
    /// a replay poison pill — a row that decodes but later fails to wire-encode, closing every
    /// subscriber that reconnects across it. The event is then written to `repo_seq` (durable)
    /// *before* it is broadcast, all under `emit_lock`, so live subscribers only ever see
    /// already-persisted events and the log stays dense. An emit with no live subscribers still
    /// consumes its `seq` and persists, keeping the sequence contiguous. Returns [`FirehoseError`]
    /// if validation, encoding, or the DB write fails — the counter is *not* advanced in that case,
    /// so the number is retried by the next emit (no hole).
    pub async fn emit_commit(&self, input: CommitInput) -> Result<u64, FirehoseError> {
        // Reject a commit whose wire frame couldn't be encoded *before* it enters the durable log.
        // Frame encoding is infallible except for CID parsing, so validating the root + op CIDs is
        // equivalent to "this commit will encode" without building the full frame here.
        validate_commit_cids(&input)?;

        let _guard = self.emit_lock.lock().await;
        // Capture the timestamp and serialize the storable form *under the lock*, in the same
        // critical section as `seq` assignment, so the stored `time`/`sequenced_at` stay monotonic
        // with seq order even when commits race. Scope the borrow of `input` so it ends before we
        // move `input`'s fields into the broadcast event below.
        let time = now_rfc3339();
        let blob = {
            let stored = StoredCommitRef {
                repo: &input.repo,
                commit: &input.commit,
                rev: &input.rev,
                since: input.since.as_deref(),
                prev_data: input.prev_data.as_deref(),
                time: &time,
                ops: input.ops.iter().map(StoredOpRef::from).collect(),
                blocks: &input.blocks,
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let mut conn = self.db.acquire().await?;
        let seq = self
            .insert_at_frontier(&mut conn, &input.repo, "commit", &blob, &time)
            .await?;
        drop(conn);
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Commit(Arc::new(CommitEvent {
            seq,
            time,
            repo: input.repo,
            commit: input.commit,
            rev: input.rev,
            since: input.since,
            prev_data: input.prev_data,
            ops: input.ops,
            blocks: input.blocks,
        }));
        // A send error means "no subscribers"; that is expected, not a failure.
        self.broadcast(event);
        Ok(seq)
    }

    /// Persist, sequence, and broadcast an `#account` event.
    ///
    /// The account analogue of [`emit_commit`]: emitted when an account is deactivated
    /// (`active = false`, `status = Some("deactivated")`) or reactivated (`active = true`,
    /// `status = None`). Shares the same sequencer and durable log so account-status frames are
    /// ordered relative to commits exactly as a relay expects.
    pub async fn emit_account(
        &self,
        did: String,
        active: bool,
        status: Option<String>,
    ) -> Result<u64, FirehoseError> {
        let _guard = self.emit_lock.lock().await;
        // Capture the timestamp and serialize under the lock so `time`/`sequenced_at` stay
        // monotonic with seq order even when emits race (same critical section as `seq`).
        let time = now_rfc3339();
        let blob = {
            let stored = StoredAccountRef {
                did: &did,
                time: &time,
                active,
                status: status.as_deref(),
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let mut conn = self.db.acquire().await?;
        let seq = self
            .insert_at_frontier(&mut conn, &did, "account", &blob, &time)
            .await?;
        drop(conn);
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Account(Arc::new(AccountEvent {
            seq,
            time,
            did,
            active,
            status,
        }));
        self.broadcast(event);
        Ok(seq)
    }

    /// Persist, sequence, and broadcast an `#identity` event.
    ///
    /// Emitted whenever an account's handle or DID document changes (a handle add/remove via the
    /// provisioning routes, a future `updateHandle` XRPC, or a PLC rotation that touches the DID
    /// doc). `handle` is the account's current handle when known (`Some`), or `None` to signal
    /// "identity changed; re-resolve the DID document" without asserting a specific handle (used
    /// when a handle is removed and no canonical replacement is asserted here).
    ///
    /// The identity analogue of [`emit_account`]: it shares the same sequencer and durable log so
    /// `#identity` frames are ordered relative to commits and account-status frames exactly as a
    /// relay expects. Like `#account`, every field is a plain scalar, so its wire encoding is
    /// infallible and needs no pre-emit CID validation.
    pub async fn emit_identity(
        &self,
        did: String,
        handle: Option<String>,
    ) -> Result<u64, FirehoseError> {
        let _guard = self.emit_lock.lock().await;
        // Capture the timestamp and serialize under the lock so `time`/`sequenced_at` stay
        // monotonic with seq order even when emits race (same critical section as `seq`).
        let time = now_rfc3339();
        let blob = {
            let stored = StoredIdentityRef {
                did: &did,
                time: &time,
                handle: handle.as_deref(),
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let mut conn = self.db.acquire().await?;
        let seq = self
            .insert_at_frontier(&mut conn, &did, "identity", &blob, &time)
            .await?;
        drop(conn);
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Identity(Arc::new(IdentityEvent {
            seq,
            time,
            did,
            handle,
        }));
        self.broadcast(event);
        Ok(seq)
    }

    /// Persist, sequence, and broadcast a `#sync` event.
    ///
    /// The Sync v1.1 state assertion analogue of [`emit_account`]: emitted (best-effort) when a
    /// relay may need an authoritative repo head to re-anchor against but there is no atomic write
    /// to bind it to. Genesis and activation stage their `#sync` inside the account transaction via
    /// [`PendingCommit::stage_sync`]/[`PendingAccount::stage_sync`] instead; this bare primitive is
    /// kept for callers (and tests) that do not need that atomicity. Shares the same sequencer and
    /// durable log so `#sync` frames are ordered relative to commits and account frames exactly as
    /// a relay expects. The commit-block CAR is capped at [`MAX_SYNC_BLOCKS_BYTES`] before persist;
    /// otherwise `blocks` is a pre-built CARv1 byte string (scalars otherwise), so its wire encoding
    /// is infallible and needs no pre-emit CID validation.
    pub async fn emit_sync(&self, input: SyncInput) -> Result<u64, FirehoseError> {
        // Reject an over-cap CAR before it enters the durable log (mirrors `validate_commit_cids`
        // in `emit_commit`), so an oversized `#sync` can't become a replay poison pill.
        validate_sync_blocks(&input.blocks)?;

        let _guard = self.emit_lock.lock().await;
        // Capture the timestamp and serialize under the lock so `time`/`sequenced_at` stay
        // monotonic with seq order even when emits race (same critical section as `seq`).
        let time = now_rfc3339();
        let blob = {
            let stored = StoredSyncRef {
                did: &input.did,
                time: &time,
                rev: &input.rev,
                blocks: &input.blocks,
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let mut conn = self.db.acquire().await?;
        let seq = self
            .insert_at_frontier(&mut conn, &input.did, "sync", &blob, &time)
            .await?;
        drop(conn);
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Sync(Arc::new(SyncEvent {
            seq,
            time,
            did: input.did,
            rev: input.rev,
            blocks: input.blocks,
        }));
        self.broadcast(event);
        Ok(seq)
    }

    /// Acquire the sequencer lock ahead of a transaction that may call
    /// [`EmitGuard::stage_commit`]/[`EmitGuard::stage_account`].
    ///
    /// **Must** be acquired *before* `db.begin()` for any transaction that might stage an event.
    /// `emit_commit`/`emit_account`/`emit_identity` acquire `emit_lock` first and only then touch
    /// the (single-connection) pool for their `repo_seq` insert; a transaction that instead opens
    /// first and acquires the lock afterward can deadlock one of those against it — the
    /// transaction holds the pool's sole connection while waiting on the lock, and the other path
    /// holds the lock while waiting on that same connection. Acquiring the lock first, and holding
    /// it for the whole transaction (via the returned guard, threaded through to
    /// [`PendingCommit`]/[`PendingAccount`]), keeps every path that touches both resources in the
    /// same order.
    pub async fn lock_emit(&self) -> EmitGuard<'_> {
        EmitGuard {
            firehose: self,
            _guard: self.emit_lock.lock().await,
        }
    }
}

/// Proof that the caller holds [`Firehose`]'s sequencer lock, acquired via
/// [`Firehose::lock_emit`] *before* opening the transaction that will call
/// [`stage_commit`](Self::stage_commit)/[`stage_account`](Self::stage_account) — see that
/// method's docs for why the ordering matters. Consumed by `stage_commit`/`stage_account`, which
/// carry it forward into the returned `Pending*` handle so the lock stays held until the caller
/// commits and finishes (or drops it, aborting).
pub struct EmitGuard<'f> {
    firehose: &'f Firehose,
    _guard: tokio::sync::MutexGuard<'f, ()>,
}

impl<'f> EmitGuard<'f> {
    /// Stage a `#commit` event's row into the caller's already-open transaction, without
    /// committing or broadcasting yet.
    ///
    /// This is the atomic counterpart to [`Firehose::emit_commit`]: the caller runs its own
    /// transactional write (the repo-root CAS) against `tx` *before* calling this, so by the time
    /// it's called the caller has already decided the write should land. `stage_commit` then
    /// assigns the event's `seq` and inserts its `repo_seq` row into that same `tx`, so the row
    /// commits (or rolls back) together with the caller's write — a failed insert here rolls
    /// `tx` back via `Drop`, taking the caller's write with it, rather than leaving a durable
    /// commit with no corresponding firehose row.
    ///
    /// The caller must `tx.commit()` and then call [`PendingCommit::finish`] — only after a
    /// successful commit — to advance the sequence counter and broadcast the event. Dropping the
    /// returned handle without finishing never advances `last_seq` or broadcasts, so an aborted
    /// write (caller rolls back instead of committing) leaves the sequence untouched, exactly
    /// like a rejected [`Firehose::emit_commit`].
    pub async fn stage_commit(
        self,
        tx: &mut Transaction<'_, Sqlite>,
        input: CommitInput,
    ) -> Result<PendingCommit<'f>, FirehoseError> {
        validate_commit_cids(&input)?;

        let firehose = self.firehose;
        let time = now_rfc3339();
        let blob = {
            let stored = StoredCommitRef {
                repo: &input.repo,
                commit: &input.commit,
                rev: &input.rev,
                since: input.since.as_deref(),
                prev_data: input.prev_data.as_deref(),
                time: &time,
                ops: input.ops.iter().map(StoredOpRef::from).collect(),
                blocks: &input.blocks,
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let seq = firehose
            .insert_at_frontier(&mut *tx, &input.repo, "commit", &blob, &time)
            .await?;

        Ok(PendingCommit {
            firehose,
            seq,
            time,
            input,
            _guard: self,
        })
    }

    /// Stage an `#account` event's row into the caller's already-open transaction (see
    /// [`stage_commit`](Self::stage_commit) — the same atomic pattern, for account-status
    /// transitions rather than commits). The caller runs `activate_account`/`deactivate_account`
    /// against `tx` first and only calls this once it knows the transition actually happened.
    pub async fn stage_account(
        self,
        tx: &mut Transaction<'_, Sqlite>,
        did: String,
        active: bool,
        status: Option<String>,
    ) -> Result<PendingAccount<'f>, FirehoseError> {
        let firehose = self.firehose;
        let time = now_rfc3339();
        let blob = {
            let stored = StoredAccountRef {
                did: &did,
                time: &time,
                active,
                status: status.as_deref(),
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let seq = firehose
            .insert_at_frontier(&mut *tx, &did, "account", &blob, &time)
            .await?;

        Ok(PendingAccount {
            firehose,
            seq,
            time,
            did,
            active,
            status,
            _guard: self,
        })
    }
}

/// A `#commit` event whose `repo_seq` row is already inserted into the caller's open transaction
/// (via [`Firehose::stage_commit`]) but not yet committed or broadcast.
///
/// The caller must commit its transaction (which includes this row) and then call [`finish`]
/// — only on that success path — to advance the sequence counter and broadcast the event.
/// Dropping this handle without finishing (e.g. because the caller rolled the transaction back
/// instead) releases `emit_lock` without advancing `last_seq`, so the seq is retried by the next
/// emit, exactly as an outright `emit_commit` failure would. The one asymmetric drop — the
/// handler future cancelled *after* its `tx.commit()` made the row durable but before `finish`
/// — leaves the frontier behind the log; the next insert self-heals past the orphaned row (see
/// [`Firehose::insert_at_frontier`]) rather than colliding with it until restart.
#[must_use = "a staged commit does nothing until the caller commits its transaction and calls `finish`"]
pub struct PendingCommit<'f> {
    firehose: &'f Firehose,
    seq: u64,
    time: String,
    input: CommitInput,
    _guard: EmitGuard<'f>,
}

impl<'f> PendingCommit<'f> {
    /// Confirm the event: advance the sequence counter and broadcast it to live subscribers.
    ///
    /// Call this **only** after the caller's transaction (which already carries this event's
    /// `repo_seq` row) has committed successfully — calling it before or instead of a real commit
    /// would broadcast an event with no durable backing.
    pub fn finish(self) {
        self.firehose.last_seq.store(self.seq, Ordering::Release);
        let event = FirehoseEvent::Commit(Arc::new(CommitEvent {
            seq: self.seq,
            time: self.time,
            repo: self.input.repo,
            commit: self.input.commit,
            rev: self.input.rev,
            since: self.input.since,
            prev_data: self.input.prev_data,
            ops: self.input.ops,
            blocks: self.input.blocks,
        }));
        self.firehose.broadcast(event);
    }

    /// Stage a Sync v1.1 `#sync` immediately after this `#commit`, in the *same* transaction and
    /// under the *same* sequencer lock, taking the next `seq`. The genesis account-creation flow
    /// uses this so a fresh repo's head assertion lands atomically with the commit that created it.
    /// The returned handle's [`finish`](PendingWithSync::finish) advances the counter past both and
    /// broadcasts commit-then-sync; dropping it without finishing broadcasts neither and advances
    /// nothing (see [`PendingCommit::finish`]).
    pub async fn stage_sync(
        self,
        tx: &mut Transaction<'_, Sqlite>,
        sync_input: SyncInput,
    ) -> Result<PendingWithSync<'f>, FirehoseError> {
        let sync_seq = self.seq + 1;
        let sync_time = now_rfc3339();
        stage_sync_row(tx, &sync_input, &sync_time, sync_seq).await?;

        let PendingCommit {
            firehose,
            seq,
            time,
            input,
            _guard,
        } = self;
        let primary = FirehoseEvent::Commit(Arc::new(CommitEvent {
            seq,
            time,
            repo: input.repo,
            commit: input.commit,
            rev: input.rev,
            since: input.since,
            prev_data: input.prev_data,
            ops: input.ops,
            blocks: input.blocks,
        }));
        Ok(PendingWithSync {
            firehose,
            primary,
            sync_seq,
            sync_time,
            sync_input,
            _guard,
        })
    }
}

/// The `#account` analogue of [`PendingCommit`] — see its docs for the commit/finish contract.
#[must_use = "a staged account event does nothing until the caller commits its transaction and calls `finish`"]
pub struct PendingAccount<'f> {
    firehose: &'f Firehose,
    seq: u64,
    time: String,
    did: String,
    active: bool,
    status: Option<String>,
    _guard: EmitGuard<'f>,
}

impl<'f> PendingAccount<'f> {
    /// Confirm the event: advance the sequence counter and broadcast it to live subscribers.
    /// Call this only after the caller's transaction has committed successfully (see
    /// [`PendingCommit::finish`]).
    pub fn finish(self) {
        self.firehose.last_seq.store(self.seq, Ordering::Release);
        let event = FirehoseEvent::Account(Arc::new(AccountEvent {
            seq: self.seq,
            time: self.time,
            did: self.did,
            active: self.active,
            status: self.status,
        }));
        self.firehose.broadcast(event);
    }

    /// Stage a Sync v1.1 `#sync` immediately after this `#account`, in the *same* transaction and
    /// under the *same* sequencer lock, taking the next `seq`. Account activation uses this so the
    /// repo's head assertion lands atomically with the status transition that reactivated it. See
    /// [`PendingCommit::stage_sync`] for the finish/drop contract.
    pub async fn stage_sync(
        self,
        tx: &mut Transaction<'_, Sqlite>,
        sync_input: SyncInput,
    ) -> Result<PendingWithSync<'f>, FirehoseError> {
        let sync_seq = self.seq + 1;
        let sync_time = now_rfc3339();
        stage_sync_row(tx, &sync_input, &sync_time, sync_seq).await?;

        let PendingAccount {
            firehose,
            seq,
            time,
            did,
            active,
            status,
            _guard,
        } = self;
        let primary = FirehoseEvent::Account(Arc::new(AccountEvent {
            seq,
            time,
            did,
            active,
            status,
        }));
        Ok(PendingWithSync {
            firehose,
            primary,
            sync_seq,
            sync_time,
            sync_input,
            _guard,
        })
    }
}

/// Insert a `#sync` event's `repo_seq` row into the caller's open transaction at the given `seq`.
/// Shared by [`PendingCommit::stage_sync`] and [`PendingAccount::stage_sync`], which chain a Sync
/// v1.1 state assertion onto their primary staged event under the same lock and transaction.
async fn stage_sync_row(
    tx: &mut Transaction<'_, Sqlite>,
    input: &SyncInput,
    time: &str,
    seq: u64,
) -> Result<(), FirehoseError> {
    // Same over-cap guard as `emit_sync`: a staged oversized `#sync` would roll the caller's
    // transaction back (via `?`) rather than persist a frame that replays as invalid.
    validate_sync_blocks(&input.blocks)?;
    let blob = {
        let stored = StoredSyncRef {
            did: &input.did,
            time,
            rev: &input.rev,
            blocks: &input.blocks,
        };
        serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
    };
    crate::db::firehose_seq::insert_event(&mut **tx, seq, &input.did, "sync", &blob, time).await?;
    Ok(())
}

/// A primary staged event (`#commit` or `#account`) chained with a trailing `#sync`, both inserted
/// into the caller's open transaction but not yet committed or broadcast. Produced by
/// [`PendingCommit::stage_sync`] / [`PendingAccount::stage_sync`]; see [`PendingCommit`]'s docs for
/// the commit/finish contract. `finish` broadcasts the primary event first (lower `seq`) then the
/// `#sync` (next `seq`), and advances the counter past both.
#[must_use = "a staged event pair does nothing until the caller commits its transaction and calls `finish`"]
pub struct PendingWithSync<'f> {
    firehose: &'f Firehose,
    primary: FirehoseEvent,
    sync_seq: u64,
    sync_time: String,
    sync_input: SyncInput,
    _guard: EmitGuard<'f>,
}

impl PendingWithSync<'_> {
    /// Confirm both events: advance the sequence counter past the `#sync` and broadcast the primary
    /// event then the `#sync`. Call this only after the caller's transaction (which carries both
    /// `repo_seq` rows) has committed successfully (see [`PendingCommit::finish`]).
    pub fn finish(self) {
        self.firehose
            .last_seq
            .store(self.sync_seq, Ordering::Release);
        self.firehose.broadcast(self.primary);
        let sync_event = FirehoseEvent::Sync(Arc::new(SyncEvent {
            seq: self.sync_seq,
            time: self.sync_time,
            did: self.sync_input.did,
            rev: self.sync_input.rev,
            blocks: self.sync_input.blocks,
        }));
        self.firehose.broadcast(sync_event);
    }
}

/// Validate that a commit's wire CIDs parse, so an un-encodable commit is rejected before it is
/// persisted (rather than poisoning replay). Mirrors the CID parsing the `#commit` frame encoder
/// does — the only fallible part of encoding it; the rest (DAG-CBOR of scalars/bytes) cannot fail.
fn validate_commit_cids(input: &CommitInput) -> Result<(), FirehoseError> {
    repo_engine::Cid::try_from(input.commit.as_str()).map_err(|e| {
        FirehoseError::Encode(format!("invalid commit CID {:?}: {e}", input.commit))
    })?;
    if let Some(prev_data) = &input.prev_data {
        repo_engine::Cid::try_from(prev_data.as_str()).map_err(|e| {
            FirehoseError::Encode(format!("invalid prevData CID {prev_data:?}: {e}"))
        })?;
    }
    for op in &input.ops {
        if let Some(cid) = &op.cid {
            repo_engine::Cid::try_from(cid.as_str())
                .map_err(|e| FirehoseError::Encode(format!("invalid op CID {cid:?}: {e}")))?;
        }
        if let Some(prev) = &op.prev {
            repo_engine::Cid::try_from(prev.as_str())
                .map_err(|e| FirehoseError::Encode(format!("invalid op prev CID {prev:?}: {e}")))?;
        }
    }
    Ok(())
}

/// Reject a `#sync` whose commit-block CAR exceeds the lexicon's [`MAX_SYNC_BLOCKS_BYTES`] cap,
/// so an oversized (and therefore unencodable-on-the-wire) frame is turned away before it is
/// persisted rather than poisoning replay. Applied by every `#sync` persistence path
/// (`emit_sync` and the staged path via [`stage_sync_row`]).
fn validate_sync_blocks(blocks: &[u8]) -> Result<(), FirehoseError> {
    if blocks.len() > MAX_SYNC_BLOCKS_BYTES {
        return Err(FirehoseError::Encode(format!(
            "#sync blocks CAR is {} bytes, over the {MAX_SYNC_BLOCKS_BYTES}-byte lexicon cap",
            blocks.len()
        )));
    }
    Ok(())
}

/// Reconstruct a [`FirehoseEvent`] from a persisted `repo_seq` row, for cursor replay.
///
/// `seq` comes from the row's primary key (not the stored payload). A reconstructed commit op
/// carries `value: None` — the record value is not part of the wire frame and is not persisted.
pub fn decode_stored_event(
    seq: u64,
    event_type: &str,
    blob: &[u8],
) -> Result<FirehoseEvent, FirehoseError> {
    match event_type {
        "commit" => {
            let s: StoredCommitOwned = serde_ipld_dagcbor::from_slice(blob)
                .map_err(|e| FirehoseError::Decode(e.to_string()))?;
            let mut ops = Vec::with_capacity(s.ops.len());
            for o in s.ops {
                let action = OpAction::from_wire(&o.action).ok_or_else(|| {
                    FirehoseError::Decode(format!("unknown op action {:?}", o.action))
                })?;
                ops.push(RepoOp {
                    action,
                    collection: o.collection,
                    rkey: o.rkey,
                    cid: o.cid,
                    prev: o.prev,
                    value: None,
                });
            }
            Ok(FirehoseEvent::Commit(Arc::new(CommitEvent {
                seq,
                time: s.time,
                repo: s.repo,
                commit: s.commit,
                rev: s.rev,
                since: s.since,
                prev_data: s.prev_data,
                ops,
                blocks: s.blocks,
            })))
        }
        "account" => {
            let s: StoredAccountOwned = serde_ipld_dagcbor::from_slice(blob)
                .map_err(|e| FirehoseError::Decode(e.to_string()))?;
            Ok(FirehoseEvent::Account(Arc::new(AccountEvent {
                seq,
                time: s.time,
                did: s.did,
                active: s.active,
                status: s.status,
            })))
        }
        "identity" => {
            let s: StoredIdentityOwned = serde_ipld_dagcbor::from_slice(blob)
                .map_err(|e| FirehoseError::Decode(e.to_string()))?;
            Ok(FirehoseEvent::Identity(Arc::new(IdentityEvent {
                seq,
                time: s.time,
                did: s.did,
                handle: s.handle,
            })))
        }
        "sync" => {
            let s: StoredSyncOwned = serde_ipld_dagcbor::from_slice(blob)
                .map_err(|e| FirehoseError::Decode(e.to_string()))?;
            Ok(FirehoseEvent::Sync(Arc::new(SyncEvent {
                seq,
                time: s.time,
                did: s.did,
                rev: s.rev,
                blocks: s.blocks,
            })))
        }
        other => Err(FirehoseError::Decode(format!(
            "unknown event_type {other:?}"
        ))),
    }
}

// ── Stored payload representations ─────────────────────────────────────────────
//
// The `repo_seq.event` blob is a DAG-CBOR map carrying everything needed to rebuild the wire
// frame for replay: the commit's metadata, its per-record ops (action/path/cid), and the CARv1
// `blocks` (stored here because post-commit GC may have reclaimed the blocks the diff was built
// from). The record `value` is deliberately omitted — it is not on the wire. Encoding borrows the
// live event (the `*Ref` structs); decoding owns the result (the `*Owned` structs). Field *names*
// must match across the pair; declaration order is irrelevant under DAG-CBOR's canonical map keys.

#[derive(Serialize)]
struct StoredCommitRef<'a> {
    repo: &'a str,
    commit: &'a str,
    rev: &'a str,
    since: Option<&'a str>,
    prev_data: Option<&'a str>,
    time: &'a str,
    ops: Vec<StoredOpRef<'a>>,
    #[serde(with = "serde_bytes")]
    blocks: &'a [u8],
}

#[derive(Serialize)]
struct StoredOpRef<'a> {
    action: &'a str,
    collection: &'a str,
    rkey: &'a str,
    cid: Option<&'a str>,
    prev: Option<&'a str>,
}

impl<'a> From<&'a RepoOp> for StoredOpRef<'a> {
    fn from(op: &'a RepoOp) -> Self {
        StoredOpRef {
            action: op.action.as_str(),
            collection: &op.collection,
            rkey: &op.rkey,
            cid: op.cid.as_deref(),
            prev: op.prev.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct StoredAccountRef<'a> {
    did: &'a str,
    time: &'a str,
    active: bool,
    status: Option<&'a str>,
}

/// Stored `#identity` payload (borrowed form, for encoding a live event).
///
/// Carries the DID, the emission `time`, and the optional `handle`. Everything needed to rebuild
/// the wire frame for replay; no CIDs or blocks. `handle` is stored explicitly (including as
/// `null` when `None`) so a reconstructed event is byte-identical to the original after a
/// round-trip, independent of the wire frame's `skip_serializing_if` omission.
#[derive(Serialize)]
struct StoredIdentityRef<'a> {
    did: &'a str,
    time: &'a str,
    handle: Option<&'a str>,
}

#[derive(Deserialize)]
struct StoredCommitOwned {
    repo: String,
    commit: String,
    rev: String,
    since: Option<String>,
    // A commit persisted before Sync v1.1 has no `prev_data` key; serde decodes a missing
    // `Option` field to `None`, so those older rows replay with `prevData` absent.
    #[serde(default)]
    prev_data: Option<String>,
    time: String,
    ops: Vec<StoredOpOwned>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
}

#[derive(Deserialize)]
struct StoredOpOwned {
    action: String,
    collection: String,
    rkey: String,
    cid: Option<String>,
    // An op persisted before per-op `prev` landed has no `prev` key; serde decodes a missing
    // `Option` field to `None`, so those older rows replay with `prev` absent.
    #[serde(default)]
    prev: Option<String>,
}

#[derive(Deserialize)]
struct StoredAccountOwned {
    did: String,
    time: String,
    active: bool,
    status: Option<String>,
}

/// Stored `#identity` payload (owned form, decoded back out for replay).
#[derive(Deserialize)]
struct StoredIdentityOwned {
    did: String,
    time: String,
    handle: Option<String>,
}

/// Stored `#sync` payload (borrowed form, for encoding a live event). Carries the DID, the
/// emission `time`, the `rev`, and the commit-block CARv1 `blocks` — everything needed to rebuild
/// the wire frame for replay.
#[derive(Serialize)]
struct StoredSyncRef<'a> {
    did: &'a str,
    time: &'a str,
    rev: &'a str,
    #[serde(with = "serde_bytes")]
    blocks: &'a [u8],
}

/// Stored `#sync` payload (owned form, decoded back out for replay).
#[derive(Deserialize)]
struct StoredSyncOwned {
    did: String,
    time: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
}

/// Current UTC time as an RFC 3339 / ISO-8601 string with millisecond precision.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

    /// A firehose backed by a fresh migrated in-memory database.
    async fn test_firehose() -> Firehose {
        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("test migrations");
        Firehose::new(db).await.expect("firehose")
    }

    /// A firehose with a tiny broadcast buffer for exercising slow-consumer lag.
    async fn test_firehose_with_capacity(capacity: usize) -> Firehose {
        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("test migrations");
        Firehose::with_capacity(db, capacity)
            .await
            .expect("firehose")
    }

    /// A valid CIDv1 (dag-cbor, sha2-256) — `emit_commit` now validates wire CIDs before
    /// persisting, so test commits must carry real CIDs rather than placeholder strings.
    const VALID_CID: &str = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";

    fn commit_input(repo: &str) -> CommitInput {
        CommitInput {
            repo: repo.to_string(),
            commit: VALID_CID.to_string(),
            rev: "3krev".to_string(),
            since: None,
            prev_data: None,
            ops: vec![RepoOp {
                action: OpAction::Create,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some(VALID_CID.to_string()),
                prev: None,
                value: Some(serde_json::json!({ "text": "hi" })),
            }],
            blocks: vec![1, 2, 3],
        }
    }

    #[test]
    fn op_helpers_build_path_and_uri() {
        let op = RepoOp {
            action: OpAction::Create,
            collection: "app.bsky.feed.post".to_string(),
            rkey: "abc".to_string(),
            cid: Some("bafy".to_string()),
            prev: None,
            value: None,
        };
        assert_eq!(op.path(), "app.bsky.feed.post/abc");
        assert_eq!(
            op.at_uri("did:plc:x"),
            "at://did:plc:x/app.bsky.feed.post/abc"
        );
        assert_eq!(op.action.as_str(), "create");
        assert_eq!(OpAction::from_wire("delete"), Some(OpAction::Delete));
        assert_eq!(OpAction::from_wire("bogus"), None);
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic_from_one() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();

        assert_eq!(fh.current_seq(), 0);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 2);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 3);
        assert_eq!(fh.current_seq(), 3);

        for expected in 1..=3 {
            match rx.recv().await.unwrap() {
                FirehoseEvent::Commit(c) => assert_eq!(c.seq, expected),
                FirehoseEvent::Account(_) | FirehoseEvent::Identity(_) | FirehoseEvent::Sync(_) => {
                    panic!("expected a #commit event")
                }
            }
        }
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_every_event() {
        let fh = test_firehose().await;
        let mut rx1 = fh.subscribe();
        let mut rx2 = fh.subscribe();
        assert_eq!(fh.subscriber_count(), 2);

        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        fh.emit_commit(commit_input("did:plc:b")).await.unwrap();

        for rx in [&mut rx1, &mut rx2] {
            let FirehoseEvent::Commit(first) = rx.recv().await.unwrap() else {
                panic!("expected a #commit event");
            };
            assert_eq!(first.seq, 1);
            assert_eq!(first.repo, "did:plc:a");
            let FirehoseEvent::Commit(second) = rx.recv().await.unwrap() else {
                panic!("expected a #commit event");
            };
            assert_eq!(second.seq, 2);
            assert_eq!(second.repo, "did:plc:b");
        }
    }

    #[tokio::test]
    async fn commit_event_carries_ops_and_blocks() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();

        let FirehoseEvent::Commit(c) = rx.recv().await.unwrap() else {
            panic!("expected a #commit event");
        };
        assert_eq!(c.blocks, vec![1, 2, 3]);
        assert_eq!(c.ops.len(), 1);
        assert_eq!(c.ops[0].action, OpAction::Create);
        assert_eq!(c.ops[0].cid.as_deref(), Some(VALID_CID));
        // The live event still carries the record value for in-process consumers.
        assert_eq!(c.ops[0].value, Some(serde_json::json!({ "text": "hi" })));
        assert!(!c.time.is_empty());
    }

    #[tokio::test]
    async fn emit_persists_each_event_to_the_log() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        fh.emit_account(
            "did:plc:a".to_string(),
            false,
            Some("deactivated".to_string()),
        )
        .await
        .unwrap();

        // Both events are durable, in order, with their types recorded.
        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 2, 10)
            .await
            .unwrap();
        let types: Vec<&str> = rows.iter().map(|r| r.event_type.as_str()).collect();
        assert_eq!(rows.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(types, vec!["commit", "account"]);
    }

    #[tokio::test]
    async fn sequence_continues_across_restart() {
        let db = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&db).await.unwrap();

        // First "process": emit two events, then drop the firehose (process exits).
        {
            let fh = Firehose::new(db.clone()).await.unwrap();
            assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
            assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 2);
        }

        // Second "process": a fresh firehose over the same DB resumes from seq 2, not 0.
        let fh2 = Firehose::new(db).await.unwrap();
        assert_eq!(fh2.current_seq(), 2, "seq must survive a restart");
        assert_eq!(
            fh2.emit_commit(commit_input("did:plc:a")).await.unwrap(),
            3,
            "the next seq must continue monotonically after restart"
        );
    }

    #[tokio::test]
    async fn replay_survives_restart() {
        // Regression: after a redeploy, a relay reconnecting with a prior cursor must replay the
        // commits it missed from the durable log, not an in-memory buffer the restart cleared.
        let db = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&db).await.unwrap();

        // First "process": three commits, then the firehose (and its broadcast backlog) is gone.
        {
            let fh = Firehose::new(db.clone()).await.unwrap();
            for _ in 0..3 {
                fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
            }
        }

        // Second "process": a fresh firehose over the same DB. A relay reconnects with cursor 1.
        let fh2 = Firehose::new(db.clone()).await.unwrap();
        let SubscribeOutcome::Subscribed(sub) = fh2.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected a subscription");
        };

        // The missed commits (seq 2, 3) come back paged from the durable log.
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(
            seqs,
            vec![2, 3],
            "missed commits replay from the durable log after a restart"
        );
    }

    #[tokio::test]
    async fn subscribe_from_pages_replay_backlog() {
        let fh = test_firehose().await;
        for _ in 0..5 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(2)).await.unwrap() else {
            panic!("expected a subscription");
        };
        // Replay carries (cursor, upper] = (2, 5] from the durable log, oldest first.
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[tokio::test]
    async fn replay_reader_returns_bounded_pages() {
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 3) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");

        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize);
        assert_eq!(first.first().map(FirehoseEvent::seq), Some(1));
        assert_eq!(
            first.last().map(FirehoseEvent::seq),
            Some(u64::from(REPLAY_BATCH))
        );

        let second = replay.next_batch().await.unwrap();
        assert_eq!(second.len(), 3);
        assert_eq!(
            second.iter().map(FirehoseEvent::seq).collect::<Vec<_>>(),
            vec![
                u64::from(REPLAY_BATCH) + 1,
                u64::from(REPLAY_BATCH) + 2,
                u64::from(REPLAY_BATCH) + 3
            ]
        );

        assert!(replay.next_batch().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn subscribe_from_without_cursor_has_empty_replay() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(None).await.unwrap() else {
            panic!("expected a subscription");
        };
        assert!(sub.replay.is_none(), "no cursor means live-only, no replay");
    }

    #[tokio::test]
    async fn subscribe_from_rejects_future_cursor() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1

        match fh.subscribe_from(Some(2)).await.unwrap() {
            SubscribeOutcome::FutureCursor { current } => assert_eq!(current, 1),
            SubscribeOutcome::Subscribed(_) => panic!("cursor 2 is in the future of seq 1"),
        }

        // The current seq itself is not "in the future": it subscribes with an empty replay.
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected a subscription");
        };
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert!(seqs.is_empty());
    }

    #[tokio::test]
    async fn subscribe_from_fails_closed_on_replay_gap() {
        let fh = test_firehose().await;
        for _ in 0..3 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1, 2, 3
        }

        // Punch a hole the sequencer would never produce: seq 2 is missing but 3 remains, so the
        // intermediate gap can only be caught by a per-row density check, not a frontier check.
        sqlx::query("DELETE FROM repo_seq WHERE seq = 2")
            .execute(&fh.db)
            .await
            .unwrap();

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(0)).await.unwrap() else {
            panic!("expected subscription setup to succeed before replay is drained");
        };
        assert!(
            matches!(collect_replay_seqs(sub.replay).await, Err(FirehoseError::Decode(_))),
            "a mid-range gap in the durable replay range must fail closed, not silently skip the missing seq"
        );
    }

    #[tokio::test]
    async fn subscribe_from_degrades_to_best_effort_after_pruned_prefix() {
        let fh = test_firehose().await;
        for _ in 0..5 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=5
        }

        // Simulate a retention sweep that pruned a contiguous prefix (seq 1 and 2) but kept the
        // dense suffix 3..=5 including the frontier.
        sqlx::query("DELETE FROM repo_seq WHERE seq <= 2")
            .execute(&fh.db)
            .await
            .unwrap();

        // A cursor inside the pruned window must NOT fail closed: it degrades to best-effort and
        // replays the retained suffix. seq 1..2 are gone (best-effort), 3..=5 are delivered.
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(0)).await.unwrap() else {
            panic!("cursor 0 below the pruned window must degrade, not fail");
        };
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(
            seqs,
            vec![3, 4, 5],
            "best-effort replays the retained suffix"
        );

        // A cursor inside the retained window replays normally (dense from cursor+1).
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(3)).await.unwrap() else {
            panic!("cursor 3 is inside the retained window");
        };
        assert_eq!(collect_replay_seqs(sub.replay).await.unwrap(), vec![4, 5]);
    }

    #[tokio::test]
    async fn replay_degrades_to_best_effort_when_pruned_mid_drain() {
        // Regression: replay no longer locks out the retention sweep, so a slow reader can
        // have rows pruned out from under it between pages. A gap that opens up mid-drain because of
        // that prune must degrade to best-effort (re-anchor to the retained suffix), not fail
        // closed as if it were a durability hole.
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 5) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=261
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");

        // First page: the dense prefix 1..=REPLAY_BATCH (upper = REPLAY_BATCH + 5).
        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize);
        assert_eq!(
            first.last().map(FirehoseEvent::seq),
            Some(u64::from(REPLAY_BATCH))
        );

        // Simulate a retention sweep pruning past the reader's position between pages: delete
        // through REPLAY_BATCH + 2 and publish the floor, exactly as `firehose_gc::sweep` does.
        let watermark = u64::from(REPLAY_BATCH) + 2;
        sqlx::query("DELETE FROM repo_seq WHERE seq <= ?")
            .bind(watermark as i64)
            .execute(&fh.db)
            .await
            .unwrap();
        fh.note_pruned(watermark);

        // Second page: the pruned run (REPLAY_BATCH+1, +2) is skipped best-effort and the retained
        // suffix (REPLAY_BATCH+3 ..= +5) is delivered dense — no error.
        let second = replay.next_batch().await.unwrap();
        assert_eq!(
            second.iter().map(FirehoseEvent::seq).collect::<Vec<_>>(),
            vec![
                u64::from(REPLAY_BATCH) + 3,
                u64::from(REPLAY_BATCH) + 4,
                u64::from(REPLAY_BATCH) + 5
            ],
            "the pruned run is skipped best-effort and the retained suffix is delivered"
        );
        assert!(replay.next_batch().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn replay_degrades_to_best_effort_when_whole_tail_pruned_mid_drain() {
        // The empty-page counterpart of the test above: when a sweep prunes the *entire* remaining
        // snapshot tail between pages, the next page is empty and never reaches `upper`. That is a
        // prune (the floor covers our position), not a durability hole, so it ends best-effort
        // rather than raising "backlog ended before the frontier".
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 5) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=261
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");
        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize); // after = REPLAY_BATCH, upper = +5

        // Prune the whole remaining snapshot tail (everything above REPLAY_BATCH) and publish it.
        let watermark = u64::from(REPLAY_BATCH) + 5;
        sqlx::query("DELETE FROM repo_seq WHERE seq > ?")
            .bind(u64::from(REPLAY_BATCH) as i64)
            .execute(&fh.db)
            .await
            .unwrap();
        fh.note_pruned(watermark);

        // The empty tail is a prune, not a hole: an empty best-effort page, no error.
        let second = replay.next_batch().await.unwrap();
        assert!(
            second.is_empty(),
            "a fully-pruned tail ends replay best-effort instead of failing closed"
        );
    }

    #[tokio::test]
    async fn subscribe_from_fails_closed_on_a_gap_at_the_cursor_when_a_row_exists_at_the_cursor() {
        // Regression: with rows {1, 3} (seq 2 missing) and cursor = 1, a row EXISTS at the cursor
        // (seq 1), so the gap above it is a mid-range hole — NOT a pruned prefix. The first-row
        // relaxation must not fire: replay must fail closed instead of silently returning [3].
        let fh = test_firehose().await;
        for _ in 0..3 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=3
        }
        sqlx::query("DELETE FROM repo_seq WHERE seq = 2")
            .execute(&fh.db)
            .await
            .unwrap(); // leaves {1, 3}

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected subscription setup to succeed before replay is drained");
        };
        assert!(
            matches!(
                collect_replay_seqs(sub.replay).await,
                Err(FirehoseError::Decode(_))
            ),
            "a gap at the cursor when a row exists at the cursor is mid-range, not a pruned prefix"
        );
    }

    #[tokio::test]
    async fn emit_commit_rejects_invalid_cid_without_persisting() {
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:a");
        input.commit = "not-a-cid".to_string();

        assert!(
            matches!(fh.emit_commit(input).await, Err(FirehoseError::Encode(_))),
            "an un-encodable commit must be rejected at emit"
        );
        // Rejected *before* persistence: no row and no consumed seq, so it can't become a durable
        // replay poison pill.
        assert_eq!(fh.current_seq(), 0);
        assert_eq!(crate::db::firehose_seq::max_seq(&fh.db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn emit_account_shares_sequencer_and_carries_status() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();

        // A commit, then a deactivation, then a reactivation — all share one sequence space.
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
        assert_eq!(
            fh.emit_account(
                "did:plc:a".to_string(),
                false,
                Some("deactivated".to_string())
            )
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            fh.emit_account("did:plc:a".to_string(), true, None)
                .await
                .unwrap(),
            3
        );

        let FirehoseEvent::Commit(c) = rx.recv().await.unwrap() else {
            panic!("expected a commit first");
        };
        assert_eq!(c.seq, 1);

        let FirehoseEvent::Account(deact) = rx.recv().await.unwrap() else {
            panic!("expected an account event");
        };
        assert_eq!(deact.seq, 2);
        assert_eq!(deact.did, "did:plc:a");
        assert!(!deact.active);
        assert_eq!(deact.status.as_deref(), Some("deactivated"));
        assert!(!deact.time.is_empty());

        let FirehoseEvent::Account(react) = rx.recv().await.unwrap() else {
            panic!("expected an account event");
        };
        assert_eq!(react.seq, 3);
        assert!(react.active);
        assert_eq!(react.status, None);
    }

    #[tokio::test]
    async fn emit_with_no_subscribers_still_advances_and_persists() {
        let fh = test_firehose().await;
        // No subscribers attached: the broadcast is dropped but the seq is consumed and persisted.
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 2);
        assert_eq!(fh.current_seq(), 2);
        assert_eq!(crate::db::firehose_seq::max_seq(&fh.db).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn decode_stored_commit_roundtrips_wire_fields() {
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:roundtrip");
        input.since = Some("3kprev".to_string());
        fh.emit_commit(input).await.unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        let event =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap();

        let FirehoseEvent::Commit(c) = event else {
            panic!("expected a #commit event");
        };
        assert_eq!(c.seq, 1);
        assert_eq!(c.repo, "did:plc:roundtrip");
        assert_eq!(c.commit, VALID_CID);
        assert_eq!(c.rev, "3krev");
        assert_eq!(c.since.as_deref(), Some("3kprev"));
        assert_eq!(c.blocks, vec![1, 2, 3]);
        assert_eq!(c.ops.len(), 1);
        assert_eq!(c.ops[0].action, OpAction::Create);
        assert_eq!(c.ops[0].collection, "app.bsky.feed.post");
        assert_eq!(c.ops[0].rkey, "abc");
        assert_eq!(c.ops[0].cid.as_deref(), Some(VALID_CID));
        // A create carries no previous record CID.
        assert_eq!(c.ops[0].prev, None);
        // The record value is not on the wire, so it is not persisted or restored.
        assert_eq!(c.ops[0].value, None);
    }

    #[tokio::test]
    async fn commit_op_prev_survives_persist_and_replay() {
        // Sync v1.1: an update/delete op's `prev` (the previous record CID) must round-trip
        // through the durable log so a relay replaying from a cursor can inductively validate it.
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:opprev");
        input.ops = vec![
            RepoOp {
                action: OpAction::Update,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some(VALID_CID.to_string()),
                prev: Some(VALID_CID.to_string()),
                value: None,
            },
            RepoOp {
                action: OpAction::Delete,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "gone".to_string(),
                cid: None,
                prev: Some(VALID_CID.to_string()),
                value: None,
            },
        ];
        fh.emit_commit(input).await.unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        let FirehoseEvent::Commit(c) =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap()
        else {
            panic!("expected a #commit event");
        };
        assert_eq!(c.ops[0].prev.as_deref(), Some(VALID_CID));
        assert_eq!(c.ops[1].prev.as_deref(), Some(VALID_CID));
    }

    #[tokio::test]
    async fn emit_commit_rejects_invalid_op_prev_cid() {
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:a");
        input.ops[0].prev = Some("not-a-cid".to_string());
        assert!(
            matches!(fh.emit_commit(input).await, Err(FirehoseError::Encode(_))),
            "a commit whose op prev won't encode must be rejected at emit"
        );
        assert_eq!(fh.current_seq(), 0);
    }

    #[tokio::test]
    async fn decode_stored_account_roundtrips() {
        let fh = test_firehose().await;
        fh.emit_account(
            "did:plc:acct".to_string(),
            false,
            Some("deactivated".to_string()),
        )
        .await
        .unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        let event =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap();

        let FirehoseEvent::Account(a) = event else {
            panic!("expected an #account event");
        };
        assert_eq!(a.seq, 1);
        assert_eq!(a.did, "did:plc:acct");
        assert!(!a.active);
        assert_eq!(a.status.as_deref(), Some("deactivated"));
    }

    #[tokio::test]
    async fn emit_identity_shares_sequencer_and_carries_handle() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();

        // A commit, then an identity-with-handle, then an identity-without-handle — all share
        // one sequence space and are delivered in seq order.
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
        assert_eq!(
            fh.emit_identity(
                "did:plc:a".to_string(),
                Some("alice.example.com".to_string()),
            )
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            fh.emit_identity("did:plc:a".to_string(), None)
                .await
                .unwrap(),
            3
        );

        let FirehoseEvent::Commit(_) = rx.recv().await.unwrap() else {
            panic!("expected a commit first");
        };
        let FirehoseEvent::Identity(with_handle) = rx.recv().await.unwrap() else {
            panic!("expected an #identity event");
        };
        assert_eq!(with_handle.seq, 2);
        assert_eq!(with_handle.did, "did:plc:a");
        assert_eq!(with_handle.handle.as_deref(), Some("alice.example.com"));
        assert!(!with_handle.time.is_empty());

        let FirehoseEvent::Identity(no_handle) = rx.recv().await.unwrap() else {
            panic!("expected an #identity event");
        };
        assert_eq!(no_handle.seq, 3);
        assert_eq!(no_handle.handle, None);
    }

    #[tokio::test]
    async fn decode_stored_identity_roundtrips() {
        let fh = test_firehose().await;
        fh.emit_identity(
            "did:plc:ident".to_string(),
            Some("bob.example.com".to_string()),
        )
        .await
        .unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        assert_eq!(rows[0].event_type, "identity");
        let event =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap();

        let FirehoseEvent::Identity(i) = event else {
            panic!("expected an #identity event");
        };
        assert_eq!(i.seq, 1);
        assert_eq!(i.did, "did:plc:ident");
        assert_eq!(i.handle.as_deref(), Some("bob.example.com"));
        // `handle: None` likewise survives a persist + decode round-trip intact.
        fh.emit_identity("did:plc:ident".to_string(), None)
            .await
            .unwrap();
        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 1, 2, 1)
            .await
            .unwrap();
        let FirehoseEvent::Identity(i2) =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap()
        else {
            panic!("expected an #identity event");
        };
        assert_eq!(i2.handle, None);
    }

    #[tokio::test]
    async fn commit_prev_data_survives_persist_and_replay() {
        // Sync v1.1: `prevData` (the previous commit's MST root CID) must round-trip through the
        // durable log so a relay replaying from a cursor still gets an inductively-verifiable frame.
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:prevdata");
        input.since = Some("3kprev".to_string());
        input.prev_data = Some(VALID_CID.to_string());
        fh.emit_commit(input).await.unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        let FirehoseEvent::Commit(c) =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap()
        else {
            panic!("expected a #commit event");
        };
        assert_eq!(c.prev_data.as_deref(), Some(VALID_CID));

        // A genesis-style commit with no predecessor persists and replays `prevData` as absent.
        let mut genesis = commit_input("did:plc:prevdata");
        genesis.prev_data = None;
        fh.emit_commit(genesis).await.unwrap();
        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 1, 2, 1)
            .await
            .unwrap();
        let FirehoseEvent::Commit(c2) =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap()
        else {
            panic!("expected a #commit event");
        };
        assert_eq!(c2.prev_data, None);
    }

    #[tokio::test]
    async fn emit_commit_rejects_invalid_prev_data_cid() {
        let fh = test_firehose().await;
        let mut input = commit_input("did:plc:a");
        input.prev_data = Some("not-a-cid".to_string());
        assert!(
            matches!(fh.emit_commit(input).await, Err(FirehoseError::Encode(_))),
            "a commit whose prevData won't encode must be rejected at emit"
        );
        assert_eq!(fh.current_seq(), 0);
    }

    fn sync_input(did: &str) -> SyncInput {
        SyncInput {
            did: did.to_string(),
            rev: "3ksync".to_string(),
            blocks: vec![0xCA, 0xFE, 0xBA, 0xBE],
        }
    }

    #[tokio::test]
    async fn emit_sync_shares_sequencer_and_broadcasts() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();

        assert_eq!(fh.emit_commit(commit_input("did:plc:a")).await.unwrap(), 1);
        assert_eq!(fh.emit_sync(sync_input("did:plc:a")).await.unwrap(), 2);

        let FirehoseEvent::Commit(_) = rx.recv().await.unwrap() else {
            panic!("expected a commit first");
        };
        let FirehoseEvent::Sync(s) = rx.recv().await.unwrap() else {
            panic!("expected a #sync event");
        };
        assert_eq!(s.seq, 2);
        assert_eq!(s.did, "did:plc:a");
        assert_eq!(s.rev, "3ksync");
        assert_eq!(s.blocks, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert!(!s.time.is_empty());
    }

    #[tokio::test]
    async fn emit_sync_rejects_oversized_blocks_without_persisting() {
        let fh = test_firehose().await;
        let mut input = sync_input("did:plc:big");
        input.blocks = vec![0u8; MAX_SYNC_BLOCKS_BYTES + 1];
        assert!(
            matches!(fh.emit_sync(input).await, Err(FirehoseError::Encode(_))),
            "a #sync CAR over the lexicon cap must be rejected at emit"
        );
        // Rejected before persistence: no row, no consumed seq.
        assert_eq!(fh.current_seq(), 0);
        assert_eq!(crate::db::firehose_seq::max_seq(&fh.db).await.unwrap(), 0);

        // A CAR exactly at the cap is accepted.
        let mut at_cap = sync_input("did:plc:big");
        at_cap.blocks = vec![0u8; MAX_SYNC_BLOCKS_BYTES];
        assert_eq!(fh.emit_sync(at_cap).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn stage_sync_rejects_oversized_blocks_and_rolls_back() {
        // A staged over-cap `#sync` must fail the whole transaction rather than persist an invalid
        // frame — the chained account write must roll back with it, leaving no durable trace. Seed
        // a genuinely-deactivated account so the in-transaction reactivation is a real change whose
        // rollback is observable in the DB afterward.
        let fh = test_firehose().await;
        insert_account(&fh.db, "did:plc:a", "root").await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = 'did:plc:a'")
            .execute(&fh.db)
            .await
            .unwrap();
        let before_deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = 'did:plc:a'")
                .fetch_one(&fh.db)
                .await
                .unwrap();

        // Acquire the sequencer lock *before* opening the transaction, per `lock_emit`'s contract.
        let emit_guard = fh.lock_emit().await;
        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let account = emit_guard
            .stage_account(&mut tx, "did:plc:a".to_string(), true, None)
            .await
            .unwrap();
        let mut oversized = sync_input("did:plc:a");
        oversized.blocks = vec![0u8; MAX_SYNC_BLOCKS_BYTES + 1];
        let result = account.stage_sync(&mut tx, oversized).await;
        assert!(
            matches!(result, Err(FirehoseError::Encode(_))),
            "an over-cap staged #sync must be rejected"
        );

        // The failed stage takes the whole transaction down with it (via `?`/Drop): the
        // reactivation rolls back, no `repo_seq` row lands, and the sequencer counter is untouched.
        drop(tx);
        let after_deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = 'did:plc:a'")
                .fetch_one(&fh.db)
                .await
                .unwrap();
        assert_eq!(
            after_deactivated_at, before_deactivated_at,
            "the reactivation must roll back with the rejected #sync"
        );
        assert_eq!(
            crate::db::firehose_seq::max_seq(&fh.db).await.unwrap(),
            0,
            "no repo_seq row must persist"
        );
        assert_eq!(
            fh.current_seq(),
            0,
            "seq must not advance on a rejected stage"
        );
    }

    #[tokio::test]
    async fn decode_stored_sync_roundtrips() {
        let fh = test_firehose().await;
        fh.emit_sync(sync_input("did:plc:sync")).await.unwrap();

        let rows = crate::db::firehose_seq::events_in_range(&fh.db, 0, 1, 1)
            .await
            .unwrap();
        assert_eq!(rows[0].event_type, "sync");
        let FirehoseEvent::Sync(s) =
            decode_stored_event(rows[0].seq as u64, &rows[0].event_type, &rows[0].event).unwrap()
        else {
            panic!("expected a #sync event");
        };
        assert_eq!(s.seq, 1);
        assert_eq!(s.did, "did:plc:sync");
        assert_eq!(s.rev, "3ksync");
        assert_eq!(s.blocks, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[tokio::test]
    async fn stage_account_then_sync_broadcasts_both_in_order_after_finish() {
        // Activation stages an `#account` (active) followed by a `#sync` in one transaction: both
        // rows persist atomically, and `finish` advances the counter past both and broadcasts
        // account-then-sync in seq order.
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();
        insert_account(&fh.db, "did:plc:a", "root").await;

        // Acquire the sequencer lock *before* opening the transaction, per `lock_emit`'s contract.
        let emit_guard = fh.lock_emit().await;
        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let pending = emit_guard
            .stage_account(&mut tx, "did:plc:a".to_string(), true, None)
            .await
            .unwrap()
            .stage_sync(&mut tx, sync_input("did:plc:a"))
            .await
            .unwrap();

        assert_eq!(fh.current_seq(), 0, "seq must not advance before finish");
        assert!(rx.try_recv().is_err(), "must not broadcast before finish");

        tx.commit().await.unwrap();
        pending.finish();

        assert_eq!(fh.current_seq(), 2, "both events consume a seq");
        let FirehoseEvent::Account(a) = rx.try_recv().unwrap() else {
            panic!("expected the #account event first");
        };
        assert_eq!(a.seq, 1);
        assert!(a.active);
        let FirehoseEvent::Sync(s) = rx.try_recv().unwrap() else {
            panic!("expected the #sync event second");
        };
        assert_eq!(s.seq, 2);
        assert_eq!(s.did, "did:plc:a");
        assert_eq!(s.rev, "3ksync");
    }

    #[tokio::test]
    async fn slow_subscriber_lags_without_blocking_producer() {
        // A tiny buffer makes overflow easy to trigger. A consumer that never drains must
        // not prevent the producer from emitting, and must observe Lagged rather than stall.
        let fh = test_firehose_with_capacity(2).await;
        let mut slow = fh.subscribe();

        // Emit more events than the buffer holds; every emit returns immediately.
        for _ in 0..10 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }
        assert_eq!(
            fh.current_seq(),
            10,
            "producer advanced despite the slow consumer"
        );

        // The slow consumer fell behind: its next recv reports how many it missed.
        match slow.recv().await {
            Err(RecvError::Lagged(missed)) => assert!(missed >= 1),
            other => panic!("expected Lagged, got {other:?}"),
        }

        // After the lag is reported, it resumes from the oldest still-buffered event and
        // continues to see the most recent ones.
        let FirehoseEvent::Commit(next) = slow.recv().await.unwrap() else {
            panic!("expected a #commit event");
        };
        assert!(
            next.seq >= 9,
            "should resume near the head, got seq {}",
            next.seq
        );
        let FirehoseEvent::Commit(last) = slow.recv().await.unwrap() else {
            panic!("expected a #commit event");
        };
        assert_eq!(last.seq, 10);
        assert_eq!(slow.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    // ── stage_commit / stage_account (atomic staging) ─────────────────────────

    /// Seed a minimal `accounts` row so a test can mutate it inside the same transaction as a
    /// staged event, to observe whether that write survives a commit or a rollback.
    async fn insert_account(db: &SqlitePool, did: &str, repo_root_cid: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, repo_root_cid, created_at, updated_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .bind(repo_root_cid)
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stage_commit_persists_and_broadcasts_only_after_finish() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();
        insert_account(&fh.db, "did:plc:a", "old-root").await;

        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET repo_root_cid = 'new-root' WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let pending = fh
            .lock_emit()
            .await
            .stage_commit(&mut tx, commit_input("did:plc:a"))
            .await
            .unwrap();

        // Before commit/finish: nothing durable yet, seq unadvanced, no broadcast.
        assert_eq!(fh.current_seq(), 0, "seq must not advance before finish");
        assert!(rx.try_recv().is_err(), "must not broadcast before finish");

        tx.commit().await.unwrap();
        pending.finish();

        assert_eq!(fh.current_seq(), 1, "finish must advance seq after commit");
        assert!(
            matches!(rx.try_recv(), Ok(FirehoseEvent::Commit(_))),
            "finish must broadcast the event"
        );
        let root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = 'did:plc:a'")
                .fetch_one(&fh.db)
                .await
                .unwrap();
        assert_eq!(root, "new-root");
    }

    #[tokio::test]
    async fn stage_commit_failure_rolls_back_the_callers_write_in_the_same_transaction() {
        // A simulated `repo_seq` insert failure must not leave the caller's other write
        // (here, the repo-root CAS) committed with no corresponding durable firehose row.
        let fh = test_firehose().await;
        insert_account(&fh.db, "did:plc:a", "old-root").await;

        // Simulate a sequencer write failure: drop `repo_seq` so the insert inside `stage_commit`
        // fails with a real DB error instead of a contrived one.
        sqlx::query("DROP TABLE repo_seq")
            .execute(&fh.db)
            .await
            .unwrap();

        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET repo_root_cid = 'new-root' WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = fh
            .lock_emit()
            .await
            .stage_commit(&mut tx, commit_input("did:plc:a"))
            .await;
        assert!(
            matches!(result, Err(FirehoseError::Db(_))),
            "the repo_seq insert must fail with a DB error"
        );

        // Never committed: dropping `tx` here rolls back the accounts UPDATE too, exactly as the
        // production call sites rely on (`?` early-return before an explicit commit).
        drop(tx);

        let root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = 'did:plc:a'")
                .fetch_one(&fh.db)
                .await
                .unwrap();
        assert_eq!(
            root, "old-root",
            "a failed firehose insert must roll back the caller's write, not leave it committed \
             with no corresponding durable event"
        );
        assert_eq!(
            fh.current_seq(),
            0,
            "seq must not advance on a failed stage"
        );
    }

    #[tokio::test]
    async fn emit_recovers_after_a_request_cancelled_between_commit_and_finish() {
        // A handler future dropped during its `tx.commit().await` (client disconnect) can leave
        // the staged `repo_seq` row durable while `finish()` — the only place `last_seq`
        // advances — never runs. The next emit computes the same seq, hits the PRIMARY KEY, and
        // without self-healing every subsequent write fails until the process restarts.
        let fh = test_firehose().await;

        let mut tx = fh.db.begin().await.unwrap();
        let pending = fh
            .lock_emit()
            .await
            .stage_commit(&mut tx, commit_input("did:plc:a"))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        // The cancellation: the row at seq 1 is durable, but finish() never runs.
        drop(pending);
        assert_eq!(
            fh.current_seq(),
            0,
            "the cancelled request must not have advanced the frontier"
        );

        let seq = fh
            .emit_commit(commit_input("did:plc:b"))
            .await
            .expect("the next emit must re-seed from the durable log, not collide forever");
        assert_eq!(seq, 2, "the orphaned durable row holds seq 1");
        assert_eq!(fh.current_seq(), 2);
    }

    #[tokio::test]
    async fn staged_write_recovers_after_a_request_cancelled_between_commit_and_finish() {
        // Same wedge as above, healed on the staged path — the one every record write and
        // account-status transition goes through.
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();

        let mut tx = fh.db.begin().await.unwrap();
        let pending = fh
            .lock_emit()
            .await
            .stage_commit(&mut tx, commit_input("did:plc:a"))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(pending);

        let mut tx = fh.db.begin().await.unwrap();
        let pending = fh
            .lock_emit()
            .await
            .stage_commit(&mut tx, commit_input("did:plc:b"))
            .await
            .expect("the next staged write must re-seed from the durable log, not fail");
        tx.commit().await.unwrap();
        pending.finish();

        assert_eq!(
            fh.current_seq(),
            2,
            "the healed write takes the next free seq"
        );
        let FirehoseEvent::Commit(c) = rx.recv().await.unwrap() else {
            panic!("expected a #commit event");
        };
        assert_eq!(c.seq, 2);
        assert_eq!(c.repo, "did:plc:b");
    }

    #[tokio::test]
    async fn stage_account_persists_and_broadcasts_only_after_finish() {
        let fh = test_firehose().await;
        let mut rx = fh.subscribe();
        insert_account(&fh.db, "did:plc:a", "root").await;

        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let pending = fh
            .lock_emit()
            .await
            .stage_account(
                &mut tx,
                "did:plc:a".to_string(),
                false,
                Some("deactivated".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(fh.current_seq(), 0, "seq must not advance before finish");
        assert!(rx.try_recv().is_err(), "must not broadcast before finish");

        tx.commit().await.unwrap();
        pending.finish();

        assert_eq!(fh.current_seq(), 1);
        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account event");
        };
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deactivated"));
    }

    #[tokio::test]
    async fn stage_account_failure_rolls_back_the_callers_write_in_the_same_transaction() {
        let fh = test_firehose().await;
        insert_account(&fh.db, "did:plc:a", "root").await;
        sqlx::query("DROP TABLE repo_seq")
            .execute(&fh.db)
            .await
            .unwrap();

        let mut tx = fh.db.begin().await.unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = 'did:plc:a'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = fh
            .lock_emit()
            .await
            .stage_account(&mut tx, "did:plc:a".to_string(), false, None)
            .await;
        assert!(matches!(result, Err(FirehoseError::Db(_))));

        drop(tx);

        let deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = 'did:plc:a'")
                .fetch_one(&fh.db)
                .await
                .unwrap();
        assert_eq!(
            deactivated_at, None,
            "a failed firehose insert must roll back the status transition too"
        );
    }

    #[tokio::test]
    async fn staged_and_plain_emit_do_not_deadlock_concurrently() {
        // Regression: `emit_identity`/`emit_commit`/`emit_account` acquire `emit_lock` *before*
        // touching the single-connection pool. A staged path that instead opened its transaction
        // first (taking the pool's sole connection) and only then acquired `emit_lock` could
        // deadlock against one of those: the staged task would hold the connection while waiting
        // on the lock, and the plain task would hold the lock while waiting on the connection.
        // `lock_emit()` must be acquired before `db.begin()` to keep both paths in the same order
        // (see `Firehose::lock_emit`'s docs) — run them concurrently and require the pair to
        // finish well inside a generous timeout.
        let fh = std::sync::Arc::new(test_firehose().await);
        insert_account(&fh.db, "did:plc:a", "root").await;

        let staged = {
            let fh = fh.clone();
            tokio::spawn(async move {
                let emit_guard = fh.lock_emit().await;
                let mut tx = fh.db.begin().await.unwrap();
                // Yield so the concurrent plain emit below has a chance to be mid-flight,
                // widening the interleaving window this test is meant to exercise.
                tokio::task::yield_now().await;
                sqlx::query(
                    "UPDATE accounts SET repo_root_cid = 'new-root' WHERE did = 'did:plc:a'",
                )
                .execute(&mut *tx)
                .await
                .unwrap();
                let pending = emit_guard
                    .stage_commit(&mut tx, commit_input("did:plc:a"))
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                pending.finish();
            })
        };

        let plain = {
            let fh = fh.clone();
            tokio::spawn(async move {
                fh.emit_identity(
                    "did:plc:a".to_string(),
                    Some("alice.example.com".to_string()),
                )
                .await
                .unwrap();
            })
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            staged.await.unwrap();
            plain.await.unwrap();
        })
        .await
        .expect("a staged commit and a concurrent plain emit must not deadlock");
    }
}
