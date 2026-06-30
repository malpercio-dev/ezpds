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

// Dead code allow: a few accessors (`subscriber_count`, the `at_uri`/`as_str` wire helpers) are
// exercised only by this module's unit tests and the `subscribeRepos` handler's tests.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::broadcast;

/// Default capacity of the broadcast ring buffer: the number of events retained for slow
/// consumers before they begin to observe `Lagged`.
const DEFAULT_CAPACITY: usize = 1024;

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

/// A frame broadcast to firehose subscribers. Modelled as an enum so further frame types
/// (e.g. `#identity`) can be added without changing the channel item type.
#[derive(Debug, Clone)]
pub enum FirehoseEvent {
    Commit(Arc<CommitEvent>),
    Account(Arc<AccountEvent>),
}

impl FirehoseEvent {
    /// The sequence number of the underlying event.
    pub fn seq(&self) -> u64 {
        match self {
            FirehoseEvent::Commit(c) => c.seq,
            FirehoseEvent::Account(a) => a.seq,
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
    pub ops: Vec<RepoOp>,
    pub blocks: Vec<u8>,
}

/// A new subscription: the durable backlog to replay first, then the live event stream.
///
/// `replay` is the materialised `(cursor, upper]` range read back from the durable log (oldest
/// first); the consumer sends it before streaming live events from `rx`. Because `rx` was taken
/// and the frontier `upper` snapshotted together under the sequencer lock — before any later emit
/// could advance the counter — every live event has `seq > upper`, so replay and the live stream
/// are exactly disjoint: no event is dropped between them and none is delivered twice.
pub struct Subscription {
    /// The missed events with `cursor < seq <= upper`, oldest first, to send before live streaming.
    /// Empty for a live-only subscription (no cursor).
    pub replay: Vec<FirehoseEvent>,
    /// Live event stream for everything emitted after this subscription was created
    /// (all with `seq > upper`).
    pub rx: broadcast::Receiver<FirehoseEvent>,
}

/// The outcome of [`Firehose::subscribe_from`].
pub enum SubscribeOutcome {
    /// The subscription was established; send `replay`, then stream `rx`.
    Subscribed(Subscription),
    /// The requested cursor is ahead of the latest assigned sequence (`current`), so it cannot
    /// be honoured — the client is claiming to have seen events that do not exist.
    FutureCursor { current: u64 },
}

/// How many backlog rows to read per query when materialising a cursor replay from the durable
/// log, so a subscriber resuming from an old cursor pages the DB rather than issuing one unbounded
/// query.
const REPLAY_BATCH: u32 = 256;

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
    /// The last sequence number assigned. Written only under `emit_lock` (after the row is
    /// persisted), so a value `<= last_seq` is always already durable. Read locklessly for
    /// diagnostics (`current_seq`) and under the lock for the subscribe frontier.
    last_seq: AtomicU64,
    tx: broadcast::Sender<FirehoseEvent>,
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
            last_seq: AtomicU64::new(last),
            tx,
        })
    }

    /// Subscribe to the live event stream only (no replay). Each subscriber receives every
    /// event emitted after it subscribes; a subscriber that falls more than the broadcast
    /// capacity behind observes `RecvError::Lagged` on its next `recv`.
    pub fn subscribe(&self) -> broadcast::Receiver<FirehoseEvent> {
        self.tx.subscribe()
    }

    /// Subscribe with optional cursor replay.
    ///
    /// Returns a [`Subscription`] whose `replay` is the materialised `(cursor, upper]` backlog read
    /// from the durable log (oldest first) and whose `rx` streams every later event. A cursor ahead
    /// of the latest assigned sequence yields [`SubscribeOutcome::FutureCursor`]; a `cursor = None`
    /// gives an empty `replay` (live-only).
    ///
    /// The live receiver and the `upper` frontier are captured together under `emit_lock`, so no
    /// concurrent emit can slip an event past both the replay range and the receiver, nor advance
    /// the counter into a spurious `FutureCursor`. Replay is then read outside the lock, bounded by
    /// `upper`, so it stays disjoint from the live stream. Events still present in the log can
    /// always be replayed; there is no in-memory buffer to age out. The retention sweep
    /// (`firehose_gc`) may prune a contiguous prefix below the live frontier, in which case a
    /// cursor inside the pruned window degrades to best-effort replay (see [`read_replay`])
    /// rather than failing closed.
    ///
    /// Returns [`FirehoseError`] if the backlog can't be assembled: a DB read failure, a stored row
    /// that won't decode, or a *mid-range* gap in the `(cursor, upper]` range (which `read_replay`
    /// rejects so a hole is never silently bridged). A cursor that falls inside a **pruned prefix**
    /// degrades to best-effort instead — the subscriber receives the retained suffix — because the
    /// retention sweep only ever removes a contiguous prefix below the live frontier. The caller
    /// fails the subscription closed only on a real error (DB/decode/mid-range gap).
    pub async fn subscribe_from(
        &self,
        cursor: Option<u64>,
    ) -> Result<SubscribeOutcome, FirehoseError> {
        let (rx, upper) = {
            let _guard = self.emit_lock.lock().await;
            // Subscribe to the live channel *before* releasing the lock so that no event emitted
            // after this snapshot can slip past both the replay range and the receiver, and read
            // the frontier under the same lock so `upper` reflects exactly what is already durable.
            (self.tx.subscribe(), self.last_seq.load(Ordering::Acquire))
        };

        let replay = match cursor {
            Some(c) if c > upper => return Ok(SubscribeOutcome::FutureCursor { current: upper }),
            Some(c) => self.read_replay(c, upper).await?,
            None => Vec::new(),
        };

        Ok(SubscribeOutcome::Subscribed(Subscription { replay, rx }))
    }

    /// Materialise the durable replay backlog for `(cursor, upper]`, oldest first.
    ///
    /// Pages the log in `REPLAY_BATCH` chunks and decodes each row into a [`FirehoseEvent`]. The
    /// range is a dense prefix (the sequencer advances `last_seq` only after a row is persisted),
    /// so this enforces density between **consecutive** rows — each `seq` must be exactly the
    /// previous plus one, and the last must reach `upper` — and returns [`FirehoseError`] on any
    /// gap rather than silently skipping a missing `seq`. A negative stored `seq` (which can't
    /// occur from our writer) or a row that won't decode is likewise a hard error: replay must be
    /// exact or fail closed.
    ///
    /// **Best-effort at the pruned prefix.** The retention sweep (`firehose_gc`) prunes a
    /// *contiguous* prefix `seq ≤ watermark`, so the first row above a cursor that falls inside
    /// the pruned window is the oldest retained row, not `cursor + 1`. The first-row density
    /// check is **relaxed only when the cursor sits below the oldest retained row** (no row at
    /// or below the cursor — i.e. `exists_at_or_below(cursor)` is false): that is a genuine pruned
    /// prefix, so replay degrades to best-effort (the subscriber receives the retained suffix)
    /// rather than failing closed. When a row *does* exist at or below the cursor, replay is
    /// dense from the cursor and any jump on the first row is a mid-range gap that fails closed.
    /// The `anchored` decision is made lazily — at the moment a gap is first observed — by
    /// re-checking `exists_at_or_below(cursor)` against the same log state the batch was read
    /// from, so a concurrent sweep cannot flip the cursor row between the decision and the batch
    /// read (no TOCTOU). The strict consecutive-row check still catches a *mid-range* hole (a
    /// durability bug, not a
    /// prune) on the second row onward, and the frontier-reach check still catches a missing tail.
    async fn read_replay(
        &self,
        cursor: u64,
        upper: u64,
    ) -> Result<Vec<FirehoseEvent>, FirehoseError> {
        let mut events = Vec::new();
        let mut after = cursor;
        // `anchored` means replay has at least one row to be dense from. It starts false, so the
        // first decoded row is allowed to start above `cursor + 1` — but only if that gap is a
        // genuine *pruned prefix* (no row at/below the cursor), not a mid-range hole. We decide
        // that LAZILY, at the moment a gap is first observed, by re-checking
        // `exists_at_or_below(cursor)` against the same log state the batch was read from. This
        // avoids the TOCTOU of deciding `anchored` up-front (a concurrent sweep could prune the
        // cursor row between an early decision and the first batch read). Once replay has a row
        // to anchor on, every subsequent row must be exactly `prev + 1`.
        let mut anchored = false;
        while after < upper {
            let batch =
                crate::db::firehose_seq::events_in_range(&self.db, after, upper, REPLAY_BATCH)
                    .await?;
            if batch.is_empty() {
                break;
            }
            let page_len = batch.len();
            for row in batch {
                let seq = u64::try_from(row.seq).map_err(|_| {
                    FirehoseError::Decode(format!("negative stored firehose seq {}", row.seq))
                })?;
                if seq != after + 1 {
                    // A gap. If we've already anchored, this is a mid-range hole — fail closed.
                    if anchored {
                        return Err(FirehoseError::Decode(format!(
                            "firehose replay gap: expected seq {}, found {seq}",
                            after + 1
                        )));
                    }
                    // First-row gap: decide pruned-prefix vs mid-range hole from the SAME log
                    // state as this batch (lazy re-check, no TOCTOU). If the cursor still has a
                    // retained row, the gap is a real mid-range hole → fail closed. If the cursor
                    // row is gone, a sweep pruned the prefix → degrade to best-effort from here.
                    let cursor_present =
                        crate::db::firehose_seq::exists_at_or_below(&self.db, cursor).await?;
                    if cursor_present {
                        return Err(FirehoseError::Decode(format!(
                            "firehose replay gap: expected seq {}, found {seq}",
                            after + 1
                        )));
                    }
                    // Pruned prefix: best-effort. Anchor here and continue dense from this row.
                    anchored = true;
                    after = seq;
                    events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
                    continue;
                }
                anchored = true;
                after = seq;
                events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
            }
            if (page_len as u32) < REPLAY_BATCH {
                break;
            }
        }
        if after < upper {
            return Err(FirehoseError::Decode(format!(
                "firehose replay backlog ended at seq {after} before the frontier {upper}"
            )));
        }
        Ok(events)
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
                time: &time,
                ops: input.ops.iter().map(StoredOpRef::from).collect(),
                blocks: &input.blocks,
            };
            serde_ipld_dagcbor::to_vec(&stored).map_err(|e| FirehoseError::Encode(e.to_string()))?
        };
        let seq = self.last_seq.load(Ordering::Acquire) + 1;
        crate::db::firehose_seq::insert_event(&self.db, seq, &input.repo, "commit", &blob, &time)
            .await?;
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Commit(Arc::new(CommitEvent {
            seq,
            time,
            repo: input.repo,
            commit: input.commit,
            rev: input.rev,
            since: input.since,
            ops: input.ops,
            blocks: input.blocks,
        }));
        // A send error means "no subscribers"; that is expected, not a failure.
        let _ = self.tx.send(event);
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
        let seq = self.last_seq.load(Ordering::Acquire) + 1;
        crate::db::firehose_seq::insert_event(&self.db, seq, &did, "account", &blob, &time).await?;
        self.last_seq.store(seq, Ordering::Release);

        let event = FirehoseEvent::Account(Arc::new(AccountEvent {
            seq,
            time,
            did,
            active,
            status,
        }));
        let _ = self.tx.send(event);
        Ok(seq)
    }
}

/// Validate that a commit's wire CIDs parse, so an un-encodable commit is rejected before it is
/// persisted (rather than poisoning replay). Mirrors the CID parsing the `#commit` frame encoder
/// does — the only fallible part of encoding it; the rest (DAG-CBOR of scalars/bytes) cannot fail.
fn validate_commit_cids(input: &CommitInput) -> Result<(), FirehoseError> {
    repo_engine::Cid::try_from(input.commit.as_str()).map_err(|e| {
        FirehoseError::Encode(format!("invalid commit CID {:?}: {e}", input.commit))
    })?;
    for op in &input.ops {
        if let Some(cid) = &op.cid {
            repo_engine::Cid::try_from(cid.as_str())
                .map_err(|e| FirehoseError::Encode(format!("invalid op CID {cid:?}: {e}")))?;
        }
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
}

impl<'a> From<&'a RepoOp> for StoredOpRef<'a> {
    fn from(op: &'a RepoOp) -> Self {
        StoredOpRef {
            action: op.action.as_str(),
            collection: &op.collection,
            rkey: &op.rkey,
            cid: op.cid.as_deref(),
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

#[derive(Deserialize)]
struct StoredCommitOwned {
    repo: String,
    commit: String,
    rev: String,
    since: Option<String>,
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
}

#[derive(Deserialize)]
struct StoredAccountOwned {
    did: String,
    time: String,
    active: bool,
    status: Option<String>,
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
            ops: vec![RepoOp {
                action: OpAction::Create,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some(VALID_CID.to_string()),
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
                FirehoseEvent::Account(_) => panic!("expected a #commit event"),
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

        // The missed commits (seq 2, 3) come back materialised from the durable log.
        let seqs: Vec<u64> = sub.replay.iter().map(|e| e.seq()).collect();
        assert_eq!(
            seqs,
            vec![2, 3],
            "missed commits replay from the durable log after a restart"
        );
    }

    #[tokio::test]
    async fn subscribe_from_materialises_replay_backlog() {
        let fh = test_firehose().await;
        for _ in 0..5 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(2)).await.unwrap() else {
            panic!("expected a subscription");
        };
        // Replay carries (cursor, upper] = (2, 5] from the durable log, oldest first.
        let seqs: Vec<u64> = sub.replay.iter().map(|e| e.seq()).collect();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[tokio::test]
    async fn subscribe_from_without_cursor_has_empty_replay() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(None).await.unwrap() else {
            panic!("expected a subscription");
        };
        assert!(
            sub.replay.is_empty(),
            "no cursor means live-only, no replay"
        );
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
        assert!(sub.replay.is_empty());
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

        assert!(
            matches!(
                fh.subscribe_from(Some(0)).await,
                Err(FirehoseError::Decode(_))
            ),
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
        let seqs: Vec<u64> = sub.replay.iter().map(|e| e.seq()).collect();
        assert_eq!(
            seqs,
            vec![3, 4, 5],
            "best-effort replays the retained suffix"
        );

        // A cursor inside the retained window replays normally (dense from cursor+1).
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(3)).await.unwrap() else {
            panic!("cursor 3 is inside the retained window");
        };
        assert_eq!(
            sub.replay.iter().map(|e| e.seq()).collect::<Vec<_>>(),
            vec![4, 5]
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

        assert!(
            matches!(
                fh.subscribe_from(Some(1)).await,
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
        // The record value is not on the wire, so it is not persisted or restored.
        assert_eq!(c.ops[0].value, None);
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
}
