// pattern: Imperative Shell

//! Persistent firehose event pipeline backing `com.atproto.sync.subscribeRepos`.
//!
//! Every repo commit (and account-status change) produces a sequenced event that is both
//! **persisted** to the `repo_seq` table and fanned out to all current subscribers over a Tokio
//! broadcast channel. The WebSocket handler (`routes/sync_subscribe_repos.rs`) encodes each event
//! into a DAG-CBOR frame.
//!
//! **Durability & restart safety.** The monotonic `seq` and the event log live in SQLite, so a
//! process restart / redeploy neither resets the sequence to 0 nor empties the replay backlog:
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
//!
//! **Module layout.** [`events`] holds the wire-facing event model (types + DAG-CBOR stored
//! encoding + decode); [`replay`] holds cursor replay over the durable log; this file holds the
//! sequencer itself — `Firehose`, the bare `emit_*` primitives, and the atomic staged-transaction
//! path (`EmitGuard`/`Pending*`). Both submodules' public types are re-exported here so consumers
//! keep using `crate::firehose::X` unchanged.

// Dead code allow: a few accessors (`subscriber_count`, the `at_uri`/`as_str` wire helpers in
// `events`) are exercised only by this module's unit tests and the `subscribeRepos` handler's
// tests.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction};
use tokio::sync::broadcast;

mod events;
mod replay;
#[cfg(test)]
mod test_support;

pub use events::{
    decode_stored_event, AccountEvent, CommitEvent, CommitInput, FirehoseError, FirehoseEvent,
    IdentityEvent, OpAction, RepoOp, SyncEvent, SyncInput,
};
#[cfg(test)]
pub(crate) use replay::collect_replay_seqs;
pub use replay::{ReplayReader, SubscribeOutcome, Subscription};

use events::{
    validate_commit_cids, validate_sync_blocks, StoredAccountRef, StoredCommitRef,
    StoredIdentityRef, StoredOpRef, StoredSyncRef,
};

use crate::time::now_rfc3339;

/// Default capacity of the broadcast ring buffer: the number of events retained for slow
/// consumers before they begin to observe `Lagged`.
const DEFAULT_CAPACITY: usize = 1024;

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
    /// Re-invites the relay via `requestCrawl` on **every** emission, not just repo commits.
    /// `None` for bare test constructions and when no crawlers are configured; `main.rs` attaches
    /// the shared notifier before Arc-wrapping. Making this the single fan-out choke point's job
    /// means a relay that dropped its subscription is re-invited by the very `#account`/`#identity`/
    /// `#sync` lifecycle frames that matter for migration visibility — the frames that, emitted to
    /// no listener, can leave a migrated DID stuck AccountDeactivated on the network. Rate limiting
    /// in the notifier collapses a commit burst into one notification per crawler per window.
    crawlers: Option<Arc<crate::crawler::CrawlerNotifier>>,
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
            crawlers: None,
        })
    }

    /// Attach the shared metrics handle so broadcast frames are counted. Called before the
    /// firehose is Arc-wrapped into `AppState`; constructions that never attach (bare unit
    /// tests) simply record nothing.
    pub fn attach_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        self.metrics = Some(metrics);
    }

    /// Attach the shared crawler notifier so every broadcast re-invites the relay via
    /// `requestCrawl`. Called before the firehose is Arc-wrapped into `AppState`; constructions
    /// that never attach (bare unit tests, or a deployment with no crawlers configured) simply
    /// never notify.
    pub fn attach_crawlers(&mut self, crawlers: Arc<crate::crawler::CrawlerNotifier>) {
        self.crawlers = Some(crawlers);
    }

    /// Broadcast one already-persisted event to live subscribers, counting it by frame type and
    /// re-inviting the relay. The send result is deliberately ignored: having no live subscribers
    /// is not an error (the event is already durable and replayable).
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
        // Re-invite the relay on *every* frame, not just repo commits. `notify` is fire-and-forget
        // (rate-limited, retrying, detached tasks) and never blocks this fan-out or the emit lock
        // held above it. This is the load-bearing half of the fix: a relay that silently dropped
        // its subscription while this PDS was quiet gets re-invited by the next lifecycle frame
        // (`#account`/`#identity`/`#sync`) instead of only by a repo commit that may never come.
        if let Some(crawlers) = &self.crawlers {
            crawlers.notify();
        }
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
                // The wedge never surfaces as an outage, so this log line is the only
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
    /// a relay expects. The commit-block CAR is capped at [`events::MAX_SYNC_BLOCKS_BYTES`]
    /// (private to `events`, enforced via `validate_sync_blocks`) before persist; otherwise
    /// `blocks` is a pre-built CARv1 byte string (scalars otherwise), so its wire encoding is
    /// infallible and needs no pre-emit CID validation.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::test_support::*;
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

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
        let db = crate::db::open_pool("sqlite::memory:").await.unwrap();
        crate::db::run_migrations(&db).await.unwrap();

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
        oversized.blocks = vec![0u8; events::MAX_SYNC_BLOCKS_BYTES + 1];
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

    /// The single fan-out choke point re-invites the relay on a **non-commit** lifecycle frame
    /// (`#account`), the exact case a commit-only notifier missed — a quiet, migrated PDS whose
    /// activation frames reached no listener.
    #[tokio::test]
    async fn broadcast_re_invites_crawlers_on_a_lifecycle_frame() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .and(body_json(
                serde_json::json!({ "hostname": "pds.example.com" }),
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1..)
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("test http client");
        let crawlers = Arc::new(crate::crawler::CrawlerNotifier::new(
            client,
            "pds.example.com".to_string(),
            &[server.uri()],
        ));

        let mut fh = test_firehose().await;
        fh.attach_crawlers(crawlers);

        // An `#account` (active) frame — not a repo commit — must still re-invite the relay.
        fh.emit_account("did:plc:quiet".to_string(), true, None)
            .await
            .unwrap();

        // `notify` is fire-and-forget (a detached task POSTs the re-invitation), so poll the mock
        // until it lands rather than asserting synchronously.
        wait_for_crawl(&server).await;
    }

    /// Poll the mock relay until it has received at least one `requestCrawl`, bounded so a genuine
    /// wiring failure fails the test instead of hanging.
    async fn wait_for_crawl(server: &wiremock::MockServer) {
        for _ in 0..100 {
            if let Some(reqs) = server.received_requests().await {
                if !reqs.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("crawler was not re-invited within the timeout");
    }
}
