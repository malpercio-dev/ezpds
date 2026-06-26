// pattern: Imperative Shell

//! In-memory firehose event pipeline backing `com.atproto.sync.subscribeRepos`.
//!
//! Every repo commit produces a sequenced [`CommitEvent`] that is fanned out to all
//! current subscribers over a Tokio broadcast channel. The sequencer is an in-process
//! monotonic counter; subscribers attach via [`Firehose::subscribe`] and the WebSocket
//! handler (a separate endpoint, implemented elsewhere) encodes each event into a
//! DAG-CBOR frame.
//!
//! **Backpressure.** The broadcast channel is bounded. Producers never block: when the
//! buffer is full the oldest events are overwritten and a lagging subscriber observes
//! [`broadcast::error::RecvError::Lagged`] on its next `recv`, which the consumer treats
//! as "you fell too far behind" and disconnects. A slow consumer therefore cannot stall
//! commit production.
//!
//! **Ordering.** Sequence assignment and broadcast happen under a single mutex, so events
//! are always delivered in strictly increasing `seq` order even when commits race across
//! concurrent requests. The critical section never awaits (it only assigns an integer and
//! does a non-blocking `send`), so a `std::sync::Mutex` is appropriate.

// Dead code allow: the subscriber-facing surface (`subscribe`, the `FirehoseEvent`/`RepoOp`
// accessors, the `#repoOp` wire helpers) is consumed by the `subscribeRepos` WebSocket
// handler, which ships separately. The emit path is already wired into the commit routes,
// and every item here is exercised by this module's unit tests.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::broadcast;

/// Default capacity of the broadcast ring buffer: the number of events retained for slow
/// consumers before they begin to observe `Lagged`.
const DEFAULT_CAPACITY: usize = 1024;

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

/// A frame broadcast to firehose subscribers. Modelled as an enum so future frame types
/// (`#identity`, `#account`) can be added without changing the channel item type.
#[derive(Debug, Clone)]
pub enum FirehoseEvent {
    Commit(Arc<CommitEvent>),
}

impl FirehoseEvent {
    /// The sequence number of the underlying event.
    pub fn seq(&self) -> u64 {
        match self {
            FirehoseEvent::Commit(c) => c.seq,
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

/// The in-memory firehose: a monotonic sequencer plus a broadcast fan-out.
///
/// The relay holds a single `Arc<Firehose>` in `AppState`; every request handler shares it.
pub struct Firehose {
    /// Guards the sequence counter and serialises broadcast order. Never held across await.
    seq: Mutex<u64>,
    tx: broadcast::Sender<FirehoseEvent>,
}

impl Firehose {
    /// Create a firehose with the default ring-buffer capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a firehose whose broadcast buffer retains `capacity` events for slow consumers.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            seq: Mutex::new(0),
            tx,
        }
    }

    /// Subscribe to the event stream. Each subscriber receives every event emitted after it
    /// subscribes; a subscriber that falls more than `capacity` events behind observes
    /// `RecvError::Lagged` on its next `recv`.
    pub fn subscribe(&self) -> broadcast::Receiver<FirehoseEvent> {
        self.tx.subscribe()
    }

    /// Number of live subscribers. Primarily for diagnostics and tests.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// The last sequence number assigned (0 if nothing has been emitted yet).
    pub fn current_seq(&self) -> u64 {
        *self.seq.lock().expect("firehose seq mutex poisoned")
    }

    /// Assign the next sequence number, build a [`CommitEvent`], and broadcast it.
    ///
    /// Returns the assigned sequence number. Never blocks and never fails: if there are no
    /// subscribers the event is simply dropped (its `seq` is still consumed, keeping the
    /// sequence dense). Sequence assignment and the broadcast are serialised so subscribers
    /// always observe events in increasing `seq` order.
    pub fn emit_commit(&self, input: CommitInput) -> u64 {
        let mut seq = self.seq.lock().expect("firehose seq mutex poisoned");
        *seq += 1;
        let assigned = *seq;
        let event = Arc::new(CommitEvent {
            seq: assigned,
            time: now_rfc3339(),
            repo: input.repo,
            commit: input.commit,
            rev: input.rev,
            since: input.since,
            ops: input.ops,
            blocks: input.blocks,
        });
        // A send error means "no subscribers"; that is expected, not a failure.
        let _ = self.tx.send(FirehoseEvent::Commit(event));
        assigned
    }
}

impl Default for Firehose {
    fn default() -> Self {
        Self::new()
    }
}

/// Current UTC time as an RFC 3339 / ISO-8601 string with millisecond precision.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

    fn commit_input(repo: &str) -> CommitInput {
        CommitInput {
            repo: repo.to_string(),
            commit: "bafycommit".to_string(),
            rev: "3krev".to_string(),
            since: None,
            ops: vec![RepoOp {
                action: OpAction::Create,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some("bafyrecord".to_string()),
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
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic_from_one() {
        let fh = Firehose::new();
        let mut rx = fh.subscribe();

        assert_eq!(fh.current_seq(), 0);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")), 1);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")), 2);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")), 3);
        assert_eq!(fh.current_seq(), 3);

        for expected in 1..=3 {
            match rx.recv().await.unwrap() {
                FirehoseEvent::Commit(c) => assert_eq!(c.seq, expected),
            }
        }
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_every_event() {
        let fh = Firehose::new();
        let mut rx1 = fh.subscribe();
        let mut rx2 = fh.subscribe();
        assert_eq!(fh.subscriber_count(), 2);

        fh.emit_commit(commit_input("did:plc:a"));
        fh.emit_commit(commit_input("did:plc:b"));

        for rx in [&mut rx1, &mut rx2] {
            let FirehoseEvent::Commit(first) = rx.recv().await.unwrap();
            assert_eq!(first.seq, 1);
            assert_eq!(first.repo, "did:plc:a");
            let FirehoseEvent::Commit(second) = rx.recv().await.unwrap();
            assert_eq!(second.seq, 2);
            assert_eq!(second.repo, "did:plc:b");
        }
    }

    #[tokio::test]
    async fn commit_event_carries_ops_and_blocks() {
        let fh = Firehose::new();
        let mut rx = fh.subscribe();
        fh.emit_commit(commit_input("did:plc:a"));

        let FirehoseEvent::Commit(c) = rx.recv().await.unwrap();
        assert_eq!(c.blocks, vec![1, 2, 3]);
        assert_eq!(c.ops.len(), 1);
        assert_eq!(c.ops[0].action, OpAction::Create);
        assert_eq!(c.ops[0].cid.as_deref(), Some("bafyrecord"));
        assert_eq!(c.ops[0].value, Some(serde_json::json!({ "text": "hi" })));
        assert!(!c.time.is_empty());
    }

    #[test]
    fn emit_with_no_subscribers_still_advances_sequence() {
        let fh = Firehose::new();
        // No subscribers attached: send drops the event but the seq is still consumed.
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")), 1);
        assert_eq!(fh.emit_commit(commit_input("did:plc:a")), 2);
        assert_eq!(fh.current_seq(), 2);
    }

    #[tokio::test]
    async fn slow_subscriber_lags_without_blocking_producer() {
        // A tiny buffer makes overflow easy to trigger. A consumer that never drains must
        // not prevent the producer from emitting, and must observe Lagged rather than stall.
        let fh = Firehose::with_capacity(2);
        let mut slow = fh.subscribe();

        // Emit more events than the buffer holds; every emit returns immediately.
        for _ in 0..10 {
            fh.emit_commit(commit_input("did:plc:a"));
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
        let FirehoseEvent::Commit(next) = slow.recv().await.unwrap();
        assert!(
            next.seq >= 9,
            "should resume near the head, got seq {}",
            next.seq
        );
        let FirehoseEvent::Commit(last) = slow.recv().await.unwrap();
        assert_eq!(last.seq, 10);
        assert_eq!(slow.try_recv().unwrap_err(), TryRecvError::Empty);
    }
}
