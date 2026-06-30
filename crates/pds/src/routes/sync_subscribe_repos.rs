// pattern: Imperative Shell

//! com.atproto.sync.subscribeRepos — the ATProto firehose WebSocket endpoint.
//!
//! BGSes and relays open a long-lived WebSocket here to index every repo commit this PDS
//! produces. Each event is a single binary message containing two concatenated DAG-CBOR
//! objects per the ATProto event-stream framing: a header (`{op, t}`) followed by the body.
//!
//! * `op = 1` is a message; `t` names the type (`#commit`).
//! * `op = -1` is an error; the body carries `{error, message}` and the stream then closes.
//!
//! A `cursor` query parameter requests replay: the firehose materialises every event whose `seq`
//! is greater than the cursor from its durable log (so replay survives a restart), and the handler
//! sends those before streaming live events with no gap. A cursor ahead of the current sequence is
//! rejected with a `FutureCursor` error frame. A
//! subscriber that cannot keep up overflows the broadcast buffer, receives a
//! `ConsumerTooSlow` error frame, and is disconnected (it can reconnect with its last cursor).
//!
//! A periodic WebSocket Ping keeps the connection alive through idle proxies and surfaces dead
//! peers. The heartbeat runs from the moment the socket attaches — including throughout any
//! replay backlog — and a peer that stops answering (no Pong within the read deadline) is
//! dropped promptly, rather than only when the next Ping send happens to fail.

use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;

use crate::app::AppState;
use crate::firehose::{
    AccountEvent, CommitEvent, FirehoseEvent, IdentityEvent, SubscribeOutcome, Subscription,
};
use repo_engine::Cid;

/// How often to send a keepalive Ping. Kept well under the reverse-proxy idle window (Railway's,
/// in production) so an otherwise-silent firehose connection is never reaped as idle.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// If the peer sends nothing — not even a Pong replying to our keepalive Ping — within this
/// window, the socket is treated as half-open and dropped. Spans several heartbeats so a single
/// dropped Pong doesn't sever a healthy connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
pub struct SubscribeReposParams {
    /// The last `seq` the consumer has already processed; replay resumes after it.
    cursor: Option<u64>,
}

/// GET /xrpc/com.atproto.sync.subscribeRepos?cursor=<seq> (WebSocket upgrade)
///
/// Unauthenticated, like the other sync endpoints. The HTTP response is a 101 Switching
/// Protocols; all subsequent traffic is the binary firehose framing described in the module
/// docs.
pub async fn subscribe_repos(
    State(state): State<AppState>,
    Query(params): Query<SubscribeReposParams>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, params.cursor))
}

/// Drive a single subscriber connection: optional replay, then live streaming with a
/// heartbeat, until the peer closes or falls too far behind.
async fn handle_socket(socket: WebSocket, state: AppState, cursor: Option<u64>) {
    let (mut sender, mut receiver) = socket.split();

    // Attach to the firehose under one lock: `subscribe_from` snapshots the live receiver and the
    // sequence frontier together (so a concurrent commit can't produce a spurious FutureCursor or
    // slip an event past the boundary), then materialises the durable replay backlog for
    // `(cursor, upper]` from `repo_seq` — paged and density-checked in the firehose layer. The
    // live stream (`rx`) then carries everything with `seq > upper`, so replay and live are exactly
    // disjoint: no gap, no duplicate across the boundary.
    let Subscription { replay, mut rx } = match state.firehose.subscribe_from(cursor).await {
        Ok(SubscribeOutcome::Subscribed(sub)) => sub,
        Ok(SubscribeOutcome::FutureCursor { .. }) => {
            // A cursor ahead of everything we've emitted is a client error: refuse and close.
            let frame = encode_error_frame("FutureCursor", "cursor is in the future");
            let _ = send_message(&mut sender, Message::Binary(frame)).await;
            let _ = tokio::time::timeout(READ_TIMEOUT, sender.close()).await;
            return;
        }
        Err(e) => {
            // The durable replay backlog couldn't be assembled (a DB error, a corrupt stored row,
            // or a sequence gap). Fail closed rather than stream live past a hole; the client
            // reconnects from its last good cursor.
            tracing::error!(error = %e, "failed to assemble firehose replay backlog; closing");
            let frame = encode_error_frame("InternalError", "failed to read replay backlog");
            let _ = send_message(&mut sender, Message::Binary(frame)).await;
            let _ = tokio::time::timeout(READ_TIMEOUT, sender.close()).await;
            return;
        }
    };

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    // The first tick fires immediately; consume it so the first real Ping waits a full interval.
    heartbeat.tick().await;
    // Don't let a stalled send (or a long replay) bunch up catch-up ticks into a Ping burst.
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Last time we heard anything from the peer; refreshed by every inbound frame (notably the
    // Pong answering our keepalive Ping) and checked against READ_TIMEOUT on each heartbeat.
    let mut last_seen = Instant::now();

    // Replay the missed backlog oldest-first before any live event, then stream live. Both
    // phases share one `select!` so the heartbeat and the read-deadline / close detection stay
    // live throughout — including during a long replay, the case a bare replay loop left silent.
    let mut replay = replay.into_iter();
    let mut replay_done = false;

    loop {
        tokio::select! {
            // While the backlog drains, the live branch below stays disabled so a newer commit
            // can't overtake a buffered one; once `replay.next()` is exhausted we flip to live.
            maybe_event = async { replay.next() }, if !replay_done => match maybe_event {
                Some(event) => {
                    if !send_event(&mut sender, &event).await {
                        break;
                    }
                }
                None => replay_done = true,
            },
            event = rx.recv(), if replay_done => match event {
                Ok(event) => {
                    if !send_event(&mut sender, &event).await {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    let frame = encode_error_frame(
                        "ConsumerTooSlow",
                        "consumer fell too far behind the firehose; reconnect with your last cursor",
                    );
                    let _ = send_message(&mut sender, Message::Binary(frame)).await;
                    let _ = tokio::time::timeout(READ_TIMEOUT, sender.close()).await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            _ = heartbeat.tick() => {
                // A conformant peer answers every keepalive Ping with a Pong, refreshing
                // `last_seen` below. If we've heard nothing within READ_TIMEOUT the socket is
                // half-open; drop it now instead of waiting for a later send to fail.
                if last_seen.elapsed() >= READ_TIMEOUT {
                    break;
                }
                if !send_message(&mut sender, Message::Ping(Vec::new())).await {
                    break;
                }
            }
            incoming = receiver.next() => match incoming {
                // Peer closed, the stream ended, or a transport error — we're done.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                // Any other frame — notably the Pong answering our keepalive Ping — proves the
                // peer is alive and refreshes the read deadline. The firehose is server→client,
                // so the frame is otherwise ignored.
                Some(Ok(_)) => last_seen = Instant::now(),
            },
        }
    }
}

/// Encode and send one firehose event. Returns `false` (the caller stops and closes) if the frame
/// cannot be encoded or the socket send fails. Failing closed on an encode error matters for the
/// no-gap contract: silently skipping an unencodable `#commit` and continuing would deliver later
/// `seq`s past the missing one. A self-written commit that won't encode signals corruption an
/// operator should see; the client reconnects from its last good cursor. `#account` frames are
/// fixed-shape (no CIDs or CAR blocks), so their encoding cannot fail.
async fn send_event(sender: &mut SplitSink<WebSocket, Message>, event: &FirehoseEvent) -> bool {
    let frame = match event {
        FirehoseEvent::Commit(commit) => match encode_commit_frame(commit) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    seq = commit.seq,
                    "failed to encode firehose #commit frame; closing"
                );
                return false;
            }
        },
        FirehoseEvent::Account(account) => encode_account_frame(account),
        FirehoseEvent::Identity(identity) => encode_identity_frame(identity),
    };
    send_message(sender, Message::Binary(frame)).await
}

/// Send one WebSocket message, bounding the write on [`READ_TIMEOUT`]. A peer that has stopped
/// reading (a full TCP receive window / half-open socket) leaves `sender.send(...)` pending
/// indefinitely; awaited bare inside the `select!`, that single write would park the whole
/// connection and starve the heartbeat tick that enforces the read deadline. The timeout caps
/// any such stall so liveness is preserved during both replay and live streaming. Returns
/// `false` on send failure or timeout (the caller should stop).
async fn send_message(sender: &mut SplitSink<WebSocket, Message>, message: Message) -> bool {
    matches!(
        tokio::time::timeout(READ_TIMEOUT, sender.send(message)).await,
        Ok(Ok(()))
    )
}

/// DAG-CBOR header for a message frame: `{op, t}`.
#[derive(Serialize)]
struct MessageHeader {
    op: i64,
    t: &'static str,
}

/// DAG-CBOR header for an error frame: `{op}` (op = -1).
#[derive(Serialize)]
struct ErrorHeader {
    op: i64,
}

/// The `#commit` message body, encoded as DAG-CBOR per com.atproto.sync.subscribeRepos.
///
/// `commit` and each op `cid` are [`Cid`]s, which serialize as DAG-CBOR tag-42 links; `blocks`
/// is the CARv1 byte string of the blocks introduced by this commit. `rebase`/`tooBig` are
/// retained for wire compatibility and always `false` (this PDS never emits oversized or
/// rebase commits).
#[derive(Serialize)]
struct CommitBody<'a> {
    seq: u64,
    rebase: bool,
    #[serde(rename = "tooBig")]
    too_big: bool,
    repo: &'a str,
    commit: Cid,
    rev: &'a str,
    since: Option<&'a str>,
    #[serde(with = "serde_bytes")]
    blocks: &'a [u8],
    ops: Vec<RepoOpWire<'a>>,
    blobs: Vec<Cid>,
    time: &'a str,
}

/// A single `#repoOp` on the wire: `action`, MST `path` (`collection/rkey`), and the record
/// `cid` (a tag-42 link, or null for a delete).
#[derive(Serialize)]
struct RepoOpWire<'a> {
    action: &'a str,
    path: String,
    cid: Option<Cid>,
}

/// Encode a [`CommitEvent`] into a complete firehose frame: the `#commit` header concatenated
/// with the DAG-CBOR body.
fn encode_commit_frame(commit: &CommitEvent) -> Result<Vec<u8>, String> {
    let commit_cid = Cid::try_from(commit.commit.as_str())
        .map_err(|e| format!("invalid commit CID {:?}: {e}", commit.commit))?;

    let mut ops = Vec::with_capacity(commit.ops.len());
    for op in &commit.ops {
        let cid = match &op.cid {
            Some(s) => {
                Some(Cid::try_from(s.as_str()).map_err(|e| format!("invalid op CID {s:?}: {e}"))?)
            }
            None => None,
        };
        ops.push(RepoOpWire {
            action: op.action.as_str(),
            path: op.path(),
            cid,
        });
    }

    let header = MessageHeader {
        op: 1,
        t: "#commit",
    };
    let body = CommitBody {
        seq: commit.seq,
        rebase: false,
        too_big: false,
        repo: &commit.repo,
        commit: commit_cid,
        rev: &commit.rev,
        since: commit.since.as_deref(),
        blocks: &commit.blocks,
        ops,
        blobs: Vec::new(),
        time: &commit.time,
    };

    let mut frame = serde_ipld_dagcbor::to_vec(&header).map_err(|e| e.to_string())?;
    let body_bytes = serde_ipld_dagcbor::to_vec(&body).map_err(|e| e.to_string())?;
    frame.extend_from_slice(&body_bytes);
    Ok(frame)
}

/// The `#account` message body, encoded as DAG-CBOR per com.atproto.sync.subscribeRepos.
///
/// Carries no CIDs or CAR blocks — just the account's new hosting status. `status` is omitted
/// from the wire when the account is active (the field is optional in the lexicon).
#[derive(Serialize)]
struct AccountBody<'a> {
    seq: u64,
    did: &'a str,
    time: &'a str,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
}

/// Encode an [`AccountEvent`] into a complete firehose frame: the `#account` header
/// concatenated with the DAG-CBOR body. Unlike `#commit`, every field is a plain scalar, so
/// encoding is infallible (matching how [`encode_error_frame`] treats its fixed-shape structs).
fn encode_account_frame(account: &AccountEvent) -> Vec<u8> {
    let header = MessageHeader {
        op: 1,
        t: "#account",
    };
    let body = AccountBody {
        seq: account.seq,
        did: &account.did,
        time: &account.time,
        active: account.active,
        status: account.status.as_deref(),
    };

    let mut frame = serde_ipld_dagcbor::to_vec(&header).expect("#account header must encode");
    let body_bytes = serde_ipld_dagcbor::to_vec(&body).expect("#account body must encode");
    frame.extend_from_slice(&body_bytes);
    frame
}

/// The `#identity` message body, encoded as DAG-CBOR per com.atproto.sync.subscribeRepos.
///
/// Carries no CIDs or blocks — just the DID, the emission `time`, and the (optional) new handle.
/// `handle` is omitted from the wire when `None` (the lexicon field is optional), matching how
/// `#account` omits `status` for an active account.
#[derive(Serialize)]
struct IdentityBody<'a> {
    seq: u64,
    did: &'a str,
    time: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
}

/// Encode an [`IdentityEvent`] into a complete firehose frame: the `#identity` header
/// concatenated with the DAG-CBOR body. Like `#account`, every field is a plain scalar, so
/// encoding is infallible.
fn encode_identity_frame(identity: &IdentityEvent) -> Vec<u8> {
    let header = MessageHeader {
        op: 1,
        t: "#identity",
    };
    let body = IdentityBody {
        seq: identity.seq,
        did: &identity.did,
        time: &identity.time,
        handle: identity.handle.as_deref(),
    };

    let mut frame = serde_ipld_dagcbor::to_vec(&header).expect("#identity header must encode");
    let body_bytes = serde_ipld_dagcbor::to_vec(&body).expect("#identity body must encode");
    frame.extend_from_slice(&body_bytes);
    frame
}

/// Encode an error frame: the `{op: -1}` header concatenated with `{error, message}`.
fn encode_error_frame(error: &str, message: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct ErrorBody<'a> {
        error: &'a str,
        message: &'a str,
    }

    // These are tiny fixed-shape structs; encoding cannot fail in practice.
    let mut frame =
        serde_ipld_dagcbor::to_vec(&ErrorHeader { op: -1 }).expect("error header must encode");
    let body =
        serde_ipld_dagcbor::to_vec(&ErrorBody { error, message }).expect("error body must encode");
    frame.extend_from_slice(&body);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::{OpAction, RepoOp};
    use ipld_core::ipld::Ipld;

    fn sample_commit() -> CommitEvent {
        CommitEvent {
            seq: 7,
            time: "2026-06-26T00:00:00.000Z".to_string(),
            repo: "did:plc:alice".to_string(),
            // A valid CIDv1 dag-cbor sha2-256 link.
            commit: "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm".to_string(),
            rev: "3krev".to_string(),
            since: Some("3kprev".to_string()),
            ops: vec![RepoOp {
                action: OpAction::Create,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some(
                    "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm".to_string(),
                ),
                value: Some(serde_json::json!({ "text": "hi" })),
            }],
            blocks: vec![0xCA, 0xFE],
        }
    }

    /// Decode the two concatenated DAG-CBOR objects in a frame into (header, body) Ipld.
    /// `from_reader_once` reads exactly one item and leaves the cursor positioned after it,
    /// so a second call reads the body — unlike `from_reader`, which rejects trailing data.
    fn decode_frame(frame: &[u8]) -> (Ipld, Ipld) {
        let mut cursor = std::io::Cursor::new(frame);
        let header: Ipld =
            serde_ipld_dagcbor::de::from_reader_once(&mut cursor).expect("decode header");
        let body: Ipld =
            serde_ipld_dagcbor::de::from_reader_once(&mut cursor).expect("decode body");
        (header, body)
    }

    fn map_get<'a>(ipld: &'a Ipld, key: &str) -> &'a Ipld {
        match ipld {
            Ipld::Map(m) => m.get(key).unwrap_or_else(|| panic!("missing key {key}")),
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn commit_frame_header_is_op1_commit() {
        let frame = encode_commit_frame(&sample_commit()).unwrap();
        let (header, _) = decode_frame(&frame);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(1));
        assert_eq!(map_get(&header, "t"), &Ipld::String("#commit".to_string()));
    }

    #[test]
    fn commit_frame_body_carries_expected_fields() {
        let event = sample_commit();
        let frame = encode_commit_frame(&event).unwrap();
        let (_, body) = decode_frame(&frame);

        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(7));
        assert_eq!(
            map_get(&body, "repo"),
            &Ipld::String("did:plc:alice".into())
        );
        assert_eq!(map_get(&body, "rev"), &Ipld::String("3krev".into()));
        assert_eq!(map_get(&body, "since"), &Ipld::String("3kprev".into()));
        assert_eq!(map_get(&body, "rebase"), &Ipld::Bool(false));
        assert_eq!(map_get(&body, "tooBig"), &Ipld::Bool(false));

        // `commit` is a CID link (DAG-CBOR tag 42 → Ipld::Link), not a string.
        match map_get(&body, "commit") {
            Ipld::Link(cid) => assert_eq!(cid.to_string(), event.commit),
            other => panic!("commit must be a CID link, got {other:?}"),
        }

        // `blocks` is a byte string, not an array of integers.
        assert_eq!(map_get(&body, "blocks"), &Ipld::Bytes(vec![0xCA, 0xFE]));
    }

    #[test]
    fn commit_frame_op_has_link_cid_and_path() {
        let event = sample_commit();
        let frame = encode_commit_frame(&event).unwrap();
        let (_, body) = decode_frame(&frame);

        let ops = match map_get(&body, "ops") {
            Ipld::List(l) => l,
            other => panic!("ops must be a list, got {other:?}"),
        };
        assert_eq!(ops.len(), 1);
        assert_eq!(map_get(&ops[0], "action"), &Ipld::String("create".into()));
        assert_eq!(
            map_get(&ops[0], "path"),
            &Ipld::String("app.bsky.feed.post/abc".into())
        );
        match map_get(&ops[0], "cid") {
            Ipld::Link(_) => {}
            other => panic!("op cid must be a CID link, got {other:?}"),
        }
    }

    #[test]
    fn delete_op_encodes_null_cid() {
        let mut event = sample_commit();
        event.ops = vec![RepoOp {
            action: OpAction::Delete,
            collection: "app.bsky.feed.post".to_string(),
            rkey: "gone".to_string(),
            cid: None,
            value: None,
        }];
        let frame = encode_commit_frame(&event).unwrap();
        let (_, body) = decode_frame(&frame);
        let ops = match map_get(&body, "ops") {
            Ipld::List(l) => l.clone(),
            other => panic!("ops must be a list, got {other:?}"),
        };
        assert_eq!(map_get(&ops[0], "action"), &Ipld::String("delete".into()));
        assert_eq!(map_get(&ops[0], "cid"), &Ipld::Null);
    }

    #[test]
    fn error_frame_is_op_minus_one_with_error_and_message() {
        let frame = encode_error_frame("FutureCursor", "cursor is in the future");
        let (header, body) = decode_frame(&frame);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(-1));
        assert_eq!(
            map_get(&body, "error"),
            &Ipld::String("FutureCursor".into())
        );
        assert_eq!(
            map_get(&body, "message"),
            &Ipld::String("cursor is in the future".into())
        );
    }

    #[test]
    fn invalid_commit_cid_is_an_error_not_a_panic() {
        let mut event = sample_commit();
        event.commit = "not-a-cid".to_string();
        assert!(encode_commit_frame(&event).is_err());
    }

    // ── End-to-end WebSocket tests ─────────────────────────────────────────────
    //
    // These drive the real Axum handler over a loopback TCP socket with a tungstenite
    // client, exercising the full upgrade → replay → live-stream path.

    use crate::firehose::{CommitInput, Firehose};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    const TEST_CID: &str = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";

    /// Bind an ephemeral port, serve the real router, and return the subscribeRepos URL plus a
    /// handle to the shared firehose so the test can emit commits into it.
    async fn spawn_server() -> (String, Arc<Firehose>) {
        let state = crate::app::test_state().await;
        let firehose = state.firehose.clone();
        let router = crate::app::app(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos"),
            firehose,
        )
    }

    async fn emit(firehose: &Firehose) -> u64 {
        firehose
            .emit_commit(CommitInput {
                repo: "did:plc:alice".to_string(),
                commit: TEST_CID.to_string(),
                rev: "3krev".to_string(),
                since: None,
                ops: Vec::new(),
                blocks: vec![1, 2, 3],
            })
            .await
            .expect("emit commit")
    }

    /// Wait (briefly) until at least `n` subscribers have attached. This makes "emit after
    /// connect" deterministic: the handler's `subscribe_from` bumps the broadcast receiver
    /// count, so once it reaches `n` a subsequent emit is guaranteed to be delivered live.
    async fn await_subscribers(firehose: &Firehose, n: usize) {
        for _ in 0..200 {
            if firehose.subscriber_count() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("subscribers did not attach in time");
    }

    /// Read the next binary frame, skipping any ping/pong control frames.
    async fn next_binary<S>(ws: &mut S) -> Vec<u8>
    where
        S: futures_util::Stream<Item = Result<WsMessage, WsError>> + Unpin,
    {
        loop {
            match ws.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => return bytes,
                Some(Ok(_)) => continue,
                other => panic!("expected a binary frame, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn websocket_streams_live_commit_events() {
        let (url, firehose) = spawn_server().await;
        let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");

        await_subscribers(&firehose, 1).await;
        let seq = emit(&firehose).await;

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "t"), &Ipld::String("#commit".into()));
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(
            map_get(&body, "repo"),
            &Ipld::String("did:plc:alice".into())
        );
    }

    #[tokio::test]
    async fn websocket_cursor_replays_missed_events() {
        let (url, firehose) = spawn_server().await;

        // Emit three events *before* anyone subscribes.
        emit(&firehose).await; // seq 1
        let seq2 = emit(&firehose).await; // seq 2
        let seq3 = emit(&firehose).await; // seq 3

        // Subscribe from cursor 1: must replay exactly seq 2 then seq 3.
        let (mut ws, _resp) = connect_async(format!("{url}?cursor=1"))
            .await
            .expect("ws connect");

        let (_, body2) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&body2, "seq"), &Ipld::Integer(seq2 as i128));
        let (_, body3) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&body3, "seq"), &Ipld::Integer(seq3 as i128));
    }

    #[tokio::test]
    async fn websocket_multiple_subscribers_each_receive_events() {
        let (url, firehose) = spawn_server().await;
        let (mut ws1, _) = connect_async(&url).await.expect("ws1 connect");
        let (mut ws2, _) = connect_async(&url).await.expect("ws2 connect");

        await_subscribers(&firehose, 2).await;
        let seq = emit(&firehose).await;

        for ws in [&mut ws1, &mut ws2] {
            let (_, body) = decode_frame(&next_binary(ws).await);
            assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        }
    }

    #[tokio::test]
    async fn websocket_future_cursor_yields_error_frame() {
        let (url, firehose) = spawn_server().await;
        emit(&firehose).await; // current seq = 1

        // Cursor far ahead of what we've emitted is a client error.
        let (mut ws, _resp) = connect_async(format!("{url}?cursor=9999"))
            .await
            .expect("ws connect");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(-1));
        assert_eq!(
            map_get(&body, "error"),
            &Ipld::String("FutureCursor".into())
        );
    }

    // ── encode_account_frame tests ─────────────────────────────────────────────

    fn sample_deactivation_event() -> AccountEvent {
        AccountEvent {
            seq: 5,
            time: "2026-06-27T00:00:00.000Z".to_string(),
            did: "did:plc:alice".to_string(),
            active: false,
            status: Some("deactivated".to_string()),
        }
    }

    fn sample_activation_event() -> AccountEvent {
        AccountEvent {
            seq: 6,
            time: "2026-06-27T01:00:00.000Z".to_string(),
            did: "did:plc:alice".to_string(),
            active: true,
            status: None,
        }
    }

    #[test]
    fn account_frame_header_is_op1_account() {
        let frame = encode_account_frame(&sample_deactivation_event());
        let (header, _) = decode_frame(&frame);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(1));
        assert_eq!(map_get(&header, "t"), &Ipld::String("#account".to_string()));
    }

    #[test]
    fn deactivation_frame_body_carries_all_fields() {
        let event = sample_deactivation_event();
        let frame = encode_account_frame(&event);
        let (_, body) = decode_frame(&frame);

        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(5));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:alice".to_string())
        );
        assert_eq!(
            map_get(&body, "time"),
            &Ipld::String("2026-06-27T00:00:00.000Z".to_string())
        );
        assert_eq!(map_get(&body, "active"), &Ipld::Bool(false));
        assert_eq!(
            map_get(&body, "status"),
            &Ipld::String("deactivated".to_string())
        );
    }

    #[test]
    fn activation_frame_body_omits_status_field() {
        let event = sample_activation_event();
        let frame = encode_account_frame(&event);
        let (_, body) = decode_frame(&frame);

        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(6));
        assert_eq!(map_get(&body, "active"), &Ipld::Bool(true));

        // `status` must be absent from the map when the account is active.
        let Ipld::Map(ref map) = body else {
            panic!("body must be a map");
        };
        assert!(
            !map.contains_key("status"),
            "status must be absent when active=true (skip_serializing_if)"
        );
    }

    // ── encode_identity_frame tests ──────────────────────────────────────────────

    fn sample_identity_with_handle() -> IdentityEvent {
        IdentityEvent {
            seq: 9,
            time: "2026-06-30T00:00:00.000Z".to_string(),
            did: "did:plc:alice".to_string(),
            handle: Some("alice.example.com".to_string()),
        }
    }

    fn sample_identity_without_handle() -> IdentityEvent {
        IdentityEvent {
            seq: 10,
            time: "2026-06-30T00:01:00.000Z".to_string(),
            did: "did:plc:alice".to_string(),
            handle: None,
        }
    }

    #[test]
    fn identity_frame_header_is_op1_identity() {
        let frame = encode_identity_frame(&sample_identity_with_handle());
        let (header, _) = decode_frame(&frame);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(1));
        assert_eq!(
            map_get(&header, "t"),
            &Ipld::String("#identity".to_string())
        );
    }

    #[test]
    fn identity_frame_with_handle_carries_all_fields() {
        let frame = encode_identity_frame(&sample_identity_with_handle());
        let (_, body) = decode_frame(&frame);

        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(9));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:alice".to_string())
        );
        assert_eq!(
            map_get(&body, "time"),
            &Ipld::String("2026-06-30T00:00:00.000Z".to_string())
        );
        assert_eq!(
            map_get(&body, "handle"),
            &Ipld::String("alice.example.com".to_string())
        );
    }

    #[test]
    fn identity_frame_without_handle_omits_field() {
        let frame = encode_identity_frame(&sample_identity_without_handle());
        let (_, body) = decode_frame(&frame);

        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(10));
        let Ipld::Map(ref map) = body else {
            panic!("body must be a map");
        };
        assert!(
            !map.contains_key("handle"),
            "handle must be absent when None (skip_serializing_if)"
        );
    }

    #[test]
    fn identity_frame_did_and_time_are_strings_not_links() {
        let frame = encode_identity_frame(&sample_identity_with_handle());
        let (_, body) = decode_frame(&frame);

        match map_get(&body, "did") {
            Ipld::String(_) => {}
            other => panic!("did must be a plain string, got {other:?}"),
        }
        match map_get(&body, "time") {
            Ipld::String(_) => {}
            other => panic!("time must be a plain string, got {other:?}"),
        }
        match map_get(&body, "handle") {
            Ipld::String(_) => {}
            other => panic!("handle must be a plain string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_streams_identity_event_with_correct_wire_format() {
        let (url, firehose) = spawn_server().await;
        let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");
        await_subscribers(&firehose, 1).await;

        let seq = firehose
            .emit_identity(
                "did:plc:eve".to_string(),
                Some("eve.example.com".to_string()),
            )
            .await
            .expect("emit identity");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(1));
        assert_eq!(
            map_get(&header, "t"),
            &Ipld::String("#identity".to_string())
        );
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:eve".to_string())
        );
        assert_eq!(
            map_get(&body, "handle"),
            &Ipld::String("eve.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn websocket_streams_identity_event_without_handle() {
        let (url, firehose) = spawn_server().await;
        let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");
        await_subscribers(&firehose, 1).await;

        let seq = firehose
            .emit_identity("did:plc:frank".to_string(), None)
            .await
            .expect("emit identity");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(
            map_get(&header, "t"),
            &Ipld::String("#identity".to_string())
        );
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        let Ipld::Map(ref map) = body else {
            panic!("body must be a map");
        };
        assert!(
            !map.contains_key("handle"),
            "handle must be absent over the wire when None"
        );
    }

    #[tokio::test]
    async fn websocket_identity_event_is_replayed_by_cursor() {
        let (url, firehose) = spawn_server().await;

        // Emit an identity event before subscribing.
        let seq = firehose
            .emit_identity(
                "did:plc:grace".to_string(),
                Some("grace.example.com".to_string()),
            )
            .await
            .expect("emit identity");

        // Subscribe from cursor 0 (before seq 1): the identity event must be replayed.
        let (mut ws, _resp) = connect_async(format!("{url}?cursor=0"))
            .await
            .expect("ws connect");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(
            map_get(&header, "t"),
            &Ipld::String("#identity".to_string())
        );
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:grace".to_string())
        );
    }

    #[test]
    fn account_frame_did_and_time_are_strings_not_links() {
        // Regression: ensure `did` and `time` are plain strings, not CID links.
        let frame = encode_account_frame(&sample_deactivation_event());
        let (_, body) = decode_frame(&frame);

        match map_get(&body, "did") {
            Ipld::String(_) => {}
            other => panic!("did must be a plain string, got {other:?}"),
        }
        match map_get(&body, "time") {
            Ipld::String(_) => {}
            other => panic!("time must be a plain string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_streams_account_event_with_correct_wire_format() {
        let (url, firehose) = spawn_server().await;
        let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");
        await_subscribers(&firehose, 1).await;

        let seq = firehose
            .emit_account(
                "did:plc:bob".to_string(),
                false,
                Some("deactivated".to_string()),
            )
            .await
            .expect("emit account");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "op"), &Ipld::Integer(1));
        assert_eq!(map_get(&header, "t"), &Ipld::String("#account".to_string()));
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:bob".to_string())
        );
        assert_eq!(map_get(&body, "active"), &Ipld::Bool(false));
        assert_eq!(
            map_get(&body, "status"),
            &Ipld::String("deactivated".to_string())
        );
    }

    #[tokio::test]
    async fn websocket_streams_activation_event_without_status() {
        let (url, firehose) = spawn_server().await;
        let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");
        await_subscribers(&firehose, 1).await;

        let seq = firehose
            .emit_account("did:plc:carol".to_string(), true, None)
            .await
            .expect("emit account");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "t"), &Ipld::String("#account".to_string()));
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(map_get(&body, "active"), &Ipld::Bool(true));

        let Ipld::Map(ref map) = body else {
            panic!("body must be a map");
        };
        assert!(
            !map.contains_key("status"),
            "status must be absent for an active account over the wire"
        );
    }

    #[tokio::test]
    async fn websocket_account_event_is_replayed_by_cursor() {
        let (url, firehose) = spawn_server().await;

        // Emit an account event before subscribing.
        let seq = firehose
            .emit_account(
                "did:plc:dave".to_string(),
                false,
                Some("deactivated".to_string()),
            )
            .await
            .expect("emit account");

        // Subscribe from cursor 0 (before seq 1): the account event must be replayed.
        let (mut ws, _resp) = connect_async(format!("{url}?cursor=0"))
            .await
            .expect("ws connect");

        let (header, body) = decode_frame(&next_binary(&mut ws).await);
        assert_eq!(map_get(&header, "t"), &Ipld::String("#account".to_string()));
        assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        assert_eq!(
            map_get(&body, "did"),
            &Ipld::String("did:plc:dave".to_string())
        );
    }
}
