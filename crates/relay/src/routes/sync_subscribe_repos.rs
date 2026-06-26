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
//! A `cursor` query parameter requests replay: the handler first sends every still-buffered
//! event whose `seq` is greater than the cursor, then streams live events with no gap. A
//! cursor ahead of the current sequence is rejected with a `FutureCursor` error frame. A
//! subscriber that cannot keep up overflows the broadcast buffer, receives a
//! `ConsumerTooSlow` error frame, and is disconnected (it can reconnect with its last cursor).
//!
//! A periodic WebSocket Ping keeps the connection alive and surfaces dead peers: once the
//! socket is gone the Ping send fails and the handler exits.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;

use crate::app::AppState;
use crate::firehose::{CommitEvent, FirehoseEvent, Subscription};
use repo_engine::Cid;

/// How often to send a keepalive Ping to detect dead connections.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

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

    // A cursor ahead of everything we've emitted is a client error: refuse and close.
    let current = state.firehose.current_seq();
    if let Some(c) = cursor {
        if c > current {
            let frame = encode_error_frame("FutureCursor", "cursor is in the future");
            let _ = sender.send(Message::Binary(frame)).await;
            let _ = sender.close().await;
            return;
        }
    }

    // Snapshot the replay backlog and attach to the live stream atomically.
    let Subscription { replay, mut rx } = state.firehose.subscribe_from(cursor);

    // Replay missed events first, oldest first, before any live event.
    for event in &replay {
        if !send_event(&mut sender, event).await {
            return;
        }
    }

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    // The first tick fires immediately; consume it so the first real Ping waits a full interval.
    heartbeat.tick().await;

    loop {
        tokio::select! {
            event = rx.recv() => match event {
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
                    let _ = sender.send(Message::Binary(frame)).await;
                    let _ = sender.close().await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            _ = heartbeat.tick() => {
                if sender.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            incoming = receiver.next() => match incoming {
                // Peer closed, the stream ended, or a transport error — we're done.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                // The firehose is server→client; Pongs and any other client frames are ignored.
                Some(Ok(_)) => {}
            },
        }
    }
}

/// Encode and send one firehose event. Returns `false` if the socket send failed (the caller
/// should stop). An event that fails to encode is logged and skipped without dropping the
/// connection — one malformed event must not kill an otherwise-healthy subscriber.
async fn send_event(sender: &mut SplitSink<WebSocket, Message>, event: &FirehoseEvent) -> bool {
    let frame = match event {
        FirehoseEvent::Commit(commit) => match encode_commit_frame(commit) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    seq = commit.seq,
                    "failed to encode firehose #commit frame; skipping event"
                );
                return true;
            }
        },
    };
    sender.send(Message::Binary(frame)).await.is_ok()
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

    fn emit(firehose: &Firehose) -> u64 {
        firehose.emit_commit(CommitInput {
            repo: "did:plc:alice".to_string(),
            commit: TEST_CID.to_string(),
            rev: "3krev".to_string(),
            since: None,
            ops: Vec::new(),
            blocks: vec![1, 2, 3],
        })
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
        let seq = emit(&firehose);

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
        emit(&firehose); // seq 1
        let seq2 = emit(&firehose); // seq 2
        let seq3 = emit(&firehose); // seq 3

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
        let seq = emit(&firehose);

        for ws in [&mut ws1, &mut ws2] {
            let (_, body) = decode_frame(&next_binary(ws).await);
            assert_eq!(map_get(&body, "seq"), &Ipld::Integer(seq as i128));
        }
    }

    #[tokio::test]
    async fn websocket_future_cursor_yields_error_frame() {
        let (url, firehose) = spawn_server().await;
        emit(&firehose); // current seq = 1

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
}
