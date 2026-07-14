// pattern: Functional Core

//! The firehose event model: the wire-facing event types (`RepoOp`, `CommitEvent`,
//! `AccountEvent`, `IdentityEvent`, `SyncEvent`, `FirehoseEvent`), their DAG-CBOR
//! stored-payload encoding, and [`decode_stored_event`], which reconstructs an event from a
//! persisted `repo_seq` row for cursor replay. Pure data plus (de)serialization — no I/O, no
//! `Firehose` sequencer state (that lives in the parent `firehose` module).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// The `com.atproto.sync.subscribeRepos` lexicon caps `#sync.blocks` (the commit-block CAR) at
/// 10,000 bytes. A `#sync` whose CAR exceeds this cannot be a valid wire frame, so it is rejected
/// before it enters the durable log rather than replaying later as an oversized frame a strict
/// subscriber would reject. In practice a single signed commit block is well under this, so the
/// check is a guard against a future caller (e.g. `importRepo`) staging an over-large CAR.
pub(super) const MAX_SYNC_BLOCKS_BYTES: usize = 10_000;

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
    /// Monotonic sequence number assigned by the [`Firehose`](super::Firehose) sequencer.
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
    /// Monotonic sequence number assigned by the [`Firehose`](super::Firehose) sequencer.
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
    /// Monotonic sequence number assigned by the [`Firehose`](super::Firehose) sequencer.
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
    /// Monotonic sequence number assigned by the [`Firehose`](super::Firehose) sequencer.
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

/// Inputs to [`Firehose::emit_commit`](super::Firehose::emit_commit) — everything about a commit
/// except the sequencer-assigned `seq` and the emission `time`.
pub struct CommitInput {
    pub repo: String,
    pub commit: String,
    pub rev: String,
    pub since: Option<String>,
    pub prev_data: Option<String>,
    pub ops: Vec<RepoOp>,
    pub blocks: Vec<u8>,
}

/// Inputs to [`Firehose::emit_sync`](super::Firehose::emit_sync) /
/// [`EmitGuard::stage_sync`](super::EmitGuard) — everything about a `#sync` state assertion
/// except the sequencer-assigned `seq` and the emission `time`.
pub struct SyncInput {
    pub did: String,
    pub rev: String,
    /// CARv1 whose root is the current commit and which carries the signed commit block.
    pub blocks: Vec<u8>,
}

/// Validate that a commit's wire CIDs parse, so an un-encodable commit is rejected before it is
/// persisted (rather than poisoning replay). Mirrors the CID parsing the `#commit` frame encoder
/// does — the only fallible part of encoding it; the rest (DAG-CBOR of scalars/bytes) cannot fail.
pub(super) fn validate_commit_cids(input: &CommitInput) -> Result<(), FirehoseError> {
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
/// (`emit_sync` and the staged path via `stage_sync_row`).
pub(super) fn validate_sync_blocks(blocks: &[u8]) -> Result<(), FirehoseError> {
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
//
// The `*Ref` structs (and their fields) are `pub(super)` — not just `pub(crate)` — because the
// parent `firehose` module's `emit_*`/`stage_*` methods construct them directly under `emit_lock`
// (see that module's docs on why the timestamp/serialize step must stay in the same critical
// section as `seq` assignment); the `*Owned` structs stay private, decoded only here.

#[derive(Serialize)]
pub(super) struct StoredCommitRef<'a> {
    pub(super) repo: &'a str,
    pub(super) commit: &'a str,
    pub(super) rev: &'a str,
    pub(super) since: Option<&'a str>,
    pub(super) prev_data: Option<&'a str>,
    pub(super) time: &'a str,
    pub(super) ops: Vec<StoredOpRef<'a>>,
    #[serde(with = "serde_bytes")]
    pub(super) blocks: &'a [u8],
}

#[derive(Serialize)]
pub(super) struct StoredOpRef<'a> {
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
pub(super) struct StoredAccountRef<'a> {
    pub(super) did: &'a str,
    pub(super) time: &'a str,
    pub(super) active: bool,
    pub(super) status: Option<&'a str>,
}

/// Stored `#identity` payload (borrowed form, for encoding a live event).
///
/// Carries the DID, the emission `time`, and the optional `handle`. Everything needed to rebuild
/// the wire frame for replay; no CIDs or blocks. `handle` is stored explicitly (including as
/// `null` when `None`) so a reconstructed event is byte-identical to the original after a
/// round-trip, independent of the wire frame's `skip_serializing_if` omission.
#[derive(Serialize)]
pub(super) struct StoredIdentityRef<'a> {
    pub(super) did: &'a str,
    pub(super) time: &'a str,
    pub(super) handle: Option<&'a str>,
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
pub(super) struct StoredSyncRef<'a> {
    pub(super) did: &'a str,
    pub(super) time: &'a str,
    pub(super) rev: &'a str,
    #[serde(with = "serde_bytes")]
    pub(super) blocks: &'a [u8],
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
pub(super) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::test_support::*;

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
}
