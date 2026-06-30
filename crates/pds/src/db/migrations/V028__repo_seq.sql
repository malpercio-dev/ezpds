-- V028: Persistent firehose event log (the subscribeRepos sequencer's backing store).
--
-- The firehose sequencer (`firehose.rs`) was in-memory only: the monotonic `seq` reset to 0
-- and the replay backlog emptied on every process restart / redeploy. A relay that reconnected
-- with a saved cursor could not be replayed across a restart, and commits written before a
-- restart were dropped from the backlog and never back-propagated.
--
-- This table is the durable event log. Each sequenced firehose event (a `#commit` or
-- `#account` frame) is persisted here *before* it is broadcast to live subscribers, so:
--   * `seq` is monotonic across restarts — the sequencer loads `MAX(seq)` on boot and
--     continues from there;
--   * `subscribeRepos` cursor replay reads missed events back out of this table (it no longer
--     depends on an in-memory buffer that a restart would clear).
--
-- `seq` is an explicit INTEGER PRIMARY KEY (a rowid alias, so range scans on `seq > ?` are
-- index-backed). It is assigned by the in-process sequencer rather than AUTOINCREMENT so that a
-- failed insert does not consume a sequence number (leaving a hole in the dense prefix that
-- cursor replay relies on).
--
-- `event` is the serialized event payload — everything needed to reconstruct the exact wire
-- frame for replay, including the commit's CARv1 diff `blocks`. The blocks are stored here (and
-- not regenerated from the block store on demand) because post-commit GC may have already
-- reclaimed the superseded blocks the diff was computed against.
--
-- The log is append-only and currently unbounded; a retention/pruning sweep is future work
-- (a relay that has consumed past `seq` N no longer needs rows at or below N).
CREATE TABLE repo_seq (
    seq          INTEGER PRIMARY KEY,             -- monotonic sequence number (assigned by the sequencer)
    did          TEXT NOT NULL,                   -- repo/account DID the event concerns
    event_type   TEXT NOT NULL,                   -- 'commit' | 'account'
    event        BLOB NOT NULL,                   -- DAG-CBOR-serialized payload (reconstructs the wire frame)
    sequenced_at TEXT NOT NULL                    -- RFC 3339 emission time (also the frame's `time`)
);
