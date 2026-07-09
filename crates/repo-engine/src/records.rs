// repo-engine: Record write/read operations for ATProto repositories.
//
// Provides put_record, get_record, and delete_record functions that wrap
// atrium-repo's Repository methods with the CommitSigner pattern.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use atrium_api::types::string::Tid;
use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use base64::Engine;
use ipld_core::ipld::Ipld;
use serde::{de::DeserializeOwned, Serialize};

use crate::signer::CommitSigner;

/// Base32-sortable alphabet for TID encoding.
///
/// Maintains lexicographic sort order when encoded TIDs are compared as strings,
/// ensuring timestamp ordering is preserved.
const BASE32_SORTABLE: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Generate a Timestamp Identifier (TID) for ATProto record keys.
///
/// A TID is a 64-bit integer encoded as a 13-character base32-sortable string:
/// - Bit 0 (MSB): Always 0
/// - Bits 1-53: Microseconds since UNIX epoch
/// - Bits 54-63: Random 10-bit clock identifier
///
/// The random clock identifier provides collision resistance when multiple workers
/// generate TIDs in the same microsecond.
pub fn generate_tid() -> String {
    encode_tid(now_tid_int())
}

/// The current time as a TID integer: microseconds since the UNIX epoch in the high bits, a
/// random 10-bit clock identifier in the low bits (collision resistance across workers).
fn now_tid_int() -> u64 {
    use rand_core::{OsRng, RngCore};
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_micros() as u64;
    let clock_id: u64 = (OsRng.next_u32() & 0x3FF) as u64;
    // 0 | micros (53 bits) | clock_id (10 bits).
    (micros << 10) | clock_id
}

/// Encode a TID integer as a 13-character base32-sortable string (big-endian).
fn encode_tid(mut v: u64) -> String {
    let mut chars = [0u8; 13];
    for i in (0..13).rev() {
        chars[i] = BASE32_SORTABLE[(v & 0x1F) as usize];
        v >>= 5;
    }
    String::from_utf8(chars.to_vec()).expect("base32 encoding is always valid ASCII")
}

/// Decode a 13-character base32-sortable TID string back to its integer value. An unknown
/// character decodes as 0, so a malformed input only weakens the monotonicity bump below —
/// it never panics.
fn decode_tid(tid: &str) -> u64 {
    let mut v = 0u64;
    for b in tid.bytes() {
        let idx = BASE32_SORTABLE.iter().position(|&c| c == b).unwrap_or(0) as u64;
        v = (v << 5) | idx;
    }
    v
}

/// Compute the `rev` for a new commit: a fresh time-ordered TID guaranteed to be strictly
/// greater than the previous commit's `rev`.
///
/// ATProto requires a repo's commit `rev`s to increase strictly — a relay drops any commit
/// whose `rev` is ≤ the last one it saw as stale, silently desyncing the repo from the
/// network. atrium's `CommitBuilder` derives `rev` purely from the wall clock with a zero
/// clock id (`Tid::now(0)`), so two commits in the same microsecond collide and a backward
/// clock step (NTP correction, VM migration) yields a *decreasing* `rev`. Bumping to
/// `prev + 1` whenever the clock hasn't advanced past `prev` mirrors the reference PDS's
/// monotonic-timestamp guard.
fn next_commit_rev(prev_rev: &str) -> Result<Tid, RecordError> {
    let next = now_tid_int().max(decode_tid(prev_rev).saturating_add(1));
    Tid::new(encode_tid(next))
        .map_err(|e| RecordError::Repo(format!("construct monotonic commit rev: {e}")))
}

/// Errors from record operations.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("repository error: {0}")]
    Repo(String),
    #[error("record not found")]
    NotFound,
    #[error("invalid record path: {0}")]
    InvalidPath(String),
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    #[error("record already exists: {0}")]
    AlreadyExists(String),
}

/// A single mutation in an [`apply_writes`] batch.
///
/// `key` is the MST key (`<collection>/<rkey>`) and must already be validated via
/// [`validate_record_path`]; this layer trusts it and does not re-check the format.
pub enum WriteOp {
    /// Create a record, failing with [`RecordError::AlreadyExists`] if `key` is present.
    Create {
        key: String,
        value: serde_json::Value,
    },
    /// Create or update a record (upsert semantics, matching `putRecord`).
    Update {
        key: String,
        value: serde_json::Value,
    },
    /// Delete a record; a no-op (no commit) if `key` is absent, matching `deleteRecord`.
    Delete { key: String },
}

/// The outcome of one applied [`WriteOp`], returned by [`apply_writes`] in batch order.
#[derive(Debug)]
pub struct WriteOutcome {
    /// The MST key that was written (`<collection>/<rkey>`).
    pub key: String,
    /// The new record block CID for create/update; `None` for delete.
    pub cid: Option<Cid>,
    /// The record's CID *before* this op ran — the ATProto `#repoOp.prev` (previous record CID)
    /// for an update or delete. `None` for a create (the key was absent) or for a delete of an
    /// already-absent key (the no-op path). Captured from the in-memory MST just before the op
    /// mutates it, so within-batch chaining is honoured: a create-then-update of the same key
    /// reports the just-created CID as the update's `prev`.
    pub prev: Option<Cid>,
}

/// Apply a batch of record writes to `repo`, signing one commit per mutating write.
///
/// Writes are applied in order against the in-memory repo, so a later write observes the
/// effects of earlier ones. The repo root advances with each write; the **caller** then
/// performs a single optimistic-concurrency swap of the persisted root to `repo.root()`.
/// That makes the batch atomic: on any error this returns before the caller swaps, so the
/// persisted root is unchanged and nothing in the batch is observable. The intermediate
/// commits become orphaned blocks reclaimed by GC — the repo durably advances to a single
/// new head commit whose MST reflects every write.
///
/// Per-op semantics mirror the standalone record routes: `Create` fails if the key already
/// exists, `Update` upserts, and `Delete` is idempotent.
pub async fn apply_writes<S>(
    repo: &mut Repository<S>,
    signer: &CommitSigner,
    writes: &[WriteOp],
) -> Result<Vec<WriteOutcome>, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    let mut outcomes = Vec::with_capacity(writes.len());
    for op in writes {
        let outcome = match op {
            WriteOp::Create { key, value } => {
                // Probe existence with a pure MST lookup (no record decode), matching the
                // Update/Delete arms below.
                if get_record_cid(repo, key).await?.is_some() {
                    return Err(RecordError::AlreadyExists(key.clone()));
                }
                let cid = put_record_json(repo, signer, key, value).await?;
                WriteOutcome {
                    key: key.clone(),
                    cid: Some(cid),
                    prev: None,
                }
            }
            WriteOp::Update { key, value } => {
                // The record being replaced, read before the write, is this op's `prev`.
                let prev = get_record_cid(repo, key).await?;
                let cid = put_record_json(repo, signer, key, value).await?;
                WriteOutcome {
                    key: key.clone(),
                    cid: Some(cid),
                    prev,
                }
            }
            WriteOp::Delete { key } => {
                // Idempotent: only commit a delete when the record is actually present. The
                // record being removed, read before the delete, is this op's `prev` (`None` on
                // the no-op path where the key was already absent).
                let prev = get_record_cid(repo, key).await?;
                if prev.is_some() {
                    delete_record(repo, signer, key).await?;
                }
                WriteOutcome {
                    key: key.clone(),
                    cid: None,
                    prev,
                }
            }
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Convert an incoming JSON record into the ATProto data model (DAG-CBOR-ready):
/// `{"$link": "<cid>"}` becomes a CID link, `{"$bytes": "<base64>"}` becomes a byte
/// string, and floats are rejected (the ATProto data model permits only integers).
///
/// Storing the raw JSON instead would encode CID links as plain maps, producing record
/// CIDs that no other ATProto implementation agrees with (and broken blob references).
pub fn json_to_record_value(json: &serde_json::Value) -> Result<Ipld, RecordError> {
    use serde_json::Value;
    match json {
        Value::Null => Ok(Ipld::Null),
        Value::Bool(b) => Ok(Ipld::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Ipld::Integer(i128::from(i)))
            } else if let Some(u) = n.as_u64() {
                Ok(Ipld::Integer(i128::from(u)))
            } else {
                Err(RecordError::InvalidRecord(
                    "floats are not allowed in ATProto records".into(),
                ))
            }
        }
        Value::String(s) => Ok(Ipld::String(s.clone())),
        Value::Array(items) => Ok(Ipld::List(
            items
                .iter()
                .map(json_to_record_value)
                .collect::<Result<_, _>>()?,
        )),
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(Value::String(cid)) = map.get("$link") {
                    let cid = Cid::try_from(cid.as_str()).map_err(|e| {
                        RecordError::InvalidRecord(format!("invalid $link CID: {e}"))
                    })?;
                    return Ok(Ipld::Link(cid));
                }
                if let Some(Value::String(b64)) = map.get("$bytes") {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|e| {
                            RecordError::InvalidRecord(format!("invalid $bytes base64: {e}"))
                        })?;
                    return Ok(Ipld::Bytes(bytes));
                }
            }
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), json_to_record_value(v)?);
            }
            Ok(Ipld::Map(out))
        }
    }
}

/// Convert a stored record (ATProto data model) back to JSON for API responses:
/// CID links become `{"$link": "<cid>"}` and byte strings become `{"$bytes": "<base64>"}`.
///
/// Errors with [`RecordError::InvalidRecord`] if the record holds an `Ipld::Integer` outside
/// the JSON-representable range (fits neither `i64` nor `u64`). Local writes can't produce such
/// a value — `json_to_record_value` only accepts `i64`/`u64` — but a record imported via CAR
/// carries whatever the DAG-CBOR bytes encode. Surfacing the error keeps a malformed import from
/// reading back as a silently-substituted `null` (lossy data mutation).
pub fn record_value_to_json(ipld: &Ipld) -> Result<serde_json::Value, RecordError> {
    use serde_json::Value;
    Ok(match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => {
            let n = i64::try_from(*i)
                .map(serde_json::Number::from)
                .or_else(|_| u64::try_from(*i).map(serde_json::Number::from))
                .map_err(|_| {
                    RecordError::InvalidRecord(format!(
                        "integer {i} is outside the JSON-representable range (i64/u64)"
                    ))
                })?;
            Value::Number(n)
        }
        Ipld::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        Ipld::String(s) => Value::String(s.clone()),
        Ipld::Bytes(b) => {
            serde_json::json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(b) })
        }
        Ipld::List(items) => Value::Array(
            items
                .iter()
                .map(record_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        Ipld::Map(map) => Value::Object(
            map.iter()
                .map(|(k, v)| record_value_to_json(v).map(|jv| (k.clone(), jv)))
                .collect::<Result<_, _>>()?,
        ),
        Ipld::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
    })
}

/// Collect the blob-reference CIDs contained in a single decoded record value.
///
/// An ATProto blob reference is a map `{"$type": "blob", "ref": <link>, ...}` whose `ref` is a
/// CID link — canonically an [`Ipld::Link`] (the form produced when a record is stored via
/// [`json_to_record_value`]), with a `{"$link": <link>}` map handled as a defensive fallback.
/// The walk recurses into every nested map and list, so a blob embedded deep inside a record
/// (e.g. `embed.images[].image`) is found. A CID may appear more than once if the same blob is
/// referenced repeatedly; the caller deduplicates.
///
/// Used by `com.atproto.repo.listMissingBlobs` (the referenced-vs-uploaded diff) and
/// `com.atproto.server.checkAccountStatus` (the expected-blob count) to derive a repo's blob
/// references without re-encoding records.
pub fn record_blob_cids(record: &Ipld) -> Vec<Cid> {
    let mut out = Vec::new();
    collect_blob_cids(record, &mut out);
    out
}

fn collect_blob_cids(ipld: &Ipld, out: &mut Vec<Cid>) {
    match ipld {
        Ipld::Map(map) => {
            if let Some(Ipld::String(typ)) = map.get("$type") {
                if typ == "blob" {
                    match map.get("ref") {
                        // Canonical: `json_to_record_value` converts `{"$link": "..."}` to a link.
                        Some(Ipld::Link(cid)) => out.push(*cid),
                        // Fallback: `ref` is still a map with a `$link` link.
                        Some(Ipld::Map(ref_map)) => {
                            if let Some(Ipld::Link(cid)) = ref_map.get("$link") {
                                out.push(*cid);
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Recurse into all map values — a blob could be nested inside an embed.
            for v in map.values() {
                collect_blob_cids(v, out);
            }
        }
        Ipld::List(items) => {
            for v in items {
                collect_blob_cids(v, out);
            }
        }
        // Scalars and links are leaves — no further recursion.
        _ => {}
    }
}

/// Write a record provided as JSON, converting it to the ATProto data model first.
/// Returns the record block CID. Errors with `InvalidRecord` for floats or malformed
/// `$link`/`$bytes`.
pub async fn put_record_json<S>(
    repo: &mut Repository<S>,
    signer: &CommitSigner,
    key: &str,
    json: &serde_json::Value,
) -> Result<Cid, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    let value = json_to_record_value(json)?;
    put_record(repo, signer, key, &value).await
}

/// Read a record and return it as JSON, mapping the ATProto data model back to its JSON
/// form (CID links → `{"$link": ...}`, byte strings → `{"$bytes": ...}`).
pub async fn get_record_json<S>(
    repo: &mut Repository<S>,
    key: &str,
) -> Result<Option<serde_json::Value>, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    let value: Option<Ipld> = get_record(repo, key).await?;
    value.map(|v| record_value_to_json(&v)).transpose()
}

/// A single record returned by [`list_records_json`].
pub struct ListedRecord {
    /// The record key (the MST key with the `<collection>/` prefix stripped).
    pub rkey: String,
    /// The CID of the record block.
    pub cid: Cid,
    /// The record value as JSON (CID links → `{"$link": ...}`, bytes → `{"$bytes": ...}`).
    pub value: serde_json::Value,
}

/// A page of records from [`list_records_json`].
pub struct ListRecordsPage {
    /// The records in this page, in traversal order.
    pub records: Vec<ListedRecord>,
    /// The cursor to pass to fetch the next page, or `None` when the listing is exhausted.
    pub cursor: Option<String>,
}

/// List records in a collection, in MST (lexicographic by rkey) order, with cursor pagination.
///
/// - `limit` caps the number of records returned (the caller is responsible for clamping it
///   to any policy bounds).
/// - `cursor`, when present, is an rkey from a previous page; only records *after* it in the
///   current traversal direction are returned.
/// - `reverse` walks the collection in descending rkey order instead of ascending.
///
/// The returned `cursor` is the last rkey of the page, set only when more records remain.
pub async fn list_records_json<S>(
    repo: &mut Repository<S>,
    collection: &str,
    limit: usize,
    cursor: Option<&str>,
    reverse: bool,
) -> Result<ListRecordsPage, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    use futures::StreamExt;

    // The MST key for a record is `<collection>/<rkey>`; the trailing slash confines the
    // prefix scan to this exact collection (so `app.bsky.feed.post` won't match
    // `app.bsky.feed.postx`).
    let prefix = format!("{collection}/");
    let strip = |key: &str| key.strip_prefix(&prefix).unwrap_or(key).to_string();

    // Collect up to `limit + 1` post-cursor entries — the extra one tells us whether more
    // records remain (and thus whether to emit a cursor) without reading the whole page.
    let want = limit.saturating_add(1);
    let mut entries: Vec<(String, Cid)> = Vec::new();
    {
        let mut tree = repo.tree();
        let mut stream = Box::pin(tree.entries_prefixed(&prefix));

        if reverse {
            // `entries_prefixed` only yields ascending order and atrium-repo exposes no
            // reverse traversal, so descending order requires materializing the collection
            // and walking it backwards. Cursor/limit are then applied while walking.
            let mut all: Vec<(String, Cid)> = Vec::new();
            while let Some(res) = stream.next().await {
                let (key, cid) =
                    res.map_err(|e| RecordError::Repo(format!("list entries: {e}")))?;
                all.push((strip(&key), cid));
            }
            for (rkey, cid) in all.into_iter().rev() {
                if cursor.is_some_and(|c| rkey.as_str() >= c) {
                    continue;
                }
                entries.push((rkey, cid));
                if entries.len() == want {
                    break;
                }
            }
        } else {
            // Ascending: skip up to and including the cursor, then take `limit + 1` and stop.
            // Memory and block reads stay proportional to the page, not the collection.
            while let Some(res) = stream.next().await {
                let (key, cid) =
                    res.map_err(|e| RecordError::Repo(format!("list entries: {e}")))?;
                let rkey = strip(&key);
                if cursor.is_some_and(|c| rkey.as_str() <= c) {
                    continue;
                }
                entries.push((rkey, cid));
                if entries.len() == want {
                    break;
                }
            }
        }
    }

    // The (limit + 1)-th entry, if present, means more records remain past this page.
    let has_more = entries.len() > limit;
    entries.truncate(limit);

    // Resolve each record's value by its MST key. `get_raw_cid` would re-enumerate the
    // entire MST per record (atrium walks every entry to prove the CID belongs to the
    // repo), making a page O(limit × repo-size) — pathological on a mature repo. We
    // already walked the tree to collect `(rkey, cid)`, so a keyed lookup (`get_raw`,
    // one tree descent) is both membership-safe and O(log n) per record.
    let mut records = Vec::with_capacity(entries.len());
    for (rkey, cid) in entries {
        let full_key = format!("{prefix}{rkey}");
        let value: Option<Ipld> = repo
            .get_raw(&full_key)
            .await
            .map_err(|e| RecordError::Repo(format!("read record block: {e}")))?;
        let value = value.ok_or(RecordError::NotFound)?;
        records.push(ListedRecord {
            rkey,
            cid,
            value: record_value_to_json(&value)?,
        });
    }

    let cursor = if has_more {
        records.last().map(|r| r.rkey.clone())
    } else {
        None
    };

    Ok(ListRecordsPage { records, cursor })
}

/// List the distinct collection NSIDs present in a repository, in lexicographic order.
///
/// Walks every MST key (`<collection>/<rkey>`) and collects the unique `<collection>`
/// prefixes. An empty repo (genesis, no records) yields an empty list. Used by
/// `com.atproto.repo.describeRepo` to report which collections a repo holds.
pub async fn list_collections<S>(repo: &mut Repository<S>) -> Result<Vec<String>, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    use futures::StreamExt;

    // MST keys arrive in lexicographic order, and every key for a collection shares the
    // `<collection>/` prefix — so any key sorting between two of a collection's keys must
    // also carry that prefix. Equal-collection keys are therefore contiguous, and a single
    // last-seen comparison dedupes them in O(n) with no intermediate set.
    let mut collections: Vec<String> = Vec::new();
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.keys());
    while let Some(res) = stream.next().await {
        let key = res.map_err(|e| RecordError::Repo(format!("list keys: {e}")))?;
        // MST keys are `<collection>/<rkey>`; the collection is everything before the
        // first slash. Keys without a slash are not valid records and are skipped.
        if let Some((collection, _)) = key.split_once('/') {
            if collections.last().map(String::as_str) != Some(collection) {
                collections.push(collection.to_string());
            }
        }
    }
    Ok(collections)
}

/// Count the total number of records across all collections in a repository.
///
/// Walks every MST key (`<collection>/<rkey>`) and counts those that name a record (i.e.
/// contain a `/`, the collection/rkey separator). Keys without a slash are not valid records
/// and are skipped, mirroring [`list_collections`]. An empty repo (genesis, no records)
/// yields 0. Used by the operator usage endpoint to report a repo's record count.
pub async fn count_records<S>(repo: &mut Repository<S>) -> Result<usize, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    use futures::StreamExt;

    let mut count = 0usize;
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.keys());
    while let Some(res) = stream.next().await {
        let key = res.map_err(|e| RecordError::Repo(format!("count keys: {e}")))?;
        if key.contains('/') {
            count += 1;
        }
    }
    Ok(count)
}

/// Validate that `collection` is a syntactically valid NSID, matching the ATProto
/// reference grammar (`@atproto/syntax`'s `ensureValidNsid`) so a collection accepted
/// here is also accepted by relays and AppViews — a collection that passes local
/// validation but fails theirs produces records that write locally yet are silently
/// rejected downstream, a confusing one-way sync.
///
/// - total length 1..=317, at least three dot-separated segments, no slashes;
/// - every segment is 1..=63 chars of `[A-Za-z0-9-]` and neither starts nor ends with a hyphen;
/// - the first (authority) segment does not start with a digit;
/// - the final (name) segment is a letter followed by letters/digits only (no hyphens).
///
/// The digit restriction is deliberately only on the *first* segment (not every authority
/// segment) to mirror the reference implementation exactly — being stricter would reject
/// collections the network accepts, the opposite one-way divergence.
pub fn validate_collection(collection: &str) -> Result<(), RecordError> {
    let invalid =
        || RecordError::InvalidPath(format!("collection is not a valid NSID: {collection}"));

    if collection.is_empty() || collection.len() > 317 {
        return Err(invalid());
    }
    let segments: Vec<&str> = collection.split('.').collect();
    if segments.len() < 3 {
        return Err(invalid());
    }
    let last = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        let bytes = seg.as_bytes();
        if seg.is_empty() || seg.len() > 63 {
            return Err(invalid());
        }
        if !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(invalid());
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(invalid());
        }
        if i == 0 && bytes[0].is_ascii_digit() {
            return Err(invalid());
        }
        // Final (name) segment: a letter followed by letters/digits only (no hyphens).
        if i == last && (!bytes[0].is_ascii_alphabetic() || seg.chars().any(|c| c == '-')) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Validate a record's collection (NSID) and record key per the ATProto spec,
/// before any repo mutation.
///
/// - `collection` must be a valid NSID (see [`validate_collection`]): at least three
///   dot-separated segments, each 1..=63 chars of `[A-Za-z0-9-]` not hyphen-bounded, the
///   first not digit-led and the last a letter followed by letters/digits only.
/// - `rkey` must be 1..=512 chars from `[A-Za-z0-9._:~-]`, and not `.` or `..`.
pub fn validate_record_path(collection: &str, rkey: &str) -> Result<(), RecordError> {
    validate_collection(collection)?;

    // Record key: 1..=512 chars from [A-Za-z0-9._:~-], and not "." or "..".
    if rkey.is_empty() || rkey.len() > 512 || rkey == "." || rkey == ".." {
        return Err(RecordError::InvalidPath(format!(
            "invalid record key: {rkey}"
        )));
    }
    if !rkey
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '~'))
    {
        return Err(RecordError::InvalidPath(format!(
            "record key has invalid characters: {rkey}"
        )));
    }

    Ok(())
}

/// Write (create or update) a record in the repository.
///
/// If the key already exists, the record is updated. If not, it is created.
/// The commit is signed with the provided signer.
///
/// Returns the CID of the new record block.
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::put_record;
///
/// let mut repo = Repository::open(&mut block_store, root_cid).await?;
/// let record_cid = put_record(&mut repo, &signer, "app.bsky.feed.post/abc123", &record_data).await?;
/// ```
pub async fn put_record<S, T>(
    repo: &mut Repository<S>,
    signer: &CommitSigner,
    key: &str,
    data: &T,
) -> Result<Cid, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
    T: Serialize,
{
    // Choose create vs update by checking existence first — robust against atrium's
    // error message wording (which a string match would couple to).
    //
    // Probe with a pure MST lookup (key → CID), never by decoding the stored record.
    // Decoding into a concrete type (e.g. `serde_json::Value`) fails for any record
    // that embeds a CID link (`$link`, CBOR tag 42) or byte string (`$bytes`) —
    // `serde_json::Value` cannot represent either — which would make every update of
    // a profile-with-avatar or post-with-image return a spurious error.
    let exists = get_record_cid(repo, key).await?.is_some();
    // Capture the previous commit's rev before the builder borrows the repo mutably, so the
    // new commit's rev can be forced strictly greater than it.
    let prev_rev = repo.commit().rev();
    let (mut commit_builder, cid) = if exists {
        repo.update_raw(key, data)
            .await
            .map_err(|e| RecordError::Repo(format!("update record: {e}")))?
    } else {
        repo.add_raw(key, data)
            .await
            .map_err(|e| RecordError::Repo(format!("add record: {e}")))?
    };
    // Force a strictly-increasing rev (atrium defaults it to the raw wall clock).
    commit_builder.rev(next_commit_rev(prev_rev.as_ref())?);

    // Sign and finalize the commit.
    let sig = signer.sign(&commit_builder.bytes());
    commit_builder
        .finalize(sig)
        .await
        .map_err(|e| RecordError::Repo(format!("finalize commit: {e}")))?;

    Ok(cid)
}

/// Return the CID of the record block currently stored at `key`, or `None` if absent.
///
/// The MST maps each record key directly to its block CID, so this is a single tree
/// lookup with no record-block fetch. Used to enforce the `swapRecord`
/// optimistic-concurrency precondition without deserializing the record itself.
pub async fn get_record_cid<S>(
    repo: &mut Repository<S>,
    key: &str,
) -> Result<Option<Cid>, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    repo.tree()
        .get(key)
        .await
        .map_err(|e| RecordError::Repo(format!("get record cid: {e}")))
}

/// Read a record from the repository.
///
/// Returns `None` if the key does not exist.
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::get_record;
///
/// let mut repo = Repository::open(&mut block_store, root_cid).await?;
/// let record: Option<MyRecord> = get_record(&mut repo, "app.bsky.feed.post/abc123").await?;
/// ```
pub async fn get_record<S, T>(repo: &mut Repository<S>, key: &str) -> Result<Option<T>, RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
    T: DeserializeOwned,
{
    repo.get_raw(key)
        .await
        .map_err(|e| RecordError::Repo(format!("get record: {e}")))
}

/// Delete a record from the repository.
///
/// Returns `Ok(())` if the record was deleted, or `Err(RecordError::NotFound)` if it doesn't exist.
/// The commit is signed with the provided signer.
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::delete_record;
///
/// let mut repo = Repository::open(&mut block_store, root_cid).await?;
/// delete_record(&mut repo, &signer, "app.bsky.feed.post/abc123").await?;
/// ```
pub async fn delete_record<S>(
    repo: &mut Repository<S>,
    signer: &CommitSigner,
    key: &str,
) -> Result<(), RecordError>
where
    S: atrium_repo::blockstore::AsyncBlockStoreRead + atrium_repo::blockstore::AsyncBlockStoreWrite,
{
    // Capture the previous commit's rev before the builder borrows the repo mutably.
    let prev_rev = repo.commit().rev();
    let mut builder = repo
        .delete_raw(key)
        .await
        .map_err(|e| RecordError::Repo(format!("delete record: {e}")))?;
    // Force a strictly-increasing rev (atrium defaults it to the raw wall clock).
    builder.rev(next_commit_rev(prev_rev.as_ref())?);

    let sig = signer.sign(&builder.bytes());
    builder
        .finalize(sig)
        .await
        .map_err(|e| RecordError::Repo(format!("finalize commit: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::MemoryBlockStore;
    use atrium_repo::repo::Repository;

    use crate::test_support::test_signer;

    const TEST_CID: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

    #[test]
    fn json_to_record_value_rejects_floats() {
        assert!(json_to_record_value(&serde_json::json!({ "x": 1.5 })).is_err());
        assert!(json_to_record_value(&serde_json::json!([1, 2.0, 3])).is_err());
    }

    #[test]
    fn record_value_round_trips_links_bytes_and_scalars() {
        let json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "count": 42,
            "ref": { "$link": TEST_CID },
            "data": { "$bytes": "AQIDBA==" },
            "nested": { "list": [1, 2, 3], "flag": true, "nothing": null }
        });
        let ipld = json_to_record_value(&json).unwrap();
        assert_eq!(record_value_to_json(&ipld).unwrap(), json);
    }

    #[test]
    fn record_value_to_json_errors_on_out_of_range_integer() {
        // A CAR import can carry a DAG-CBOR integer outside both `i64` and `u64` range
        // (`json_to_record_value` can't produce one). Reading it back must error, not
        // silently substitute `null` — the historical bug.
        let too_big = Ipld::Integer(i128::from(u64::MAX) + 1);
        assert!(record_value_to_json(&too_big).is_err());

        let too_negative = Ipld::Integer(i128::from(i64::MIN) - 1);
        assert!(record_value_to_json(&too_negative).is_err());

        // The error must propagate up when the offending value is nested inside a record.
        let nested = Ipld::Map(BTreeMap::from([(
            "embed".to_string(),
            Ipld::List(vec![Ipld::Integer(i128::from(u64::MAX) + 1)]),
        )]));
        assert!(record_value_to_json(&nested).is_err());

        // The boundary values still round-trip: `u64::MAX` and `i64::MIN` are in range.
        assert_eq!(
            record_value_to_json(&Ipld::Integer(i128::from(u64::MAX))).unwrap(),
            serde_json::json!(u64::MAX)
        );
        assert_eq!(
            record_value_to_json(&Ipld::Integer(i128::from(i64::MIN))).unwrap(),
            serde_json::json!(i64::MIN)
        );
    }

    #[tokio::test]
    async fn put_get_json_round_trips_cid_link() {
        let (mut repo, signer) = create_test_repo("did:plc:linktest").await;
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "embed": { "$link": TEST_CID }
        });
        let key = "app.bsky.feed.post/abc";
        put_record_json(&mut repo, &signer, key, &record)
            .await
            .unwrap();
        let got = get_record_json(&mut repo, key).await.unwrap();
        assert_eq!(
            got,
            Some(record),
            "a $link must survive a store/read round-trip"
        );
    }

    #[tokio::test]
    async fn canonical_link_encoding_differs_from_raw_map() {
        // The whole point: a $link must encode as a CID tag, not a plain map — so the
        // record CID differs from naively storing the JSON. Other implementations agree
        // only with the canonical (CID-tag) encoding.
        let (mut repo, signer) = create_test_repo("did:plc:enctest").await;
        let with_link = serde_json::json!({ "ref": { "$link": TEST_CID } });
        let canonical = put_record_json(&mut repo, &signer, "app.bsky.feed.post/a", &with_link)
            .await
            .unwrap();
        let raw_map = put_record(&mut repo, &signer, "app.bsky.feed.post/b", &with_link)
            .await
            .unwrap();
        assert_ne!(canonical, raw_map);
    }

    #[test]
    fn record_blob_cids_finds_nested_blob_refs() {
        // A blob nested inside an embed, plus a non-blob $link that must NOT be collected.
        let json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "embed": {
                "images": [
                    { "image": { "$type": "blob", "ref": { "$link": TEST_CID }, "mimeType": "image/png", "size": 1 } }
                ]
            },
            "notablob": { "$link": TEST_CID }
        });
        let ipld = json_to_record_value(&json).unwrap();
        let cids = record_blob_cids(&ipld);
        assert_eq!(cids.len(), 1, "only the $type:blob ref is a blob CID");
        assert_eq!(cids[0].to_string(), TEST_CID);
    }

    #[test]
    fn record_blob_cids_empty_for_no_blobs() {
        let ipld = json_to_record_value(&serde_json::json!({ "text": "no blobs here" })).unwrap();
        assert!(record_blob_cids(&ipld).is_empty());
    }

    #[test]
    fn validate_record_path_accepts_valid() {
        assert!(validate_record_path("app.bsky.feed.post", "3jzfcijpj2z2a").is_ok());
        // A hyphen is allowed inside an authority segment (but not the name segment).
        assert!(validate_record_path("com.ex-ample.foo", "self").is_ok());
        assert!(validate_record_path("app.bsky.feed.post", "a.b_c~d:e-f").is_ok());
    }

    #[test]
    fn validate_record_path_rejects_bad_collection() {
        assert!(validate_record_path("", "x").is_err()); // empty
        assert!(validate_record_path("foo", "x").is_err()); // too few segments
        assert!(validate_record_path("app.bsky", "x").is_err()); // 2 segments
        assert!(validate_record_path("app..post", "x").is_err()); // empty segment
        assert!(validate_record_path("app/bsky/post", "x").is_err()); // slashes
        assert!(validate_record_path("app.bsky.po st", "x").is_err()); // space
    }

    /// The tightened NSID grammar (matching `@atproto/syntax`'s `ensureValidNsid`): segment
    /// length ≤ 63, no hyphen-bounded segments, first segment not digit-led, and a name
    /// segment that is a letter followed by letters/digits only.
    #[test]
    fn validate_collection_matches_atproto_nsid_grammar() {
        // Accepted: canonical NSIDs, a hyphen inside an authority segment, and a digit-led
        // *interior* authority segment (the reference impl restricts digit-leading to the
        // first segment only).
        assert!(validate_collection("app.bsky.feed.post").is_ok());
        assert!(validate_collection("com.ex-ample.foo").is_ok());
        assert!(validate_collection("com.4chan.post").is_ok());
        assert!(validate_collection("com.example.name2").is_ok()); // digit inside name ok

        // Segment longer than 63 chars.
        let long_seg = "a".repeat(64);
        assert!(validate_collection(&format!("com.example.{long_seg}")).is_err());
        assert!(validate_collection(&format!("com.{long_seg}.post")).is_err());

        // Hyphen at a segment boundary.
        assert!(validate_collection("com.-example.post").is_err()); // leading hyphen
        assert!(validate_collection("com.example-.post").is_err()); // trailing hyphen

        // First segment starts with a digit.
        assert!(validate_collection("4com.example.post").is_err());

        // Name (final) segment must be a letter then letters/digits only.
        assert!(validate_collection("com.example.a-b").is_err()); // hyphen in name
        assert!(validate_collection("com.example.1abc").is_err()); // digit-led name
    }

    #[test]
    fn validate_record_path_rejects_bad_rkey() {
        assert!(validate_record_path("app.bsky.feed.post", "").is_err()); // empty
        assert!(validate_record_path("app.bsky.feed.post", ".").is_err()); // dot
        assert!(validate_record_path("app.bsky.feed.post", "..").is_err()); // dotdot
        assert!(validate_record_path("app.bsky.feed.post", "a/b").is_err()); // slash
        assert!(validate_record_path("app.bsky.feed.post", "a b").is_err()); // space
        assert!(validate_record_path("app.bsky.feed.post", &"x".repeat(513)).is_err());
        // too long
    }

    async fn create_test_repo(did: &str) -> (Repository<MemoryBlockStore>, CommitSigner) {
        let bs = MemoryBlockStore::new();
        let signer = test_signer();
        let did_typed = atrium_api::types::string::Did::new(did.to_string()).unwrap();

        let repo_builder = Repository::create(bs, did_typed).await.unwrap();
        let sig = signer.sign(&repo_builder.bytes());
        let repo = repo_builder.finalize(sig).await.unwrap();

        (repo, signer)
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestRecord {
        text: String,
        created_at: String,
    }

    #[tokio::test]
    async fn put_and_get_record_roundtrip() {
        let (mut repo, signer) = create_test_repo("did:plc:roundtrip").await;

        let record = TestRecord {
            text: "Hello, ATProto!".to_string(),
            created_at: "2026-06-22T00:00:00Z".to_string(),
        };

        let key = "app.bsky.feed.post/test123";
        let cid = put_record(&mut repo, &signer, key, &record).await.unwrap();

        // CID should be non-nil.
        assert_ne!(cid.to_string(), "");

        // Read it back.
        let loaded: Option<TestRecord> = get_record(&mut repo, key).await.unwrap();
        assert_eq!(loaded, Some(record));
    }

    #[tokio::test]
    async fn get_nonexistent_record_returns_none() {
        let (mut repo, _signer) = create_test_repo("did:plc:notfound").await;

        let result: Option<TestRecord> = get_record(&mut repo, "app.bsky.feed.post/nope")
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn tid_encode_decode_round_trips() {
        for v in [
            0u64,
            1,
            1023,
            1 << 10,
            (1_700_000_000_000_000u64 << 10) | 42,
        ] {
            assert_eq!(decode_tid(&encode_tid(v)), v, "round-trip failed for {v}");
        }
    }

    /// `next_commit_rev` is strictly greater than the previous rev in every regime:
    /// clock ahead of prev (normal), clock equal to / behind prev (same-microsecond
    /// collision or backward clock step).
    #[test]
    fn next_commit_rev_is_strictly_monotonic() {
        // Normal case: a real "now" TID; the next rev must exceed it.
        let prev = generate_tid();
        let next = next_commit_rev(&prev).unwrap();
        assert!(
            next.as_ref() > prev.as_str(),
            "next {next:?} must exceed prev {prev}"
        );

        // Backward clock / future prev: prev is far ahead of the wall clock, so the bump path
        // (prev + 1) must engage and still produce a strictly greater rev.
        let future = encode_tid((4_000_000_000_000_000u64 << 10) | 1000);
        let next = next_commit_rev(&future).unwrap();
        assert!(
            next.as_ref() > future.as_str(),
            "next {next:?} must exceed a future prev {future}"
        );
        assert_eq!(
            decode_tid(next.as_ref()),
            decode_tid(&future) + 1,
            "bump path must yield exactly prev + 1"
        );
    }

    /// Consecutive commits (which land in the same or near-same microsecond) must carry
    /// strictly increasing revs, or relays drop them as stale.
    #[tokio::test]
    async fn consecutive_commits_have_strictly_increasing_revs() {
        let (mut repo, signer) = create_test_repo("did:plc:revmono").await;
        let mut prev = repo.commit().rev().as_ref().to_string();
        for i in 0..25 {
            let key = format!("app.bsky.feed.post/rev{i}");
            put_record_json(
                &mut repo,
                &signer,
                &key,
                &serde_json::json!({ "text": "x" }),
            )
            .await
            .unwrap();
            let rev = repo.commit().rev().as_ref().to_string();
            assert!(
                rev > prev,
                "commit {i}: rev {rev} must be strictly greater than previous {prev}"
            );
            prev = rev;
        }
    }

    #[tokio::test]
    async fn put_then_update_record() {
        let (mut repo, signer) = create_test_repo("did:plc:update").await;

        let key = "app.bsky.feed.post/update1";

        let record1 = TestRecord {
            text: "first version".to_string(),
            created_at: "2026-06-22T00:00:00Z".to_string(),
        };
        let record2 = TestRecord {
            text: "second version".to_string(),
            created_at: "2026-06-22T00:01:00Z".to_string(),
        };

        // Create.
        put_record(&mut repo, &signer, key, &record1).await.unwrap();

        // Update.
        put_record(&mut repo, &signer, key, &record2).await.unwrap();

        // Read back — should be the updated version.
        let loaded: Option<TestRecord> = get_record(&mut repo, key).await.unwrap();
        assert_eq!(loaded, Some(record2));
    }

    /// Updating a record that embeds a blob ref (a `$link` CID) or `$bytes` must work.
    /// This is the profile-with-avatar / post-with-image case: the existence probe in
    /// `put_record` must not try to decode the stored record into a type that cannot
    /// represent DAG-CBOR links or byte strings.
    #[tokio::test]
    async fn update_record_containing_link_and_bytes() {
        let (mut repo, signer) = create_test_repo("did:plc:blobref").await;

        let key = "app.bsky.actor.profile/self";
        // A realistic profile: displayName + an avatar blob ref (CBOR tag-42 link).
        let avatar_cid = "bafkreie5b5c5wxrxwqsc6xzjmkq2b6f3v6xq7q7q7q7q7q7q7q7q7q7q7q";
        let v1 = serde_json::json!({
            "displayName": "v1",
            "avatar": {
                "$type": "blob",
                "ref": { "$link": avatar_cid },
                "mimeType": "image/jpeg",
                "size": 12345
            },
            "sig": { "$bytes": "aGVsbG8=" }
        });
        put_record_json(&mut repo, &signer, key, &v1).await.unwrap();

        // The update must succeed — the existence probe reads the stored record.
        let v2 = serde_json::json!({
            "displayName": "v2",
            "avatar": {
                "$type": "blob",
                "ref": { "$link": avatar_cid },
                "mimeType": "image/jpeg",
                "size": 12345
            },
            "sig": { "$bytes": "aGVsbG8=" }
        });
        put_record_json(&mut repo, &signer, key, &v2)
            .await
            .expect("updating a record with a $link/$bytes must succeed");

        let loaded = get_record_json(&mut repo, key).await.unwrap().unwrap();
        assert_eq!(loaded["displayName"], "v2");
        assert_eq!(loaded["avatar"]["ref"]["$link"], avatar_cid);
    }

    #[tokio::test]
    async fn delete_record_removes_it() {
        let (mut repo, signer) = create_test_repo("did:plc:delete").await;

        let key = "app.bsky.feed.post/delete1";
        let record = TestRecord {
            text: "to be deleted".to_string(),
            created_at: "2026-06-22T00:00:00Z".to_string(),
        };

        // Create.
        put_record(&mut repo, &signer, key, &record).await.unwrap();

        // Verify it exists.
        let loaded: Option<TestRecord> = get_record(&mut repo, key).await.unwrap();
        assert!(loaded.is_some());

        // Delete.
        delete_record(&mut repo, &signer, key).await.unwrap();

        // Verify it's gone.
        let loaded: Option<TestRecord> = get_record(&mut repo, key).await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn delete_nonexistent_record_returns_error() {
        let (mut repo, signer) = create_test_repo("did:plc:deletemissing").await;

        let result = delete_record(&mut repo, &signer, "app.bsky.feed.post/nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn apply_writes_batch_creates_updates_and_deletes() {
        let (mut repo, signer) = create_test_repo("did:plc:applybatch").await;

        let writes = vec![
            WriteOp::Create {
                key: "app.bsky.feed.post/a".into(),
                value: serde_json::json!({ "text": "a" }),
            },
            WriteOp::Create {
                key: "app.bsky.feed.post/b".into(),
                value: serde_json::json!({ "text": "b" }),
            },
            WriteOp::Update {
                key: "app.bsky.feed.post/a".into(),
                value: serde_json::json!({ "text": "a2" }),
            },
            WriteOp::Delete {
                key: "app.bsky.feed.post/b".into(),
            },
        ];

        let outcomes = apply_writes(&mut repo, &signer, &writes).await.unwrap();
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes[0].cid.is_some(), "create yields a record CID");
        assert!(outcomes[3].cid.is_none(), "delete yields no CID");

        // `prev` chains the record's prior CID for updates/deletes and is absent for creates.
        assert!(outcomes[0].prev.is_none(), "create has no previous record");
        assert!(outcomes[1].prev.is_none(), "create has no previous record");
        assert_eq!(
            outcomes[2].prev, outcomes[0].cid,
            "update's prev is the CID it replaced (a's create)"
        );
        assert_eq!(
            outcomes[3].prev, outcomes[1].cid,
            "delete's prev is the CID it removed (b's create)"
        );

        // Final state reflects the whole batch: a updated, b gone.
        let a = get_record_json(&mut repo, "app.bsky.feed.post/a")
            .await
            .unwrap();
        assert_eq!(a, Some(serde_json::json!({ "text": "a2" })));
        let b = get_record_json(&mut repo, "app.bsky.feed.post/b")
            .await
            .unwrap();
        assert_eq!(b, None);
    }

    #[tokio::test]
    async fn apply_writes_create_on_existing_key_errors() {
        let (mut repo, signer) = create_test_repo("did:plc:applydup").await;

        apply_writes(
            &mut repo,
            &signer,
            &[WriteOp::Create {
                key: "app.bsky.feed.post/x".into(),
                value: serde_json::json!({ "text": "first" }),
            }],
        )
        .await
        .unwrap();

        let err = apply_writes(
            &mut repo,
            &signer,
            &[WriteOp::Create {
                key: "app.bsky.feed.post/x".into(),
                value: serde_json::json!({ "text": "again" }),
            }],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RecordError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn apply_writes_delete_missing_is_noop() {
        let (mut repo, signer) = create_test_repo("did:plc:applydelmissing").await;
        let root_before = repo.root();

        let outcomes = apply_writes(
            &mut repo,
            &signer,
            &[WriteOp::Delete {
                key: "app.bsky.feed.post/ghost".into(),
            }],
        )
        .await
        .unwrap();

        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].cid.is_none());
        assert!(
            outcomes[0].prev.is_none(),
            "a no-op delete of an absent key has no previous record CID"
        );
        // A no-op delete must not write a commit, so the root is unchanged.
        assert_eq!(repo.root(), root_before);
    }

    #[tokio::test]
    async fn list_collections_returns_distinct_sorted_names() {
        let (mut repo, signer) = create_test_repo("did:plc:collections").await;

        // Empty repo: no collections.
        assert!(list_collections(&mut repo).await.unwrap().is_empty());

        // Two records in one collection, one in another (inserted out of order).
        for key in [
            "app.bsky.feed.post/b",
            "app.bsky.feed.like/x",
            "app.bsky.feed.post/a",
        ] {
            put_record_json(&mut repo, &signer, key, &serde_json::json!({ "t": 1 }))
                .await
                .unwrap();
        }

        let collections = list_collections(&mut repo).await.unwrap();
        assert_eq!(
            collections,
            vec![
                "app.bsky.feed.like".to_string(),
                "app.bsky.feed.post".to_string()
            ],
            "collections must be distinct and lexicographically sorted"
        );
    }

    #[tokio::test]
    async fn count_records_counts_across_collections() {
        let (mut repo, signer) = create_test_repo("did:plc:countrecords").await;

        // Empty repo: zero records.
        assert_eq!(count_records(&mut repo).await.unwrap(), 0);

        for key in [
            "app.bsky.feed.post/b",
            "app.bsky.feed.like/x",
            "app.bsky.feed.post/a",
        ] {
            put_record_json(&mut repo, &signer, key, &serde_json::json!({ "t": 1 }))
                .await
                .unwrap();
        }

        // Three records total, spanning two collections.
        assert_eq!(count_records(&mut repo).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn put_multiple_records() {
        let (mut repo, signer) = create_test_repo("did:plc:multi").await;

        let records = vec![
            (
                "app.bsky.feed.post/1",
                TestRecord {
                    text: "first".to_string(),
                    created_at: "t1".to_string(),
                },
            ),
            (
                "app.bsky.feed.post/2",
                TestRecord {
                    text: "second".to_string(),
                    created_at: "t2".to_string(),
                },
            ),
            (
                "app.bsky.feed.post/3",
                TestRecord {
                    text: "third".to_string(),
                    created_at: "t3".to_string(),
                },
            ),
        ];

        for (key, record) in &records {
            put_record(&mut repo, &signer, key, record).await.unwrap();
        }

        // Verify all three can be read back.
        for (key, expected) in &records {
            let loaded: Option<TestRecord> = get_record(&mut repo, key).await.unwrap();
            assert_eq!(loaded.as_ref(), Some(expected), "record {key} should match");
        }
    }
}
