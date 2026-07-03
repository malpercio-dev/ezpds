// pattern: Functional Core

/// One of the requester's records selected for merging, with the metadata a munge needs.
#[derive(Debug, Clone)]
pub struct RecordDescript {
    pub uri: String,
    pub cid: String,
    /// RFC 3339 timestamp — the commit's emission time (firehose CommitEvent.time),
    /// used as the record's indexedAt for feed ordering and lag computation.
    pub indexed_at: String,
    pub record: serde_json::Value,
}

/// The requester's records written since the AppView's last-indexed rev.
#[derive(Debug, Clone, Default)]
pub struct LocalRecords {
    pub count: usize,
    pub profile: Option<RecordDescript>,
    pub posts: Vec<RecordDescript>,
}

/// Munge functions are modeled as `pub(crate) async fn(viewer, original, local, requester) -> serde_json::Value`
/// dispatched by NSID in `pipethrough_munged`. Because Rust async closures are awkward as trait-object args,
/// each munge is a standalone async function matched by a `match` statement on the method string in `mod.rs`.
/// This allows munges to share code (helpers in this types module) without the overhead of boxed closures.
