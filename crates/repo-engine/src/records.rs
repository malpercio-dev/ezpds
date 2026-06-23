// repo-engine: Record write/read operations for ATProto repositories.
//
// Provides put_record, get_record, and delete_record functions that wrap
// atrium-repo's Repository methods with the CommitSigner pattern.

use std::collections::BTreeMap;

use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use base64::Engine;
use ipld_core::ipld::Ipld;
use serde::{de::DeserializeOwned, Serialize};

use crate::signer::CommitSigner;

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
pub fn record_value_to_json(ipld: &Ipld) -> serde_json::Value {
    use serde_json::Value;
    match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => i64::try_from(*i)
            .map(|n| Value::Number(n.into()))
            .or_else(|_| u64::try_from(*i).map(|n| Value::Number(n.into())))
            .unwrap_or(Value::Null),
        Ipld::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        Ipld::String(s) => Value::String(s.clone()),
        Ipld::Bytes(b) => {
            serde_json::json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(b) })
        }
        Ipld::List(items) => Value::Array(items.iter().map(record_value_to_json).collect()),
        Ipld::Map(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), record_value_to_json(v)))
                .collect(),
        ),
        Ipld::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
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
    Ok(value.map(|v| record_value_to_json(&v)))
}

/// Validate a record's collection (NSID) and record key per the ATProto spec,
/// before any repo mutation.
///
/// - `collection` must be a valid NSID: at least three dot-separated segments,
///   each alphanumeric-or-hyphen and non-empty, total length 1..=317, no slashes.
/// - `rkey` must be 1..=512 chars from `[A-Za-z0-9._:~-]`, and not `.` or `..`.
pub fn validate_record_path(collection: &str, rkey: &str) -> Result<(), RecordError> {
    // Collection: NSID — >=3 dot segments, each [A-Za-z0-9-] and non-empty.
    if collection.is_empty() || collection.len() > 317 {
        return Err(RecordError::InvalidPath("collection length".into()));
    }
    let segments: Vec<&str> = collection.split('.').collect();
    if segments.len() < 3
        || segments
            .iter()
            .any(|s| s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        return Err(RecordError::InvalidPath(format!(
            "collection is not a valid NSID: {collection}"
        )));
    }

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
    let exists = repo
        .get_raw::<serde_json::Value>(key)
        .await
        .map_err(|e| RecordError::Repo(format!("check record: {e}")))?
        .is_some();
    let (commit_builder, cid) = if exists {
        repo.update_raw(key, data)
            .await
            .map_err(|e| RecordError::Repo(format!("update record: {e}")))?
    } else {
        repo.add_raw(key, data)
            .await
            .map_err(|e| RecordError::Repo(format!("add record: {e}")))?
    };

    // Sign and finalize the commit.
    let sig = signer.sign(&commit_builder.bytes());
    commit_builder
        .finalize(sig)
        .await
        .map_err(|e| RecordError::Repo(format!("finalize commit: {e}")))?;

    Ok(cid)
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
    let builder = repo
        .delete_raw(key)
        .await
        .map_err(|e| RecordError::Repo(format!("delete record: {e}")))?;

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
    use p256::ecdsa::SigningKey;

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
        assert_eq!(record_value_to_json(&ipld), json);
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
    fn validate_record_path_accepts_valid() {
        assert!(validate_record_path("app.bsky.feed.post", "3jzfcijpj2z2a").is_ok());
        assert!(validate_record_path("com.example.a-b", "self").is_ok());
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

    fn test_signer() -> CommitSigner {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = key.to_bytes().into();
        CommitSigner::from_bytes(&bytes).unwrap()
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
