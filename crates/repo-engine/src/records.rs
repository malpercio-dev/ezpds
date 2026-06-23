// repo-engine: Record write/read operations for ATProto repositories.
//
// Provides put_record, get_record, and delete_record functions that wrap
// atrium-repo's Repository methods with the CommitSigner pattern.

use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use serde::{de::DeserializeOwned, Serialize};

use crate::signer::CommitSigner;

/// Errors from record operations.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("repository error: {0}")]
    Repo(String),
    #[error("record not found")]
    NotFound,
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
    // Try to add the record. If it already exists, update it.
    let (commit_builder, cid) = match repo.add_raw(key, data).await {
        Ok((builder, cid)) => (builder, cid),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already present")
                || msg.contains("already exists")
                || msg.contains("duplicate")
            {
                // Key exists, fall through to update.
                repo.update_raw(key, data)
                    .await
                    .map_err(|e| RecordError::Repo(format!("update record: {e}")))?
            } else {
                return Err(RecordError::Repo(format!("add record: {e}")));
            }
        }
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
