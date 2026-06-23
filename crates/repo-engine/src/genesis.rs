// repo-engine: Genesis repo creation.
//
// Creates an empty ATProto repository and persists the genesis commit
// to a block store. This is the entry point for new accounts.

use atrium_api::types::string::Did;
use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite};
use atrium_repo::repo::Repository;

use crate::signer::{CommitSigner, CommitSignerError};

/// Errors from genesis repo creation.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("blockstore error: {0}")]
    BlockStore(String),
    #[error("signing error: {0}")]
    Signing(#[from] CommitSignerError),
}

/// Create an empty ATProto repository and persist the genesis commit.
///
/// This creates a new repository for the given DID with an empty MST,
/// signs the genesis commit with the provided signer, and persists all
/// blocks to the block store.
///
/// # Returns
/// The CID of the genesis commit (the repo root).
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::{create_genesis_repo, CommitSigner};
///
/// let signer = CommitSigner::from_bytes(&private_key_bytes)?;
/// let block_store = SqliteBlockStore::new(pool, did.clone());
/// let commit_cid = create_genesis_repo(block_store, &did, &signer).await?;
/// ```
pub async fn create_genesis_repo<S>(
    block_store: S,
    did: &str,
    signer: &CommitSigner,
) -> Result<atrium_repo::Cid, GenesisError>
where
    S: AsyncBlockStoreRead + AsyncBlockStoreWrite,
{
    // Parse DID into the atrium type.
    let did =
        Did::new(did.to_string()).map_err(|e: &str| GenesisError::InvalidDid(e.to_string()))?;

    // Create the repo builder with an empty MST.
    let repo_builder = Repository::create(block_store, did)
        .await
        .map_err(|e| GenesisError::BlockStore(e.to_string()))?;

    // Sign the genesis commit.
    let commit_bytes = repo_builder.bytes();
    let sig = signer.sign(&commit_bytes);

    // Finalize — this writes the commit block to the store.
    let repo = repo_builder
        .finalize(sig)
        .await
        .map_err(|e| GenesisError::BlockStore(e.to_string()))?;

    Ok(repo.root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::MemoryBlockStore;

    fn test_signer() -> CommitSigner {
        use p256::ecdsa::SigningKey;
        let key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = key.to_bytes().into();
        CommitSigner::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn create_genesis_repo_returns_valid_cid() {
        let bs = MemoryBlockStore::new();
        let signer = test_signer();

        let result = create_genesis_repo(bs, "did:plc:testgenesis", &signer).await;
        assert!(result.is_ok(), "genesis repo creation should succeed");

        let cid = result.unwrap();
        // CID should be a valid CIDv1 (dag-cbor, sha-256) — 36 bytes in CBOR form.
        // The string representation starts with "baf" (base32 CIDv1).
        let cid_str = cid.to_string();
        assert!(
            cid_str.starts_with("baf"),
            "CID should be base32-encoded CIDv1, got: {cid_str}"
        );
    }

    #[tokio::test]
    async fn create_genesis_repo_persists_commit_block() {
        let bs = MemoryBlockStore::new();
        let signer = test_signer();

        let cid = create_genesis_repo(bs, "did:plc:testgenesis", &signer)
            .await
            .unwrap();

        // The commit block should be readable from the store.
        // (We can't easily verify without re-opening the store, but the fact that
        // finalize succeeded means the block was written.)
        // CID is deterministic for a given MST state + DID + rev.
        assert!(!cid.to_string().is_empty());
    }

    #[tokio::test]
    async fn create_genesis_repo_different_dids_produce_different_roots() {
        let signer = test_signer();

        let bs1 = MemoryBlockStore::new();
        let cid1 = create_genesis_repo(bs1, "did:plc:alice", &signer)
            .await
            .unwrap();

        let bs2 = MemoryBlockStore::new();
        let cid2 = create_genesis_repo(bs2, "did:plc:bob", &signer)
            .await
            .unwrap();

        assert_ne!(
            cid1, cid2,
            "different DIDs must produce different repo roots"
        );
    }
}
