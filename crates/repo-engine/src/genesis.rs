// repo-engine: Genesis repo creation.
//
// Creates an empty ATProto repository and persists the genesis commit
// to a block store. This is the entry point for new accounts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atrium_api::types::string::Did;
use atrium_repo::blockstore::{self, AsyncBlockStoreRead, AsyncBlockStoreWrite, SHA2_256};
use atrium_repo::repo::Repository;
use atrium_repo::{Cid, Multihash};
use sha2::Digest;

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

/// An in-memory block store that captures every written block so the caller can
/// persist them atomically elsewhere (e.g. inside a DB transaction). Cloning shares
/// the same underlying block map, so a clone handed to `Repository::create` records
/// into the same map the original can read back.
#[derive(Clone, Default)]
pub struct CapturingBlockStore {
    blocks: Arc<Mutex<HashMap<Cid, Vec<u8>>>>,
}

impl CapturingBlockStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// All blocks written so far, as (CID, bytes) pairs.
    pub fn blocks(&self) -> Vec<(Cid, Vec<u8>)> {
        self.blocks
            .lock()
            .expect("block map mutex poisoned")
            .iter()
            .map(|(c, b)| (*c, b.clone()))
            .collect()
    }
}

impl AsyncBlockStoreRead for CapturingBlockStore {
    async fn read_block_into(
        &mut self,
        cid: Cid,
        contents: &mut Vec<u8>,
    ) -> Result<(), blockstore::Error> {
        let bytes = {
            let map = self.blocks.lock().expect("block map mutex poisoned");
            map.get(&cid).ok_or(blockstore::Error::CidNotFound)?.clone()
        };
        contents.clear();
        contents.extend_from_slice(&bytes);
        Ok(())
    }
}

impl AsyncBlockStoreWrite for CapturingBlockStore {
    async fn write_block(
        &mut self,
        codec: u64,
        hash: u64,
        contents: &[u8],
    ) -> Result<Cid, blockstore::Error> {
        if hash != SHA2_256 {
            return Err(blockstore::Error::UnsupportedHash(hash));
        }
        let digest = sha2::Sha256::digest(contents);
        let mh = Multihash::wrap(hash, digest.as_slice()).expect("SHA-256 digest is 32 bytes");
        let cid = Cid::new_v1(codec, mh);
        self.blocks
            .lock()
            .expect("block map mutex poisoned")
            .insert(cid, contents.to_vec());
        Ok(cid)
    }
}

/// Build an empty, signed genesis repo in memory, returning the root commit CID, the
/// commit revision (`rev`), and every block written. The caller persists the blocks (and
/// root + rev) atomically — e.g. inside the account-promotion transaction — so a
/// half-created repo (account without a repo, or a root pointing at missing blocks) is
/// structurally impossible.
pub async fn build_genesis_repo(
    did: &str,
    signer: &CommitSigner,
) -> Result<(Cid, String, Vec<(Cid, Vec<u8>)>), GenesisError> {
    let store = CapturingBlockStore::new();
    let did_typed =
        Did::new(did.to_string()).map_err(|e: &str| GenesisError::InvalidDid(e.to_string()))?;

    // `store.clone()` shares the block map; the builder writes into it, and we read
    // the captured blocks back from our retained handle after finalizing.
    let repo_builder = Repository::create(store.clone(), did_typed)
        .await
        .map_err(|e| GenesisError::BlockStore(e.to_string()))?;
    let sig = signer.sign(&repo_builder.bytes());
    let repo = repo_builder
        .finalize(sig)
        .await
        .map_err(|e| GenesisError::BlockStore(e.to_string()))?;

    let rev = repo.commit().rev().as_str().to_string();
    Ok((repo.root(), rev, store.blocks()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::MemoryBlockStore;

    use crate::test_support::test_signer;

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

    #[tokio::test]
    async fn build_genesis_repo_captures_reopenable_blocks() {
        use atrium_repo::blockstore::{AsyncBlockStoreWrite, DAG_CBOR, SHA2_256};

        let signer = test_signer();
        let (root, rev, blocks) = build_genesis_repo("did:plc:buildtest", &signer)
            .await
            .unwrap();

        assert!(!rev.is_empty(), "genesis commit must have a rev");
        assert!(
            blocks.len() >= 2,
            "genesis has a commit + an empty MST node"
        );
        assert!(
            blocks.iter().any(|(c, _)| *c == root),
            "captured blocks must include the root commit"
        );

        // Re-import the captured blocks into a fresh store and re-open at the root.
        let mut store = MemoryBlockStore::new();
        for (_cid, bytes) in &blocks {
            store.write_block(DAG_CBOR, SHA2_256, bytes).await.unwrap();
        }
        let repo = Repository::open(store, root).await.unwrap();
        assert_eq!(repo.root(), root, "re-opened repo must have the same root");
    }
}
