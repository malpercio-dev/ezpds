// repo-engine: CAR file export for ATProto repositories.
//
// Exports a repository as a CARv1 file for the com.atproto.sync.getRepo endpoint.

use std::io::Cursor;

use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, CarStore, SHA2_256};
use atrium_repo::Cid;

/// Errors from CAR export operations.
#[derive(Debug, thiserror::Error)]
pub enum CarExportError {
    #[error("blockstore error: {0}")]
    BlockStore(String),
}

/// Export a repository as a CARv1 file given its root CID.
///
/// The block store must contain all blocks for the repo (commit, MST nodes, records).
/// Returns the raw CAR bytes with `root_cid` as the CAR root.
///
/// For an empty repo (just a genesis commit), the CAR contains only the commit block.
/// For a repo with records, the CAR contains: the signed commit (root), MST nodes, and records.
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::export_repo_car;
///
/// let mut block_store = SqliteBlockStore::new(pool, did.clone());
/// let car_bytes = export_repo_car(&mut block_store, root_cid).await?;
/// // Return car_bytes as application/vnd.ipld.car
/// ```
pub async fn export_repo_car<S>(
    block_store: &mut S,
    root_cid: Cid,
) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let mut car_buf = Vec::new();

    // Scope the CarStore so we can return car_buf after it's dropped.
    {
        let mut car: CarStore<Cursor<&mut Vec<u8>>> =
            CarStore::create_with_roots(Cursor::new(&mut car_buf), [root_cid])
                .await
                .map_err(|e| CarExportError::BlockStore(format!("create CAR: {e}")))?;

        // Read the root block (signed commit) and write it to the CAR.
        let mut root_block = Vec::new();
        block_store
            .read_block_into(root_cid, &mut root_block)
            .await
            .map_err(|e| CarExportError::BlockStore(format!("read root block: {e}")))?;

        car.write_block(root_cid.codec(), SHA2_256, &root_block)
            .await
            .map_err(|e| CarExportError::BlockStore(format!("write root to CAR: {e}")))?;

        // For Phase 6, we only write the commit block.
        // Phase 7 will add MST walking to include all record blocks.
    }

    Ok(car_buf)
}
