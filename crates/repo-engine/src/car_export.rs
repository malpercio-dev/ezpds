// repo-engine: CAR file export + reachability for ATProto repositories.
//
// Exports a repository as a CARv1 file for com.atproto.sync.getRepo, and computes
// the set of blocks reachable from a root commit (used by CAR export and block GC).

use std::collections::HashSet;
use std::io::Cursor;

use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, CarStore, SHA2_256};
use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use futures::StreamExt;

/// Errors from CAR export / reachability operations.
#[derive(Debug, thiserror::Error)]
pub enum CarExportError {
    #[error("blockstore error: {0}")]
    BlockStore(String),
}

/// Collect every block reachable from a repo's root commit: the commit itself, all
/// MST node blocks, and every record block referenced by an MST entry.
///
/// This deliberately does NOT follow the commit's `prev` link — that is repo history,
/// not part of the current repo's block set. The result is the live block set for the
/// given root, used both to export a complete CAR and to identify garbage for GC.
pub async fn collect_reachable_cids<S>(store: &mut S, root: Cid) -> Result<Vec<Cid>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let mut repo = Repository::open(&mut *store, root)
        .await
        .map_err(|e| CarExportError::BlockStore(format!("open repo: {e}")))?;

    // The commit block + every MST node block.
    let mut reachable: HashSet<Cid> = repo
        .export()
        .await
        .map_err(|e| CarExportError::BlockStore(format!("export: {e}")))?
        .collect();

    // Every record block (the value CID of each MST entry).
    {
        let mut tree = repo.tree();
        let mut entries = Box::pin(tree.entries());
        while let Some(res) = entries.next().await {
            let (_key, value) =
                res.map_err(|e| CarExportError::BlockStore(format!("walk entries: {e}")))?;
            reachable.insert(value);
        }
    }

    Ok(reachable.into_iter().collect())
}

/// Export a repository as a CARv1 file given its root CID.
///
/// The CAR contains the signed commit (declared as the CAR root), all MST nodes, and
/// all record blocks — a complete repo that another implementation can re-import.
pub async fn export_repo_car<S>(store: &mut S, root_cid: Cid) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let reachable = collect_reachable_cids(&mut *store, root_cid).await?;
    build_car(store, root_cid, reachable).await
}

/// Export the blocks introduced by a single commit as a CARv1 file.
///
/// Computes the set difference `reachable(new_root) − reachable(prev_root)` — i.e. the
/// commit block, any MST nodes the write rewrote, and any newly created record blocks —
/// and packages them into a CAR whose declared root is the new commit. This is the
/// `blocks` payload the ATProto firehose attaches to a `#commit` frame, so downstream
/// consumers (a BGS/relay) can apply the diff without re-fetching the whole repo.
///
/// `prev_root` is `None` only for a repo's first commit (genesis), where every reachable
/// block is new. Both roots' block sets must still be present in `store` — call this
/// before any post-commit GC reclaims the superseded blocks.
pub async fn export_commit_blocks_car<S>(
    store: &mut S,
    prev_root: Option<Cid>,
    new_root: Cid,
) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let new_set: HashSet<Cid> = collect_reachable_cids(&mut *store, new_root)
        .await?
        .into_iter()
        .collect();

    let prev_set: HashSet<Cid> = match prev_root {
        Some(prev) => collect_reachable_cids(&mut *store, prev)
            .await?
            .into_iter()
            .collect(),
        None => HashSet::new(),
    };

    let diff: Vec<Cid> = new_set.difference(&prev_set).copied().collect();
    build_car(store, new_root, diff).await
}

/// Build a CARv1 file declaring `root` as its single root and containing exactly `cids`.
///
/// Shared by [`export_repo_car`] (full repo) and [`export_commit_blocks_car`] (commit diff);
/// every CID in `cids` must be readable from `store`.
async fn build_car<S>(store: &mut S, root: Cid, cids: Vec<Cid>) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let mut car_buf = Vec::new();
    {
        let mut car: CarStore<Cursor<&mut Vec<u8>>> =
            CarStore::create_with_roots(Cursor::new(&mut car_buf), [root])
                .await
                .map_err(|e| CarExportError::BlockStore(format!("create CAR: {e}")))?;

        for cid in cids {
            let mut block = Vec::new();
            store
                .read_block_into(cid, &mut block)
                .await
                .map_err(|e| CarExportError::BlockStore(format!("read block {cid}: {e}")))?;
            car.write_block(cid.codec(), SHA2_256, &block)
                .await
                .map_err(|e| CarExportError::BlockStore(format!("write block to CAR: {e}")))?;
        }
    }

    Ok(car_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::MemoryBlockStore;

    use crate::genesis::create_genesis_repo;
    use crate::test_support::test_signer;

    /// Build a repo with one record. Returns (store, new_root, record_cid).
    async fn repo_with_record() -> (MemoryBlockStore, Cid, Cid) {
        let mut store = MemoryBlockStore::new();
        let signer = test_signer();
        let root = create_genesis_repo(&mut store, "did:plc:cartest", &signer)
            .await
            .unwrap();
        let mut repo = Repository::open(&mut store, root).await.unwrap();
        let record = serde_json::json!({ "text": "hello" });
        let record_cid =
            crate::records::put_record(&mut repo, &signer, "app.bsky.feed.post/abc", &record)
                .await
                .unwrap();
        let new_root = repo.root();
        (store, new_root, record_cid)
    }

    #[tokio::test]
    async fn collect_reachable_includes_commit_mst_and_records() {
        let (mut store, root, record_cid) = repo_with_record().await;
        let reachable = collect_reachable_cids(&mut store, root).await.unwrap();
        assert!(reachable.contains(&root), "must include the commit (root)");
        assert!(
            reachable.contains(&record_cid),
            "must include the record block"
        );
        // commit + at least one MST node + the record.
        assert!(
            reachable.len() >= 3,
            "got {} reachable cids",
            reachable.len()
        );
    }

    #[tokio::test]
    async fn commit_blocks_car_contains_only_the_diff() {
        // genesis → commit A (record r1) → commit B (record r2). The diff CAR for the
        // B commit must include B's commit block and r2, but NOT r1 (carried over from A).
        let mut store = MemoryBlockStore::new();
        let signer = test_signer();
        let genesis = create_genesis_repo(&mut store, "did:plc:diff", &signer)
            .await
            .unwrap();

        let mut repo = Repository::open(&mut store, genesis).await.unwrap();
        let r1 = crate::records::put_record(
            &mut repo,
            &signer,
            "app.bsky.feed.post/r1",
            &serde_json::json!({ "text": "one" }),
        )
        .await
        .unwrap();
        let root_a = repo.root();

        let mut repo = Repository::open(&mut store, root_a).await.unwrap();
        let r2 = crate::records::put_record(
            &mut repo,
            &signer,
            "app.bsky.feed.post/r2",
            &serde_json::json!({ "text": "two" }),
        )
        .await
        .unwrap();
        let root_b = repo.root();

        let car = export_commit_blocks_car(&mut store, Some(root_a), root_b)
            .await
            .unwrap();

        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        assert_eq!(
            car_store.roots().collect::<Vec<_>>(),
            vec![root_b],
            "diff CAR root must be the new commit"
        );

        // New commit block and the newly added record are present...
        let mut buf = Vec::new();
        car_store
            .read_block_into(root_b, &mut buf)
            .await
            .expect("new commit block must be in the diff CAR");
        car_store
            .read_block_into(r2, &mut buf)
            .await
            .expect("newly added record block must be in the diff CAR");
        // ...but the record carried over from the previous commit is not.
        assert!(
            car_store.read_block_into(r1, &mut buf).await.is_err(),
            "unchanged record from the prior commit must be excluded from the diff"
        );
    }

    #[tokio::test]
    async fn commit_blocks_car_with_no_prev_is_full_repo() {
        // With prev_root = None (genesis emission), every reachable block is "new", so the
        // diff CAR equals the full export: commit + MST + record block.
        let (mut store, root, record_cid) = repo_with_record().await;
        let car = export_commit_blocks_car(&mut store, None, root)
            .await
            .unwrap();

        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        let mut buf = Vec::new();
        car_store
            .read_block_into(root, &mut buf)
            .await
            .expect("commit block must be in the CAR");
        car_store
            .read_block_into(record_cid, &mut buf)
            .await
            .expect("record block must be in the CAR");
    }

    #[tokio::test]
    async fn exported_car_round_trips_records() {
        let (mut store, root, record_cid) = repo_with_record().await;
        let car = export_repo_car(&mut store, root).await.unwrap();

        // Re-open the CAR and confirm the record block is present — proves the CAR is
        // complete (commit + MST + record), not just the commit block (the old stub).
        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        let mut commit_block = Vec::new();
        car_store
            .read_block_into(root, &mut commit_block)
            .await
            .expect("commit block must be in the CAR");
        let mut record_block = Vec::new();
        car_store
            .read_block_into(record_cid, &mut record_block)
            .await
            .expect("record block must be in the CAR");
        assert!(!record_block.is_empty());
    }
}
