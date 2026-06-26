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

/// Export a single record together with its MST proof as a CARv1 file.
///
/// The CAR's declared root is the signed commit and always carries the commit block plus the MST
/// node path from the tree root down to the node that holds — or *would* hold — `key`. The proof
/// it encodes depends on whether the record exists:
///
/// * **Record present** → an *inclusion* proof: the node path plus the record block itself. A
///   consumer verifies the record is committed by walking `commit.data` → MST root → … → the
///   record CID, checking each block hashes to the CID that references it.
/// * **Record absent** → an *exclusion* proof: the covering MST nodes that prove no entry for
///   `key` exists, and no record block. A consumer verifies absence by walking the same path and
///   finding the key missing from the covering node.
///
/// This matches the reference PDS, whose `getRecord` lexicon returns the blocks needed to prove
/// "the existence or non-existence of a record". `key` is the MST key (`<collection>/<rkey>`).
/// The repo's blocks must be present in `store`; a genuinely missing block (corruption) surfaces
/// as an error, not as a (false) exclusion proof.
pub async fn export_record_proof_car<S>(
    store: &mut S,
    root_cid: Cid,
    key: &str,
) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    let mut repo = Repository::open(&mut *store, root_cid)
        .await
        .map_err(|e| CarExportError::BlockStore(format!("open repo: {e}")))?;

    let mut tree = repo.tree();

    // Proof path: every MST node CID from the tree root down to the node that holds the key
    // (present) or that would hold it (absent). For a present key `extract_path` also appends the
    // record block; for an absent key it yields only the covering nodes — an exclusion proof, not a
    // 404. Collect while `tree` is still borrowed — the returned iterator captures it.
    let mut blocks: HashSet<Cid> = tree
        .extract_path(key)
        .await
        .map_err(|e| CarExportError::BlockStore(format!("extract proof path: {e}")))?
        .collect();

    // Add the commit block (the declared CAR root). For a present key the record block is already
    // in `blocks` via `extract_path`'s append (the `HashSet` would dedup a duplicate anyway), so we
    // deliberately avoid a second `tree.get` walk just to re-insert it. That the record block is
    // always carried is pinned end to end by `record_proof_car_resolves_record_from_proof_blocks_only`.
    blocks.insert(root_cid);

    build_car(store, root_cid, blocks.into_iter().collect()).await
}

/// CARv1 header shape, serialized as DAG-CBOR. Mirrors the `{version, roots}` field order
/// of the header `CarStore` writes, so a hand-streamed CAR (see [`car_v1_header`]) is parsed
/// identically by `CarStore::open` and by any other CARv1 reader.
#[derive(serde::Serialize)]
struct CarV1Header {
    version: u64,
    roots: Vec<Cid>,
}

/// Append `n` as an unsigned LEB128 varint — the length prefix CARv1 puts before its header
/// and before every block frame.
fn write_uvarint(buf: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        buf.push((n as u8) | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
}

/// Encode the length-prefixed CARv1 header declaring `root` as the file's single root.
///
/// Emit this once, before any block frames, to stream a CAR without buffering the whole archive
/// in memory: a consumer reads the header, then each [`car_v1_block_frame`] as it arrives. The
/// bytes are identical to what [`build_car`] (via `CarStore`) would write for the same root.
pub fn car_v1_header(root: Cid) -> Vec<u8> {
    let header = CarV1Header {
        version: 1,
        roots: vec![root],
    };
    // The header is a tiny fixed-shape map; DAG-CBOR encoding cannot fail.
    let header_bytes = serde_ipld_dagcbor::to_vec(&header).expect("encode CAR header");

    let mut out = Vec::with_capacity(header_bytes.len() + 2);
    write_uvarint(&mut out, header_bytes.len() as u64);
    out.extend_from_slice(&header_bytes);
    out
}

/// Encode one length-prefixed CARv1 block frame: `uvarint(len(cid) + len(data)) || cid || data`.
///
/// `data` must be the exact bytes that hash to `cid` (the caller reads them straight from the
/// blockstore). Pairs with [`car_v1_header`] to stream a CAR block-by-block.
pub fn car_v1_block_frame(cid: Cid, data: &[u8]) -> Vec<u8> {
    let cid_bytes = cid.to_bytes();

    let mut frame = Vec::with_capacity(cid_bytes.len() + data.len() + 4);
    write_uvarint(&mut frame, (cid_bytes.len() + data.len()) as u64);
    frame.extend_from_slice(&cid_bytes);
    frame.extend_from_slice(data);
    frame
}

/// Build a CARv1 file declaring `root` as its single root and containing exactly `cids`.
///
/// Shared by [`export_repo_car`] (full repo) and [`export_commit_blocks_car`] (commit diff);
/// every CID in `cids` must be readable from `store`.
///
/// Blocks are written in a deterministic, root-first order: the CARv1 spec does not mandate
/// block ordering, but many streaming parsers and interop tools expect the declared root
/// block first, and the inputs here are `HashSet`-derived (otherwise non-reproducible). The
/// root sorts ahead of everything else; the remaining blocks follow in CID order.
async fn build_car<S>(
    store: &mut S,
    root: Cid,
    mut cids: Vec<Cid>,
) -> Result<Vec<u8>, CarExportError>
where
    S: AsyncBlockStoreRead,
{
    cids.sort_unstable_by_key(|c| (*c != root, *c));

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
    async fn commit_blocks_car_is_deterministic() {
        // HashSet iteration order is not stable across runs; the root-first sort in build_car
        // must make the CAR byte-identical every time (and the declared root the first block).
        let (mut store, root, _record_cid) = repo_with_record().await;

        let car_a = export_commit_blocks_car(&mut store, None, root)
            .await
            .unwrap();
        let car_b = export_commit_blocks_car(&mut store, None, root)
            .await
            .unwrap();
        assert_eq!(car_a, car_b, "CAR output must be deterministic across runs");
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
    async fn record_proof_car_contains_commit_and_record() {
        // The proof CAR's declared root is the commit, and it carries both the commit block
        // and the target record block (plus the MST nodes between them).
        let (mut store, root, record_cid) = repo_with_record().await;
        let car = export_record_proof_car(&mut store, root, "app.bsky.feed.post/abc")
            .await
            .unwrap();

        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        assert_eq!(
            car_store.roots().collect::<Vec<_>>(),
            vec![root],
            "proof CAR root must be the commit CID"
        );

        let mut buf = Vec::new();
        car_store
            .read_block_into(root, &mut buf)
            .await
            .expect("commit block must be in the proof CAR");
        car_store
            .read_block_into(record_cid, &mut buf)
            .await
            .expect("record block must be in the proof CAR");
    }

    #[tokio::test]
    async fn record_proof_car_missing_record_is_exclusion_proof() {
        // An absent record yields an exclusion-proof CAR (not None): root is the commit, the commit
        // block is present, and there is no record block for the non-existent key.
        let (mut store, root, record_cid) = repo_with_record().await;
        let car = export_record_proof_car(&mut store, root, "app.bsky.feed.post/nope")
            .await
            .unwrap();

        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        assert_eq!(
            car_store.roots().collect::<Vec<_>>(),
            vec![root],
            "exclusion-proof CAR root must be the commit CID"
        );

        let mut buf = Vec::new();
        car_store
            .read_block_into(root, &mut buf)
            .await
            .expect("commit block must be in the exclusion-proof CAR");

        // The only record in the repo lives at a different key; its block is not part of the
        // exclusion proof for `nope`, confirming the CAR carries covering MST nodes only.
        assert!(
            car_store
                .read_block_into(record_cid, &mut buf)
                .await
                .is_err(),
            "exclusion proof must not carry an unrelated record block"
        );
    }

    #[tokio::test]
    async fn record_proof_car_exclusion_resolves_absent_from_proof_blocks_only() {
        // End-to-end exclusion verification: re-open the proof CAR as the *only* blockstore and walk
        // commit → MST root → … → covering node, confirming the key resolves to absent. If
        // `extract_path` ever returned an incomplete covering path, a block read during the walk
        // would fail and this resolution would error — a structural presence check wouldn't catch it.
        let mut store = MemoryBlockStore::new();
        let signer = test_signer();
        let root = create_genesis_repo(&mut store, "did:plc:exclusionwalk", &signer)
            .await
            .unwrap();
        // Enough records to push the MST past a single node, so the covering path has interior nodes.
        let mut repo = Repository::open(&mut store, root).await.unwrap();
        for i in 0..64 {
            crate::records::put_record(
                &mut repo,
                &signer,
                &format!("app.bsky.feed.post/rec{i:03}"),
                &serde_json::json!({ "text": format!("post {i}") }),
            )
            .await
            .unwrap();
        }
        let root = repo.root();

        // A key that is absent but sorts among the present keys, so its covering node is interior.
        let absent_key = "app.bsky.feed.post/rec042missing";
        assert!(
            repo.tree().get(absent_key).await.unwrap().is_none(),
            "test key must genuinely be absent"
        );

        let proof = export_record_proof_car(&mut store, root, absent_key)
            .await
            .unwrap();

        // Resolve the key using nothing but the blocks carried in the proof CAR.
        let car_store = CarStore::open(Cursor::new(&proof)).await.unwrap();
        let mut proof_repo = Repository::open(car_store, root)
            .await
            .expect("commit block must be readable from the exclusion-proof CAR");
        let resolved = proof_repo
            .tree()
            .get(absent_key)
            .await
            .expect("MST walk must succeed using only the proof blocks");
        assert_eq!(
            resolved, None,
            "exclusion proof must resolve the absent key to None by walking commit → MST → covering node"
        );
    }

    #[tokio::test]
    async fn record_proof_car_excludes_sibling_records() {
        // The proof is a path, not the whole tree: it carries the target record block but NOT
        // sibling record blocks, even though both exist in the full repo export.
        let mut store = MemoryBlockStore::new();
        let signer = test_signer();
        let root = create_genesis_repo(&mut store, "did:plc:proofsubset", &signer)
            .await
            .unwrap();
        let mut repo = Repository::open(&mut store, root).await.unwrap();
        let mut record_cids = Vec::new();
        for i in 0..8 {
            let cid = crate::records::put_record(
                &mut repo,
                &signer,
                &format!("app.bsky.feed.post/rec{i}"),
                &serde_json::json!({ "text": format!("post {i}") }),
            )
            .await
            .unwrap();
            record_cids.push(cid);
        }
        let root = repo.root();

        let proof = export_record_proof_car(&mut store, root, "app.bsky.feed.post/rec3")
            .await
            .unwrap();

        // The full export holds every record block, including the sibling rec0.
        let full = export_repo_car(&mut store, root).await.unwrap();
        let mut full_store = CarStore::open(Cursor::new(&full)).await.unwrap();
        let mut buf = Vec::new();
        full_store
            .read_block_into(record_cids[0], &mut buf)
            .await
            .expect("sibling record block must be in the full export");

        // The proof holds the target record block but not the sibling's.
        let mut proof_store = CarStore::open(Cursor::new(&proof)).await.unwrap();
        proof_store
            .read_block_into(record_cids[3], &mut buf)
            .await
            .expect("target record block must be in the proof CAR");
        assert!(
            proof_store
                .read_block_into(record_cids[0], &mut buf)
                .await
                .is_err(),
            "a sibling record block must NOT be in a single-record proof"
        );
    }

    #[tokio::test]
    async fn record_proof_car_resolves_record_from_proof_blocks_only() {
        // End-to-end proof verification: re-open the proof CAR as the *only* blockstore and walk
        // commit → MST root → … → record. If `extract_path` ever returned an incomplete path
        // (e.g. skipping an intermediate MST node), a block read during the tree walk would fail
        // and this resolution would error — structural presence checks alone wouldn't catch that.
        let mut store = MemoryBlockStore::new();
        let signer = test_signer();
        let root = create_genesis_repo(&mut store, "did:plc:proofwalk", &signer)
            .await
            .unwrap();
        // Enough records to push the MST past a single node, so the proof has intermediate nodes.
        let mut repo = Repository::open(&mut store, root).await.unwrap();
        for i in 0..64 {
            crate::records::put_record(
                &mut repo,
                &signer,
                &format!("app.bsky.feed.post/rec{i:03}"),
                &serde_json::json!({ "text": format!("post {i}") }),
            )
            .await
            .unwrap();
        }
        let root = repo.root();

        let key = "app.bsky.feed.post/rec042";
        let expected = repo.tree().get(key).await.unwrap().expect("record present");

        let proof = export_record_proof_car(&mut store, root, key)
            .await
            .unwrap();

        // Resolve the record using nothing but the blocks carried in the proof CAR.
        let car_store = CarStore::open(Cursor::new(&proof)).await.unwrap();
        let mut proof_repo = Repository::open(car_store, root)
            .await
            .expect("commit block must be readable from the proof CAR");
        let resolved = proof_repo
            .tree()
            .get(key)
            .await
            .expect("MST walk must succeed using only the proof blocks");
        assert_eq!(
            resolved,
            Some(expected),
            "proof must resolve the record CID by walking commit → MST → record"
        );
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

    #[tokio::test]
    async fn streamed_car_frames_parse_as_a_valid_car() {
        // A CAR assembled by hand from car_v1_header + car_v1_block_frame (the streaming path)
        // must be byte-compatible with a real CARv1 reader: re-open it with atrium's CarStore and
        // confirm the declared root and every block resolve. This pins the framing wire format.
        let (mut store, root, record_cid) = repo_with_record().await;
        let reachable = collect_reachable_cids(&mut store, root).await.unwrap();

        let mut car = car_v1_header(root);
        for cid in &reachable {
            let mut block = Vec::new();
            store.read_block_into(*cid, &mut block).await.unwrap();
            car.extend_from_slice(&car_v1_block_frame(*cid, &block));
        }

        let mut car_store = CarStore::open(Cursor::new(&car)).await.unwrap();
        assert_eq!(
            car_store.roots().collect::<Vec<_>>(),
            vec![root],
            "streamed CAR must declare the commit as its root"
        );
        let mut buf = Vec::new();
        car_store
            .read_block_into(root, &mut buf)
            .await
            .expect("commit block must be readable from the streamed CAR");
        car_store
            .read_block_into(record_cid, &mut buf)
            .await
            .expect("record block must be readable from the streamed CAR");
    }

    #[tokio::test]
    async fn streamed_car_header_matches_carstore_header() {
        // The hand-rolled header must be byte-identical to the one CarStore writes, so both export
        // paths (buffered build_car and the streaming framing) emit the same bytes for a given root.
        let (mut store, root, _record_cid) = repo_with_record().await;

        // build_car with only the root yields: [uvarint len][header][root block frame]. Slice off
        // the header portion and compare against car_v1_header.
        let buffered = build_car(&mut store, root, vec![root]).await.unwrap();
        let streamed_header = car_v1_header(root);

        assert_eq!(
            &buffered[..streamed_header.len()],
            streamed_header.as_slice(),
            "streamed header bytes must match CarStore's header bytes"
        );
    }
}
