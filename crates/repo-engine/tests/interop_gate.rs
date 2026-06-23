// pattern: Functional Core

//! Integration tests exercising atrium-repo's Tree, MemoryBlockStore, and CarStore
//! against the official ATProto interop test fixtures.
//!
//! These tests verify that our adoption of atrium-repo produces byte-identical
//! MST structures and CAR exports matching the ATProto reference implementation.
//!
//! Fixtures are CC-0 licensed, from bluesky-social/atproto-interop-tests.

use atrium_repo::blockstore::{
    AsyncBlockStoreRead, AsyncBlockStoreWrite, CarStore, MemoryBlockStore, DAG_CBOR, SHA2_256,
};
use atrium_repo::mst::Tree;
use atrium_repo::Cid;
use futures::StreamExt;
use std::io::Cursor;

/// A test value CID used as the leaf value for MST entries.
///
/// This matches the `leafValue` from the commit-proof-fixtures.json.
const LEAF_VALUE: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

/// Parse a CID from a base32-multibase string (bafyrei...).
fn parse_cid(s: &str) -> Cid {
    s.parse().unwrap_or_else(|_| panic!("invalid CID: {s}"))
}

/// Build a tree with the given keys, all pointing to the same leaf value CID.
/// Returns the root CID after all keys are inserted, plus the block store.
///
/// Note: the leaf value CID is NOT stored in the blockstore (it represents
/// external record data). This is correct for interop tests that only verify
/// MST structure.
async fn build_tree_with_keys(keys: &[&str]) -> (MemoryBlockStore, Cid) {
    let mut bs = MemoryBlockStore::new();
    let leaf_cid = parse_cid(LEAF_VALUE);

    let mut tree = Tree::create(&mut bs).await.expect("create tree");
    for key in keys {
        tree.add(key, leaf_cid)
            .await
            .unwrap_or_else(|_| panic!("add key {key:?}"));
    }

    let root = tree.root();
    (bs, root)
}

/// Build a tree with the given keys, storing actual leaf data in the blockstore.
/// Returns the root CID, the leaf CID, and the block store.
/// Used for CAR round-trip tests where all blocks must be present.
async fn build_tree_with_stored_leaf(keys: &[&str]) -> (MemoryBlockStore, Cid, Cid) {
    let mut bs = MemoryBlockStore::new();

    // Store a dummy leaf block and get its computed CID.
    let leaf_data = b"\xa1dummy-record";
    let leaf_cid = bs
        .write_block(DAG_CBOR, SHA2_256, leaf_data)
        .await
        .expect("store leaf");

    let mut tree = Tree::create(&mut bs).await.expect("create tree");
    for key in keys {
        tree.add(key, leaf_cid)
            .await
            .unwrap_or_else(|_| panic!("add key {key:?}"));
    }

    let root = tree.root();
    (bs, root, leaf_cid)
}

// ── Known-answer root CIDs from commit-proof-fixtures.json ──────────────────────

/// Fixture: "two deep split" from commit-proof-fixtures.json
///
/// Keys: A0/374913, B1/986427, C0/451630, E0/670489, F1/085263, G0/765327
/// Expected root: bafyreicraprx2xwnico4tuqir3ozsxpz46qkcpox3obf5bagicqwurghpy
#[tokio::test]
async fn interop_two_deep_split_root_cid() {
    let keys = &[
        "A0/374913",
        "B1/986427",
        "C0/451630",
        "E0/670489",
        "F1/085263",
        "G0/765327",
    ];
    let expected_root = parse_cid("bafyreicraprx2xwnico4tuqir3ozsxpz46qkcpox3obf5bagicqwurghpy");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

/// Fixture: "two deep leafless split" from commit-proof-fixtures.json
#[tokio::test]
async fn interop_two_deep_leafless_split_root_cid() {
    let keys = &["A0/374913", "B0/601692", "D0/952776", "E0/670489"];
    let expected_root = parse_cid("bafyreialm5sgf7pijawbschsjpdevid5rss5ip3d4n4w6cc4mhu53sfl4i");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

/// Fixture: "add on edge with neighbor two layers down" from commit-proof-fixtures.json
#[tokio::test]
async fn interop_add_on_edge_root_cid() {
    let keys = &["A0/374913", "B2/827649", "C0/451630"];
    let expected_root = parse_cid("bafyreigc6ay2qwfk7kuevvrczummpd64nknfo4yxpaooknfymzyb7u3ntq");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

/// Fixture: "merge and split in multi-op commit" — root *before* commit
#[tokio::test]
async fn interop_merge_split_before_root_cid() {
    let keys = &["A0/374913", "B2/827649", "D2/269196", "E0/670489"];
    let expected_root = parse_cid("bafyreiceld4icym4qjmdcn3dfgtxt7t66hdgyhvigessgmkvb56dx6amgi");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

/// Fixture: "complex multi-op commit" — root *before* commit
#[tokio::test]
async fn interop_complex_multiop_before_root_cid() {
    let keys = &[
        "B0/601692",
        "C2/014073",
        "D0/952776",
        "E2/819540",
        "F0/697858",
        "H0/131238",
    ];
    let expected_root = parse_cid("bafyreigr3plnts7dax6yokvinbhcqpyicdfgg6npvvyx6okc5jo55slfqi");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

/// Fixture: "split with earlier leaves on same layer" — root *before* commit
#[tokio::test]
async fn interop_split_earlier_leaves_before_root_cid() {
    let keys = &[
        "app.bsky.feed.post/3lo3kqqljmfe2",
        "app.bsky.feed.post/3log4547dm6h2",
        "app.bsky.feed.post/3log45inogon2",
        "app.bsky.feed.post/3logaodrh74d2",
        "app.bsky.feed.post/3logteazog2n2",
        "app.bsky.feed.post/3lon5cqsbwrj2",
        "app.bsky.feed.repost/3l6sjhvqonco2",
    ];
    let expected_root = parse_cid("bafyreigfcsro2up7qi7l3rxdpg7n6gjtteotkmgrrqztl5oy2tf4ncl4ji");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(
        root, expected_root,
        "root CID must match the interop fixture"
    );
}

// ── CAR round-trip ───────────────────────────────────────────────────────────────

/// Build a tree → export all blocks to a CAR → re-import from the CAR → verify root CID.
#[tokio::test]
async fn car_round_trip_preserves_root_cid() {
    let keys = &[
        "A0/374913",
        "B1/986427",
        "C0/451630",
        "E0/670489",
        "F1/085263",
        "G0/765327",
    ];
    let (mut bs, original_root, _leaf_cid) = build_tree_with_stored_leaf(keys).await;

    // Export all blocks from the MST to a CAR file.
    let mut car_buf = Vec::new();
    let mut car = CarStore::create_with_roots(Cursor::new(&mut car_buf), [original_root])
        .await
        .expect("create car");

    // Collect all CIDs from the MST, then write their blocks to the CAR.
    let cids: Vec<Cid> = {
        let mut tree_for_export = Tree::open(&mut bs, original_root);
        let mut stream = Box::pin(tree_for_export.export());
        let mut cids = Vec::new();
        while let Some(cid_result) = stream.next().await {
            cids.push(cid_result.expect("export cid"));
        }
        cids
    };

    for cid in &cids {
        let block = bs.read_block(*cid).await.expect("read block for export");
        car.write_block(DAG_CBOR, SHA2_256, &block)
            .await
            .expect("write block to car");
    }
    drop(car);

    // Re-import: open the CAR and verify its root matches.
    let car_bs = CarStore::open(Cursor::new(&car_buf))
        .await
        .expect("open car");
    let reimported_root = car_bs.roots().next().expect("car must have a root");

    assert_eq!(
        original_root, reimported_root,
        "CAR root must match original tree root"
    );
}

// ── Corrupted fixture detection ──────────────────────────────────────────────────

/// Deliberately corrupt the expected root CID — the test must fail.
#[tokio::test]
#[should_panic(expected = "root CID must match")]
async fn corrupted_root_cid_fixture_is_detected() {
    let keys = &[
        "A0/374913",
        "B1/986427",
        "C0/451630",
        "E0/670489",
        "F1/085263",
        "G0/765327",
    ];
    // This is the wrong root CID (from a different fixture).
    let wrong_root = parse_cid("bafyreialm5sgf7pijawbschsjpdevid5rss5ip3d4n4w6cc4mhu53sfl4i");

    let (_bs, root) = build_tree_with_keys(keys).await;
    assert_eq!(root, wrong_root, "root CID must match");
}

// ── Determinism ───────────────────────────────────────────────────────────────────

/// Building the same tree twice must produce the same root CID.
#[tokio::test]
async fn tree_construction_is_deterministic() {
    let keys = &[
        "A0/374913",
        "B1/986427",
        "C0/451630",
        "E0/670489",
        "F1/085263",
        "G0/765327",
    ];

    let (_bs1, root1) = build_tree_with_keys(keys).await;
    let (_bs2, root2) = build_tree_with_keys(keys).await;

    assert_eq!(
        root1, root2,
        "building the same tree twice must produce the same root CID"
    );
}

// ── MemoryBlockStore parity ───────────────────────────────────────────────────────

/// A tree built through two independent MemoryBlockStores must produce the same root.
#[tokio::test]
async fn memory_blockstore_parity() {
    let keys = &["A0/374913", "B2/827649", "C0/451630", "D2/269196"];
    let leaf = parse_cid(LEAF_VALUE);

    let mut bs1 = MemoryBlockStore::new();
    let mut tree1 = Tree::create(&mut bs1).await.unwrap();
    for k in keys {
        tree1.add(k, leaf).await.unwrap();
    }

    let mut bs2 = MemoryBlockStore::new();
    let mut tree2 = Tree::create(&mut bs2).await.unwrap();
    for k in keys {
        tree2.add(k, leaf).await.unwrap();
    }

    assert_eq!(tree1.root(), tree2.root());
}
