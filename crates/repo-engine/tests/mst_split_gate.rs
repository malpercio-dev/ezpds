//! Gate for the vendored atrium-repo MST split patch (`vendor/atrium-repo-patch`).
//!
//! Upstream atrium-repo 0.1.8 `split_subtree` silently drops sibling entries when a
//! higher-layer insert splits a multi-level subtree and one side of the deepest split
//! is empty: the walk-back-up loop only re-attaches each parent level's orphaned
//! entries to a side that already exists, so a `None` side discards them. Every key
//! sorting on that side of the insertion point — records, whole collections — vanishes
//! from the tree with no error, while the commit chain stays perfectly consistent.
//! (Reported upstream as atrium-rs/atrium#343, unfixed as of 0.1.8.)
//!
//! These tests pin the two minimal orphan shapes plus a randomized model check, and
//! fail against an unpatched atrium-repo — so a future dependency bump that drops the
//! `[patch.crates-io]` entry without an upstream fix cannot merge quietly.

use atrium_repo::blockstore::MemoryBlockStore;
use atrium_repo::mst::Tree;
use futures::TryStreamExt;
use ipld_core::cid::Cid;
use std::collections::BTreeSet;

fn dummy_value() -> Cid {
    Cid::try_from("bafyreidofvwoqvd2cnzbun6dkzgfucxh57tur73dfx2oeeggmgtakpjepi").unwrap()
}

/// Insert `keys` one at a time, asserting after every insert that the full key
/// enumeration still matches the set inserted so far.
async fn insert_and_verify(keys: &[&str]) {
    let mut tree = Tree::create(MemoryBlockStore::new()).await.unwrap();
    let mut expected = BTreeSet::new();

    for key in keys {
        tree.add(key, dummy_value()).await.unwrap();
        expected.insert(key.to_string());

        let got: BTreeSet<String> = tree.keys().try_collect().await.unwrap();
        let missing: Vec<_> = expected.difference(&got).collect();
        assert!(
            missing.is_empty(),
            "MST lost keys after inserting {key}: missing {missing:?}"
        );
        assert_eq!(
            got, expected,
            "MST enumeration diverged after inserting {key}"
        );
    }
}

/// The key layers below (0/1/2, from the leading-zero-bitpair count of each key's
/// SHA-256 hash) were found by brute-forcing the numeric suffix; the letter prefix
/// fixes the lexicographic order the shapes need.
///
/// Right-orphan shape: inserting the layer-2 key `e74` (which sorts after every key
/// in the subtree it splits) makes the deepest split's right side empty, and
/// unpatched code then drops `f9` and `g0` — the parent-level entries right of the
/// split. This is the exact mechanism that destroyed the
/// `id.sifa.*`/`page.mooring.*`/`sh.tangled.*`/`site.standard.*` collections from a
/// production repo on 2026-08-27.
#[tokio::test]
async fn higher_layer_insert_keeps_right_siblings() {
    insert_and_verify(&[
        "com.example.rec/a0",  // layer 0
        "com.example.rec/b1",  // layer 1
        "com.example.rec/c2",  // layer 0
        "com.example.rec/d1",  // layer 0
        "com.example.rec/f9",  // layer 1
        "com.example.rec/g0",  // layer 0
        "com.example.rec/e74", // layer 2 — the splitting insert
    ])
    .await;
}

/// Mirror image: inserting the layer-2 key `b2` (which sorts before every key in the
/// subtree it splits) makes the deepest split's left side empty, and unpatched code
/// drops `a0` and `b1` — the parent-level entries left of the split.
#[tokio::test]
async fn higher_layer_insert_keeps_left_siblings() {
    insert_and_verify(&[
        "com.example.rec/a0", // layer 0
        "com.example.rec/b1", // layer 1
        "com.example.rec/c2", // layer 0
        "com.example.rec/d1", // layer 0
        "com.example.rec/b2", // layer 2 — the splitting insert
    ])
    .await;
}

/// Randomized add/delete sequences checked against a `BTreeSet` model after every
/// operation. Upstream reports ~24% of random 20-insert sequences lose data on 0.1.8,
/// so this fails fast unpatched; with the patch it doubles as a tripwire for any other
/// latent restructuring bug in add/delete/merge. Seeded xorshift, fully deterministic.
#[tokio::test]
async fn randomized_ops_match_model() {
    for seed in 0u64..40 {
        let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1);
        let mut next = move || {
            // xorshift64*: deterministic, no dependency, good enough dispersion here.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545f4914f6cdd1d)
        };

        let mut tree = Tree::create(MemoryBlockStore::new()).await.unwrap();
        let mut model: BTreeSet<String> = BTreeSet::new();

        for op in 0..30 {
            // Every fifth operation deletes a random present key, exercising the
            // delete/merge/prune paths between the splitting inserts.
            if op % 5 == 4 && !model.is_empty() {
                let victim = model
                    .iter()
                    .nth(next() as usize % model.len())
                    .cloned()
                    .unwrap();
                tree.delete(&victim).await.unwrap();
                model.remove(&victim);
            } else {
                let key = format!("stress.rec/k{:06x}", next() % 0x100_0000);
                if !model.insert(key.clone()) {
                    continue;
                }
                tree.add(&key, dummy_value()).await.unwrap();
            }

            let got: BTreeSet<String> = tree.keys().try_collect().await.unwrap();
            assert_eq!(
                got,
                model,
                "MST diverged from model (seed {seed}, op {op}): missing {:?}, extra {:?}",
                model.difference(&got).collect::<Vec<_>>(),
                got.difference(&model).collect::<Vec<_>>(),
            );
        }
    }
}
