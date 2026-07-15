// pattern: Functional Core

//! Integration tests exercising atrium-repo's Tree, MemoryBlockStore, and CarStore
//! against the official ATProto interop test fixtures.
//!
//! These tests verify that our adoption of atrium-repo produces byte-identical
//! MST structures and CAR exports matching the ATProto reference implementation.
//!
//! Fixtures are vendored under `tests/fixtures/interop/` — CC-0 from
//! bluesky-social/atproto-interop-tests, except commit-proof-fixtures.json,
//! which is MIT from the bluesky-social/atproto monorepo. See that directory's
//! README for per-file provenance.

use atrium_repo::blockstore::{
    AsyncBlockStoreRead, AsyncBlockStoreWrite, CarStore, MemoryBlockStore, DAG_CBOR, SHA2_256,
};
use atrium_repo::mst::Tree;
use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use futures::StreamExt;
use ipld_core::ipld::Ipld;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use repo_engine::{build_genesis_repo, generate_tid, CommitSigner};
use std::io::Cursor;

/// A test value CID used as the leaf value for MST entries.
///
/// This matches the `leafValue` from the commit-proof-fixtures.json.
const LEAF_VALUE: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

/// Parse a CID from a base32-multibase string (bafyrei...).
fn parse_cid(s: &str) -> Cid {
    s.parse().unwrap_or_else(|_| panic!("invalid CID: {s}"))
}

/// Parse a vendored `syntax/*.txt` interop file into its cases: one per line,
/// with blank lines and `#`-prefixed comments removed.
fn load_syntax_cases(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// One entry of `mst/commit-proof-fixtures.json` (bluesky-social/atproto, MIT).
#[derive(serde::Deserialize)]
struct CommitProofFixture {
    comment: String,
    keys: Vec<String>,
    #[serde(rename = "leafValue")]
    leaf_value: String,
    #[serde(rename = "rootBeforeCommit")]
    root_before: String,
    #[serde(rename = "rootAfterCommit")]
    root_after: String,
    adds: Vec<String>,
    dels: Vec<String>,
}

/// One entry of `data-model/data-model-fixtures.json` (CC0). The `json` source
/// object is intentionally ignored — we verify CID computation over the already-
/// canonical DAG-CBOR bytes, decoupled from any JSON→CBOR encoder.
#[derive(serde::Deserialize)]
struct DataModelFixture {
    cbor_base64: String,
    cid: String,
}

/// Build an MST from `keys` (all pointing at `leaf_cid`) and return its root CID.
async fn build_root(keys: &[String], leaf_cid: Cid) -> Cid {
    let mut bs = MemoryBlockStore::new();
    let mut tree = Tree::create(&mut bs).await.expect("create tree");
    for key in keys {
        tree.add(key, leaf_cid)
            .await
            .unwrap_or_else(|_| panic!("add key {key:?}"));
    }
    tree.root()
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
//
// Loaded from the real upstream mst/commit-proof-fixtures.json vendored under
// tests/fixtures/interop/ (see that dir's README), rather than hand-transcribed
// per-fixture — every entry (and any upstream additions) is exercised.

#[tokio::test]
async fn commit_proof_root_cids_match_interop_fixtures() {
    let raw = include_str!("fixtures/interop/commit-proof-fixtures.json");
    let fixtures: Vec<CommitProofFixture> =
        serde_json::from_str(raw).expect("parse commit-proof-fixtures.json");
    assert!(
        !fixtures.is_empty(),
        "commit-proof fixtures must not be empty"
    );

    for f in &fixtures {
        let leaf = parse_cid(&f.leaf_value);

        // Root *before* the commit: the MST built from the fixture's key set.
        let before = build_root(&f.keys, leaf).await;
        assert_eq!(
            before,
            parse_cid(&f.root_before),
            "[{}] rootBeforeCommit must match the interop fixture",
            f.comment,
        );

        // Root *after* the commit: an MST is canonical on its key set, so a tree
        // built from (keys ∪ adds) \ dels from scratch equals the post-commit root
        // without replaying the individual add/delete operations.
        let dels: std::collections::HashSet<&str> = f.dels.iter().map(String::as_str).collect();
        let mut after_keys: Vec<String> = f
            .keys
            .iter()
            .filter(|k| !dels.contains(k.as_str()))
            .cloned()
            .collect();
        after_keys.extend(f.adds.iter().cloned());
        let after = build_root(&after_keys, leaf).await;
        assert_eq!(
            after,
            parse_cid(&f.root_after),
            "[{}] rootAfterCommit must match the interop fixture",
            f.comment,
        );
    }
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

// ── CAR byte-compatibility (atproto interop: CARv1 wire format) ──────────────────
//
// The round-trip test above proves we can read what we write. These pin the *exact
// bytes* of our CARv1 output against an independently derived reference so we stay
// byte-compatible with go-car / js-car (the implementations every other ATProto peer
// uses). The reference encodes a one-block CAR whose single root/block is the
// dag-cbor empty map `{}` (0xa0):
//
//   header = uvarint(len) || dag-cbor({roots: [cid], version: 1})   (keys canonically
//            ordered: "roots" before "version")
//   frame  = uvarint(len(cid) + len(data)) || cid_bytes || data
//
// Reference: https://ipld.io/specs/transport/car/carv1/

/// CIDv1 / dag-cbor / sha2-256 CID of the dag-cbor block `0xa0` (`{}`).
const CAR_BLOCK: &[u8] = &[0xa0];
const CAR_BLOCK_CID: &str = "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua";

/// Canonical CARv1 header for `roots = [CAR_BLOCK_CID], version = 1`.
const REF_CAR_HEADER_HEX: &str = "3aa265726f6f747381d82a58250001711220c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a06776657273696f6e01";

/// Canonical CARv1 block frame for `CAR_BLOCK` under `CAR_BLOCK_CID`.
const REF_CAR_FRAME_HEX: &str =
    "2501711220c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0a0";

/// Decode a lowercase hex string into bytes. Local helper — no hex crate dependency.
fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Concatenate the canonical CARv1 reference header and block frame into a single buffer.
fn reference_car_bytes() -> Vec<u8> {
    let mut v = from_hex(REF_CAR_HEADER_HEX);
    v.extend_from_slice(&from_hex(REF_CAR_FRAME_HEX));
    v
}

#[test]
fn car_header_is_byte_compatible_with_reference() {
    let cid = parse_cid(CAR_BLOCK_CID);
    let header = repo_engine::car_v1_header(cid);
    assert_eq!(
        header,
        from_hex(REF_CAR_HEADER_HEX),
        "CARv1 header bytes must match the canonical reference encoding",
    );
}

#[test]
fn car_block_frame_is_byte_compatible_with_reference() {
    let cid = parse_cid(CAR_BLOCK_CID);
    let frame = repo_engine::car_v1_block_frame(cid, CAR_BLOCK);
    assert_eq!(
        frame,
        from_hex(REF_CAR_FRAME_HEX),
        "CARv1 block frame bytes must match the canonical reference encoding",
    );
}

#[tokio::test]
async fn single_block_car_is_byte_exact_against_reference() {
    let mut bs = MemoryBlockStore::new();
    let cid = bs
        .write_block(DAG_CBOR, SHA2_256, CAR_BLOCK)
        .await
        .expect("write block");
    assert_eq!(cid.to_string(), CAR_BLOCK_CID, "sanity: known block CID");

    let car = repo_engine::build_car_from_cids(&mut bs, cid, vec![cid])
        .await
        .expect("build car");

    assert_eq!(
        car,
        reference_car_bytes(),
        "full one-block CAR must be byte-identical to the reference (header || frame)",
    );
}

#[tokio::test]
async fn reference_car_bytes_parse_and_verify() {
    // Read direction: open the independently-derived reference CAR and confirm a real
    // CARv1 reader resolves its root, and that the carried block is content-addressed
    // (its bytes hash to the declared CID).
    let reference = reference_car_bytes();
    let expected_cid = parse_cid(CAR_BLOCK_CID);

    let mut car_store = CarStore::open(Cursor::new(&reference))
        .await
        .expect("reference CAR must parse");
    assert_eq!(
        car_store.roots().collect::<Vec<_>>(),
        vec![expected_cid],
        "reference CAR must declare the known block as its root",
    );

    let mut block = Vec::new();
    car_store
        .read_block_into(expected_cid, &mut block)
        .await
        .expect("root block must be readable from the reference CAR");
    assert_eq!(block, CAR_BLOCK, "carried block bytes must round-trip");

    // Content addressing: the block bytes must hash to the digest embedded in the CID.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(&block);
    assert_eq!(
        expected_cid.hash().digest(),
        digest.as_slice(),
        "carried block must hash to its declared CID",
    );
}

#[test]
#[should_panic(expected = "must match the canonical reference")]
fn corrupted_car_header_fixture_is_detected() {
    let cid = parse_cid(CAR_BLOCK_CID);
    let header = repo_engine::car_v1_header(cid);
    // Compare against the frame bytes (wrong) — the gate must catch the mismatch.
    assert_eq!(
        header,
        from_hex(REF_CAR_FRAME_HEX),
        "CARv1 header bytes must match the canonical reference",
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

// ── TID syntax (atproto interop: syntax/tid_syntax.json) ────────────────────────
//
// A TID is exactly 13 chars from the base32-sortable alphabet
// `234567abcdefghijklmnopqrstuvwxyz`, with the leading character restricted to the
// first 16 of that alphabet (`234567abcdefghij`) because a TID's high bit is always
// zero. Reference: https://atproto.com/specs/tid

const TID_ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Validate a TID string against the atproto syntax rules. Kept local to the test
/// so the production `generate_tid` stays a pure generator with no parsing surface.
fn tid_is_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 13 {
        return false;
    }
    if !bytes.iter().all(|c| TID_ALPHABET.contains(c)) {
        return false;
    }
    // Leading char must fall in the first 16 alphabet positions (high bit clear).
    TID_ALPHABET[..16].contains(&bytes[0])
}

#[test]
fn tid_syntax_matches_interop_fixture() {
    // Loaded from the real upstream syntax/tid_syntax_{valid,invalid}.txt files
    // vendored under tests/fixtures/interop/ (one case per line; blank lines and
    // `#` comments ignored), rather than hand-transcribed inline.
    let valid = load_syntax_cases(include_str!("fixtures/interop/tid_syntax_valid.txt"));
    let invalid = load_syntax_cases(include_str!("fixtures/interop/tid_syntax_invalid.txt"));
    assert!(
        !valid.is_empty() && !invalid.is_empty(),
        "TID syntax fixtures must not be empty",
    );

    for tid in &valid {
        assert!(
            tid_is_valid(tid),
            "tid_is_valid({tid:?}) should be true (interop fixture: valid)",
        );
    }
    for tid in &invalid {
        assert!(
            !tid_is_valid(tid),
            "tid_is_valid({tid:?}) should be false (interop fixture: invalid)",
        );
    }
}

#[test]
fn generated_tids_conform_to_syntax() {
    // Every TID the engine mints must satisfy the interop syntax rules.
    for _ in 0..1000 {
        let tid = generate_tid();
        assert!(
            tid_is_valid(&tid),
            "generate_tid produced a syntactically invalid TID: {tid:?}",
        );
    }
}

#[test]
fn generated_tids_advance_with_the_clock() {
    // The base32-sortable encoding preserves chronological order across distinct
    // timestamps. Within a single microsecond the low 10 bits are a *random* clock
    // identifier (collision resistance) and span the final two characters, so order
    // there is not defined — we compare only the leading 11-character timestamp
    // prefix to assert the clock-driven portion never regresses.
    let prefix = |t: &str| t[..11].to_string();
    let mut prev = generate_tid();
    for _ in 0..1000 {
        let next = generate_tid();
        assert!(
            prefix(&next) >= prefix(&prev),
            "TID timestamp prefix regressed: {next:?} precedes {prev:?}",
        );
        prev = next;
    }
}

#[test]
#[should_panic(expected = "should be true")]
fn corrupted_tid_fixture_is_detected() {
    // A clearly invalid TID asserted as valid must trip the gate.
    assert!(tid_is_valid("not-a-tid"), "tid should be true");
}

// ── Repo commit: structure + signing (atproto interop: repo commit object) ──────
//
// A genesis commit is a dag-cbor object {did, version: 3, data, rev, sig}. The
// signature is a P-256 ECDSA signature over the *unsigned* commit bytes (the same
// object without `sig`). Reference: https://atproto.com/specs/repository

/// A fixed, non-zero 32-byte P-256 scalar so the commit test is fully deterministic
/// (no OsRng). Valid because it is well below the curve order.
const FIXED_PRIV_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

#[tokio::test]
async fn genesis_commit_has_canonical_structure() {
    let signer = CommitSigner::from_bytes(&FIXED_PRIV_KEY).expect("valid key");
    let did = "did:plc:interopcommitstructure";

    let (root, _rev, blocks) = build_genesis_repo(did, &signer)
        .await
        .expect("build genesis");

    // Decode the root commit block and assert the canonical field set + values.
    let root_block = blocks
        .iter()
        .find(|(c, _)| *c == root)
        .map(|(_, b)| b.clone())
        .expect("blocks must contain the root commit");
    let decoded: Ipld =
        serde_ipld_dagcbor::from_slice(&root_block).expect("root block must be dag-cbor");

    let map = match decoded {
        Ipld::Map(m) => m,
        other => panic!("commit must be a dag-cbor map, got {other:?}"),
    };

    // Pin the *exact* canonical field set, not just presence, so a stray extra key
    // can't slip through. A genesis commit is {did, version, data, rev, prev, sig}
    // with `prev` present and null (first commit has no predecessor).
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["data", "did", "prev", "rev", "sig", "version"],
        "commit must contain exactly did, version, data, rev, prev, sig",
    );
    assert_eq!(
        map.get("prev"),
        Some(&Ipld::Null),
        "a genesis commit's prev must be null",
    );

    assert_eq!(
        map.get("version"),
        Some(&Ipld::Integer(3)),
        "commit version must be the fixed value 3",
    );
    assert_eq!(
        map.get("did"),
        Some(&Ipld::String(did.to_string())),
        "commit did must match the account DID",
    );
    assert!(
        matches!(map.get("data"), Some(Ipld::Link(_))),
        "commit data must be a CID link to the MST root",
    );
    assert!(
        matches!(map.get("rev"), Some(Ipld::String(_))),
        "commit rev must be a TID string",
    );
    assert!(
        matches!(map.get("sig"), Some(Ipld::Bytes(_))),
        "signed commit must carry a sig byte string",
    );
}

#[tokio::test]
async fn genesis_commit_signature_verifies() {
    let signer = CommitSigner::from_bytes(&FIXED_PRIV_KEY).expect("valid key");
    let verifying_key =
        VerifyingKey::from(&SigningKey::from_bytes(&FIXED_PRIV_KEY.into()).expect("valid key"));
    let did = "did:plc:interopcommitsigning";

    let (root, _rev, blocks) = build_genesis_repo(did, &signer)
        .await
        .expect("build genesis");

    // Re-import the captured blocks and re-open the repo to read the signed commit
    // back exactly as a remote consumer would.
    let mut store = MemoryBlockStore::new();
    for (_cid, bytes) in &blocks {
        store
            .write_block(DAG_CBOR, SHA2_256, bytes)
            .await
            .expect("re-import block");
    }
    let repo = Repository::open(store, root).await.expect("reopen repo");
    let commit = repo.commit();

    // The signature must be 64-byte r‖s and verify over the unsigned commit bytes.
    assert_eq!(commit.sig().len(), 64, "P-256 sig must be 64 bytes (r‖s)");
    let signature = Signature::from_slice(commit.sig()).expect("sig must parse as P-256 r‖s");
    assert!(
        signature.normalize_s().is_none(),
        "commit signature must be canonical low-S",
    );
    verifying_key
        .verify(&commit.bytes(), &signature)
        .expect("commit signature must verify over the unsigned commit bytes");

    // The committed `data` pointer is the MST root and is itself a CIDv1/dag-cbor CID.
    let data_cid = commit.data();
    assert_eq!(data_cid.codec(), DAG_CBOR, "MST root must be dag-cbor");

    // A tampered message must NOT verify — guards against an accidentally permissive check.
    let mut tampered = commit.bytes();
    tampered[0] ^= 0xff;
    assert!(
        verifying_key.verify(&tampered, &signature).is_err(),
        "a tampered commit must fail signature verification",
    );
}

// ── CID content addressing (atproto interop: CIDv1 / dag-cbor / sha2-256) ────────
//
// ATProto CIDs are CIDv1, dag-cbor codec (0x71), sha2-256 multihash (0x12). The
// reference strings below were derived independently of this codebase (raw dag-cbor
// bytes → sha2-256 → CIDv1 → base32) and pin the block store's CID computation to a
// byte-exact, reproducible answer. Reference: https://atproto.com/specs/data-model

/// SHA2-256 multihash code, per the multiformats table.
const SHA2_256_CODE: u64 = 0x12;

#[tokio::test]
async fn cid_computation_matches_interop_fixtures() {
    use base64::Engine;
    let raw = include_str!("fixtures/interop/data-model-fixtures.json");
    let fixtures: Vec<DataModelFixture> =
        serde_json::from_str(raw).expect("parse data-model-fixtures.json");
    assert!(
        !fixtures.is_empty(),
        "data-model fixtures must not be empty"
    );

    let mut bs = MemoryBlockStore::new();
    for f in &fixtures {
        let cbor = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&f.cbor_base64)
            .expect("decode cbor_base64");
        let cid = bs
            .write_block(DAG_CBOR, SHA2_256, &cbor)
            .await
            .expect("write block");

        assert_eq!(
            cid.to_string(),
            f.cid,
            "CID for the data-model fixture must match the reference",
        );
        // Structural invariants of every ATProto CID. (The full string match above
        // already pins the CIDv1 prefix; these assert the codec/hash explicitly.)
        assert_eq!(cid.codec(), DAG_CBOR, "codec must be dag-cbor (0x71)");
        assert_eq!(
            cid.hash().code(),
            SHA2_256_CODE,
            "multihash must be sha2-256 (0x12)",
        );
        assert_eq!(cid.hash().size(), 32, "sha2-256 digest is 32 bytes");

        // Parsing the expected string back must round-trip to the same CID.
        assert_eq!(cid, f.cid.parse::<Cid>().expect("parse reference CID"));
    }
}

#[tokio::test]
#[should_panic(expected = "must match the reference")]
async fn corrupted_cid_fixture_is_detected() {
    let mut bs = MemoryBlockStore::new();
    // dag-cbor `{}` (0xa0) paired with the wrong reference CID (the one for `1`).
    let raw: &[u8] = &[0xa0];
    let wrong = "bafyreicl6ujc6ncfktctxxroxognfn7d2fqavvrryoc2lv6m4i6hpbkfti";
    let cid = bs.write_block(DAG_CBOR, SHA2_256, raw).await.unwrap();
    assert_eq!(cid.to_string(), wrong, "CID must match the reference");
}
