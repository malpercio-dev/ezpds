// pattern: Imperative Shell
//
// End-to-end coverage of the `com.atproto.space.*` sync surface (listRepoOps, getRepo,
// getBlob, listBlobs), driven through the real router so the lexicon layer, the space read
// seam, and the store are all in the path. Cross-route journeys live here because routes may
// not import one another (the `space_routes_test.rs` convention).
//
// Fixtures write through `space_record_write::apply_space_writes` directly — the same choke
// point the write routes call — because what is under test is the *read* side.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::app::AppState;
use crate::routes::test_utils::{
    access_jwt, body_json, seed_account_with_repo, state_with_master_key,
};
use crate::space_record_write::{apply_space_writes, SpaceWriteAction, SpaceWriteOp};

const DID: &str = "did:plc:spacesyncaaaaaaaaaaaaaaa";
const SPACE: &str = "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

async fn setup() -> (AppState, crypto::P256Keypair) {
    let state = state_with_master_key().await;
    let kp = seed_account_with_repo(&state.db, DID).await;
    (state, kp)
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/{uri}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn space_ref() -> crate::space_uri::SpaceRef {
    crate::space_uri::parse_space_ref(SPACE).unwrap()
}

/// One committed write of a single op; returns the commit's rev.
async fn write_one(state: &AppState, action: SpaceWriteAction, rkey: &str, text: &str) -> String {
    let value = (action != SpaceWriteAction::Delete).then(|| serde_json::json!({ "text": text }));
    apply_space_writes(
        state,
        &space_ref(),
        DID,
        &[SpaceWriteOp {
            action,
            collection: COLLECTION.to_string(),
            rkey: rkey.to_string(),
            value,
        }],
    )
    .await
    .unwrap()
    .rev
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

// ── listRepoOps ─────────────────────────────────────────────────────────────

/// A head response carries every op in commit order, the current signed commit, and no
/// cursor. Creates carry a null `prev`, updates the previous cid, and only a record's
/// *current* value is inlined — the superseded create's value is left off.
#[tokio::test]
async fn list_repo_ops_reports_ops_values_and_head_commit() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    write_one(&state, SpaceWriteAction::Create, "aaa", "one").await;
    let head_rev = write_one(&state, SpaceWriteAction::Put, "aaa", "two").await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 2);
    assert!(ops[0]["prev"].is_null(), "a create has no prev");
    assert!(!ops[0]["cid"].is_null());
    assert_eq!(
        ops[1]["prev"], ops[0]["cid"],
        "the update's prev is the create's cid"
    );
    assert!(
        ops[0].get("value").is_none(),
        "the superseded create's stale value is not inlined"
    );
    assert_eq!(
        ops[1]["value"]["text"], "two",
        "the current value is inlined on the op that wrote it"
    );

    assert_eq!(
        body["commit"]["rev"], head_rev,
        "a head response carries the current signed commit"
    );
    assert!(body["commit"]["hash"]["$bytes"].is_string());
    assert!(body.get("cursor").is_none(), "no cursor at the head");
}

/// `since` returns only ops strictly after that rev; a delete op carries a null cid and no
/// value; `excludeValues` strips values everywhere.
#[tokio::test]
async fn list_repo_ops_since_delete_and_exclude_values() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let rev1 = write_one(&state, SpaceWriteAction::Create, "aaa", "one").await;
    write_one(&state, SpaceWriteAction::Create, "bbb", "two").await;
    write_one(&state, SpaceWriteAction::Delete, "aaa", "").await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&since={rev1}"),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 2, "only ops after `since`");
    assert_eq!(ops[0]["rkey"], "bbb");
    let delete = &ops[1];
    assert_eq!(delete["rkey"], "aaa");
    assert!(delete["cid"].is_null(), "a delete's cid is null");
    assert!(!delete["prev"].is_null());
    assert!(delete.get("value").is_none());

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&excludeValues=true"),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert!(
        body["ops"]
            .as_array()
            .unwrap()
            .iter()
            .all(|op| op.get("value").is_none()),
        "excludeValues strips every value"
    );
}

/// A full page carries a cursor and no commit; the cursor resumes exactly where the page
/// ended, and the final (short) page carries the commit.
#[tokio::test]
async fn list_repo_ops_paginates_with_cursor() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    for rkey in ["aaa", "bbb", "ccc"] {
        write_one(&state, SpaceWriteAction::Create, rkey, rkey).await;
    }

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&limit=2"),
            &token,
        ))
        .await
        .unwrap();
    let first = body_json(response).await;
    assert_eq!(first["ops"].as_array().unwrap().len(), 2);
    assert!(
        first.get("commit").is_none(),
        "a full page does not sign a commit"
    );
    let cursor = first["cursor"].as_str().unwrap().to_string();

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!(
                "com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&limit=2&cursor={cursor}"
            ),
            &token,
        ))
        .await
        .unwrap();
    let second = body_json(response).await;
    let ops = second["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["rkey"], "ccc");
    assert!(
        second["commit"].is_object(),
        "the short page reaches the head"
    );
    assert!(second.get("cursor").is_none());
}

/// An account holding no repo in the space answers RepoNotFound — not an empty oplog, which
/// would read to a syncer as "this repo is empty".
#[tokio::test]
async fn list_repo_ops_unknown_repo_is_repo_not_found() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "RepoNotFound");
}

// ── getRepo ─────────────────────────────────────────────────────────────────

/// A parsed CARv1: declared roots plus the blocks in file order.
struct ParsedCar {
    roots: Vec<repo_engine::Cid>,
    blocks: Vec<(repo_engine::Cid, Vec<u8>)>,
}

/// Hand-parse a CARv1 byte stream. Deliberately not a CarStore: block *order* is part of the
/// format under test (blocks must follow the index's canonical order), and a store API
/// deduplicates that away.
fn parse_car(bytes: &[u8]) -> ParsedCar {
    fn read_uvarint(bytes: &[u8], at: &mut usize) -> u64 {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            let b = bytes[*at];
            *at += 1;
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return out;
            }
            shift += 7;
        }
    }

    #[derive(serde::Deserialize)]
    struct Header {
        #[allow(dead_code)]
        version: u64,
        roots: Vec<repo_engine::Cid>,
    }

    let mut at = 0usize;
    let header_len = read_uvarint(bytes, &mut at) as usize;
    let header: Header = serde_ipld_dagcbor::from_slice(&bytes[at..at + header_len]).unwrap();
    at += header_len;

    let mut blocks = Vec::new();
    while at < bytes.len() {
        let frame_len = read_uvarint(bytes, &mut at) as usize;
        let frame = &bytes[at..at + frame_len];
        at += frame_len;
        let mut cursor = std::io::Cursor::new(frame);
        let cid = repo_engine::Cid::read_bytes(&mut cursor).unwrap();
        let data = frame[cursor.position() as usize..].to_vec();
        blocks.push((cid, data));
    }
    ParsedCar {
        roots: header.roots,
        blocks,
    }
}

/// The decoded signed-commit root block.
#[derive(serde::Deserialize)]
struct CommitBlock {
    ver: u8,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ikm: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    mac: Vec<u8>,
    rev: String,
}

/// The full streaming-verification journey a syncer takes: two roots in order (commit,
/// index), commit verifies against the author's signing key, the index folds to an LtHash
/// digest equal to the commit's hash, and the record blocks follow in the index's canonical
/// order with bytes that hash to the CIDs the index promised.
#[tokio::test]
async fn get_repo_car_verifies_end_to_end() {
    let (state, kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    // rkeys chosen so canonical (length-first) order differs from plain lexicographic:
    // "zz" (shorter) must sort ahead of "aaa" (longer).
    write_one(&state, SpaceWriteAction::Create, "aaa", "long-key").await;
    let head_rev = write_one(&state, SpaceWriteAction::Create, "zz", "short-key").await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.ipld.car"
    );
    let car = parse_car(&body_bytes(response).await);

    // Two roots, in order; the file carries commit, index, then the record blocks.
    assert_eq!(car.roots.len(), 2);
    assert_eq!(car.blocks.len(), 4);
    assert_eq!(car.blocks[0].0, car.roots[0], "commit block first");
    assert_eq!(car.blocks[1].0, car.roots[1], "index block second");

    // The commit block verifies as a deniable commit by this author over this repo head.
    let commit: CommitBlock = serde_ipld_dagcbor::from_slice(&car.blocks[0].1).unwrap();
    assert_eq!(commit.rev, head_rev);
    let signed = crypto::SignedSpaceCommit {
        ver: commit.ver,
        hash: commit.hash.clone().try_into().unwrap(),
        ikm: commit.ikm.clone().try_into().unwrap(),
        sig: commit.sig.clone().try_into().unwrap(),
        mac: commit.mac.clone().try_into().unwrap(),
        rev: commit.rev.clone(),
    };
    crypto::verify_space_commit(
        &signed,
        &crypto::SpaceCommitCtx {
            space: SPACE,
            author: DID,
            rev: &head_rev,
        },
        &kp.key_id,
    )
    .expect("commit must verify against the account's signing key");

    // The index decodes as a path → CID-link map in canonical key order, and folding its
    // entries into an LtHash reproduces the commit's hash — the syncer's integrity check.
    let index: Vec<(String, ipld_core::ipld::Ipld)> = {
        let decoded: std::collections::BTreeMap<String, ipld_core::ipld::Ipld> =
            serde_ipld_dagcbor::from_slice(&car.blocks[1].1).unwrap();
        // BTreeMap loses wire order; recover it from the raw bytes by key position.
        let mut entries: Vec<_> = decoded.into_iter().collect();
        entries.sort_by_key(|(path, _)| {
            let mut needle = Vec::new();
            // Paths here are < 24 bytes, so the text header is a single byte.
            needle.push(0x60 + path.len() as u8);
            needle.extend_from_slice(path.as_bytes());
            car.blocks[1]
                .1
                .windows(needle.len())
                .position(|w| w == needle.as_slice())
                .unwrap()
        });
        entries
    };
    let paths: Vec<&str> = index.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            format!("{COLLECTION}/zz").as_str(),
            format!("{COLLECTION}/aaa").as_str()
        ],
        "index keys in canonical order: shorter path first"
    );

    let mut fold = crypto::LtHash::new();
    for (path, cid) in &index {
        let ipld_core::ipld::Ipld::Link(cid) = cid else {
            panic!("index value must be a CID link");
        };
        fold.add(&format!("{path}/{cid}"));
    }
    assert_eq!(
        fold.digest().as_slice(),
        commit.hash.as_slice(),
        "index entries must fold to the commit hash"
    );

    // Record blocks follow in index order, each hashing to the CID the index promised.
    for (i, (path, cid)) in index.iter().enumerate() {
        let ipld_core::ipld::Ipld::Link(cid) = cid else {
            unreachable!()
        };
        let (block_cid, block_bytes) = &car.blocks[2 + i];
        assert_eq!(
            block_cid, cid,
            "block order must match index order ({path})"
        );
        assert_eq!(
            &repo_engine::dag_cbor_block_cid(block_bytes).unwrap(),
            cid,
            "block bytes must hash to the index's CID"
        );
    }
}

/// `excludeValues` writes only the two roots; the index still folds to the commit hash, so a
/// syncer can diff against a local copy without the blocks.
#[tokio::test]
async fn get_repo_exclude_values_carries_only_roots() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    write_one(&state, SpaceWriteAction::Create, "aaa", "one").await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}&excludeValues=true"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let car = parse_car(&body_bytes(response).await);
    assert_eq!(car.roots.len(), 2);
    assert_eq!(car.blocks.len(), 2, "no record blocks under excludeValues");
}

/// An empty repo (never written) is RepoNotFound — there is no commit to sign.
#[tokio::test]
async fn get_repo_unknown_repo_is_repo_not_found() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "RepoNotFound");
}

// ── getBlob / listBlobs ─────────────────────────────────────────────────────

/// Store `content` as a blob owned by DID; returns its CID.
async fn add_blob(state: &AppState, content: &[u8]) -> String {
    let stored =
        crate::blob_store::store_blob(&state.config.data_dir, content, "application/octet-stream")
            .await
            .unwrap();
    crate::db::blobs::insert_blob(
        &state.db,
        &stored.cid,
        DID,
        &stored.mime_type,
        stored.size_bytes as i64,
        &stored.storage_path,
        "2030-01-01 00:00:00",
    )
    .await
    .unwrap();
    stored.cid
}

/// A record value carrying one blob reference (the shape `record_blob_cids` walks).
fn blob_record(cid: &str) -> serde_json::Value {
    serde_json::json!({
        "$type": "org.example.note",
        "text": "with attachment",
        "attachment": { "$type": "blob", "ref": { "$link": cid }, "mimeType": "image/png", "size": 10 }
    })
}

/// Write a record referencing `blob_cid`; returns the commit rev.
async fn write_blob_record(state: &AppState, rkey: &str, blob_cid: &str) -> String {
    apply_space_writes(
        state,
        &space_ref(),
        DID,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: COLLECTION.to_string(),
            rkey: rkey.to_string(),
            value: Some(blob_record(blob_cid)),
        }],
    )
    .await
    .unwrap()
    .rev
}

/// listBlobs enumerates exactly the referenced CIDs (ascending, deduplicated), `since`
/// restricts to records written after that rev, and a full page carries the last CID as its
/// cursor.
#[tokio::test]
async fn list_blobs_enumerates_referenced_cids() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let blob_a = add_blob(&state, b"space blob a").await;
    let blob_b = add_blob(&state, b"space blob b").await;
    // A stored-but-unreferenced blob must never appear.
    let unreferenced = add_blob(&state, b"unreferenced").await;

    let rev1 = write_blob_record(&state, "one", &blob_a).await;
    write_blob_record(&state, "two", &blob_b).await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listBlobs?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let mut expected = vec![blob_a.clone(), blob_b.clone()];
    expected.sort();
    let cids: Vec<String> = body["cids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(cids, expected, "referenced blobs only, ascending");
    assert!(!cids.contains(&unreferenced));
    assert!(body.get("cursor").is_none(), "a short page has no cursor");

    // `since` keeps only blobs referenced by records written after rev1.
    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listBlobs?space={SPACE}&repo={DID}&since={rev1}"),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert_eq!(
        body["cids"],
        serde_json::json!([blob_b]),
        "only the record written after `since` contributes"
    );

    // limit=1 → full page with cursor; the cursor continues to the remaining CID.
    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listBlobs?space={SPACE}&repo={DID}&limit=1"),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert_eq!(body["cids"].as_array().unwrap().len(), 1);
    assert_eq!(body["cids"][0], expected[0]);
    let cursor = body["cursor"].as_str().unwrap().to_string();
    assert_eq!(cursor, expected[0]);

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!(
                "com.atproto.space.listBlobs?space={SPACE}&repo={DID}&limit=1&cursor={cursor}"
            ),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert_eq!(body["cids"][0], expected[1]);
}

/// getBlob serves a referenced blob's bytes privately, and answers the same BlobNotFound for
/// a stored-but-unreferenced blob as for an unknown CID — existence is never disclosed.
#[tokio::test]
async fn get_blob_serves_referenced_and_hides_unreferenced() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let referenced = add_blob(&state, b"the referenced bytes").await;
    let unreferenced = add_blob(&state, b"the unreferenced bytes").await;
    write_blob_record(&state, "one", &referenced).await;

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getBlob?space={SPACE}&repo={DID}&cid={referenced}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"],
        "private",
        "a space blob is never publicly cacheable"
    );
    assert_eq!(body_bytes(response).await, b"the referenced bytes");

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getBlob?space={SPACE}&repo={DID}&cid={unreferenced}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "BlobNotFound");
}

/// The read seam applies to the sync surface exactly as to the record reads: an account
/// credential naming someone else's repo learns only RepoNotFound.
#[tokio::test]
async fn sync_reads_of_anothers_repo_are_repo_not_found() {
    let (state, _kp) = setup().await;
    write_one(&state, SpaceWriteAction::Create, "aaa", "one").await;

    let other = "did:plc:spacesyncother4aaaaaaa";
    seed_account_with_repo(&state.db, other).await;
    let token = access_jwt(&state.jwt_secret, other);

    for route in [
        format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}"),
        format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
        format!("com.atproto.space.listBlobs?space={SPACE}&repo={DID}"),
    ] {
        let response = crate::app::app(state.clone())
            .oneshot(get(&route, &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{route}");
        assert_eq!(
            body_json(response).await["error"],
            "RepoNotFound",
            "{route}"
        );
    }
}
