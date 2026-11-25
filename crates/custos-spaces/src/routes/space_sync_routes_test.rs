// pattern: Imperative Shell
//
// End-to-end coverage of the `com.atproto.space.*` sync surface (listRepoOps, getRepo,
// getBlob, listBlobs), driven through the real router so the lexicon layer, the space read
// seam, and the store are all in the path. Cross-route journeys live here because routes may
// not import one another (the `space_routes_test.rs` convention).
//
// Fixtures write through `space_record_write::apply_space_writes` directly — the same choke
// point the write routes call — because what is under test is the *read* side.

use axum::http::StatusCode;
use custos_core::CoreState;
use tower::ServiceExt;

use crate::space_record_write::{apply_space_writes, SpaceWriteAction, SpaceWriteOp};
use crate::test_support::xrpc_get as get;
use crate::test_support::{access_jwt, body_json, seed_account_with_repo, state_with_master_key};

const DID: &str = "did:plc:spacesyncaaaaaaaaaaaaaaa";
const SPACE: &str = "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

async fn setup() -> (CoreState, crypto::P256Keypair) {
    let state = state_with_master_key().await;
    let kp = seed_account_with_repo(&state.db, DID).await;
    (state, kp)
}

fn space_ref() -> custos_core::space_uri::SpaceRef {
    custos_core::space_uri::parse_space_ref(SPACE).unwrap()
}

/// One committed write of a single op; returns the commit's rev.
async fn write_one(state: &CoreState, action: SpaceWriteAction, rkey: &str, text: &str) -> String {
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

/// A head response carries every op in commit order, the current commit, and no
/// cursor. Creates carry a null `prev`, updates the previous cid, and only a record's
/// *current* value is inlined — the superseded create's value is left off.
#[tokio::test]
async fn list_repo_ops_reports_ops_values_and_head_commit() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    write_one(&state, SpaceWriteAction::Create, "aaa", "one").await;
    let head_rev = write_one(&state, SpaceWriteAction::Put, "aaa", "two").await;

    let response = crate::test_support::test_app(state.clone())
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
        "a head response carries the current commit"
    );
    assert_eq!(body["commit"]["repo"], DID);
    assert_eq!(body["commit"]["space"], SPACE);
    assert!(body["commit"]["data"]["$bytes"].is_string());
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

    let response = crate::test_support::test_app(state.clone())
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

    let response = crate::test_support::test_app(state.clone())
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

/// Every page carries the commit, and a full page a cursor too; the cursor resumes exactly
/// where the page ended, and the final (short) page has none.
#[tokio::test]
async fn list_repo_ops_paginates_with_cursor() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let mut revs = Vec::new();
    for rkey in ["aaa", "bbb", "ccc"] {
        revs.push(write_one(&state, SpaceWriteAction::Create, rkey, rkey).await);
    }

    let response = crate::test_support::test_app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&limit=2"),
            &token,
        ))
        .await
        .unwrap();
    let first = body_json(response).await;
    assert_eq!(first["ops"].as_array().unwrap().len(), 2);
    assert_eq!(
        first["commit"]["rev"], revs[2],
        "a full page carries the current commit too"
    );
    let cursor = first["cursor"].as_str().unwrap().to_string();

    let response = crate::test_support::test_app(state.clone())
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

    // `cursor` and `since` filter together, as in the reference: a `since` at the head
    // empties a cursor-driven page...
    let head_rev = &revs[2];
    let response = crate::test_support::test_app(state.clone())
        .oneshot(get(
            &format!(
                "com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&limit=2&cursor={cursor}&since={head_rev}"
            ),
            &token,
        ))
        .await
        .unwrap();
    let with_since = body_json(response).await;
    assert_eq!(
        with_since["ops"].as_array().unwrap().len(),
        0,
        "`since` at the head excludes every op past the cursor: {with_since}"
    );

    // ...and a `since` past the cursor's position skips the ops between them.
    let response = crate::test_support::test_app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&limit=1"),
            &token,
        ))
        .await
        .unwrap();
    let early_cursor = body_json(response).await["cursor"]
        .as_str()
        .unwrap()
        .to_string();
    let since = &revs[1];
    let response = crate::test_support::test_app(state.clone())
        .oneshot(get(
            &format!(
                "com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&cursor={early_cursor}&since={since}"
            ),
            &token,
        ))
        .await
        .unwrap();
    let both = body_json(response).await;
    let rkeys: Vec<_> = both["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op["rkey"].as_str().unwrap())
        .collect();
    assert_eq!(rkeys, ["ccc"], "both filters apply: {both}");
}

/// A cursor that does not parse as `rev/idx` answers `InvalidCursor`, as the lexicon declares.
#[tokio::test]
async fn list_repo_ops_malformed_cursor_is_invalid_cursor() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    write_one(&state, SpaceWriteAction::Create, "aaa", "aaa").await;

    for cursor in ["norev", "rev/notanumber"] {
        let response = crate::test_support::test_app(state.clone())
            .oneshot(get(
                &format!("com.atproto.space.listRepoOps?space={SPACE}&repo={DID}&cursor={cursor}"),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{cursor}");
        let body = body_json(response).await;
        assert_eq!(body["error"], "InvalidCursor", "{cursor}: {body}");
    }
}

/// An account holding no repo in the space answers RepoNotFound — not an empty oplog, which
/// would read to a syncer as "this repo is empty".
#[tokio::test]
async fn list_repo_ops_unknown_repo_is_repo_not_found() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::test_support::test_app(state.clone())
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

/// The full streaming-verification journey a syncer takes: an `atproto-space-repo` STAR whose
/// metadata is this repo's commit, records in strict bytewise path order, each value hashing to
/// a CID that, folded with its path into an LtHash, reproduces the commit's `data`. (The MAC
/// over the commit is `space_mac_test`'s.)
#[tokio::test]
async fn get_repo_star_verifies_end_to_end() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    // Written out of order, and with "zz" longer-key-last: bytewise order is "aaa" then "zz".
    write_one(&state, SpaceWriteAction::Create, "zz", "short-key").await;
    let head_rev = write_one(&state, SpaceWriteAction::Create, "aaa", "long-key").await;

    let response = crate::test_support::test_app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.dasl.star"
    );
    assert_eq!(
        response.headers()["cache-control"],
        "private",
        "a permissioned repo export is never publicly cacheable"
    );
    let bytes = body_bytes(response).await;

    // The profile reader checks the `$type`, the frame limits and the key order.
    let star =
        repo_engine::SpaceStarReader::new(repo_engine::StarProfile::SpaceRepo, &bytes[..]).unwrap();
    let meta = star.meta().clone();
    use ipld_core::ipld::Ipld;
    assert_eq!(meta["ver"], Ipld::Integer(1));
    assert_eq!(meta["repo"], Ipld::String(DID.to_string()));
    assert_eq!(meta["space"], Ipld::String(SPACE.to_string()));
    assert_eq!(meta["rev"], Ipld::String(head_rev));
    let Ipld::Bytes(data) = &meta["data"] else {
        panic!("commit data must be bytes");
    };

    let pairs: Vec<_> = star.collect::<Result<_, _>>().unwrap();
    let paths: Vec<String> = pairs
        .iter()
        .map(|p| String::from_utf8(p.key.clone()).unwrap())
        .collect();
    assert_eq!(
        paths,
        vec![format!("{COLLECTION}/aaa"), format!("{COLLECTION}/zz")]
    );
    let mut fold = crypto::LtHash::new();
    for (path, pair) in paths.iter().zip(&pairs) {
        let cid = repo_engine::dag_cbor_block_cid(&pair.value).unwrap();
        fold.add(&format!("{path}/{cid}"));
    }
    assert_eq!(
        fold.digest().as_slice(),
        data.as_slice(),
        "records must fold to the commit's data"
    );
}

/// An empty repo (never written) is RepoNotFound — there is no commit.
#[tokio::test]
async fn get_repo_unknown_repo_is_repo_not_found() {
    let (state, _kp) = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::test_support::test_app(state.clone())
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
async fn add_blob(state: &CoreState, content: &[u8]) -> String {
    let stored = custos_core::blob_store::store_blob(
        &state.config.data_dir,
        content,
        "application/octet-stream",
    )
    .await
    .unwrap();
    custos_db::blobs::insert_blob(
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
async fn write_blob_record(state: &CoreState, rkey: &str, blob_cid: &str) -> String {
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

    let response = crate::test_support::test_app(state.clone())
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
    let response = crate::test_support::test_app(state.clone())
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
    let response = crate::test_support::test_app(state.clone())
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

    let response = crate::test_support::test_app(state.clone())
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

    let response = crate::test_support::test_app(state.clone())
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

    let response = crate::test_support::test_app(state.clone())
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
        let response = crate::test_support::test_app(state.clone())
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
