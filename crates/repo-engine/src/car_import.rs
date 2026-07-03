// repo-engine: CAR import for account migration.
//
// Ingests a full repository CAR (as exported by `com.atproto.sync.getRepo`) into an
// in-memory block set, validating the CAR's block hashes and MST integrity. The imported
// commit is preserved verbatim — its signature, root CID, and revision are unchanged — so an
// export → import round-trip is an exact identity. Re-signing the commit under the destination
// account's own key is the identity-signing leg of migration and intentionally out of scope
// here (these functions are the path-agnostic data-transfer core).
//
// Functional Core — no HTTP, no DB, no process state.

use std::io::Cursor;

use atrium_repo::blockstore::CarStore;
use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use ipld_core::ipld::Ipld;

use crate::genesis::CapturingBlockStore;

/// Fixed repo-format version every ATProto commit carries.
const REPO_VERSION: i64 = 3;

/// Errors from importing a repository CAR.
#[derive(Debug, thiserror::Error)]
pub enum CarImportError {
    #[error("failed to read CAR file: {0}")]
    Car(String),
    #[error("CAR must declare exactly one root commit, found {0}")]
    RootCount(usize),
    #[error("failed to load repo from CAR: {0}")]
    Repo(String),
    #[error("commit block is malformed: {0}")]
    MalformedCommit(String),
    #[error("commit is bound to DID {found}, expected {expected}")]
    DidMismatch { expected: String, found: String },
}

/// A repository parsed from an imported CAR, ready to persist under an account.
#[derive(Debug)]
pub struct ImportedRepo {
    /// The repo's root commit CID (unchanged from the source).
    pub root: Cid,
    /// The commit revision (TID) as a string.
    pub rev: String,
    /// The account DID the commit is bound to (verified against the caller).
    pub did: String,
    /// Every block reachable from the root — the commit, MST nodes, and record blocks — as
    /// `(CID, bytes)`. Blob content is NOT included: blobs are transferred separately and
    /// discovered via `listMissingBlobs`.
    pub blocks: Vec<(Cid, Vec<u8>)>,
}

/// Parse and validate a repository CAR for import into `expected_did`'s account.
///
/// Validation performed:
/// * the CAR is well-formed and every block's bytes hash to its CID (enforced by `CarStore`);
/// * the CAR declares exactly one root;
/// * the root block decodes as a commit (version 3) whose `did` matches `expected_did`;
/// * the full MST is walkable from the root — a dangling or missing block fails the import
///   rather than persisting a structurally broken repo.
///
/// Returns the reachable block set (commit + MST + records) plus the root, rev, and DID. The
/// commit is preserved exactly as signed by the source PDS; this function does not re-sign.
pub async fn import_repo_car(
    car_bytes: &[u8],
    expected_did: &str,
) -> Result<ImportedRepo, CarImportError> {
    let car = CarStore::open(Cursor::new(car_bytes))
        .await
        .map_err(|e| CarImportError::Car(e.to_string()))?;

    let roots: Vec<Cid> = car.roots().collect();
    if roots.len() != 1 {
        return Err(CarImportError::RootCount(roots.len()));
    }
    let root = roots[0];

    // Open the repo over the CAR (reads + decodes the root commit), then walk the full reachable
    // set into a capturing store. `export_into` traverses the MST, so a missing block errors here
    // — the import is all-or-nothing.
    let mut repo = Repository::open(car, root)
        .await
        .map_err(|e| CarImportError::Repo(e.to_string()))?;
    let capture = CapturingBlockStore::new();
    repo.export_into(capture.clone())
        .await
        .map_err(|e| CarImportError::Repo(e.to_string()))?;
    let blocks = capture.blocks();

    // Decode the root commit block to read and verify its DID and version.
    let root_bytes = blocks
        .iter()
        .find(|(c, _)| *c == root)
        .map(|(_, b)| b.as_slice())
        .ok_or_else(|| CarImportError::MalformedCommit("root commit block absent".to_string()))?;
    let found_did = commit_did(root_bytes)?;
    if found_did != expected_did {
        return Err(CarImportError::DidMismatch {
            expected: expected_did.to_string(),
            found: found_did,
        });
    }

    let rev = repo.commit().rev().as_str().to_string();

    Ok(ImportedRepo {
        root,
        rev,
        did: found_did,
        blocks,
    })
}

/// Decode a commit block and return its `did`, checking the repo-format `version`.
fn commit_did(bytes: &[u8]) -> Result<String, CarImportError> {
    let ipld: Ipld = serde_ipld_dagcbor::from_slice(bytes)
        .map_err(|e| CarImportError::MalformedCommit(e.to_string()))?;
    let Ipld::Map(map) = ipld else {
        return Err(CarImportError::MalformedCommit(
            "commit is not a map".to_string(),
        ));
    };
    match map.get("version") {
        Some(Ipld::Integer(v)) if *v == i128::from(REPO_VERSION) => {}
        _ => {
            return Err(CarImportError::MalformedCommit(
                "commit has an unsupported or missing version".to_string(),
            ))
        }
    }
    match map.get("did") {
        Some(Ipld::String(did)) => Ok(did.clone()),
        _ => Err(CarImportError::MalformedCommit(
            "commit is missing a did field".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::MemoryBlockStore;

    use crate::car_export::export_repo_car;
    use crate::records::put_record_json;
    use crate::test_support::test_signer;

    /// Build a genesis repo with a couple of records in a `MemoryBlockStore`, returning the
    /// store, the DID, and the root CID — the source side of a round-trip.
    async fn seed_repo(did: &str) -> (MemoryBlockStore, Cid) {
        let bs = MemoryBlockStore::new();
        let signer = test_signer();
        let did_typed = atrium_api::types::string::Did::new(did.to_string()).unwrap();
        let builder = Repository::create(bs, did_typed).await.unwrap();
        let sig = signer.sign(&builder.bytes());
        let mut repo = builder.finalize(sig).await.unwrap();

        put_record_json(
            &mut repo,
            &signer,
            "app.bsky.feed.post/a",
            &serde_json::json!({ "text": "hello" }),
        )
        .await
        .unwrap();
        put_record_json(
            &mut repo,
            &signer,
            "app.bsky.feed.post/b",
            &serde_json::json!({ "text": "world" }),
        )
        .await
        .unwrap();

        let root = repo.root();
        // Recover the underlying store to export from it.
        let mut store = MemoryBlockStore::new();
        repo.export_into(&mut store).await.unwrap();
        (store, root)
    }

    #[tokio::test]
    async fn import_round_trips_root_and_records() {
        let did = "did:plc:importtest";
        let (mut store, root) = seed_repo(did).await;
        let car = export_repo_car(&mut store, root).await.unwrap();

        let imported = import_repo_car(&car, did).await.unwrap();
        assert_eq!(imported.root, root, "root CID must be preserved verbatim");
        assert_eq!(imported.did, did);
        assert!(!imported.rev.is_empty());
        assert!(
            imported.blocks.iter().any(|(c, _)| *c == root),
            "imported blocks must include the root commit"
        );

        // Re-open from the imported block set and confirm the records survived.
        let mut dest = MemoryBlockStore::new();
        for (cid, bytes) in &imported.blocks {
            use atrium_repo::blockstore::{AsyncBlockStoreWrite, DAG_CBOR, SHA2_256};
            let written = dest.write_block(DAG_CBOR, SHA2_256, bytes).await.unwrap();
            assert_eq!(written, *cid, "block must hash to its stated CID");
        }
        let mut repo = Repository::open(dest, imported.root).await.unwrap();
        let post: Option<serde_json::Value> =
            crate::records::get_record_json(&mut repo, "app.bsky.feed.post/a")
                .await
                .unwrap();
        assert_eq!(post, Some(serde_json::json!({ "text": "hello" })));
    }

    #[tokio::test]
    async fn import_rejects_did_mismatch() {
        let (mut store, root) = seed_repo("did:plc:realowner").await;
        let car = export_repo_car(&mut store, root).await.unwrap();

        let err = import_repo_car(&car, "did:plc:someoneelse")
            .await
            .unwrap_err();
        assert!(matches!(err, CarImportError::DidMismatch { .. }));
    }

    #[tokio::test]
    async fn import_rejects_garbage_bytes() {
        let err = import_repo_car(b"not a car file", "did:plc:x")
            .await
            .unwrap_err();
        assert!(matches!(err, CarImportError::Car(_)));
    }
}
