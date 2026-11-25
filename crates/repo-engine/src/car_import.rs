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

use atrium_repo::blockstore::{CarStore, DAG_CBOR, SHA2_256};
use atrium_repo::repo::Repository;
use atrium_repo::Cid;
use ipld_core::cid::Version;
use ipld_core::ipld::Ipld;
use sha2::Digest;

use crate::genesis::CapturingBlockStore;

/// Fixed repo-format version every ATProto commit carries.
const REPO_VERSION: i64 = 3;

/// The `raw` multicodec. The ATProto data model allows exactly two block codecs, `dag-cbor`
/// and `raw`; a repo CAR is all dag-cbor, but `raw` is tolerated so a CAR carrying extra
/// unreachable blocks doesn't fail structural validation for the wrong reason.
const RAW: u64 = 0x55;

/// SHA2-256 digests are always 32 bytes.
const SHA2_256_DIGEST_LEN: u8 = 32;

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
/// * the CAR's framing is structurally sound — every declared header/frame length fits the
///   remaining input, every block CID is CIDv1 (dag-cbor or raw) with a 32-byte SHA2-256
///   multihash, and every block's bytes hash to its CID (checked by `validate_car` *before*
///   any `CarStore` parsing, so hostile framing is rejected instead of panicking the task or
///   driving attacker-sized allocations);
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
    validate_car(car_bytes)?;

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

/// Structurally validate raw CAR bytes before any `CarStore` parsing.
///
/// `CarStore::open` trusts the input's declared lengths: a frame length shorter than its CID
/// underflows an unchecked subtraction, and a giant declared header or multihash length drives
/// an allocation sized by the attacker — both reachable panics/OOM from user-supplied bytes.
/// It also skips hash verification for non-SHA2-256 CIDs, which the SHA2-256 re-hash on capture
/// would silently re-key, persisting a repo whose MST references the original CID — dangling.
///
/// This front-end closes all three: every declared length must fit the remaining input, every
/// block CID must be CIDv1 (dag-cbor or raw) with a 32-byte SHA2-256 multihash, and every
/// block's bytes must hash to its CID.
fn validate_car(car_bytes: &[u8]) -> Result<(), CarImportError> {
    let err = |msg: &str| CarImportError::Car(msg.to_string());

    let (header_len, rest) =
        decode_varint(car_bytes).ok_or_else(|| err("malformed CAR header length varint"))?;
    let header_len =
        usize::try_from(header_len).map_err(|_| err("CAR header length overflows usize"))?;
    if header_len > rest.len() {
        return Err(err("declared CAR header length exceeds input"));
    }
    let mut rest = &rest[header_len..];

    while !rest.is_empty() {
        let (frame_len, after) =
            decode_varint(rest).ok_or_else(|| err("malformed CAR block frame length varint"))?;
        let frame_len = usize::try_from(frame_len)
            .map_err(|_| err("CAR block frame length overflows usize"))?;
        if frame_len > after.len() {
            return Err(err(
                "declared CAR block frame length exceeds remaining input",
            ));
        }
        let frame = &after[..frame_len];

        // The CID must parse *within its frame* — `CarStore` reads it from the unbounded
        // stream instead, which is exactly how a short frame underflows its data length.
        let mut cid_reader = Cursor::new(frame);
        let cid = Cid::read_bytes(&mut cid_reader)
            .map_err(|e| CarImportError::Car(format!("CAR block frame has an invalid CID: {e}")))?;
        let data = &frame[cid_reader.position() as usize..];

        if cid.version() != Version::V1 {
            return Err(err("CAR block CID is not CIDv1"));
        }
        if cid.codec() != DAG_CBOR && cid.codec() != RAW {
            return Err(err("CAR block CID has an unsupported codec"));
        }
        if cid.hash().code() != SHA2_256 || cid.hash().size() != SHA2_256_DIGEST_LEN {
            return Err(err(
                "CAR block CID has an unsupported multihash (must be SHA2-256)",
            ));
        }
        if cid.hash().digest() != sha2::Sha256::digest(data).as_slice() {
            return Err(err("CAR block bytes do not hash to the block CID"));
        }

        rest = &after[frame_len..];
    }

    Ok(())
}

/// Decode an unsigned LEB128 varint from the front of `input`, returning the value and the
/// remaining bytes. `None` on truncated input or a value overflowing u64. Anything accepted
/// here consumes exactly the same bytes in `CarStore`'s varint reader, so offsets agree;
/// where the two decoders' error domains differ, the stricter side rejects cleanly — the
/// divergence can never reach `CarStore`'s panic paths.
fn decode_varint(input: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    for (i, &byte) in input.iter().enumerate() {
        let bits = u64::from(byte & 0x7f);
        let shift = 7 * i as u32;
        if shift >= 64 || (shift == 63 && bits > 1) {
            return None;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Some((value, &input[i + 1..]));
        }
    }
    None
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

    /// Encode a u64 as an unsigned LEB128 varint (test-side mirror of `decode_varint`).
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// A CAR frame: varint(total length) ++ CID bytes ++ block data.
    fn frame(cid: &Cid, data: &[u8]) -> Vec<u8> {
        let cid_bytes = cid.to_bytes();
        let mut out = varint((cid_bytes.len() + data.len()) as u64);
        out.extend_from_slice(&cid_bytes);
        out.extend_from_slice(data);
        out
    }

    async fn valid_car() -> Vec<u8> {
        let (mut store, root) = seed_repo("did:plc:hostile").await;
        export_repo_car(&mut store, root).await.unwrap()
    }

    fn assert_rejected_as_car_error(result: Result<ImportedRepo, CarImportError>, want: &str) {
        match result {
            Err(CarImportError::Car(msg)) => assert!(
                msg.contains(want),
                "expected rejection mentioning {want:?}, got {msg:?}"
            ),
            other => panic!("expected CarImportError::Car, got {other:?}"),
        }
    }

    /// A frame whose declared length is shorter than its CID underflows an unchecked
    /// subtraction inside `CarStore` (panic in debug, capacity-overflow panic in release).
    /// The validator must reject it before `CarStore` ever parses.
    #[tokio::test]
    async fn import_rejects_frame_shorter_than_its_cid() {
        let mut car = valid_car().await;
        car.extend_from_slice(&varint(2));
        // A valid CIDv1 (dag-cbor, SHA2-256) encoding — 36 bytes, far beyond the declared 2.
        car.extend_from_slice(&[0x01, 0x71, 0x12, 0x20]);
        car.extend_from_slice(&[0u8; 32]);

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "invalid CID");
    }

    /// A giant declared header length must be rejected against the remaining input, not
    /// allocated (`CarStore` does `vec![0; header_len]` before reading).
    #[tokio::test]
    async fn import_rejects_giant_declared_header_length() {
        let mut car = varint(1 << 40);
        car.extend_from_slice(b"tiny");

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "header length exceeds input");
    }

    /// A giant declared block frame length must likewise be bounded by the remaining input.
    #[tokio::test]
    async fn import_rejects_giant_declared_frame_length() {
        let mut car = valid_car().await;
        car.extend_from_slice(&varint(1 << 40));

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "frame length exceeds remaining input");
    }

    /// A block CID with a non-SHA2-256 multihash skips `CarStore`'s hash verification and is
    /// silently re-keyed under a SHA2-256 CID on capture — the dangling-MST-reference vector.
    /// The validator rejects any non-SHA2-256 multihash outright.
    #[tokio::test]
    async fn import_rejects_non_sha256_multihash_cid() {
        use atrium_repo::Multihash;

        let data = b"smuggled";
        // 0x00 is the identity multihash: "digest" = the bytes themselves, nothing to verify.
        let mh = Multihash::wrap(0x00, data).unwrap();
        let cid = Cid::new_v1(DAG_CBOR, mh);

        let mut car = valid_car().await;
        car.extend_from_slice(&frame(&cid, data));

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "unsupported multihash");
    }

    /// A CIDv0 block is outside the ATProto data model (CIDv1 required).
    #[tokio::test]
    async fn import_rejects_cidv0_block() {
        use atrium_repo::Multihash;

        let data = b"old style";
        let mh = Multihash::wrap(SHA2_256, sha2::Sha256::digest(data).as_slice()).unwrap();
        let cid = Cid::new_v0(mh).unwrap();

        let mut car = valid_car().await;
        car.extend_from_slice(&frame(&cid, data));

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "not CIDv1");
    }

    /// Block bytes that don't hash to their stated CID must be rejected.
    #[tokio::test]
    async fn import_rejects_block_hash_mismatch() {
        use atrium_repo::Multihash;

        let mh = Multihash::wrap(SHA2_256, sha2::Sha256::digest(b"good bytes").as_slice()).unwrap();
        let cid = Cid::new_v1(DAG_CBOR, mh);

        let mut car = valid_car().await;
        car.extend_from_slice(&frame(&cid, b"evil bytes"));

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "do not hash to the block CID");
    }

    /// A truncated trailing varint (a lone continuation byte) is malformed framing.
    #[tokio::test]
    async fn import_rejects_truncated_trailing_varint() {
        let mut car = valid_car().await;
        car.push(0x80);

        let result = import_repo_car(&car, "did:plc:hostile").await;
        assert_rejected_as_car_error(result, "frame length varint");
    }
}
