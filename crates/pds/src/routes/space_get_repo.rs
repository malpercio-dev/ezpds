// pattern: Imperative Shell

//! com.atproto.space.getRepo — export a permissioned repo as a two-root CAR, for full-state
//! recovery.
//!
//! The CAR declares two roots in order: the signed commit, then a DRISL index mapping
//! `{collection}/{rkey}` to record CID in canonical DAG-CBOR map key order (shortest key
//! first, then bytewise). Record blocks follow in the index's order, so a consumer can verify
//! as it streams: check sig+mac, fold the index into a running LtHash and compare against the
//! commit's hash, then check each block against the CID the index promised. `excludeValues`
//! writes only the two roots — the index still authenticates against the commit, since the set
//! hash folds from index entries rather than blocks. Blobs are never included (`getBlob`).

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::ser::SerializeMap;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};
use repo_engine::Cid;

#[derive(Deserialize)]
pub struct SpaceGetRepoParams {
    space: String,
    repo: String,
    #[serde(default, rename = "excludeValues")]
    exclude_values: bool,
}

/// GET /xrpc/com.atproto.space.getRepo
pub async fn space_get_repo(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetRepoParams>,
) -> Result<Response, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let repo = super::space_views::load_repo(&state, &space.uri, &params.repo).await?;

    // The index has to precede the blocks it describes, so paths are collected up front; only
    // the record blocks themselves stream lazily.
    let mut entries = crate::db::space_repos::list_record_index(&state.db, &space.uri, &params.repo)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to read space record index");
            ApiError::new(ErrorCode::InternalError, "failed to export space repo")
        })?
        .into_iter()
        .map(|(collection, rkey, cid)| {
            let cid = Cid::try_from(cid.as_str()).map_err(|e| {
                tracing::error!(error = %e, space = %space.uri, cid = %cid, "stored record cid is malformed");
                ApiError::new(ErrorCode::InternalError, "failed to export space repo")
            })?;
            Ok((format!("{collection}/{rkey}"), cid))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    // A consumer walks the index as the cbor encoder ordered its keys, so blocks follow the
    // same canonical order.
    entries.sort_unstable_by(|(a, _), (b, _)| canonical_key_order(a, b));

    // The index and the commit must describe the same head: a write landing between the head
    // read and the index read would yield a 200 CAR whose index cannot fold to the commit's
    // hash. The rev is monotonic, so an unchanged rev on a second read brackets the index read
    // between two identical-head observations.
    let head = super::space_views::load_repo(&state, &space.uri, &params.repo).await?;
    if head.rev != repo.rev {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "space repo was modified concurrently; retry against the current head",
        ));
    }

    let commit =
        super::space_views::sign_current_commit(&state, &space, &params.repo, &repo).await?;
    let commit_bytes = encode_commit_block(&commit);
    let index_bytes = encode_index_block(&entries);
    let (commit_cid, index_cid) = match (
        repo_engine::dag_cbor_block_cid(&commit_bytes),
        repo_engine::dag_cbor_block_cid(&index_bytes),
    ) {
        (Ok(c), Ok(i)) => (c, i),
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!(error = %e, space = %space.uri, "failed to hash space CAR root block");
            return Err(ApiError::new(
                ErrorCode::InternalError,
                "failed to export space repo",
            ));
        }
    };

    let mut head = repo_engine::car_v1_header_roots(vec![commit_cid, index_cid]);
    head.extend_from_slice(&repo_engine::car_v1_block_frame(commit_cid, &commit_bytes));
    head.extend_from_slice(&repo_engine::car_v1_block_frame(index_cid, &index_bytes));

    Ok(stream_car(
        state,
        space.uri.clone(),
        params.repo,
        head,
        if params.exclude_values {
            Vec::new()
        } else {
            entries
        },
    ))
}

/// Canonical DAG-CBOR map key order: shortest first, then bytewise.
fn canonical_key_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// The signed-commit root block, encoded as canonical DAG-CBOR.
///
/// serde_ipld_dagcbor writes struct fields in declaration order, so this struct declares them
/// in canonical map key order — length first, then bytewise: ikm, mac, rev, sig, ver, hash. A
/// unit test pins the byte-level ordering against a decoder.
fn encode_commit_block(commit: &crypto::SignedSpaceCommit) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct CommitBlock<'a> {
        #[serde(with = "serde_bytes")]
        ikm: &'a [u8],
        #[serde(with = "serde_bytes")]
        mac: &'a [u8],
        rev: &'a str,
        #[serde(with = "serde_bytes")]
        sig: &'a [u8],
        ver: u8,
        #[serde(with = "serde_bytes")]
        hash: &'a [u8],
    }
    // A tiny fixed-shape map; DAG-CBOR encoding cannot fail.
    serde_ipld_dagcbor::to_vec(&CommitBlock {
        ikm: &commit.ikm,
        mac: &commit.mac,
        rev: &commit.rev,
        sig: &commit.sig,
        ver: commit.ver,
        hash: &commit.hash,
    })
    .expect("encode space commit block")
}

/// The DRISL index root block: `{collection}/{rkey}` → record CID link, entries already in
/// canonical order (the caller sorted them; serde_ipld_dagcbor writes map entries as fed).
fn encode_index_block(entries: &[(String, Cid)]) -> Vec<u8> {
    struct IndexBlock<'a>(&'a [(String, Cid)]);
    impl serde::Serialize for IndexBlock<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for (path, cid) in self.0 {
                map.serialize_entry(path, cid)?;
            }
            map.end()
        }
    }
    serde_ipld_dagcbor::to_vec(&IndexBlock(entries)).expect("encode space repo index")
}

/// Stream the CAR: the pre-built header + two root frames, then one frame per index entry,
/// each record block fetched as its turn comes (memory bounds to one block).
///
/// A block whose current CID no longer matches the index — a concurrent write landed
/// mid-stream — ends the stream with an error rather than emitting a CAR whose blocks
/// contradict its own commit; the client retries against the new head.
fn stream_car(
    state: AppState,
    space_uri: String,
    did: String,
    head: Vec<u8>,
    entries: Vec<(String, Cid)>,
) -> Response {
    struct CarStream {
        state: AppState,
        space_uri: String,
        did: String,
        head: Option<Vec<u8>>,
        entries: Vec<(String, Cid)>,
        next: usize,
    }

    let init = CarStream {
        state,
        space_uri,
        did,
        head: Some(head),
        entries,
        next: 0,
    };

    let stream = futures_util::stream::unfold(init, |mut st| async move {
        if let Some(head) = st.head.take() {
            return Some((Ok::<Bytes, std::io::Error>(Bytes::from(head)), st));
        }
        if st.next >= st.entries.len() {
            return None;
        }
        let (path, cid) = st.entries[st.next].clone();
        st.next += 1;
        let (collection, rkey) = path.split_once('/').expect("index path shape");
        match crate::db::space_repos::get_record(
            &st.state.db,
            &st.space_uri,
            &st.did,
            collection,
            rkey,
        )
        .await
        {
            Ok(Some(row)) if row.cid == cid.to_string() => {
                let frame = repo_engine::car_v1_block_frame(cid, &row.value);
                Some((Ok(Bytes::from(frame)), st))
            }
            Ok(_) => {
                tracing::warn!(space = %st.space_uri, did = %st.did, %path, "space record changed mid-export");
                st.next = st.entries.len(); // stop after this error frame
                let err = std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "record changed during space repo export",
                );
                Some((Err(err), st))
            }
            Err(e) => {
                tracing::error!(error = %e, space = %st.space_uri, did = %st.did, %path, "failed to read record during export");
                st.next = st.entries.len();
                let err = std::io::Error::other("failed to read space record");
                Some((Err(err), st))
            }
        }
    });

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/vnd.ipld.car"),
            // Same posture as space.getBlob: permissioned bytes, never publicly cacheable.
            (header::CACHE_CONTROL, "private"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_commit() -> crypto::SignedSpaceCommit {
        crypto::SignedSpaceCommit {
            ver: 1,
            hash: [1; 32],
            ikm: [2; 32],
            sig: [3; 64],
            mac: [4; 32],
            rev: "3lztsjenmq22a".to_string(),
        }
    }

    /// The commit block's map keys must come out in canonical DAG-CBOR order (length first,
    /// then bytewise) — the ordering the reference's canonical encoder produces, and what the
    /// spec pins for the CAR. Decoding into an order-preserving probe would need a custom
    /// Deserialize; scanning for the key byte-patterns in the tiny encoded map is enough.
    #[test]
    fn commit_block_keys_are_canonically_ordered() {
        let bytes = encode_commit_block(&test_commit());
        let positions: Vec<usize> = ["ikm", "mac", "rev", "sig", "ver", "hash"]
            .iter()
            .map(|key| {
                // A text-string key of length n < 24 is encoded as 0x60+n followed by the
                // UTF-8 bytes; search for that exact pattern.
                let mut needle = vec![0x60 + key.len() as u8];
                needle.extend_from_slice(key.as_bytes());
                bytes
                    .windows(needle.len())
                    .position(|w| w == needle.as_slice())
                    .unwrap_or_else(|| panic!("key {key} not found in commit block"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "commit block keys must appear in canonical order ikm, mac, rev, sig, ver, hash; got positions {positions:?}"
        );
    }

    /// The index block round-trips as a DAG-CBOR map whose values are CID links, with entries
    /// in exactly the order fed in.
    #[test]
    fn index_block_encodes_paths_to_cid_links() {
        let cid_a = repo_engine::dag_cbor_block_cid(b"a").unwrap();
        let cid_b = repo_engine::dag_cbor_block_cid(b"b").unwrap();
        let entries = vec![
            ("a.b.c/one".to_string(), cid_a),
            ("a.b.c/three".to_string(), cid_b),
        ];
        let bytes = encode_index_block(&entries);

        let decoded: std::collections::BTreeMap<String, ipld_core::ipld::Ipld> =
            serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        match &decoded["a.b.c/one"] {
            ipld_core::ipld::Ipld::Link(link) => assert_eq!(*link, cid_a),
            other => panic!("index value must be a CID link, got {other:?}"),
        }
    }

    /// Canonical order sorts by length before bytes: a shorter path sorts first even when it
    /// is lexicographically greater.
    #[test]
    fn canonical_order_is_length_first() {
        let mut paths = vec!["a.b.c/zz", "a.b.c/aaa", "z.z.z/a"];
        paths.sort_unstable_by(|a, b| canonical_key_order(a, b));
        assert_eq!(paths, vec!["z.z.z/a", "a.b.c/zz", "a.b.c/aaa"]);
    }
}
