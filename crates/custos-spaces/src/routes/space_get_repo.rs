// pattern: Imperative Shell

//! com.atproto.space.getRepo — export a space repo as an `atproto-space-repo` STAR archive
//! (`crate::space_migration`), for full-state recovery and migration.
//!
//! The archive's metadata is the commit, and the MAC over it rides the response headers
//! (`space_mac`), not the body. Records follow in strict bytewise path order, each read as its
//! turn comes, so memory bounds to one record. A consumer verifies as it streams: check the MAC
//! over the commit, fold each record's path and CID into a running set hash, and compare it with
//! the commit's `data` once the archive ends. Blobs are never included (`getBlob`).

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, Did, ErrorCode};
use crypto::http_signature::MacProfile;
use custos_core::lexicon::LexiconParams;
use repo_engine::SpaceStarWriter;

#[derive(Deserialize)]
pub struct SpaceGetRepoParams {
    space: String,
    repo: Did,
}

/// GET /xrpc/com.atproto.space.getRepo
pub async fn space_get_repo(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetRepoParams>,
) -> Result<Response, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    let reader = crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let mac =
        crate::space_mac::mac_grant(&state, &headers, &reader, &params.repo, MacProfile::Commit)
            .await?;
    let repo = crate::views::load_repo(&state, &space.uri, &params.repo).await?;
    let export_error = |e: &dyn std::fmt::Display| {
        tracing::error!(error = %e, space = %space.uri, "failed to export space repo");
        ApiError::new(ErrorCode::InternalError, "failed to export space repo")
    };

    // The paths are collected up front so the head can be re-read around them; only the record
    // values stream lazily. SQL orders `(collection, rkey)`, which is not the archive's bytewise
    // order of `collection/rkey` (`a.b.c/x` sorts before `a.b/x`), so they are sorted here.
    let mut entries: Vec<(String, String)> =
        crate::db::space_repos::list_record_index(&state.db, &space.uri, &params.repo)
            .await
            .map_err(|e| export_error(&e))?
            .into_iter()
            .map(|(collection, rkey, cid)| (format!("{collection}/{rkey}"), cid))
            .collect();
    entries.sort_unstable();

    // The records and the commit must describe the same head: a write landing between the head
    // read and the path read would yield an archive whose records cannot fold to the commit's
    // data. The rev is monotonic, so an unchanged rev on a second read brackets the path read
    // between two identical-head observations.
    let head = crate::views::load_repo(&state, &space.uri, &params.repo).await?;
    if head.rev != repo.rev {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "space repo was modified concurrently; retry against the current head",
        ));
    }

    let commit = crate::views::current_commit(&space, &params.repo, &repo)?;
    let (writer, header) = crate::space_migration::repo_star_writer(&commit)?;
    let response = stream_star(
        state,
        space.uri.clone(),
        params.repo.clone(),
        writer,
        header,
        entries,
    );
    crate::space_mac::with_commit_mac(response, &commit, mac.as_ref())
}

/// Stream the archive: the header, then one pair per record, each fetched as its turn comes,
/// then the end byte.
///
/// A record whose current CID no longer matches the one listed (a concurrent write landed
/// mid-stream), or that the profile refuses, ends the stream with an error rather than an
/// archive that contradicts its own commit; the client retries against the new head.
fn stream_star(
    state: CoreState,
    space_uri: String,
    repo: Did,
    writer: SpaceStarWriter,
    header: Vec<u8>,
    entries: Vec<(String, String)>,
) -> Response {
    struct StarStream {
        state: CoreState,
        space_uri: String,
        repo: Did,
        writer: Option<SpaceStarWriter>,
        header: Option<Vec<u8>>,
        entries: std::vec::IntoIter<(String, String)>,
    }

    let init = StarStream {
        state,
        space_uri,
        repo,
        writer: Some(writer),
        header: Some(header),
        entries: entries.into_iter(),
    };

    let stream = futures_util::stream::unfold(init, |mut st| async move {
        if let Some(header) = st.header.take() {
            return Some((Ok::<Bytes, std::io::Error>(Bytes::from(header)), st));
        }
        let writer = st.writer.as_mut()?;
        let Some((path, cid)) = st.entries.next() else {
            let end = st.writer.take()?.end();
            return Some((Ok(Bytes::from(vec![end])), st));
        };
        let frame = match next_frame(&st.state, &st.space_uri, &st.repo, writer, &path, &cid).await
        {
            Ok(frame) => Ok(Bytes::from(frame)),
            Err(e) => {
                st.writer = None; // stop after this error
                Err(e)
            }
        };
        Some((frame, st))
    });

    async fn next_frame(
        state: &CoreState,
        space_uri: &str,
        repo: &Did,
        writer: &mut SpaceStarWriter,
        path: &str,
        cid: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        let Some((collection, rkey)) = path.split_once('/') else {
            return Err(std::io::Error::other("stored record path is malformed"));
        };
        match crate::db::space_repos::get_record(
            &state.db,
            space_uri,
            repo,
            collection,
            rkey,
        )
        .await
        {
            Ok(Some(row)) if row.cid == cid => {
                writer.pair(path.as_bytes(), &row.value).map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %repo, %path, "space record does not fit the repo archive");
                    std::io::Error::other("space record does not fit the repo archive")
                })
            }
            Ok(_) => {
                tracing::warn!(space = %space_uri, did = %repo, %path, "space record changed mid-export");
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "record changed during space repo export",
                ))
            }
            Err(e) => {
                tracing::error!(error = %e, space = %space_uri, did = %repo, %path, "failed to read record during export");
                Err(std::io::Error::other("failed to read space record"))
            }
        }
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/vnd.dasl.star"),
            // Same posture as space.getBlob: permissioned bytes, never publicly cacheable.
            (header::CACHE_CONTROL, "private"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}
